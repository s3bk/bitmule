//! The account record — the thing the browser keeps and the native app has to
//! open (web/vault.js, rev 21).
//!
//! An account is one P-256 key pair (ECDH: the key an invite seals to and a
//! hosted upload's file key is wrapped to) plus the granter tokens of the
//! invites it made and the links of the shares it created. It lives on the
//! device as a single JSON record: a header that is not secret (format, KDF
//! parameters, salt, the public key) and one AES-256-GCM ciphertext holding
//! the private key. The key to that ciphertext is PBKDF2-SHA-256 over a
//! password the user chose, which is never stored, never sent and cannot be
//! reset — there is no server side to an account.
//!
//! The format is deliberately boring so both clients open the same record:
//!
//! ```json
//! { "v": 1, "kind": "bitmule-account",
//!   "created": "<ISO 8601>", "label": "<name>", "plan": "basic" | "extended",
//!   "pub": "<b64url, raw P-256 uncompressed point>",
//!   "kdf": { "alg": "PBKDF2-SHA-256", "iters": 600000, "salt": "<b64url>" },
//!   "cipher": { "alg": "AES-256-GCM", "iv": "<b64url>" },
//!   "ct": "<b64url>" }
//! ```
//!
//! The additional data is the ASCII string
//!
//! ```text
//! bitmule-account-v1|created|label|plan|iters|salt|pub
//! ```
//!
//! with `plan` only when the record carries it (a record written before the
//! field existed still opens), `iters` in decimal and both other values
//! base64url — so a record whose header was edited does not open even when the
//! password is right. The plaintext is the [`Account`].
//!
//! Nothing here talks to a server: minting an account record is local, and the
//! server's answer to the account's registration (its id and the bearer it
//! hands back) is stored inside the ciphertext.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Raised only with the format: it is written into every record, so an old
/// backup keeps opening at the cost it was made with.
pub const ITERS: u32 = 600_000;
pub const MIN_PASSWORD: usize = 10;
pub const PLAN_DEFAULT: &str = "basic";
const AAD_TAG: &str = "bitmule-account-v1";

pub type Result<T> = std::result::Result<T, anyhow::Error>;

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kdf {
    pub alg: String,
    pub iters: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub alg: String,
    pub iv: String,
}

/// The stored record. Fields are kept as the browser writes them — including
/// `plan`, which old records do not have and new ones must not lose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    pub kind: String,
    pub created: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(rename = "pub")]
    pub public_key: String,
    pub kdf: Kdf,
    pub cipher: Cipher,
    pub ct: String,
}

impl Record {
    /// Everything a reader trusts before decrypting, in the order vault.js
    /// builds it. `plan` is in the string only when the record carries it.
    pub fn aad(&self) -> Vec<u8> {
        let mut parts = vec![
            AAD_TAG.to_string(),
            self.created.clone(),
            self.label.clone(),
        ];
        if let Some(plan) = self.plan.as_deref() {
            parts.push(plan.to_string());
        }
        parts.push(self.kdf.iters.to_string());
        parts.push(self.kdf.salt.clone());
        parts.push(self.public_key.clone());
        parts.join("|").into_bytes()
    }

    pub fn plan(&self) -> &str {
        self.plan.as_deref().unwrap_or(PLAN_DEFAULT)
    }
}

/// Parse and check a record, with the same refusals vault.js makes: a
/// different format, an unknown KDF or cipher, an incomplete record.
pub fn parse(json: &str) -> Result<Record> {
    let r: Record =
        serde_json::from_str(json).map_err(|_| anyhow::anyhow!("that is not JSON"))?;
    if r.v != 1 || r.kind != "bitmule-account" {
        anyhow::bail!("that is not a bitmule account record");
    }
    if r.kdf.alg != "PBKDF2-SHA-256" || r.kdf.salt.is_empty() || r.kdf.iters == 0 {
        anyhow::bail!("unknown key derivation in the record");
    }
    if r.cipher.alg != "AES-256-GCM" || r.cipher.iv.is_empty() {
        anyhow::bail!("unknown cipher in the record");
    }
    if r.ct.is_empty() || r.public_key.is_empty() || r.created.is_empty() {
        anyhow::bail!("the record is incomplete");
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// The account inside it
// ---------------------------------------------------------------------------

/// The plaintext. `invites` and `shares` stay as JSON values on purpose: they
/// are lists the app appends to, and a client that re-seals a record must not
/// drop fields a newer version wrote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub v: u32,
    pub kind: String,
    pub created: String,
    pub label: String,
    #[serde(rename = "pub")]
    pub public_key: String,
    #[serde(rename = "priv")]
    pub private_jwk: serde_json::Value,
    #[serde(default)]
    pub invites: Vec<serde_json::Value>,
    #[serde(default)]
    pub shares: Vec<serde_json::Value>,
    /// What the server knows this account by. Inside the ciphertext, not in
    /// the AAD, so a record written before accounts existed still opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl Account {
    /// The raw public point, as the server is given it.
    pub fn public_raw(&self) -> Result<Vec<u8>> {
        Ok(B64.decode(&self.public_key)?)
    }

    /// The private scalar, rebuilt from the JWK the browser exported.
    pub fn secret_key(&self) -> Result<SecretKey> {
        let d = jwk_field(&self.private_jwk, "d")?;
        Ok(SecretKey::from_slice(&d)?)
    }
}

fn jwk_field(jwk: &serde_json::Value, name: &str) -> Result<Vec<u8>> {
    let s = jwk
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("the private key has no `{name}`"))?;
    Ok(B64.decode(s)?)
}

// ---------------------------------------------------------------------------
// Making one
// ---------------------------------------------------------------------------

/// A fresh P-256 key pair, in both shapes the record needs: the raw
/// uncompressed point the server and the links carry, and the JWK the
/// ciphertext holds.
pub struct Keypair {
    pub public_raw: Vec<u8>,
    pub private_jwk: serde_json::Value,
    secret: Zeroizing<Vec<u8>>,
}

impl Keypair {
    /// The key in the shape an invite's `granter` field wants.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

pub fn generate_keypair() -> Result<Keypair> {
    let secret = SecretKey::random(&mut OsRng);
    keypair_from(secret)
}

fn keypair_from(secret: SecretKey) -> Result<Keypair> {
    let point = secret.public_key().to_encoded_point(false);
    let public_raw = point.as_bytes().to_vec();
    let x = point.x().ok_or_else(|| anyhow::anyhow!("no x"))?;
    let y = point.y().ok_or_else(|| anyhow::anyhow!("no y"))?;
    let d = secret.to_bytes(); // zeroizes on drop
    let private_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64.encode(x),
        "y": B64.encode(y),
        "d": B64.encode(&*d),
    });
    Ok(Keypair {
        public_raw,
        private_jwk,
        secret: Zeroizing::new(d.to_vec()),
    })
}

/// First run: mint a pair and seal it under a new password.
pub fn create(label: &str, password: &str, plan: Option<&str>) -> Result<(Record, Account)> {
    if password.chars().count() < MIN_PASSWORD {
        anyhow::bail!("Use at least {MIN_PASSWORD} characters.");
    }
    let keys = generate_keypair()?;
    create_with_iters(label, password, plan, &keys, ITERS)
}

fn create_with_iters(
    label: &str,
    password: &str,
    plan: Option<&str>,
    keys: &Keypair,
    iters: u32,
) -> Result<(Record, Account)> {
    let created = iso8601_now();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut record = Record {
        v: 1,
        kind: "bitmule-account".into(),
        created: created.clone(),
        label: label.trim().to_string(),
        plan: Some(plan.unwrap_or(PLAN_DEFAULT).to_string()),
        public_key: B64.encode(&keys.public_raw),
        kdf: Kdf {
            alg: "PBKDF2-SHA-256".into(),
            iters,
            salt: B64.encode(salt),
        },
        cipher: Cipher {
            alg: "AES-256-GCM".into(),
            iv: String::new(),
        },
        ct: String::new(),
    };
    let account = Account {
        v: 1,
        kind: "bitmule-account-key".into(),
        created,
        label: record.label.clone(),
        public_key: record.public_key.clone(),
        private_jwk: keys.private_jwk.clone(),
        invites: Vec::new(),
        shares: Vec::new(),
        account_id: None,
        secret: None,
    };
    seal_into(&mut record, password, &account)?;
    Ok((record, account))
}

// ---------------------------------------------------------------------------
// Opening and sealing
// ---------------------------------------------------------------------------

/// The one decryption: a record and a password in, the account out. A client
/// that stays unlocked derives the key once (`record_key`) and then calls
/// `open_with_key`, so the password itself need not be kept in memory.
pub fn open(record: &Record, password: &str) -> Result<Account> {
    open_with_key(record, &*record_key(record, password)?)
}

/// The record's key, derived from a password at the record's own salt and
/// cost. The caller may hold this instead of the password while it stays
/// unlocked; it opens this record and nothing else.
pub fn record_key(record: &Record, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    Ok(derive(password, &B64.decode(&record.kdf.salt)?, record.kdf.iters))
}

/// Decrypt with a key already derived by `record_key`.
pub fn open_with_key(record: &Record, key: &[u8; 32]) -> Result<Account> {
    let iv = B64.decode(&record.cipher.iv)?;
    if iv.len() != 12 {
        anyhow::bail!("the record's IV is not 12 bytes");
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &B64.decode(&record.ct)?,
                aad: &record.aad(),
            },
        )
        .map_err(|_| anyhow::anyhow!("wrong password, or the record was edited"))?;
    let account: Account = serde_json::from_slice(&plain)?;
    Ok(account)
}

/// Re-seal an account into a record (new IV every time, new salt only on a
/// password change — which is what `record` carries).
pub fn seal_into(record: &mut Record, password: &str, account: &Account) -> Result<()> {
    seal_with_key(record, &*record_key(record, password)?, account)
}

/// Re-seal with a key already derived by `record_key`. The salt in the record
/// is left alone, so the same key opens it again.
pub fn seal_with_key(record: &mut Record, key: &[u8; 32], account: &Account) -> Result<()> {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let plain = serde_json::to_vec(account)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &plain,
                aad: &record.aad(),
            },
        )
        .map_err(|_| anyhow::anyhow!("could not seal the account"))?;
    record.cipher.iv = B64.encode(iv);
    record.ct = B64.encode(ct);
    Ok(())
}

/// Change the password: a new salt at the current cost, the same account.
pub fn change_password(record: &mut Record, old: &str, new: &str) -> Result<()> {
    if new.chars().count() < MIN_PASSWORD {
        anyhow::bail!("Use at least {MIN_PASSWORD} characters.");
    }
    let account = open(record, old)?;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    record.kdf.salt = B64.encode(salt);
    record.kdf.iters = ITERS;
    seal_into(record, new, &account)
}

/// PBKDF2-HMAC-SHA-256, one block (32 bytes out), as WebCrypto's
/// `deriveKey(PBKDF2, AES-GCM-256)` produces it.
pub fn derive(password: &str, salt: &[u8], iters: u32) -> Zeroizing<[u8; 32]> {
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let mac_for = |key: &[u8]| -> Hmac<Sha256> {
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key")
    };
    let mut mac = mac_for(&password);
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;
    for _ in 1..iters.max(1) {
        let mut mac = mac_for(&password);
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= *b;
        }
    }
    u.zeroize();
    Zeroizing::new(out)
}

// ---------------------------------------------------------------------------
// What the key is for
// ---------------------------------------------------------------------------

/// ECDH against a peer's raw public point (an invite names this account's
/// `pub`, so an uploader can wrap a file key to it).
pub fn ecdh(account: &Account, peer_raw: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let secret = account.secret_key()?;
    let peer = PublicKey::from_sec1_bytes(peer_raw)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(Zeroizing::new(*shared.raw_secret_bytes().as_ref()))
}

// ---------------------------------------------------------------------------
// Time, without a date crate
// ---------------------------------------------------------------------------

/// `2026-11-25T21:10:45.123Z`, which is what `new Date().toISOString()` gives
/// and what the AAD carries — so it has to match, field for field.
pub fn iso8601_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    iso8601_from(now.as_secs(), now.subsec_millis())
}

fn iso8601_from(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-from-civil, inverted.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_the_known_vector() {
        // RFC 7914 §11 / the usual PBKDF2-HMAC-SHA256 vector.
        let dk = derive("passwd", b"salt", 1);
        assert_eq!(
            hex(&*dk),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        let dk = derive("Password", b"NaCl", 80000);
        assert_eq!(
            hex(&*dk),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn round_trip_small_iters() {
        let keys = generate_keypair().unwrap();
        let (mut rec, acct) =
            create_with_iters("me", "correct horse battery", Some("extended"), &keys, 1000)
                .unwrap();
        let opened = open(&rec, "correct horse battery").unwrap();
        assert_eq!(opened.label, "me");
        assert_eq!(opened.public_key, acct.public_key);
        assert_eq!(opened.private_jwk, acct.private_jwk);
        assert_eq!(rec.plan(), "extended");

        // the same record re-sealed under the same password still opens
        let mut copy = acct.clone();
        copy.account_id = Some("acct_1".into());
        seal_into(&mut rec, "correct horse battery", &copy).unwrap();
        assert_eq!(open(&rec, "correct horse battery").unwrap().account_id.as_deref(), Some("acct_1"));

        assert!(open(&rec, "correct horse batterY").is_err());
    }

    #[test]
    fn an_edited_header_does_not_open() {
        let keys = generate_keypair().unwrap();
        let (rec, _) = create_with_iters("me", "correct horse battery", None, &keys, 1000).unwrap();
        for edit in 0..3 {
            let mut r = rec.clone();
            match edit {
                0 => r.plan = Some("extended".into()),
                1 => r.kdf.iters = 1001,
                _ => r.label = "someone else".into(),
            }
            assert!(open(&r, "correct horse battery").is_err(), "edit {edit} opened");
        }
    }

    #[test]
    fn refuses_what_vault_refuses() {
        assert!(parse("not json").is_err());
        assert!(parse(r#"{"v":2,"kind":"bitmule-account"}"#).is_err());
        let keys = generate_keypair().unwrap();
        let (rec, _) = create_with_iters("me", "correct horse battery", None, &keys, 10).unwrap();
        let mut other = rec.clone();
        other.kdf.alg = "scrypt".into();
        assert!(parse(&serde_json::to_string(&other).unwrap()).is_err());
        assert!(create("me", "short", None).is_err());
    }

    #[test]
    fn ecdh_agrees_both_ways() {
        let a = generate_keypair().unwrap();
        let b = generate_keypair().unwrap();
        let (_, acct_a) = create_with_iters("a", "correct horse battery", None, &a, 10).unwrap();
        let (_, acct_b) = create_with_iters("b", "correct horse battery", None, &b, 10).unwrap();
        let ab = ecdh(&acct_a, &b.public_raw).unwrap();
        let ba = ecdh(&acct_b, &a.public_raw).unwrap();
        assert_eq!(*ab, *ba);
        assert_ne!(*ab, [0u8; 32]);
    }

    #[test]
    fn dates_look_like_javascript() {
        assert_eq!(iso8601_from(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_from(1_764_105_045, 123), "2025-11-25T21:10:45.123Z");
    }

    /// The promise vault.js makes in its header: the native app opens the
    /// record the browser wrote. `tests/fixtures/browser-account.json` is
    /// produced by WebCrypto itself (`node tests/make-fixture.js`).
    #[test]
    fn opens_a_record_the_browser_wrote() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/browser-account.json");
        let json = std::fs::read_to_string(path).unwrap();
        let rec = parse(&json).unwrap();
        let acct = open(&rec, "correct horse battery staple").unwrap();
        assert_eq!(acct.label, "browser");
        assert_eq!(acct.public_key, rec.public_key);
        assert_eq!(acct.kind, "bitmule-account-key");
        // the private key in the record is the one for that public point
        let secret = acct.secret_key().unwrap();
        let point = secret.public_key().to_encoded_point(false);
        assert_eq!(B64.encode(point.as_bytes()), rec.public_key);
        assert!(open(&rec, "correct horse battery stapl").is_err());
    }
}
