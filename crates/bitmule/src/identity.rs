//! Local identity storage for the `bitmule` CLI.
//!
//! Each identity is a `(name, Ed25519 signing keypair, X25519 KEX keypair)`
//! triple. Both public keys are shared with peers so they can verify
//! signatures AND run a session-key exchange without pulling in the
//! Ed25519→Montgomery conversion.
//!
//! Layout under `$XDG_CONFIG_HOME/bitmule/identities/`:
//!
//! ```text
//! <name>.json          mode 0600
//! ```
//!
//! The link + QR the CLI hands out contains ONLY the public halves.
//! Private halves never leave the config file.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

/// Persisted identity file. Both key pairs live here in URL-safe-no-pad
/// base64. Human-readable so users can grep, back up, and inspect.
#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub created_unix: u64,
    /// 32-byte Ed25519 signing secret, base64url no-pad.
    pub ed25519_secret_b64: String,
    /// 32-byte Ed25519 verifying key, base64url no-pad.
    pub ed25519_public_b64: String,
    /// 32-byte X25519 secret, base64url no-pad.
    pub x25519_secret_b64: String,
    /// 32-byte X25519 public, base64url no-pad.
    pub x25519_public_b64: String,
}

impl Identity {
    pub fn generate(name: impl Into<String>) -> Self {
        let name = name.into();
        let mut csprng = OsRng;
        let ed_sk = SigningKey::generate(&mut csprng);
        let ed_pk = ed_sk.verifying_key();

        // x25519-dalek 2.x StaticSecret needs a 32-byte array; fill from OsRng.
        let mut x_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut x_seed);
        let x_sk = XSecret::from(x_seed);
        let x_pk = XPublic::from(&x_sk);

        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            name,
            created_unix,
            ed25519_secret_b64: URL_SAFE_NO_PAD.encode(ed_sk.to_bytes()),
            ed25519_public_b64: URL_SAFE_NO_PAD.encode(ed_pk.to_bytes()),
            x25519_secret_b64: URL_SAFE_NO_PAD.encode(x_sk.to_bytes()),
            x25519_public_b64: URL_SAFE_NO_PAD.encode(x_pk.to_bytes()),
        }
    }

    /// Concat `[ed25519_pub || x25519_pub]` = 64 bytes, then URL-safe base64.
    /// This is the "one public key" surface users share.
    pub fn public_blob_b64(&self) -> Result<String> {
        let ed = URL_SAFE_NO_PAD
            .decode(&self.ed25519_public_b64)
            .context("bad ed25519_public_b64")?;
        let x = URL_SAFE_NO_PAD
            .decode(&self.x25519_public_b64)
            .context("bad x25519_public_b64")?;
        if ed.len() != 32 || x.len() != 32 {
            bail!("public halves must be 32 bytes each");
        }
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&ed);
        buf.extend_from_slice(&x);
        Ok(URL_SAFE_NO_PAD.encode(buf))
    }

    /// Sharable link. Uses `<contact_base>/c/<name>/<pubkey>` so a recipient
    /// can paste it into `bitmule add <url>` OR open it in a browser and get
    /// a well-known contact landing page from `bitmule.net` (or self-hosted).
    pub fn share_link(&self, contact_base: &str) -> Result<String> {
        let pk = self.public_blob_b64()?;
        let name = utf8_percent_encode(&self.name, NON_ALPHANUMERIC).to_string();
        Ok(format!("{}/c/{}/{}", contact_base.trim_end_matches('/'), name, pk))
    }
}

/// Default HTTPS root for `share_link`. Users can override with
/// `--contact-base <url>` on `identity add`.
pub const DEFAULT_CONTACT_BASE: &str = "https://bitmule.net";

/// Parse a `<contact_base>/c/<name>/<pubkey_b64url>` URL into (name, pubkey_b64url).
/// Rejects malformed forms with a readable error. Accepts any host; only the
/// path shape is load-bearing.
pub fn parse_contact_url(s: &str) -> Result<(String, String)> {
    let after_scheme = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .ok_or_else(|| anyhow!("contact URL must start with https:// or http://"))?;

    // path segments start after the first `/`
    let (_host, path) = after_scheme
        .split_once('/')
        .ok_or_else(|| anyhow!("contact URL is missing a path"))?;
    let path = path.trim_end_matches('/');
    let parts: Vec<&str> = path.split('/').collect();
    // expected shape: ["c", "<name>", "<pubkey>"]
    let (name, pk) = match parts.as_slice() {
        ["c", name, pk] => (*name, *pk),
        _ => bail!("contact URL path must be /c/<name>/<pubkey>, got /{path}"),
    };
    let name = percent_encoding::percent_decode_str(name)
        .decode_utf8()
        .map_err(|e| anyhow!("decode contact name: {e}"))?
        .into_owned();
    if !is_safe_name(&name) {
        bail!("contact name {name:?} must be [A-Za-z0-9._-]{{1,64}}");
    }
    // Validate pubkey decodes to 64 bytes so a garbage URL fails at parse time.
    let decoded = URL_SAFE_NO_PAD
        .decode(pk)
        .map_err(|e| anyhow!("pubkey base64: {e}"))?;
    if decoded.len() != 64 {
        bail!("contact pubkey must be 64 bytes (32 ed25519 || 32 x25519), got {}", decoded.len());
    }
    Ok((name, pk.to_string()))
}

/// Root config dir for the CLI: `$XDG_CONFIG_HOME/bitmule/` or the
/// platform equivalent.
pub fn config_root() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("no config dir on this platform"))?;
    Ok(base.join("bitmule"))
}

pub fn identities_dir() -> Result<PathBuf> {
    Ok(config_root()?.join("identities"))
}

pub fn contacts_dir() -> Result<PathBuf> {
    Ok(config_root()?.join("contacts"))
}

fn identity_path(dir: &Path, name: &str) -> Result<PathBuf> {
    if !is_safe_name(name) {
        bail!(
            "identity name {name:?} must be [A-Za-z0-9._-]{{1,64}} (no path traversal)"
        );
    }
    Ok(dir.join(format!("{name}.json")))
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Persisted contact file. Just the public halves plus provenance.
#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub added_unix: u64,
    /// 64-byte concat blob (32 ed25519 || 32 x25519), base64url no-pad.
    pub public_blob_b64: String,
    /// Where the contact came from: "raw" (name + key on the CLI) or the URL text.
    pub source: String,
}

/// Save a contact under `name` with `pubkey_b64` (must decode to 64 bytes).
/// Refuses to overwrite an existing contact with a different key.
pub async fn save_contact(name: &str, pubkey_b64: &str, source: &str) -> Result<Contact> {
    // Validate name + key up front.
    if !is_safe_name(name) {
        bail!("contact name {name:?} must be [A-Za-z0-9._-]{{1,64}}");
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(pubkey_b64)
        .map_err(|e| anyhow!("pubkey base64: {e}"))?;
    if decoded.len() != 64 {
        bail!(
            "contact pubkey must be 64 bytes (32 ed25519 || 32 x25519), got {}",
            decoded.len()
        );
    }

    let dir = contacts_dir()?;
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create {}", dir.display()))?;
    let path = identity_path(&dir, name)?;

    if let Ok(existing_bytes) = tokio::fs::read(&path).await {
        if let Ok(existing) = serde_json::from_slice::<Contact>(&existing_bytes) {
            if existing.public_blob_b64 == pubkey_b64 {
                // Idempotent re-add: no-op.
                return Ok(existing);
            }
            bail!(
                "contact {name:?} already exists at {} with a DIFFERENT key. \
                 Remove the file explicitly to replace.",
                path.display()
            );
        }
    }

    let added_unix = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let contact = Contact {
        name: name.to_string(),
        added_unix,
        public_blob_b64: pubkey_b64.to_string(),
        source: source.to_string(),
    };
    let json = serde_json::to_vec_pretty(&contact)?;
    tokio::fs::write(&path, &json).await?;
    Ok(contact)
}

/// Create + persist a new identity under `name`. Refuses to overwrite.
pub async fn create(name: &str) -> Result<Identity> {
    let dir = identities_dir()?;
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create {}", dir.display()))?;
    let path = identity_path(&dir, name)?;
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        bail!(
            "identity {name:?} already exists at {} (remove it explicitly to replace)",
            path.display()
        );
    }
    let id = Identity::generate(name);
    let json = serde_json::to_vec_pretty(&id)?;

    // Write with 0600 mode. Create the file with restrictive perms up front
    // rather than fs::write + chmod (avoids a race where a reader could see
    // the world-readable file before we tighten).
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .await
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(&json).await?;
        f.sync_all().await?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(&path, &json).await?;
    }

    Ok(id)
}
