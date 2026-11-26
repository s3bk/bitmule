//! The account, in the native client.
//!
//! The record on disk is the very one bitmule.net/app writes (`web/vault.js`,
//! `bm.account.v1`): one P-256 key pair, sealed under the password with
//! PBKDF2-HMAC-SHA-256 and AES-256-GCM. A backup taken in the browser opens
//! here, and a backup taken here opens in the browser — `bitmule-account`
//! keeps the two byte-for-byte in step, including the AAD.
//!
//! What the app does with it, in the spec's order (§5.2): create on this
//! device, unlock with the password, and *activate* once against the server
//! with a token the operator minted. Activation is the only step that talks
//! to the server, and it is what makes the account allowed to mint storage
//! (`POST /v1/pub/shares`, `POST /v1/pub/i/<id>`); nothing after it asks for
//! the password again until the app is locked.
//!
//! The password is not kept while unlocked: `record_key` is derived once and
//! the derived key is held instead, and it is that key which re-seals the
//! record when activation stores the account id and secret.
//!
//! The password itself lives in the desktop's keyring (`keyring.rs`: KWallet 6
//! or GNOME Keyring over the Secret Service API) whenever one is there, so it
//! is typed once and never again. A person who would rather not have one at
//! all can leave the field empty: the app then makes a random password, seals
//! the record with it and puts it in the keyring — the record stays exactly
//! the browser's shape, so a backup still opens at bitmule.net/app with the
//! password the app showed once. Where there is no keyring, the password is
//! asked for, as before.

use crate::keyring;
use base64::Engine;
use bitmule_account as vault;
use qmetaobject::*;
use std::path::PathBuf;
use zeroize::Zeroizing;

const ACCOUNT_FILE_NAME: &str = "account.json";
const DEFAULT_SERVER: &str = "https://bitmule.qdat.net";

/// Run one keyring call to completion on the thread that asked. The keyring is
/// D-Bus, which is async; these calls are short (a search, a store) and happen
/// once per create, unlock or forget, beside a PBKDF2 that already blocks
/// longer.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
        .block_on(fut)
}

/// A password nobody has to invent: 32 random bytes in base64url — 43
/// characters, the same shape a person could have typed.
fn made_up_password() -> Zeroizing<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).expect("the system's randomness");
    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

fn account_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")).unwrap_or_default()
        });
    base.join("bitmule").join(ACCOUNT_FILE_NAME)
}

struct Local {
    record: vault::Record,
    key: Zeroizing<[u8; 32]>,
    account: vault::Account,
}

#[derive(Debug)]
struct Activation {
    account_id: String,
    secret: String,
    plan: Option<String>,
}

#[derive(QObject, Default)]
pub struct AccountApi {
    base: qt_base_class!(trait QObject),

    /// `"none"` (nothing on this device) | `"locked"` (a record, no key) |
    /// `"unlocked"`.
    state: qt_property!(QString; NOTIFY state_changed),
    /// The record's label (what the person called this account).
    label: qt_property!(QString; NOTIFY account_changed),
    plan: qt_property!(QString; NOTIFY account_changed),
    /// `acct_…` once activated, empty before that.
    account_id: qt_property!(QString; NOTIFY account_changed),
    /// True when the account has been activated on the server — i.e. it may
    /// mint a share or an invite. An unactivated record is a key and nothing
    /// more, and the QML offers the token field only in that state.
    activated: qt_property!(bool; NOTIFY account_changed),
    /// One line for the person; empty when there is nothing to say.
    error: qt_property!(QString; NOTIFY error_changed),
    busy: qt_property!(bool; NOTIFY busy_changed),
    /// Where activation talks to. Kept a property so a self-hosted instance
    /// can be typed in instead of the public one.
    server: qt_property!(QString; NOTIFY server_changed),
    /// What the keyring says: `""` (not asked yet — the form is the way in),
    /// `"checking"`, `"stored"` (it holds this account's password),
    /// `"nothing"` (it works, nothing stored) or `"unavailable"` (no Secret
    /// Service on this session, so a password is a thing to remember).
    keyring: qt_property!(QString; NOTIFY keyring_changed),
    /// The password the app made, shown once after creation so a backup can
    /// be opened in the browser. Empty whenever the person typed their own.
    recovery: qt_property!(QString; NOTIFY recovery_changed),
    /// Keep the password in the keyring. On by default: the point of the
    /// keyring is not to remember one, and it can be turned off for a record
    /// that is meant to need the password every time.
    remember: qt_property!(bool; NOTIFY remember_changed),

    state_changed: qt_signal!(),
    account_changed: qt_signal!(),
    error_changed: qt_signal!(),
    busy_changed: qt_signal!(),
    server_changed: qt_signal!(),
    keyring_changed: qt_signal!(),
    recovery_changed: qt_signal!(),
    remember_changed: qt_signal!(),

    /// `init_from_qml` — read what is on disk and set `state`. With a record
    /// on disk there and a keyring that has its password, this also opens it,
    /// so a restart asks for nothing.
    init_from_qml: qt_method!(fn(&mut self)),
    /// Create a record on this device (no server involved). An empty password
    /// means "make one and keep it in the keyring".
    create_account: qt_method!(fn(&mut self, label: QString, password: QString) -> bool),
    /// Open the record with the password.
    unlock: qt_method!(fn(&mut self, password: QString) -> bool),
    /// Open the record with the password the keyring holds. Runs off the Qt
    /// thread, since asking KWallet can wait on its own prompt.
    unlock_from_keyring: qt_method!(fn(&mut self)),
    /// Keep (or stop keeping) the password in the keyring from now on.
    set_remember: qt_method!(fn(&mut self, on: bool)),
    /// Drop the key from memory. The record stays on disk.
    lock: qt_method!(fn(&mut self)),
    /// Spend a one-time token on this account: `POST /v1/pub/accounts`.
    activate: qt_method!(fn(&mut self, token: QString)),
    /// Delete the record on this device (QML asks first).
    forget: qt_method!(fn(&mut self) -> bool),
    /// Set the server base URL.
    set_server: qt_method!(fn(&mut self, url: QString)),

    local: std::rc::Rc<std::cell::RefCell<Option<Local>>>,
}

impl AccountApi {
    fn set_error(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        let q = QString::from(msg);
        if self.error != q {
            self.error = q;
            self.error_changed();
        }
    }

    fn clear_error(&mut self) {
        self.set_error(String::new());
    }

    fn set_state(&mut self, s: &str) {
        let q = QString::from(s);
        if self.state != q {
            self.state = q;
            self.state_changed();
        }
    }

    fn set_keyring(&mut self, s: &str) {
        let q = QString::from(s);
        if self.keyring != q {
            self.keyring = q;
            self.keyring_changed();
        }
    }

    fn set_recovery(&mut self, s: String) {
        let q = QString::from(s);
        if self.recovery != q {
            self.recovery = q;
            self.recovery_changed();
        }
    }

    /// Put the password in the keyring when the person asked for that and the
    /// session has one. A failure is not an error: the password still works,
    /// it just has to be typed at the next start.
    fn keep_in_keyring(&mut self, password: &str) {
        if !self.remember {
            return;
        }
        match block_on(keyring::store(password)) {
            Ok(()) => self.set_keyring("stored"),
            Err(_) => self.set_keyring("unavailable"),
        }
    }

    fn set_remember(&mut self, on: bool) {
        if self.remember == on {
            return;
        }
        self.remember = on;
        self.remember_changed();
        // Turning it off takes the entry back out at once; the record and the
        // password the person typed are untouched. Turning it on cannot do
        // the reverse — only the password's owner has the password, and the
        // app holds the derived key instead — so it applies from the next
        // unlock on.
        if !on {
            let _ = block_on(keyring::forget());
            self.set_keyring("nothing");
        }
    }

    fn publish(&mut self) {
        let (label, plan, id, activated) = match self.local.borrow().as_ref() {
            Some(l) => (
                l.record.label.clone(),
                l.record.plan().to_string(),
                l.account.account_id.clone().unwrap_or_default(),
                l.account.secret.is_some(),
            ),
            None => (self.label.to_string(), self.plan.to_string(), String::new(), false),
        };
        self.label = QString::from(label);
        self.plan = QString::from(plan);
        self.account_id = QString::from(id);
        self.activated = activated;
        self.account_changed();
    }

    fn store(&mut self, record: vault::Record, key: Zeroizing<[u8; 32]>, account: vault::Account) -> Result<(), String> {
        let text = serde_json::to_string(&record).map_err(|e| e.to_string())?;
        let path = account_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("couldn't make {}: {e}", dir.display()))?;
        }
        std::fs::write(&path, text).map_err(|e| format!("couldn't write {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        *self.local.borrow_mut() = Some(Local { record, key, account });
        Ok(())
    }
}

impl AccountApi {
    fn init_from_qml(&mut self) {
        self.server = QString::from(DEFAULT_SERVER);
        let path = account_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => match vault::parse(&text) {
                Ok(record) => {
                    self.label = QString::from(record.label.clone());
                    self.plan = QString::from(record.plan().to_string());
                    self.set_state("locked");
                    // A record is on disk: if the keyring has its password,
                    // the app opens itself and nobody is asked anything.
                    self.unlock_from_keyring();
                }
                Err(e) => {
                    self.set_state("none");
                    self.set_error(format!("{}: {e}", path.display()));
                }
            },
            Err(_) => self.set_state("none"),
        }
    }

    fn create_account(&mut self, label: QString, password: QString) -> bool {
        self.clear_error();
        self.set_recovery(String::new());
        let label = label.to_string().trim().to_string();
        let mut password = Zeroizing::new(password.to_string());
        if label.is_empty() {
            self.set_error("Give the account a name you'll recognise — it is only ever shown here.");
            return false;
        }
        // An empty field means "I don't want to remember one": make a strong
        // one and let the keyring hold it. That is only honest if the keyring
        // is there — a record sealed under a password nobody holds is a
        // brick — so the keyring is asked first, before the record exists.
        let made_up = password.is_empty();
        if made_up {
            if !block_on(keyring::available()) {
                self.set_keyring("unavailable");
                self.set_error(
                    "No keyring is available on this session (KWallet 6 or GNOME \
                     Keyring), so the record needs a password of yours.",
                );
                return false;
            }
            *password = made_up_password().to_string();
            if let Err(e) = block_on(keyring::store(&password)) {
                self.set_keyring("unavailable");
                self.set_error(format!("Couldn't put the password in the keyring: {e}"));
                return false;
            }
            self.set_keyring("stored");
        } else if password.chars().count() < vault::MIN_PASSWORD {
            self.set_error(format!(
                "Use at least {} characters, or leave it empty to keep one in the keyring.",
                vault::MIN_PASSWORD
            ));
            return false;
        }
        let (record, _account) = match vault::create(&label, &password, None) {
            Ok(v) => v,
            Err(e) => {
                if made_up {
                    let _ = block_on(keyring::forget());
                }
                self.set_error(e.to_string());
                return false;
            }
        };
        let key = match vault::record_key(&record, &password) {
            Ok(k) => k,
            Err(e) => {
                if made_up {
                    let _ = block_on(keyring::forget());
                }
                self.set_error(e.to_string());
                return false;
            }
        };
        let account = match vault::open_with_key(&record, &key) {
            Ok(a) => a,
            Err(e) => {
                if made_up {
                    let _ = block_on(keyring::forget());
                }
                self.set_error(e.to_string());
                return false;
            }
        };
        if let Err(e) = self.store(record, key, account) {
            if made_up {
                let _ = block_on(keyring::forget());
            }
            self.set_error(e);
            return false;
        }
        if made_up {
            // Shown once: this is the only copy outside the keyring, and the
            // only way a browser backup of this record can be opened.
            self.set_recovery(password.to_string());
        } else {
            self.keep_in_keyring(&password);
        }
        self.set_state("unlocked");
        self.publish();
        true
    }

    fn unlock(&mut self, password: QString) -> bool {
        let password = Zeroizing::new(password.to_string());
        self.unlock_with(&password, true)
    }

    /// Open the record with the password the keyring holds, in the background
    /// so a KWallet prompt cannot freeze the window. Called by the QML about
    /// a second after start, and by the "Unlock with KWallet" button.
    fn unlock_from_keyring(&mut self) {
        self.clear_error();
        self.set_keyring("checking");
        let qpointer = QPointer::from(&*self);
        qmetaobject::future::execute_async(async move {
            let outcome = keyring::load().await;
            if let Some(api) = qpointer.as_pinned() {
                let mut a = api.borrow_mut();
                match outcome {
                    Ok(Some(password)) => {
                        a.set_keyring("stored");
                        if a.unlock_with(&password, false) {
                            a.set_error(String::new());
                        } else {
                            // The entry is stale: the record was re-sealed
                            // since. Drop it rather than offer it again, and
                            // say nothing — the form in front of the person
                            // is the answer.
                            let _ = keyring::forget().await;
                            a.set_keyring("nothing");
                            a.set_error(String::new());
                        }
                    }
                    Ok(None) => a.set_keyring("nothing"),
                    Err(_) => a.set_keyring("unavailable"),
                }
            }
        });
    }

    /// The work behind both ways in. `keep` says whether a password that
    /// worked is put in the keyring — not when the keyring is where it came
    /// from, and not when the person asked for it not to be.
    fn unlock_with(&mut self, password: &str, keep: bool) -> bool {
        self.clear_error();
        let path = account_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => {
                self.set_state("none");
                self.set_error("There is no account on this device.");
                return false;
            }
        };
        let record = match vault::parse(&text) {
            Ok(r) => r,
            Err(e) => {
                self.set_error(e.to_string());
                return false;
            }
        };
        let key = match vault::record_key(&record, password) {
            Ok(k) => k,
            Err(e) => {
                self.set_error(e.to_string());
                return false;
            }
        };
        match vault::open_with_key(&record, &key) {
            Ok(account) => {
                if let Err(e) = self.store(record, key, account) {
                    self.set_error(e);
                    return false;
                }
                self.set_state("unlocked");
                self.publish();
                if keep {
                    self.keep_in_keyring(password);
                }
                true
            }
            Err(e) => {
                self.set_error(format!("{e}."));
                false
            }
        }
    }

    fn lock(&mut self) {
        self.clear_error();
        *self.local.borrow_mut() = None;
        self.account_id = QString::from("");
        self.activated = false;
        self.account_changed();
        self.set_state("locked");
    }

    fn forget(&mut self) -> bool {
        self.clear_error();
        let path = account_path();
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                self.set_error(format!("couldn't remove {}: {e}", path.display()));
                return false;
            }
        }
        // The keyring entry goes with the record: a password with nothing to
        // open is litter, and the next record must not inherit it.
        let _ = block_on(keyring::forget());
        self.set_keyring("nothing");
        self.set_recovery(String::new());
        *self.local.borrow_mut() = None;
        self.label = QString::from("");
        self.plan = QString::from("");
        self.account_id = QString::from("");
        self.activated = false;
        self.account_changed();
        self.set_state("none");
        true
    }

    fn set_server(&mut self, url: QString) {
        let url = url.to_string().trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return;
        }
        self.server = QString::from(url);
        self.server_changed();
    }

    fn activate(&mut self, token: QString) {
        self.clear_error();
        let token = token.to_string().trim().to_string();
        if token.is_empty() {
            self.set_error("Paste the one-time token the operator gave you.");
            return;
        }
        let taken = {
            let local = self.local.borrow();
            local.as_ref().map(|l| (l.record.clone(), l.key.clone(), l.record.public_key.clone()))
        };
        let (record, key, pubkey) = match taken {
            Some(v) => v,
            None => {
                self.set_error("Unlock the account first.");
                return;
            }
        };
        if self.activated {
            self.set_error("This account is already activated on the server.");
            return;
        }
        let server = self.server.to_string();
        self.busy = true;
        self.busy_changed();
        let qpointer = QPointer::from(&*self);
        qmetaobject::future::execute_async(async move {
            let outcome = activate_on(&server, &token, &pubkey).await;
            if let Some(api) = qpointer.as_pinned() {
                let mut a = api.borrow_mut();
                match outcome {
                    Ok(act) => {
                        let mut record = record;
                        let current = {
                            let local = a.local.borrow();
                            local.as_ref().map(|l| l.account.clone())
                        };
                        let mut account = match current {
                            Some(acc) => acc,
                            None => {
                                a.busy = false;
                                a.busy_changed();
                                a.set_error("Locked during activation.");
                                return;
                            }
                        };
                        account.account_id = Some(act.account_id.clone());
                        account.secret = Some(act.secret.clone());
                        if let Some(plan) = act.plan.clone() {
                            record.plan = Some(plan);
                            account.label = record.label.clone();
                        }
                        if let Err(e) = vault::seal_with_key(&mut record, &key, &account) {
                            a.busy = false;
                            a.busy_changed();
                            a.set_error(format!("activated, but couldn't save the record: {e}"));
                            return;
                        }
                        *a.local.borrow_mut() = Some(Local { record, key, account });
                        a.busy = false;
                        a.busy_changed();
                        a.publish();
                        a.set_error(String::new());
                        // the secret exists only now; write it down at once
                        if let Some(l) = a.local.borrow().as_ref() {
                            let text = serde_json::to_string(&l.record).unwrap_or_default();
                            let _ = std::fs::write(account_path(), text);
                        }
                    }
                    Err(e) => {
                        a.busy = false;
                        a.busy_changed();
                        a.set_error(e);
                    }
                }
            }
        });
    }
}

/// `POST /v1/pub/accounts` — spend the token on this record's public key.
/// The account id is derived by the server from the key, so activating the
/// same key again with a fresh token rotates the secret rather than making a
/// second account.
async fn activate_on(server: &str, token: &str, public_key: &str) -> Result<Activation, String> {
    let url = format!("{}/v1/pub/accounts", server.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "token": token, "pub": public_key }))
        .send()
        .await
        .map_err(|e| format!("couldn't reach {server}: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let msg = v
            .get("message")
            .and_then(|m| m.as_str())
            .or_else(|| v.get("error").and_then(|m| m.as_str()))
            .unwrap_or("the server refused the token");
        return Err(msg.to_string());
    }
    let field = |name: &str| v.get(name).and_then(|x| x.as_str()).map(|s| s.to_string());
    Ok(Activation {
        account_id: field("account_id").ok_or("the server did not name the account")?,
        secret: field("secret").ok_or("the server did not return a secret")?,
        plan: field("plan"),
    })
}

#[cfg(test)]
mod tests {
    //! The activation call is the one place the account leaves the device, so
    //! it is tested against a socket rather than trusted: the request carries
    //! the token and the public point, and both an account and a refusal are
    //! read back the way the prototype server writes them.

    use super::{activate_on, made_up_password};
    use bitmule_account as vault;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// What the app invents when the password field is left empty has to be a
    /// password the vault seals under and the browser's field would take:
    /// base64url, 43 characters, and not the same twice.
    #[test]
    fn the_made_up_password_is_a_password() {
        let a = made_up_password();
        let b = made_up_password();
        assert_ne!(*a, *b);
        assert_eq!(a.chars().count(), 43);
        assert!(
            a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{}",
            a.as_str()
        );
        assert!(a.chars().count() >= vault::MIN_PASSWORD);
        // and it does the job it is made for: seal a record, open it again
        let (record, _) = vault::create("laptop", &a, None).unwrap();
        assert_eq!(vault::open(&record, &a).unwrap().label, "laptop");
    }

    /// Answer one request with `status` and `body`, and hand back what was
    /// asked.
    async fn serve_once(status: &'static str, body: &'static str) -> (String, Arc<Mutex<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let seen_in_task = seen.clone();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                *seen_in_task.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    #[tokio::test]
    async fn activation_reads_the_id_and_secret() {
        let (server, seen) = serve_once(
            "201 Created",
            "{\"account_id\":\"acct_pN4MLTZRzxazbjWYXIp9mw\",\"secret\":\"ak_0Ffutb\",\"plan\":\"basic\",\"label\":\"dash\"}",
        )
        .await;
        let act = activate_on(&server, "tk_test", "BAMLrHG0ii6Tw21w").await.unwrap();
        assert_eq!(act.account_id, "acct_pN4MLTZRzxazbjWYXIp9mw");
        assert_eq!(act.secret, "ak_0Ffutb");
        assert_eq!(act.plan.as_deref(), Some("basic"));
        let asked = seen.lock().unwrap().clone();
        assert!(asked.starts_with("POST /v1/pub/accounts "), "{asked}");
        assert!(asked.contains("tk_test"), "{asked}");
        assert!(asked.contains("BAMLrHG0ii6Tw21w"), "{asked}");
    }

    #[tokio::test]
    async fn a_spent_token_reports_the_server_message() {
        let (server, _seen) = serve_once(
            "403 Forbidden",
            "{\"error\":\"bad_token\",\"message\":\"that token is unknown or already used\"}",
        )
        .await;
        let err = activate_on(&server, "tk_spent", "BAMLrHG0ii6Tw21w").await.unwrap_err();
        assert_eq!(err, "that token is unknown or already used");
    }
}
