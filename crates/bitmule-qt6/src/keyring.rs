//! The account key, kept where the desktop keeps its secrets.
//!
//! KWallet 6 on KDE and GNOME Keyring elsewhere both implement the Secret
//! Service API (`org.freedesktop.secrets`) on the session bus, so one
//! implementation serves both desktops; on a machine with neither, the
//! functions here fail and the app falls back to asking for the password.
//!
//! What goes in is the key itself — the 32 bytes the record is sealed under,
//! base64url so it is text like everything else in a keyring. That is what
//! Signal Desktop does with its database key, and it has two consequences
//! worth the trade: opening the record costs no PBKDF2, and a key that is
//! already in memory (unlocking by typing the password) can be put in at
//! once, where a password could only be kept from the next unlock on.
//!
//! The record on disk is unchanged — sealed exactly as the browser seals it,
//! under a password. So a keyring entry is a convenience and never the
//! account: losing it costs a password prompt, nothing else, and a backup
//! record still opens anywhere the password is known.

use base64::Engine;
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// What identifies the item in a search. Deliberately not the account label:
/// a label is the person's to change and must not strand the entry.
const ATTRS: [(&str, &str); 2] = [("application", "bitmule"), ("purpose", "account-key")];
const ITEM_LABEL: &str = "bitmule account key";
const CONTENT_TYPE: &str = "text/plain";

fn attrs() -> HashMap<&'static str, &'static str> {
    ATTRS.into_iter().collect()
}

async fn service() -> Result<SecretService<'static>, String> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| format!("no secret service: {e}"))
}

/// True when this session has a keyring we can write to. Asking the default
/// collection is the cheap probe; on KWallet it also opens the wallet if the
/// desktop has it set up to open by itself.
pub async fn available() -> bool {
    match service().await {
        Ok(ss) => ss.get_default_collection().await.is_ok(),
        Err(_) => false,
    }
}

/// Put `key` in the keyring, replacing any entry this app left before.
pub async fn store(key: &[u8; 32]) -> Result<(), String> {
    let text = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key));
    let ss = service().await?;
    let collection = ss
        .get_default_collection()
        .await
        .map_err(|e| format!("no default keyring: {e}"))?;
    collection
        .create_item(ITEM_LABEL, attrs(), text.as_bytes(), true, CONTENT_TYPE)
        .await
        .map_err(|e| format!("couldn't save it: {e}"))?;
    Ok(())
}

/// The key we stored, if there is one. `None` means the keyring works and
/// holds nothing for us; `Err` means there is no keyring to ask.
pub async fn load() -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    let ss = service().await?;
    let found = ss
        .search_items(attrs())
        .await
        .map_err(|e| format!("couldn't search the keyring: {e}"))?;
    let mut item = found.unlocked.into_iter().next();
    if item.is_none() {
        if let Some(locked) = found.locked.into_iter().next() {
            locked
                .unlock()
                .await
                .map_err(|e| format!("the keyring is locked: {e}"))?;
            item = Some(locked);
        }
    }
    match item {
        None => Ok(None),
        Some(item) => {
            let bytes = item
                .get_secret()
                .await
                .map_err(|e| format!("couldn't read it: {e}"))?;
            let text = Zeroizing::new(
                String::from_utf8(bytes).map_err(|_| "the stored key is not text".to_string())?,
            );
            let raw = Zeroizing::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(text.trim())
                    .map_err(|_| "the stored key is not base64".to_string())?,
            );
            let key: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| "the stored key is not 32 bytes".to_string())?;
            Ok(Some(Zeroizing::new(key)))
        }
    }
}

/// Run one keyring call to completion on a thread of its own.
///
/// The Qt side reaches these from a slot on the GUI thread, and `main` is
/// `#[tokio::main]`, so that thread is already inside a runtime: a `block_on`
/// there panics ("Cannot start a runtime from within a runtime"). Building the
/// future on the new thread rather than passing it across also means it need
/// not be `Send`. The round trips on the session bus stay off the UI thread,
/// which is the second reason these are offered in a blocking shape.
fn on_own_thread<T, F, Fut>(make: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T>,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a tokio runtime for the keyring")
            .block_on(make())
    })
    .join()
    .map_err(|_| "the keyring call panicked".to_string())
}

/// `available` for callers on the GUI thread.
pub fn available_now() -> bool {
    on_own_thread(|| async { available().await }).unwrap_or(false)
}

/// `store` for callers on the GUI thread.
pub fn store_now(key: &[u8; 32]) -> Result<(), String> {
    let key = *key;
    on_own_thread(move || async move { store(&key).await })?
}

/// `forget` for callers on the GUI thread.
pub fn forget_now() -> Result<(), String> {
    on_own_thread(|| async { forget().await })?
}

/// Drop our entry. Used when the record is forgotten, and when a key we kept
/// turns out not to open the record (a stale entry).
pub async fn forget() -> Result<(), String> {
    let ss = service().await?;
    let found = ss
        .search_items(attrs())
        .await
        .map_err(|e| format!("couldn't search the keyring: {e}"))?;
    for item in found.unlocked.iter().chain(found.locked.iter()) {
        item.delete()
            .await
            .map_err(|e| format!("couldn't remove it: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::on_own_thread;

    /// The Qt slots run on the thread `#[tokio::main]` is driving, so the
    /// blocking shape of these calls has to work from *inside* a runtime —
    /// the first version made its own runtime there and panicked with
    /// "Cannot start a runtime from within a runtime". Outside one must work
    /// just as well.
    #[test]
    fn a_keyring_call_survives_being_made_from_inside_a_runtime() {
        assert_eq!(on_own_thread(|| async { 7u32 }).unwrap(), 7);

        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        let from_inside = rt.block_on(async { on_own_thread(|| async { 11u32 }) });
        assert_eq!(from_inside.unwrap(), 11);

        // ... and from a task the runtime is driving, which is where the Qt
        // event loop actually sits.
        let from_a_task = rt.block_on(async { tokio::spawn(async { on_own_thread(|| async { 13u32 }) }).await });
        assert_eq!(from_a_task.unwrap().unwrap(), 13);
    }
}
