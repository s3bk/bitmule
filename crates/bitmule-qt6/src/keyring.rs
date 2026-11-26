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
