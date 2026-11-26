//! The account password, kept where the desktop keeps its secrets.
//!
//! KWallet 6 on KDE and GNOME Keyring elsewhere both implement the Secret
//! Service API (`org.freedesktop.secrets`) on the session bus, so one
//! implementation serves both desktops; on a machine with neither, the
//! functions here fail and the app falls back to asking for the password.
//!
//! Only the password goes in: the record itself stays in
//! `~/.config/bitmule/account.json`, sealed exactly as the browser seals it,
//! so a keyring entry is a convenience and never the account. Losing it costs
//! the password, nothing else — a backup record still opens anywhere the
//! password is known.

use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// What identifies the item in a search. Deliberately not the account label:
/// a label is the person's to change and must not strand the entry.
const ATTRS: [(&str, &str); 2] = [("application", "bitmule"), ("purpose", "account-password")];
const ITEM_LABEL: &str = "bitmule account password";
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

/// Put `password` in the keyring, replacing any entry this app left before.
pub async fn store(password: &str) -> Result<(), String> {
    let ss = service().await?;
    let collection = ss
        .get_default_collection()
        .await
        .map_err(|e| format!("no default keyring: {e}"))?;
    collection
        .create_item(
            ITEM_LABEL,
            attrs(),
            password.as_bytes(),
            true,
            CONTENT_TYPE,
        )
        .await
        .map_err(|e| format!("couldn't save it: {e}"))?;
    Ok(())
}

/// The password we stored, if there is one. `None` means the keyring works
/// and holds nothing for us; `Err` means there is no keyring to ask.
pub async fn load() -> Result<Option<Zeroizing<String>>, String> {
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
            let text = String::from_utf8(bytes)
                .map_err(|_| "the stored password is not text".to_string())?;
            Ok(Some(Zeroizing::new(text)))
        }
    }
}

/// Drop our entry. Used when the record is forgotten, and when a password we
/// sealed with turns out not to open the record (a stale entry).
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
