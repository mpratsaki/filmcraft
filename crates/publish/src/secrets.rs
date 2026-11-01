//! Where a signed-in account's refresh token is kept: the operating system's credential store
//! ([`KeychainStore`], feature `keychain`: Windows Credential Manager, macOS Keychain, a Secret
//! Service on Linux), as craft-ai-integrations and craft-anything keep their keys. A caller with no
//! store, or whose store fails, keeps the account in an owner-only file instead.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

/// A small store of named secrets. No error text quotes a secret.
pub trait SecretStore: Send + Sync {
    /// What the store is, for logs ("keychain", "memory").
    fn name(&self) -> &'static str;
    /// The secret kept under `key`, if any.
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// Keep `value` under `key`, replacing what was there.
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
    /// Forget `key`; a key that isn't there is not an error.
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// Secrets in memory, gone when the store is dropped (tests, and callers that must not touch the
/// operating system's store).
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: Mutex<BTreeMap<String, String>>,
}

impl SecretStore for MemoryStore {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn get(&self, key: &str) -> Result<Option<String>, String> {
        Ok(self.entries.lock().unwrap_or_else(PoisonError::into_inner).get(key).cloned())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner).insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner).remove(key);
        Ok(())
    }
}

#[cfg(all(feature = "keychain", not(target_family = "wasm")))]
pub use keychain::KeychainStore;

#[cfg(all(feature = "keychain", not(target_family = "wasm")))]
mod keychain {
    use std::time::Duration;

    use super::SecretStore;

    /// The service name entries are filed under.
    pub const SERVICE: &str = "FilmCraft";
    /// A locked desktop keyring can wait for its password prompt: never wait longer than this.
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Secrets held by the operating system, one entry per key under one service name.
    #[derive(Clone, Debug)]
    pub struct KeychainStore {
        service: String,
    }

    impl KeychainStore {
        pub fn new() -> Self {
            Self::with_service(SERVICE)
        }

        /// Entries under another service name, so tests never touch the real account.
        pub fn with_service(service: impl Into<String>) -> Self {
            Self { service: service.into() }
        }

        /// Whether this machine has a credential store to keep secrets in.
        pub fn available() -> bool {
            keyring::Entry::store_status().is_ok()
        }

        /// Run `op` on the entry for `key`, giving up after [`TIMEOUT`]. The thread of a call that
        /// timed out is left to finish on its own.
        fn with_entry<T: Send + 'static>(&self, key: &str, op: impl FnOnce(&keyring::Entry) -> Result<T, String> + Send + 'static) -> Result<T, String> {
            if !Self::available() {
                return Err("no credential store on this system".into());
            }
            let (service, key) = (self.service.clone(), key.to_string());
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("filmcraft-keychain".into())
                .spawn(move || {
                    let r = keyring::Entry::new(&service, &key).map_err(|e| describe(&e)).and_then(|entry| op(&entry));
                    let _ = tx.send(r);
                })
                .map_err(|e| format!("can't reach the credential store: {e}"))?;
            rx.recv_timeout(TIMEOUT).map_err(|_| "the credential store did not answer".to_string())?
        }
    }

    impl Default for KeychainStore {
        fn default() -> Self {
            Self::new()
        }
    }

    /// What went wrong, from the variants that carry no secret bytes only.
    fn describe(e: &keyring::Error) -> String {
        use keyring::Error as E;
        match e {
            E::NoDefaultStore | E::NotSupportedByStore(_) => "no credential store on this system".into(),
            E::NoStorageAccess(err) => format!("the credential store refused access: {err}"),
            E::PlatformFailure(err) => format!("the credential store failed: {err}"),
            E::TooLong(..) => "the value is too long for the credential store".into(),
            E::Ambiguous(_) => "more than one stored entry matches".into(),
            _ => "the stored entry could not be read".into(),
        }
    }

    impl SecretStore for KeychainStore {
        fn name(&self) -> &'static str {
            "keychain"
        }

        fn get(&self, key: &str) -> Result<Option<String>, String> {
            self.with_entry(key, |entry| match entry.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(describe(&e)),
            })
        }

        fn set(&self, key: &str, value: &str) -> Result<(), String> {
            let value = value.to_string();
            self.with_entry(key, move |entry| entry.set_password(&value).map_err(|e| describe(&e)))
        }

        fn delete(&self, key: &str) -> Result<(), String> {
            self.with_entry(key, |entry| match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(describe(&e)),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_keeps_replaces_and_forgets() {
        let s = MemoryStore::default();
        assert_eq!(s.get("a"), Ok(None));
        s.set("a", "1").unwrap();
        s.set("a", "2").unwrap();
        assert_eq!(s.get("a"), Ok(Some("2".into())));
        s.delete("a").unwrap();
        s.delete("a").unwrap();
        assert_eq!(s.get("a"), Ok(None));
    }

    /// The real store, under a test service name: Windows always has one; elsewhere the test
    /// skips when the machine has none (a headless Linux box).
    #[cfg(all(feature = "keychain", not(target_family = "wasm")))]
    #[test]
    fn keychain_store_round_trips_under_a_test_service() {
        if !KeychainStore::available() {
            #[cfg(windows)]
            panic!("Windows has a credential store");
            #[cfg(not(windows))]
            return;
        }
        let s = KeychainStore::with_service(format!("FilmCraft tests {}", std::process::id()));
        let key = "round-trip";
        let _ = s.delete(key);
        assert_eq!(s.get(key), Ok(None));
        s.set(key, "secret 1").unwrap();
        s.set(key, "secret 2").unwrap();
        assert_eq!(s.get(key), Ok(Some("secret 2".into())));
        s.delete(key).unwrap();
        assert_eq!(s.get(key), Ok(None), "deleted");
        s.delete(key).unwrap();
    }
}
