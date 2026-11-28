//! Keeping a wallet's state safe at rest, and making old copies of it useless.
//!
//! A wallet's state file holds its secret keys and its signing log: every
//! coin state it has signed away. The log is what stops an honest wallet
//! from signing one state twice. Signing twice is what evidence catches,
//! so a wallet restored from an old backup would frame its own owner.
//!
//! The whole state is sealed (encrypted and authenticated) under a key from
//! a [`Keystore`]. Every save seals under a fresh key and retires the old
//! one, so in a keystore that is *rollback-resistant* an old copy of the
//! state file can no longer be opened. Restoring a backup then fails
//! loudly instead of quietly re-enabling spent coins.
//!
//! - [`SoftwareKeystore`] keeps its key in a file beside the state. That
//!   protects against someone reading the state file alone, but anyone who
//!   copies both files can roll both back. It is what runs in this repo.
//! - On a phone the keystore is the platform's: an Android Keystore key
//!   with rollback resistance, or a Secure Enclave key on iOS. See
//!   `docs/phone-keys.md` for what each platform can and can't promise.
//! - [`MemoryKeystore`] stands in for a rollback-resistant keystore in
//!   tests: its keys live outside the files, and retired keys are gone.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub trait Keystore: Send {
    /// Seal `data` under a fresh key. Earlier keys stay usable until
    /// [`Keystore::commit`], so a crash before the new state is written
    /// loses nothing.
    fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, String>;
    /// Retire every key but the newest.
    fn commit(&mut self) -> Result<(), String>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String>;
    /// Can an old copy of the state be opened after a commit, by someone
    /// who also copied this keystore's storage? False means yes.
    fn rollback_resistant(&self) -> bool;
}

fn seal_with(version: u64, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: data,
                aad: &version.to_be_bytes(),
            },
        )
        .map_err(|_| "seal failed")?;
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_with(keys: &BTreeMap<u64, [u8; 32]>, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 8 + 24 + 16 {
        return Err("not a sealed wallet state".into());
    }
    let version = u64::from_be_bytes(sealed[..8].try_into().unwrap());
    let key = keys.get(&version).ok_or("this state was sealed under a retired key: it is an old copy, and restoring it could sign spent coins again")?;
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(&sealed[8..32]),
            chacha20poly1305::aead::Payload {
                msg: &sealed[32..],
                aad: &version.to_be_bytes(),
            },
        )
        .map_err(|_| "the state doesn't open under its key: tampered or corrupt".into())
}

fn fresh_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// Keys in a file beside the state (mode 0600). Not rollback-resistant.
pub struct SoftwareKeystore {
    path: PathBuf,
    keys: BTreeMap<u64, [u8; 32]>,
}

impl SoftwareKeystore {
    /// The keystore for a state file at `state`.
    pub fn for_state(state: &Path) -> Result<Self, String> {
        let path = state.with_extension("vault");
        let keys = match std::fs::read(&path) {
            Ok(b) => ciborium::from_reader(b.as_slice())
                .map_err(|e| format!("{}: {e}", path.display()))?,
            Err(_) => BTreeMap::new(),
        };
        Ok(SoftwareKeystore { path, keys })
    }

    fn write(&self) -> Result<(), String> {
        let tmp = self.path.with_extension("vault.tmp");
        std::fs::write(&tmp, pave_kernel::hash::encode(&self.keys)).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
}

impl Keystore for SoftwareKeystore {
    fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let v = self.keys.keys().next_back().map_or(1, |v| v + 1);
        self.keys.insert(v, fresh_key());
        self.write()?;
        seal_with(v, &self.keys[&v], data)
    }

    fn commit(&mut self) -> Result<(), String> {
        if let Some(&v) = self.keys.keys().next_back() {
            self.keys.retain(|k, _| *k == v);
            self.write()?;
        }
        Ok(())
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        open_with(&self.keys, sealed)
    }

    fn rollback_resistant(&self) -> bool {
        false
    }
}

/// A stand-in for a rollback-resistant keystore: keys live outside the
/// wallet's files, and a retired key is gone for good. Clones share keys,
/// as one device's keystore would.
#[derive(Clone, Default)]
pub struct MemoryKeystore {
    keys: Arc<Mutex<BTreeMap<u64, [u8; 32]>>>,
}

impl Keystore for MemoryKeystore {
    fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut keys = self.keys.lock().unwrap();
        let v = keys.keys().next_back().map_or(1, |v| v + 1);
        keys.insert(v, fresh_key());
        seal_with(v, &keys[&v], data)
    }

    fn commit(&mut self) -> Result<(), String> {
        let mut keys = self.keys.lock().unwrap();
        if let Some(&v) = keys.keys().next_back() {
            keys.retain(|k, _| *k == v);
        }
        Ok(())
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        open_with(&self.keys.lock().unwrap(), sealed)
    }

    fn rollback_resistant(&self) -> bool {
        true
    }
}
