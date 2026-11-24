//! Hashing and canonical encoding.
//!
//! Everything signed or identified by hash is encoded as CBOR in field
//! declaration order, then hashed with SHA-256 under a domain tag.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "serde_bytes")] pub [u8; 32]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

/// Canonical encoding of a value.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("encoding to a Vec cannot fail");
    buf
}

/// Hash raw bytes under a domain tag.
pub fn hash_bytes(domain: &str, data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update((domain.len() as u32).to_be_bytes());
    h.update(domain.as_bytes());
    h.update(data);
    Hash(h.finalize().into())
}

/// Hash a value's canonical encoding under a domain tag.
pub fn hash_of<T: Serialize>(domain: &str, value: &T) -> Hash {
    hash_bytes(domain, &encode(value))
}
