//! The credential scheme slot.
//!
//! The kernel never looks inside a credential or a signature. A [`Scheme`]
//! makes holding credentials, signs with an optional basename and reports the
//! pseudonym ("nym") a basename-signature carries. Two signatures by the same
//! holder under the same basename carry the same nym; that is all conflict
//! evidence needs (kernel invariant 6).
//!
//! Schemes that fit: Briolette v1 ECDAA, BBS with per-verifier pseudonyms, or
//! a post-quantum linkable scheme. [`DevScheme`] is for tests only: it is
//! *not anonymous* (the credential is a plain Ed25519 key).

use crate::hash::hash_bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A public holding credential, opaque to the kernel.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Credential(pub Vec<u8>);

/// A signature, opaque to the kernel.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sig(pub Vec<u8>);

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cred:")?;
        for b in self.0.iter().take(4) {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sig({}B)", self.0.len())
    }
}

/// A credential scheme.
pub trait Scheme {
    /// Secret material a wallet keeps.
    type HolderKey;

    /// A holding credential for `key`. Anonymous schemes return a fresh,
    /// unlinkable randomization each call.
    fn credential(&self, key: &Self::HolderKey) -> Credential;

    /// Sign `msg` as the holder of `cred`, with an optional basename.
    fn sign(
        &self,
        key: &Self::HolderKey,
        cred: &Credential,
        msg: &[u8],
        basename: Option<&[u8]>,
    ) -> Sig;

    /// Verify a signature made as the holder of `cred`.
    fn verify(&self, cred: &Credential, msg: &[u8], basename: Option<&[u8]>, sig: &Sig) -> bool;

    /// The pseudonym a basename-signature carries, if any.
    fn nym(&self, sig: &Sig) -> Option<Vec<u8>>;
}

/// Test-only scheme over Ed25519. Not anonymous: every credential for a key
/// is the same public key, and the nym is a hash of key and basename.
#[derive(Clone, Default)]
pub struct DevScheme;

impl DevScheme {
    pub fn keygen() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn signed_bytes(msg: &[u8], basename: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::with_capacity(msg.len() + 40);
        match basename {
            Some(b) => {
                out.push(1);
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(b);
            }
            None => out.push(0),
        }
        out.extend_from_slice(msg);
        out
    }

    fn nym_for(vk: &[u8], basename: &[u8]) -> Vec<u8> {
        let mut data = vk.to_vec();
        data.extend_from_slice(basename);
        hash_bytes("pave/dev/nym", &data).0.to_vec()
    }
}

impl Scheme for DevScheme {
    type HolderKey = SigningKey;

    fn credential(&self, key: &SigningKey) -> Credential {
        Credential(key.verifying_key().to_bytes().to_vec())
    }

    fn sign(&self, key: &SigningKey, _cred: &Credential, msg: &[u8], basename: Option<&[u8]>) -> Sig {
        let sig = key.sign(&Self::signed_bytes(msg, basename));
        let mut out = sig.to_bytes().to_vec();
        if let Some(b) = basename {
            out.extend_from_slice(&Self::nym_for(key.verifying_key().as_bytes(), b));
        }
        Sig(out)
    }

    fn verify(&self, cred: &Credential, msg: &[u8], basename: Option<&[u8]>, sig: &Sig) -> bool {
        let Ok(vk_bytes) = <[u8; 32]>::try_from(cred.0.as_slice()) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
            return false;
        };
        let expected_len = if basename.is_some() { 96 } else { 64 };
        if sig.0.len() != expected_len {
            return false;
        }
        let Ok(s) = Signature::from_slice(&sig.0[..64]) else {
            return false;
        };
        if vk.verify(&Self::signed_bytes(msg, basename), &s).is_err() {
            return false;
        }
        match basename {
            Some(b) => sig.0[64..] == Self::nym_for(&vk_bytes, b)[..],
            None => true,
        }
    }

    fn nym(&self, sig: &Sig) -> Option<Vec<u8>> {
        (sig.0.len() == 96).then(|| sig.0[64..].to_vec())
    }
}
