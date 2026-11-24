//! Briolette v1 as a pave credential scheme.
//!
//! ECDAA over BLS12-381 from `briolette-crypto`. A holder's issued credential
//! is re-randomized for every holding, so holdings are unlinkable; signing
//! with a basename yields the pseudonym K = H(basename)^sk, the same for every
//! credential of one key, which is what makes conflict evidence work.
//!
//! Sizes (v1): credential 192 B (four G1 points); signature 288 B, which
//! embeds the signing credential, or 336 B with the 48 B pseudonym.

use briolette_crypto::v1;
use pave_kernel::{Credential, Scheme, Sig};

/// Encoding sizes from `briolette-crypto` v1 (BLS12-381).
pub const G1_LENGTH: usize = 48;
pub const SIGNATURE_LENGTH: usize = 3 * 32 + 4 * G1_LENGTH;
pub const SIGNATURE_WITH_NYM_LENGTH: usize = SIGNATURE_LENGTH + G1_LENGTH;

/// The scheme: verification needs only the issuer's group public key.
#[derive(Clone)]
pub struct BrioletteV1 {
    pub group_public_key: Vec<u8>,
}

/// The group issuer: enrolls members by issuing their credentials. In pave
/// terms, the registrar.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Issuer {
    secret_key: Vec<u8>,
    pub group_public_key: Vec<u8>,
}

/// A holder's secret key and its issued (base) credential. Keep it secret.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HolderKey {
    secret_key: Vec<u8>,
    credential: Vec<u8>,
}

impl Issuer {
    pub fn new() -> Self {
        let (mut secret_key, mut group_public_key) = (Vec::new(), Vec::new());
        assert!(v1::generate_issuer_keypair(&mut secret_key, &mut group_public_key));
        Issuer { secret_key, group_public_key }
    }

    pub fn scheme(&self) -> BrioletteV1 {
        BrioletteV1 { group_public_key: self.group_public_key.clone() }
    }

    /// Enroll a new holder: generate a wallet key and issue its credential.
    pub fn enroll(&self) -> HolderKey {
        let mut nonce = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let (mut sk, mut pk) = (Vec::new(), Vec::new());
        assert!(v1::generate_wallet_keypair(&nonce, &mut sk, &mut pk));
        let (mut cred, mut cred_sig) = (Vec::new(), Vec::new());
        assert!(v1::issue_credential(&pk, &self.secret_key, &nonce, &mut cred, &mut cred_sig));
        HolderKey { secret_key: sk, credential: cred }
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheme for BrioletteV1 {
    type HolderKey = HolderKey;

    fn credential(&self, key: &HolderKey) -> Credential {
        let mut out = Vec::new();
        assert!(v1::randomize_credential(&key.credential, &mut out));
        Credential(out)
    }

    fn sign(&self, key: &HolderKey, cred: &Credential, msg: &[u8], basename: Option<&[u8]>) -> Sig {
        let mut sig = Vec::new();
        let ok = v1::sign(
            &msg.to_vec(),
            &cred.0,
            &key.secret_key,
            &basename.map(|b| b.to_vec()),
            false,
            &mut sig,
        );
        assert!(ok, "briolette v1 sign failed");
        Sig(sig)
    }

    fn verify(&self, cred: &Credential, msg: &[u8], basename: Option<&[u8]>, sig: &Sig) -> bool {
        !msg.is_empty()
            && v1::verify(
                &self.group_public_key,
                &basename.map(|b| b.to_vec()),
                &Some(cred.0.clone()),
                &sig.0,
                &msg.to_vec(),
            )
    }

    fn nym(&self, sig: &Sig) -> Option<Vec<u8>> {
        (sig.0.len() >= SIGNATURE_WITH_NYM_LENGTH).then(|| sig.0[sig.0.len() - G1_LENGTH..].to_vec())
    }
}
