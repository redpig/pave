//! Briolette v1 as a pave credential scheme.
//!
//! ECDAA over BLS12-381 from `briolette-crypto`. A holder's issued credential
//! is re-randomized for every holding, so holdings are unlinkable; signing
//! with a basename yields the pseudonym K = H(basename)^sk, the same for every
//! credential of one key, which is what makes conflict evidence work.
//!
//! Sizes (v1): credential 192 B (four G1 points); signature 288 B, which
//! embeds the signing credential, or 336 B with the 48 B pseudonym.

pub mod nonrevoked;

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

/// The group issuer: issues credentials on holders' public keys. In pave
/// terms, the registrar. It never sees a holder's secret key, so it can't sign
/// as a holder or forge evidence against one.
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

/// A holder's key before its credential arrives. Keep it secret.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingKey {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

/// What a holder sends the issuer to join: its public key, with a proof of
/// knowledge of the secret key bound to the issuer's nonce.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JoinRequest {
    pub public_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// The issuer's answer: the holder's base credential.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JoinReply {
    pub credential: Vec<u8>,
}

/// A fresh random join nonce. A replayed join request only yields a credential
/// for the requester's own key, so the holder may choose it.
pub fn join_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    nonce
}

impl PendingKey {
    /// Holder side, step 1: generate a key on the holder's own device and a
    /// join request for it.
    pub fn generate(nonce: &[u8]) -> (PendingKey, JoinRequest) {
        let (mut sk, mut pk) = (Vec::new(), Vec::new());
        assert!(v1::generate_wallet_keypair(&nonce.to_vec(), &mut sk, &mut pk));
        (PendingKey { secret_key: sk, public_key: pk.clone() }, JoinRequest { public_key: pk, nonce: nonce.to_vec() })
    }

    /// Holder side, step 2: accept the issued credential, checking that it is
    /// in the issuer's group and bound to this key.
    pub fn finish(self, scheme: &BrioletteV1, reply: &JoinReply) -> Result<HolderKey, String> {
        let cred = &reply.credential;
        if cred.len() != 4 * G1_LENGTH || cred[3 * G1_LENGTH..] != self.public_key[..G1_LENGTH] {
            return Err("credential is not bound to this key".into());
        }
        if !v1::credential_in_group(cred, &scheme.group_public_key) {
            return Err("credential is not in the issuer's group".into());
        }
        Ok(HolderKey { secret_key: self.secret_key, credential: cred.clone() })
    }
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

    /// Issue a credential on a join request. Fails unless the request proves
    /// knowledge of the key's secret.
    pub fn issue(&self, req: &JoinRequest) -> Result<JoinReply, String> {
        let (mut cred, mut cred_sig) = (Vec::new(), Vec::new());
        if !v1::issue_credential(&req.public_key, &self.secret_key, &req.nonce, &mut cred, &mut cred_sig) {
            return Err("join request has no valid proof of key".into());
        }
        Ok(JoinReply { credential: cred })
    }

    /// Run both sides of a join in one process. Only for keys this process
    /// will hold itself, such as an operator's own role keys, and for tests.
    pub fn join_locally(&self) -> HolderKey {
        let nonce = join_nonce();
        let (pending, req) = PendingKey::generate(&nonce);
        let reply = self.issue(&req).expect("local join");
        pending.finish(&self.scheme(), &reply).expect("local join")
    }
}

/// A fresh randomization of a base credential. Anyone holding the base
/// credential can do this; only the key's holder can sign with the result.
pub fn randomize(credential: &[u8]) -> Credential {
    let mut out = Vec::new();
    assert!(v1::randomize_credential(&credential.to_vec(), &mut out));
    Credential(out)
}

impl HolderKey {
    /// The holder's base credential, as issued. Don't use it directly: it
    /// links everything signed with it.
    pub fn base_credential(&self) -> &[u8] {
        &self.credential
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
        randomize(&key.credential)
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

    fn prove_not_cheat(&self, key: &HolderKey, cred: &Credential, cheats: &[(Vec<u8>, Vec<u8>)], ctx: &[u8]) -> Option<Vec<u8>> {
        nonrevoked::prove(&key.secret_key, &cred.0, cheats, ctx)
    }

    fn verify_not_cheat(&self, cred: &Credential, cheats: &[(Vec<u8>, Vec<u8>)], ctx: &[u8], proof: &[u8]) -> bool {
        v1::credential_in_group(&cred.0, &self.group_public_key) && nonrevoked::verify(&cred.0, cheats, ctx, proof)
    }
}
