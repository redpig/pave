//! Proofs that a credential's key is not a known cheat, without revealing
//! anything else about it.
//!
//! Evidence of a double spend carries a basename `bsn` and the cheat's
//! pseudonym `K = H(bsn)^f`, where `f` is the cheat's secret key. Anyone who
//! holds that evidence can ask a holder to prove, for a credential the holder
//! is using, that its key `f'` has `H(bsn)^f' != K`. An honest holder can; the
//! cheat can't, under any of its unlinkable credentials. The proof reveals
//! nothing about `H(bsn)^f'`, so answering it links the holder to nothing.
//!
//! This is the non-revoked proof from EPID (Brickell and Li), built from
//! Camenisch and Shoup's proof of inequality of discrete logs. For a
//! randomized credential (R, S, T, W) with W = S^f, and an entry (B, K) with
//! B = H(bsn):
//!
//! - pick a random `mu`, and publish `T_i = B^(f mu) K^(-mu)`;
//! - prove knowledge of `a = f mu` and `b = mu` with `T_i = B^a K^(-b)` and
//!   `1 = S^a W^(-b)`.
//!
//! The second relation forces `a = f b`, so `T_i = (B^f / K)^b`, which is the
//! identity exactly when `B^f = K`. The verifier checks `T_i` isn't the
//! identity. `T_i` is uniformly random otherwise, so it hides `B^f`.
//!
//! Each entry costs 144 bytes (one point, three scalars).

use bls12_381_plus::elliptic_curve::hash2curve::ExpandMsgXmd;
use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::Sha256;

/// Must match briolette-crypto v1, so `H(bsn)` here is the same point the
/// signature's pseudonym was computed from.
const DOMAIN_HASH_TO_G1: &[u8] = b"BRIOLETTE-V1-BLS12381_XMD:SHA-256_SSWU_RO_";
const DOMAIN_CHALLENGE: &[u8] = b"PAVE-V0-NONREVOKED_XMD:SHA-256_";

pub const ENTRY_PROOF_LENGTH: usize = 48 + 3 * 32;

fn hash_to_g1(data: &[u8]) -> G1Projective {
    G1Projective::hash::<ExpandMsgXmd<Sha256>>(data, DOMAIN_HASH_TO_G1)
}

fn point(data: &[u8]) -> Option<G1Projective> {
    let buf: [u8; 48] = data.get(..48)?.try_into().ok()?;
    let a: Option<G1Affine> = G1Affine::from_compressed(&buf).into();
    a.map(|a| G1Projective::from(&a))
}

fn scalar(data: &[u8]) -> Option<Scalar> {
    let buf: [u8; 32] = data.get(..32)?.try_into().ok()?;
    Scalar::from_be_bytes(&buf).into()
}

fn enc(p: &G1Projective) -> [u8; 48] {
    G1Affine::from(p).to_compressed()
}

/// S and W from a randomized credential (R, S, T, W).
fn s_and_w(credential: &[u8]) -> Option<(G1Projective, G1Projective)> {
    if credential.len() != 4 * 48 {
        return None;
    }
    let (s, w) = (point(&credential[48..96])?, point(&credential[144..192])?);
    (!bool::from(s.is_identity()) && !bool::from(w.is_identity())).then_some((s, w))
}

#[allow(clippy::too_many_arguments)]
fn challenge(ctx: &[u8], credential: &[u8], bsn: &[u8], k: &G1Projective, t: &G1Projective, u1: &G1Projective, u2: &G1Projective) -> Scalar {
    let mut d = Vec::new();
    for part in [ctx, credential, bsn] {
        d.extend_from_slice(&(part.len() as u64).to_be_bytes());
        d.extend_from_slice(part);
    }
    for p in [k, t, u1, u2] {
        d.extend_from_slice(&enc(p));
    }
    Scalar::hash::<ExpandMsgXmd<Sha256>>(&d, DOMAIN_CHALLENGE)
}

/// Prove that the key behind `credential` isn't the one behind any of
/// `entries` (basename, pseudonym). `ctx` binds the proof to one use, such as
/// a payment or a ticket request. Returns None if the key is one of them, or
/// if an input is malformed.
pub fn prove(secret_key: &[u8], credential: &[u8], entries: &[(Vec<u8>, Vec<u8>)], ctx: &[u8]) -> Option<Vec<u8>> {
    let f = scalar(secret_key)?;
    let (s, w) = s_and_w(credential)?;
    if s * f != w {
        return None;
    }
    let mut out = Vec::with_capacity(entries.len() * ENTRY_PROOF_LENGTH);
    for (bsn, k) in entries {
        let b = hash_to_g1(bsn);
        let k = point(k)?;
        if b * f == k {
            return None;
        }
        let mu = Scalar::random(OsRng);
        let (a, bb) = (f * mu, mu);
        let t = b * a - k * bb;
        let (ra, rb) = (Scalar::random(OsRng), Scalar::random(OsRng));
        let u1 = b * ra - k * rb;
        let u2 = s * ra - w * rb;
        let c = challenge(ctx, credential, bsn, &k, &t, &u1, &u2);
        out.extend_from_slice(&enc(&t));
        out.extend_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&(ra + c * a).to_be_bytes());
        out.extend_from_slice(&(rb + c * bb).to_be_bytes());
    }
    Some(out)
}

/// Check a proof from `prove`.
pub fn verify(credential: &[u8], entries: &[(Vec<u8>, Vec<u8>)], ctx: &[u8], proof: &[u8]) -> bool {
    let Some((s, w)) = s_and_w(credential) else { return false };
    if proof.len() != entries.len() * ENTRY_PROOF_LENGTH {
        return false;
    }
    for ((bsn, k), p) in entries.iter().zip(proof.chunks(ENTRY_PROOF_LENGTH)) {
        let (Some(k), Some(t), Some(c), Some(sa), Some(sb)) = (point(k), point(&p[..48]), scalar(&p[48..80]), scalar(&p[80..112]), scalar(&p[112..144])) else {
            return false;
        };
        if bool::from(t.is_identity()) {
            return false;
        }
        let b = hash_to_g1(bsn);
        let u1 = b * sa - k * sb - t * c;
        let u2 = s * sa - w * sb;
        if challenge(ctx, credential, bsn, &k, &t, &u1, &u2) != c {
            return false;
        }
    }
    true
}
