//! Hardware attestation at enrollment: a device proves its class instead
//! of the operator declaring it.
//!
//! A joining phone makes a key in its secure hardware and has the platform
//! attest it, with the join request bound in:
//!
//! - **Android Key Attestation.** The attestation challenge is
//!   [`challenge`] of the join. The certificate chain must reach a root the
//!   town trusts. The key must be in the TEE or StrongBox, the boot verified
//!   and the bootloader locked, and the attestation made for an app the
//!   town trusts (package and signing certificate).
//! - **Apple App Attest.** The client data hash is [`challenge`] of the
//!   join. The chain must reach a root the town trusts. The nonce must bind
//!   the auth data and that hash, the key id must be the attested key's,
//!   the app id one the town trusts, and the counter zero. Development
//!   attestations count only if the town allows them.
//!
//! Every signature in a chain is checked (ECDSA on P-256 or P-384,
//! RSA PKCS#1 v1.5 with SHA-256), every certificate must be in its
//! validity period, and every issuer must be a CA. Anything unknown is
//! refused, and so is everything when the town trusts no root for that
//! platform: an unconfigured town grants no attested class.
//!
//! The challenge binds the join's keys, so an attestation can't be lifted
//! from one device onto keys made on another. Attestation shows what kind of
//! device a member has; it isn't who they are, and it doesn't stop one
//! person enrolling twice: that is the root of trust's nullifier.

use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use x509_cert::Certificate;

/// What a joining device sends with its request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attestation {
    /// The attested key's certificate chain, leaf first, DER.
    Android { chain: Vec<ByteBuf> },
    /// The App Attest attestation object, and the attested key's id.
    Apple { object: ByteBuf, key_id: ByteBuf },
}

/// What a verified attestation shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Attested {
    AndroidTee,
    AndroidStrongBox,
    AppleAppAttest,
}

/// An Android app the town trusts: its package name and the SHA-256 of its
/// signing certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidApp {
    pub package: String,
    pub signer_sha256: ByteBuf,
}

/// What a town trusts, and which class each attestation earns.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Policy {
    /// Trusted Android attestation roots, DER.
    pub android_roots: Vec<ByteBuf>,
    pub android_apps: Vec<AndroidApp>,
    /// Accept a device whose bootloader is unlocked or boot unverified.
    pub allow_unlocked: bool,
    /// Trusted App Attest roots, DER.
    pub apple_roots: Vec<ByteBuf>,
    /// App ids, as `TEAMID.bundle.id`.
    pub apple_app_ids: Vec<String>,
    /// Accept App Attest's development environment.
    pub allow_apple_development: bool,
    /// The class each attestation earns.
    pub earns: BTreeMap<Attested, String>,
}

impl Policy {
    /// The classes only an attestation can grant.
    pub fn attested_classes(&self) -> impl Iterator<Item = &String> {
        self.earns.values()
    }
}

/// What a device's attestation must bind: the join's two public keys.
pub fn challenge(join: &crate::node::Join) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pave/attest/v1");
    h.update(pave_kernel::hash::encode(&(&join.transfer, &join.access)));
    h.finalize().into()
}

/// Verify `a` against `challenge` and the town's policy, at `now` (seconds
/// since 1970).
pub fn verify(
    p: &Policy,
    a: &Attestation,
    challenge: &[u8; 32],
    now: u64,
) -> Result<Attested, String> {
    match a {
        Attestation::Android { chain } => android(p, chain, challenge, now),
        Attestation::Apple { object, key_id } => apple(p, object, key_id, challenge, now),
    }
}

// ---- Certificate chains ----------------------------------------------------

const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";
const RSA: &str = "1.2.840.113549.1.1.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const BASIC_CONSTRAINTS: &str = "2.5.29.19";

/// Parse `ders` (leaf first) and check it reaches one of `roots`: the last
/// certificate is a root, or is issued by one. Returns the chain, leaf first,
/// ending at the root.
fn chain(ders: &[&[u8]], roots: &[ByteBuf], now: u64) -> Result<Vec<Certificate>, String> {
    if roots.is_empty() {
        return Err("the town trusts no root for this platform".into());
    }
    if ders.is_empty() {
        return Err("empty certificate chain".into());
    }
    let mut certs = ders
        .iter()
        .map(|d| Certificate::from_der(d).map_err(|e| format!("certificate: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let last = ders.last().unwrap();
    if !roots.iter().any(|r| r.as_slice() == *last) {
        let issuer = &certs.last().unwrap().tbs_certificate.issuer;
        let root = roots
            .iter()
            .filter_map(|r| Certificate::from_der(r).ok())
            .find(|r| &r.tbs_certificate.subject == issuer)
            .ok_or("the chain doesn't reach a trusted root")?;
        certs.push(root);
    }
    for c in &certs {
        valid_at(c, now)?;
    }
    for pair in certs.windows(2) {
        let (subject, issuer) = (&pair[0], &pair[1]);
        if subject.tbs_certificate.issuer != issuer.tbs_certificate.subject {
            return Err("a certificate's issuer isn't the next in the chain".into());
        }
        if !is_ca(issuer) {
            return Err("a certificate is issued by one that isn't a CA".into());
        }
        signed_by(subject, issuer)?;
    }
    Ok(certs)
}

fn valid_at(c: &Certificate, now: u64) -> Result<(), String> {
    let v = &c.tbs_certificate.validity;
    let (from, to) = (
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    );
    if now < from || now > to {
        return Err("a certificate in the chain is outside its validity period".into());
    }
    Ok(())
}

fn is_ca(c: &Certificate) -> bool {
    let Some(exts) = &c.tbs_certificate.extensions else {
        return false;
    };
    exts.iter()
        .filter(|e| e.extn_id.to_string() == BASIC_CONSTRAINTS)
        .any(|e| {
            x509_cert::ext::pkix::BasicConstraints::from_der(e.extn_value.as_bytes())
                .is_ok_and(|b| b.ca)
        })
}

fn signed_by(subject: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| e.to_string())?;
    let sig = subject
        .signature
        .as_bytes()
        .ok_or("signature isn't whole bytes")?;
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or("key isn't whole bytes")?;
    let alg = subject.signature_algorithm.oid.to_string();
    let key_alg = spki.algorithm.oid.to_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
        .map(|o| o.to_string());
    let bad = |e: &dyn std::fmt::Display| format!("a signature in the chain doesn't verify: {e}");
    match (alg.as_str(), key_alg.as_str(), curve.as_deref()) {
        (ECDSA_SHA256 | ECDSA_SHA384, EC_PUBLIC_KEY, Some(c)) => {
            let digest: Vec<u8> = if alg == ECDSA_SHA256 {
                Sha256::digest(&tbs).to_vec()
            } else {
                Sha384::digest(&tbs).to_vec()
            };
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            match c {
                P256 => {
                    let vk =
                        p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|e| bad(&e))?;
                    let s = p256::ecdsa::DerSignature::try_from(sig).map_err(|e| bad(&e))?;
                    vk.verify_prehash(&digest, &s).map_err(|e| bad(&e))
                }
                P384 => {
                    let vk =
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|e| bad(&e))?;
                    let s = p384::ecdsa::DerSignature::try_from(sig).map_err(|e| bad(&e))?;
                    vk.verify_prehash(&digest, &s).map_err(|e| bad(&e))
                }
                other => Err(format!("unsupported curve {other}")),
            }
        }
        (RSA_SHA256, RSA, _) => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::signature::Verifier;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(key).map_err(|e| bad(&e))?;
            let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| bad(&e))?;
            vk.verify(&tbs, &s).map_err(|e| bad(&e))
        }
        _ => Err(format!("unsupported signature: {alg} with a {key_alg} key")),
    }
}

fn extension<'a>(c: &'a Certificate, oid: &str) -> Option<&'a [u8]> {
    c.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id.to_string() == oid)
        .map(|e| e.extn_value.as_bytes())
}

// ---- A small DER reader, for the attestation extensions ---------------------

/// One DER element: its class (0 universal, 2 context), whether it's
/// constructed, its tag number, and its content.
struct Tlv<'a> {
    class: u8,
    number: u32,
    content: &'a [u8],
}

fn tlv(b: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let short = || "truncated DER".to_string();
    let first = *b.first().ok_or_else(short)?;
    let mut i = 1;
    let mut number = (first & 0x1f) as u32;
    if number == 0x1f {
        number = 0;
        loop {
            let x = *b.get(i).ok_or_else(short)?;
            i += 1;
            number = number.checked_mul(128).ok_or("DER tag too large")? | (x & 0x7f) as u32;
            if x & 0x80 == 0 {
                break;
            }
        }
    }
    let l0 = *b.get(i).ok_or_else(short)?;
    i += 1;
    let len = if l0 & 0x80 == 0 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("unsupported DER length".into());
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | *b.get(i).ok_or_else(short)? as usize;
            i += 1;
        }
        l
    };
    let content = b.get(i..i + len).ok_or_else(short)?;
    Ok((
        Tlv {
            class: first >> 6,
            number,
            content,
        },
        &b[i + len..],
    ))
}

fn items(mut b: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = vec![];
    while !b.is_empty() {
        let (t, rest) = tlv(b)?;
        out.push(t);
        b = rest;
    }
    Ok(out)
}

fn integer(t: &Tlv) -> Result<u64, String> {
    if t.content.is_empty() || t.content.len() > 8 {
        return Err("bad DER integer".into());
    }
    Ok(t.content.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
}

// ---- Android Key Attestation -----------------------------------------------

const ANDROID_KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";
const ROOT_OF_TRUST: u32 = 704;
const APPLICATION_ID: u32 = 709;

fn android(
    p: &Policy,
    chain_der: &[ByteBuf],
    challenge: &[u8; 32],
    now: u64,
) -> Result<Attested, String> {
    let ders: Vec<&[u8]> = chain_der.iter().map(|d| d.as_slice()).collect();
    let certs = chain(&ders, &p.android_roots, now)?;
    let ext = extension(&certs[0], ANDROID_KEY_DESCRIPTION)
        .ok_or("no key attestation in the leaf certificate")?;
    let (desc, _) = tlv(ext)?;
    let f = items(desc.content)?;
    if f.len() < 8 {
        return Err("short key description".into());
    }
    let (attest_level, keymint_level) = (integer(&f[1])?, integer(&f[3])?);
    if f[4].content != challenge {
        return Err("the attestation doesn't bind this join".into());
    }
    if !matches!(attest_level, 1 | 2) || !matches!(keymint_level, 1 | 2) {
        return Err("the key isn't in secure hardware".into());
    }
    let (software, hardware) = (items(f[6].content)?, items(f[7].content)?);

    // The boot: verified, and the bootloader locked.
    let rot = hardware
        .iter()
        .find(|t| t.class == 2 && t.number == ROOT_OF_TRUST)
        .ok_or("no root of trust in hardware")?;
    let (rot, _) = tlv(rot.content)?;
    let rot = items(rot.content)?;
    if rot.len() < 3 {
        return Err("short root of trust".into());
    }
    let locked = rot[1].content == [0xff];
    let verified = integer(&rot[2])? == 0;
    if !(locked && verified) && !p.allow_unlocked {
        return Err("the device's bootloader is unlocked or its boot unverified".into());
    }

    // The app it was made for.
    if p.android_apps.is_empty() {
        return Err("the town trusts no Android app".into());
    }
    let app = software
        .iter()
        .chain(hardware.iter())
        .find(|t| t.class == 2 && t.number == APPLICATION_ID)
        .ok_or("no application id in the attestation")?;
    let (octets, _) = tlv(app.content)?;
    let (aid, _) = tlv(octets.content)?;
    let parts = items(aid.content)?;
    if parts.len() < 2 {
        return Err("short application id".into());
    }
    let packages: Vec<Vec<u8>> = items(parts[0].content)?
        .iter()
        .filter_map(|pi| items(pi.content).ok()?.first().map(|n| n.content.to_vec()))
        .collect();
    let digests: Vec<&[u8]> = items(parts[1].content)?.iter().map(|d| d.content).collect();
    let trusted = p.android_apps.iter().any(|a| {
        packages.iter().any(|n| n == a.package.as_bytes())
            && digests.contains(&a.signer_sha256.as_slice())
    });
    if !trusted {
        return Err("the attestation is for an app the town doesn't trust".into());
    }
    Ok(if attest_level == 2 {
        Attested::AndroidStrongBox
    } else {
        Attested::AndroidTee
    })
}

// ---- Apple App Attest ------------------------------------------------------

const APPLE_NONCE: &str = "1.2.840.113635.100.8.2";
const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";

fn cbor_field<'a>(m: &'a ciborium::Value, k: &str) -> Option<&'a ciborium::Value> {
    m.as_map()?
        .iter()
        .find(|(f, _)| f.as_text() == Some(k))
        .map(|(_, v)| v)
}

fn apple(
    p: &Policy,
    object: &[u8],
    key_id: &[u8],
    challenge: &[u8; 32],
    now: u64,
) -> Result<Attested, String> {
    let v: ciborium::Value =
        ciborium::from_reader(object).map_err(|e| format!("attestation object: {e}"))?;
    if cbor_field(&v, "fmt").and_then(|f| f.as_text()) != Some("apple-appattest") {
        return Err("not an App Attest attestation".into());
    }
    let x5c = cbor_field(&v, "attStmt")
        .and_then(|s| cbor_field(s, "x5c"))
        .and_then(|x| x.as_array())
        .ok_or("no certificate chain")?;
    let ders: Vec<&[u8]> = x5c
        .iter()
        .map(|c| {
            c.as_bytes()
                .map(|b| b.as_slice())
                .ok_or("a certificate isn't bytes")
        })
        .collect::<Result<_, _>>()?;
    let auth = cbor_field(&v, "authData")
        .and_then(|a| a.as_bytes())
        .ok_or("no auth data")?;
    let certs = chain(&ders, &p.apple_roots, now)?;

    // The nonce binds the auth data and the join.
    let nonce = Sha256::digest([auth.as_slice(), challenge.as_slice()].concat());
    let ext = extension(&certs[0], APPLE_NONCE).ok_or("no nonce in the leaf certificate")?;
    let (seq, _) = tlv(ext)?;
    let (tagged, _) = tlv(seq.content)?;
    let (octets, _) = tlv(tagged.content)?;
    if tagged.class != 2 || tagged.number != 1 || octets.content != nonce.as_slice() {
        return Err("the attestation doesn't bind this join".into());
    }

    // The key id is the attested key's.
    let leaf_key = certs[0]
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or("key isn't whole bytes")?;
    if Sha256::digest(leaf_key).as_slice() != key_id {
        return Err("the key id isn't the attested key's".into());
    }

    // The auth data: app id, counter, environment, credential.
    if auth.len() < 55 {
        return Err("short auth data".into());
    }
    if p.apple_app_ids.is_empty()
        || !p
            .apple_app_ids
            .iter()
            .any(|id| Sha256::digest(id.as_bytes()).as_slice() == &auth[..32])
    {
        return Err("the attestation is for an app the town doesn't trust".into());
    }
    if auth[33..37] != [0, 0, 0, 0] {
        return Err("the attestation's counter isn't zero".into());
    }
    let aaguid = &auth[37..53];
    if aaguid != AAGUID_PRODUCTION && !(p.allow_apple_development && aaguid == AAGUID_DEVELOPMENT) {
        return Err("not a production App Attest attestation".into());
    }
    let n = u16::from_be_bytes([auth[53], auth[54]]) as usize;
    if auth.get(55..55 + n) != Some(key_id) {
        return Err("the auth data's credential isn't the key id".into());
    }
    Ok(Attested::AppleAppAttest)
}
