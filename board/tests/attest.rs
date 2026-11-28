//! Hardware attestation at enrollment, against synthetic vendor chains: an
//! Android chain from an RSA root through P-384 and P-256 issuers, and an
//! App Attest chain from a P-384 root. Each refusal rule has its case,
//! including a forged chain that ends in the genuine root's certificate.

use der::oid::{AssociatedOid, ObjectIdentifier};
use der::Encode;
use rsa::signature::Keypair;
use pave_board::attest::{challenge, verify, AndroidApp, Attestation, Attested, Policy};
use pave_board::node::{Node, PendingJoin};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

// ---- DER, by hand, for the attestation extensions --------------------------

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let n = content.len();
    if n < 128 {
        out.push(n as u8);
    } else if n < 256 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}
fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &parts.concat())
}
fn int(n: u8) -> Vec<u8> {
    tlv(&[0x02], &[n])
}
fn enumerated(n: u8) -> Vec<u8> {
    tlv(&[0x0a], &[n])
}
fn octets(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}
fn boolean(b: bool) -> Vec<u8> {
    tlv(&[0x01], &[if b { 0xff } else { 0 }])
}
/// An explicit context tag with a high tag number, as Android's lists use.
fn ctx(n: u32, inner: Vec<u8>) -> Vec<u8> {
    tlv(&[0xbf, 0x80 | (n >> 7) as u8, (n & 0x7f) as u8], &inner)
}

#[derive(Clone, Copy)]
struct Android {
    challenge: [u8; 32],
    level: u8,
    locked: bool,
    boot: u8,
    package: &'static str,
    signer: [u8; 32],
}

impl Android {
    fn key_description(&self) -> Vec<u8> {
        let app = seq(&[set(&[seq(&[octets(self.package.as_bytes()), int(1)])]), set(&[octets(&self.signer)])]);
        seq(&[
            int(4),
            enumerated(self.level),
            int(41),
            enumerated(self.level),
            octets(&self.challenge),
            octets(&[]),
            seq(&[ctx(709, octets(&app))]),
            seq(&[ctx(704, seq(&[octets(&[0; 32]), boolean(self.locked), enumerated(self.boot), octets(&[0; 32])]))]),
        ])
    }
}

macro_rules! ext {
    ($name:ident, $oid:expr) => {
        struct $name(Vec<u8>);
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
        impl der::Encode for $name {
            fn encoded_len(&self) -> der::Result<der::Length> {
                der::Length::try_from(self.0.len())
            }
            fn encode(&self, w: &mut impl der::Writer) -> der::Result<()> {
                w.write(&self.0)
            }
        }
        impl AsExtension for $name {
            fn critical(&self, _: &Name, _: &[x509_cert::ext::Extension]) -> bool {
                false
            }
        }
    };
}
ext!(KeyDescription, "1.3.6.1.4.1.11129.2.1.17");
ext!(AppleNonce, "1.2.840.113635.100.8.2");

// ---- Certificates ----------------------------------------------------------

fn name(cn: &str) -> Name {
    Name::from_str(&format!("CN={cn}")).unwrap()
}
fn day() -> Validity {
    Validity::from_now(Duration::from_secs(86_400)).unwrap()
}
fn serial(n: u8) -> SerialNumber {
    SerialNumber::new(&[n]).unwrap()
}
fn der_of(c: Certificate) -> Vec<u8> {
    c.to_der().unwrap()
}

struct Keys {
    rsa: rsa::pkcs1v15::SigningKey<Sha256>,
    p384: p384::ecdsa::SigningKey,
    p256: p256::ecdsa::SigningKey,
    leaf: p256::ecdsa::SigningKey,
}

fn keys() -> Keys {
    let mut rng = rand::thread_rng();
    Keys {
        rsa: rsa::pkcs1v15::SigningKey::new(rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap()),
        p384: p384::ecdsa::SigningKey::random(&mut rng),
        p256: p256::ecdsa::SigningKey::random(&mut rng),
        leaf: p256::ecdsa::SigningKey::random(&mut rng),
    }
}

fn spki<K: x509_cert::spki::EncodePublicKey>(k: K) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(k).unwrap()
}

fn sub_ca(issuer: &str, cn: &str, n: u8) -> Profile {
    let _ = cn;
    let _ = n;
    Profile::SubCA { issuer: name(issuer), path_len_constraint: None }
}

fn leaf_profile(issuer: &str) -> Profile {
    Profile::Leaf { issuer: name(issuer), enable_key_agreement: false, enable_key_encipherment: false }
}

/// An Android chain, leaf first: leaf ← batch (P-256) ← intermediate
/// (P-384) ← root (RSA). Returns the chain and the root.
fn android_chain(k: &Keys, desc: &Android, leaf_validity: Validity) -> (Vec<Vec<u8>>, Vec<u8>) {
    android_chain_from(k, desc, leaf_validity, "Test Android Root")
}

fn android_chain_from(k: &Keys, desc: &Android, leaf_validity: Validity, root_name: &str) -> (Vec<Vec<u8>>, Vec<u8>) {
    let root = CertificateBuilder::new(Profile::Root, serial(1), day(), name(root_name), spki(k.rsa.verifying_key()), &k.rsa).unwrap().build::<rsa::pkcs1v15::Signature>().unwrap();
    let inter = CertificateBuilder::new(sub_ca(root_name, "", 0), serial(2), day(), name("Test Intermediate"), spki(*k.p384.verifying_key()), &k.rsa).unwrap().build::<rsa::pkcs1v15::Signature>().unwrap();
    let batch = CertificateBuilder::new(sub_ca("Test Intermediate", "", 0), serial(3), day(), name("Test Batch"), spki(*k.p256.verifying_key()), &k.p384).unwrap().build::<p384::ecdsa::DerSignature>().unwrap();
    let mut b = CertificateBuilder::new(leaf_profile("Test Batch"), serial(4), leaf_validity, name("Android Keystore Key"), spki(*k.leaf.verifying_key()), &k.p256).unwrap();
    b.add_extension(&KeyDescription(desc.key_description())).unwrap();
    let leaf = b.build::<p256::ecdsa::DerSignature>().unwrap();
    let root_der = der_of(root);
    (vec![der_of(leaf), der_of(batch), der_of(inter), root_der.clone()], root_der)
}

fn android_policy(root: &[u8], signer: [u8; 32]) -> Policy {
    Policy {
        android_roots: vec![ByteBuf::from(root.to_vec())],
        android_apps: vec![AndroidApp { package: "org.pave.wallet".into(), signer_sha256: ByteBuf::from(signer.to_vec()) }],
        ..Default::default()
    }
}

fn now() -> u64 {
    pave_board::bulletin::now()
}

fn android_attestation(chain: Vec<Vec<u8>>) -> Attestation {
    Attestation::Android { chain: chain.into_iter().map(ByteBuf::from).collect() }
}

#[test]
fn android_key_attestation() {
    let k = keys();
    let ch = [7u8; 32];
    let signer = [9u8; 32];
    let good = Android { challenge: ch, level: 2, locked: true, boot: 0, package: "org.pave.wallet", signer };
    let (chain, root) = android_chain(&k, &good, day());
    let p = android_policy(&root, signer);
    assert_eq!(verify(&p, &android_attestation(chain.clone()), &ch, now()), Ok(Attested::AndroidStrongBox));
    let (tee, _) = android_chain(&k, &Android { level: 1, ..good }, day());
    assert_eq!(verify(&p, &android_attestation(tee), &ch, now()), Ok(Attested::AndroidTee));

    let refused = |p: &Policy, d: Android, why: &str| {
        let (c, _) = android_chain(&k, &d, day());
        let e = verify(p, &android_attestation(c), &ch, now()).unwrap_err();
        assert!(e.contains(why), "{why}: got {e}");
    };
    // An unconfigured town trusts nothing.
    assert!(verify(&Policy::default(), &android_attestation(chain.clone()), &ch, now()).unwrap_err().contains("trusts no root"));
    refused(&p, Android { challenge: [8; 32], ..good }, "doesn't bind this join");
    refused(&p, Android { level: 0, ..good }, "secure hardware");
    refused(&p, Android { locked: false, ..good }, "unlocked");
    refused(&p, Android { boot: 2, ..good }, "unlocked");
    refused(&p, Android { package: "com.other.app", ..good }, "doesn't trust");
    refused(&p, Android { signer: [1; 32], ..good }, "doesn't trust");
    refused(&Policy { android_apps: vec![], ..p.clone() }, good, "trusts no Android app");
    let (c, _) = android_chain(&k, &Android { locked: false, ..good }, day());
    assert!(verify(&Policy { allow_unlocked: true, ..p.clone() }, &android_attestation(c), &ch, now()).is_ok(), "a town can allow unlocked devices");

    // A chain to another root, of the same name or another.
    let (other, _) = android_chain(&keys(), &good, day());
    assert!(verify(&p, &android_attestation(other), &ch, now()).is_err());
    let (other, _) = android_chain_from(&keys(), &good, day(), "Some Other Root");
    assert!(verify(&p, &android_attestation(other.clone()), &ch, now()).unwrap_err().contains("trusted root"));
    let (no_root, _) = (other[..3].to_vec(), ());
    assert!(verify(&p, &android_attestation(no_root), &ch, now()).unwrap_err().contains("trusted root"));

    // A forged chain: the attacker's own intermediate, named as if the
    // genuine root issued it and marked RSA-signed, with the genuine root's
    // certificate on the end. Every signature is checked, so it fails.
    let evil = keys();
    let (mut forged, _) = android_chain(&evil, &good, day());
    *forged.last_mut().unwrap() = root.clone();
    let e = verify(&p, &android_attestation(forged), &ch, now()).unwrap_err();
    assert!(e.contains("doesn't verify"), "{e}");

    // An expired leaf.
    let past = Validity { not_before: Time::try_from(std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000)).unwrap(), not_after: Time::try_from(std::time::UNIX_EPOCH + Duration::from_secs(1_000_086_400)).unwrap() };
    let (old, _) = android_chain(&k, &good, past);
    assert!(verify(&p, &android_attestation(old), &ch, now()).unwrap_err().contains("validity"));

    // A genuine device's own key signing a further "leaf": its issuer isn't a CA.
    let mut b = CertificateBuilder::new(leaf_profile("Android Keystore Key"), serial(5), day(), name("Fake"), spki(*keys().leaf.verifying_key()), &k.leaf).unwrap();
    b.add_extension(&KeyDescription(Android { challenge: [3; 32], ..good }.key_description())).unwrap();
    let fake = der_of(b.build::<p256::ecdsa::DerSignature>().unwrap());
    let mut longer = vec![fake];
    longer.extend(chain.clone());
    assert!(verify(&p, &android_attestation(longer), &[3; 32], now()).unwrap_err().contains("isn't a CA"));
}

// ---- Apple App Attest ------------------------------------------------------

const APP_ID: &str = "TEAM123456.org.pave.wallet";

struct Apple {
    challenge: [u8; 32],
    app_id: &'static str,
    counter: u32,
    aaguid: &'static [u8; 16],
}

/// An App Attest object, its key id, and the root.
fn apple_object(a: &Apple, k: &Keys, key_id_override: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    apple_object_with(a, k, key_id_override, None)
}

/// As [`apple_object`], with the auth data's credential id set to `cred`.
fn apple_object_with(a: &Apple, k: &Keys, key_id_override: Option<Vec<u8>>, cred: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = CertificateBuilder::new(Profile::Root, serial(1), day(), name("Test App Attest Root"), spki(*k.p384.verifying_key()), &k.p384).unwrap().build::<p384::ecdsa::DerSignature>().unwrap();
    let inter = CertificateBuilder::new(sub_ca("Test App Attest Root", "", 0), serial(2), day(), name("Test App Attest CA 1"), spki(*k.p256.verifying_key()), &k.p384).unwrap().build::<p384::ecdsa::DerSignature>().unwrap();
    let leaf_key = k.leaf.verifying_key().to_encoded_point(false);
    let key_id = Sha256::digest(leaf_key.as_bytes()).to_vec();
    let mut auth = Sha256::digest(a.app_id.as_bytes()).to_vec();
    auth.push(0x40);
    auth.extend_from_slice(&a.counter.to_be_bytes());
    auth.extend_from_slice(a.aaguid);
    let cred = cred.unwrap_or_else(|| key_id.clone());
    auth.extend_from_slice(&(cred.len() as u16).to_be_bytes());
    auth.extend_from_slice(&cred);
    let nonce = Sha256::digest([auth.as_slice(), a.challenge.as_slice()].concat());
    let mut b = CertificateBuilder::new(leaf_profile("Test App Attest CA 1"), serial(3), day(), name("App Attest Key"), spki(*k.leaf.verifying_key()), &k.p256).unwrap();
    b.add_extension(&AppleNonce(seq(&[tlv(&[0xa1], &octets(&nonce))]))).unwrap();
    let leaf = b.build::<p256::ecdsa::DerSignature>().unwrap();
    use ciborium::Value::{Array, Bytes, Map, Text};
    let obj = Map(vec![
        (Text("fmt".into()), Text("apple-appattest".into())),
        (Text("attStmt".into()), Map(vec![(Text("x5c".into()), Array(vec![Bytes(der_of(leaf)), Bytes(der_of(inter))])), (Text("receipt".into()), Bytes(vec![]))])),
        (Text("authData".into()), Bytes(auth)),
    ]);
    let mut out = vec![];
    ciborium::into_writer(&obj, &mut out).unwrap();
    (out, key_id_override.unwrap_or(key_id), der_of(root))
}

#[test]
fn apple_app_attest() {
    let k = keys();
    let ch = [5u8; 32];
    let good = Apple { challenge: ch, app_id: APP_ID, counter: 0, aaguid: b"appattest\0\0\0\0\0\0\0" };
    let (obj, kid, root) = apple_object(&good, &k, None);
    let p = Policy { apple_roots: vec![ByteBuf::from(root)], apple_app_ids: vec![APP_ID.into()], ..Default::default() };
    let att = |o: Vec<u8>, id: Vec<u8>| Attestation::Apple { object: ByteBuf::from(o), key_id: ByteBuf::from(id) };
    assert_eq!(verify(&p, &att(obj.clone(), kid.clone()), &ch, now()), Ok(Attested::AppleAppAttest));

    let refused = |a: Apple, kid: Option<Vec<u8>>, p: &Policy, why: &str| {
        let (o, id, _) = apple_object(&a, &k, kid);
        let e = verify(p, &att(o, id), &ch, now()).unwrap_err();
        assert!(e.contains(why), "{why}: got {e}");
    };
    assert!(verify(&Policy::default(), &att(obj, kid), &ch, now()).unwrap_err().contains("trusts no root"));
    refused(Apple { challenge: [6; 32], ..good }, None, &p, "doesn't bind this join");
    // A key id that isn't the attested key's, even with the auth data agreeing.
    let (o, _, _) = apple_object_with(&Apple { ..good }, &k, None, Some(vec![0; 32]));
    assert!(verify(&p, &att(o, vec![0; 32]), &ch, now()).unwrap_err().contains("attested key"));
    // The right key id, but auth data naming another credential.
    let (o, id, _) = apple_object_with(&Apple { ..good }, &k, None, Some(vec![1; 32]));
    assert!(verify(&p, &att(o, id), &ch, now()).unwrap_err().contains("credential"));
    refused(Apple { app_id: "TEAM999999.com.other", ..good }, None, &p, "doesn't trust");
    refused(Apple { counter: 1, ..good }, None, &p, "counter");
    refused(Apple { aaguid: b"appattestdevelop", ..good }, None, &p, "production");
    let (o, id, _) = apple_object(&Apple { aaguid: b"appattestdevelop", ..good }, &k, None);
    assert!(verify(&Policy { allow_apple_development: true, ..p.clone() }, &att(o, id), &ch, now()).is_ok());
    // A chain to another root.
    let (o, id, _) = apple_object(&good, &keys(), None);
    assert!(verify(&p, &att(o, id), &ch, now()).is_err());
}

// ---- Enrollment ------------------------------------------------------------

#[test]
fn enrollment_grants_hardware_only_on_attestation() {
    let dir = std::env::temp_dir().join(format!("pave-attest-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let k = keys();
    let signer = [9u8; 32];

    let (pending, mut join) = PendingJoin::generate();
    let ch = challenge(&join);
    let desc = Android { challenge: ch, level: 2, locked: true, boot: 0, package: "org.pave.wallet", signer };
    let (chain, root) = android_chain(&k, &desc, day());
    let mut p = android_policy(&root, signer);
    p.earns.insert(Attested::AndroidStrongBox, "hardware".into());
    p.earns.insert(Attested::AndroidTee, "hardware".into());
    town.operator.as_mut().unwrap().attest = p;

    // Without an attestation the operator can't grant hardware.
    assert!(town.enroll(&join, "hardware", &[]).err().unwrap().contains("needs a hardware attestation"));
    // One bound to another join is refused.
    let (_, other) = PendingJoin::generate();
    let mut borrowed = other.clone();
    borrowed.attestation = Some(android_attestation(chain.clone()));
    assert!(town.enroll(&borrowed, "hardware", &[]).err().unwrap().contains("doesn't bind this join"));
    // Software needs nothing.
    assert!(town.enroll(&other, "software", &[]).is_ok());
    // This device's own attestation earns hardware.
    join.attestation = Some(android_attestation(chain));
    let e = town.enroll(&join, "hardware", &[100]).unwrap();
    assert_eq!(e.class, "hardware");
    let n = Node::finish_enrollment(pending, &e, "ana", &dir.join("ana")).unwrap();
    assert_eq!(n.my_coins().iter().map(|c| c.amount).sum::<u64>(), 100);

    // A town where only StrongBox earns hardware: a TEE attestation that
    // verifies still doesn't.
    let (_, mut tee_join) = PendingJoin::generate();
    let (tee_chain, _) = android_chain(&k, &Android { challenge: challenge(&tee_join), level: 1, ..desc }, day());
    tee_join.attestation = Some(android_attestation(tee_chain));
    let op = town.operator.as_mut().unwrap();
    op.attest.earns.remove(&Attested::AndroidTee);
    assert!(town.enroll(&tee_join, "hardware", &[]).err().unwrap().contains("doesn't earn"));
    let _ = std::fs::remove_dir_all(&dir);
}
