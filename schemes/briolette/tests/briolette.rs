//! The kernel's conflict and evidence properties with real ECDAA.

use pave_kernel::invariants::{check_all, no_false_flag};
use pave_kernel::receipt::Receipt;
use pave_kernel::*;
use pave_scheme_briolette::{BrioletteV1, HolderKey, Issuer, SIGNATURE_WITH_NYM_LENGTH};
use std::collections::BTreeSet;

struct P {
    key: HolderKey,
    cred: Credential,
}

fn holder(issuer: &Issuer, scheme: &BrioletteV1) -> P {
    let key = issuer.join_locally();
    let cred = scheme.credential(&key);
    P { key, cred }
}

#[test]
fn holdings_are_unlinkable_but_reuse_links() {
    let issuer = Issuer::new();
    let scheme = issuer.scheme();
    let key = issuer.join_locally();
    let (c1, c2) = (scheme.credential(&key), scheme.credential(&key));
    assert_ne!(c1, c2, "each holding gets a fresh randomized credential");

    let msg = b"pay".to_vec();
    let s_plain = scheme.sign(&key, &c1, &msg, None);
    assert!(scheme.verify(&c1, &msg, None, &s_plain));
    assert!(scheme.nym(&s_plain).is_none(), "no basename, no pseudonym");

    let (b1, b2) = (b"state-1".as_slice(), b"state-2".as_slice());
    let x = scheme.sign(&key, &c1, &msg, Some(b1));
    let y = scheme.sign(&key, &c2, b"other", Some(b1));
    let z = scheme.sign(&key, &c1, &msg, Some(b2));
    assert_eq!(x.0.len(), SIGNATURE_WITH_NYM_LENGTH);
    assert_eq!(scheme.nym(&x), scheme.nym(&y), "same key, same basename: same pseudonym");
    assert_ne!(scheme.nym(&x), scheme.nym(&z), "different basename: unlinkable");
    assert!(!scheme.verify(&c2, &msg, Some(b1), &x), "bound to the signing credential");
}

#[test]
fn offline_double_spend_with_ecdaa() {
    let issuer = Issuer::new();
    let scheme = issuer.scheme();
    let root = holder(&issuer, &scheme);
    let (minter, m, a, b) = (holder(&issuer, &scheme), holder(&issuer, &scheme), holder(&issuer, &scheme), holder(&issuer, &scheme));
    let genesis = Genesis { label: "ecdaa town".into(), root_rules: ScopeRules::default(), rooting: root.cred.clone() };
    let mut base = View::new(scheme.clone(), genesis);
    let schema = Schema { label: "test credit".into(), divisible: true, soft_expiry: Some(4), hard_expiry: Some(8), offline_transfers: Some(3), max_per_holder: None, sequence: None };
    let issue = sign(&scheme, &root.key, &root.cred, Op::IssueBudget { authority: base.genesis().rooting_capability(), schema, amount: 10, to: minter.cred.clone() });
    assert_eq!(base.apply(&issue), Ok(Applied::Accepted));
    let mint = sign(&scheme, &minter.key, &minter.cred, Op::Mint { budget: issue.output(0), amount: 10, to: m.cred.clone(), change_to: minter.cred.clone() });
    assert_eq!(base.apply(&mint), Ok(Applied::Accepted));
    let coin = mint.output(0);

    let (mut x, mut y) = (base.clone(), base);
    let rcpt = Receipt::leaf(b"lunch".to_vec()).root();
    assert_eq!(x.apply(&sign(&scheme, &m.key, &m.cred, Op::Transfer { state: coin, to: a.cred.clone(), receipt: rcpt })), Ok(Applied::Accepted));
    assert_eq!(y.apply(&sign(&scheme, &m.key, &m.cred, Op::Transfer { state: coin, to: b.cred.clone(), receipt: rcpt })), Ok(Applied::Accepted));
    assert_eq!(x.merge_from(&y), vec![coin]);

    let honest: BTreeSet<_> = [&a, &b, &minter, &root].iter().map(|p| p.cred.clone()).collect();
    no_false_flag(&x, &honest).unwrap();
    assert_eq!(x.flagged(), [m.cred.clone()].into_iter().collect());
    check_all(&x).unwrap();
    let ev = x.evidence().next().unwrap();
    assert!(verify_evidence(&scheme, ev));
    println!("evidence: nym {} B, two records with signatures of {} B each", ev.nym.len(), ev.first.sigs[0].0.len());
}

#[test]
fn join_keeps_the_secret_key_with_the_holder() {
    use pave_scheme_briolette::{join_nonce, PendingKey};
    let issuer = Issuer::new();
    let scheme = issuer.scheme();
    let nonce = join_nonce();
    let (pending, req) = PendingKey::generate(&nonce);
    // The request carries only a public key and a proof of its secret; a
    // tampered key or a different nonce has no valid proof.
    let mut bad = req.clone();
    bad.public_key[5] ^= 1;
    assert!(issuer.issue(&bad).is_err());
    let mut renonced = req.clone();
    renonced.nonce = join_nonce();
    assert!(issuer.issue(&renonced).is_err());
    let reply = issuer.issue(&req).unwrap();
    // A credential for someone else's key is refused by the holder.
    let (other, _) = PendingKey::generate(&nonce);
    assert!(other.finish(&scheme, &reply).is_err());
    let key = pending.finish(&scheme, &reply).unwrap();
    let c = scheme.credential(&key);
    let s = scheme.sign(&key, &c, b"msg", Some(b"bsn"));
    assert!(scheme.verify(&c, b"msg", Some(b"bsn"), &s));
}
