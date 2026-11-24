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

#[test]
fn anyone_can_prove_they_are_not_the_cheat_except_the_cheat() {
    let issuer = Issuer::new();
    let scheme = issuer.scheme();
    let (cheat, honest, other) = (issuer.join_locally(), issuer.join_locally(), issuer.join_locally());

    // The cheat signs one state twice; that is what evidence holds.
    let state = b"state-7";
    let c1 = scheme.credential(&cheat);
    let s1 = scheme.sign(&cheat, &c1, b"pay bob", Some(state));
    let list = vec![(state.to_vec(), scheme.nym(&s1).unwrap())];

    // An honest holder proves it, for any of its credentials.
    let h = scheme.credential(&honest);
    let proof = scheme.prove_not_cheat(&honest, &h, &list, b"pay alice").unwrap();
    assert_eq!(proof.len(), pave_scheme_briolette::nonrevoked::ENTRY_PROOF_LENGTH);
    assert!(scheme.verify_not_cheat(&h, &list, b"pay alice", &proof));
    // Bound to its use, its credential and its list.
    assert!(!scheme.verify_not_cheat(&h, &list, b"pay carol", &proof));
    assert!(!scheme.verify_not_cheat(&scheme.credential(&honest), &list, b"pay alice", &proof));
    assert!(!scheme.verify_not_cheat(&h, &[(b"state-8".to_vec(), list[0].1.clone())], b"pay alice", &proof));
    let mut bad = proof.clone();
    bad[60] ^= 1;
    assert!(!scheme.verify_not_cheat(&h, &list, b"pay alice", &bad));
    // Two proofs by the same holder share nothing: no linking.
    let again = scheme.prove_not_cheat(&honest, &h, &list, b"pay alice").unwrap();
    assert_ne!(proof[..48], again[..48]);

    // The cheat can't, under any of its unlinkable credentials, and can't
    // borrow someone else's proof.
    for _ in 0..3 {
        let c = scheme.credential(&cheat);
        assert!(scheme.prove_not_cheat(&cheat, &c, &list, b"pay alice").is_none());
        assert!(!scheme.verify_not_cheat(&c, &list, b"pay alice", &proof));
    }
    // Nor with a credential that isn't its own.
    let o = scheme.credential(&other);
    assert!(scheme.prove_not_cheat(&cheat, &o, &list, b"x").is_none());
    // A credential from another issuer is refused.
    let stranger = Issuer::new().join_locally();
    let sc = Issuer::new().scheme().credential(&stranger);
    assert!(!scheme.verify_not_cheat(&sc, &list, b"x", &[]));
    // An empty list needs an empty proof.
    assert!(scheme.verify_not_cheat(&h, &[], b"x", &scheme.prove_not_cheat(&honest, &h, &[], b"x").unwrap()));
}
