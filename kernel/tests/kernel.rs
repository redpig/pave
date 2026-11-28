//! Kernel tests. Each mirrors a property or injected fault in the TLA+ models
//! (see formal/TRACEABILITY.md); the fault name is in the test name.

use ed25519_dalek::SigningKey;
use pave_kernel::invariants::{check_all, conservation, detected, no_false_flag};
use pave_kernel::objects::rights;
use pave_kernel::receipt::Receipt;
use pave_kernel::scheme::DevScheme;
use pave_kernel::*;
use std::collections::BTreeSet;

struct Person {
    key: SigningKey,
    cred: Credential,
}

fn person() -> Person {
    let key = DevScheme::keygen();
    let cred = DevScheme.credential(&key);
    Person { key, cred }
}

fn cash(divisible: bool) -> Schema {
    Schema {
        label: "test credit".into(),
        divisible,
        soft_expiry: Some(4),
        hard_expiry: Some(8),
        offline_transfers: Some(3),
        max_per_holder: Some(1_000),
        sequence: None,
    }
}

struct World {
    view: View<DevScheme>,
    root: Person,
}

fn world() -> World {
    let root = person();
    let genesis = Genesis {
        label: "test town".into(),
        root_rules: ScopeRules::default(),
        rooting: root.cred.clone(),
    };
    World {
        view: View::new(DevScheme, genesis),
        root,
    }
}

fn op(p: &Person, op: Op) -> Record {
    sign(&DevScheme, &p.key, &p.cred, op)
}

/// Issue a budget to `minter` and mint `amount` to `to`. Returns the value state.
fn mint_to(
    w: &mut World,
    schema: Schema,
    budget: u64,
    amount: u64,
    minter: &Person,
    to: &Credential,
) -> Hash {
    let auth = w.view.genesis().rooting_capability();
    let issue = op(
        &w.root,
        Op::IssueBudget {
            authority: auth,
            schema,
            amount: budget,
            to: minter.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&issue), Ok(Applied::Accepted));
    let b = issue.output(0);
    let m = op(
        minter,
        Op::Mint {
            budget: b,
            amount,
            to: to.clone(),
            change_to: minter.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&m), Ok(Applied::Accepted));
    m.output(0)
}

fn transfer(from: &Person, state: Hash, to: &Credential) -> Record {
    op(
        from,
        Op::Transfer {
            state,
            to: to.clone(),
            receipt: Receipt::leaf(b"t".to_vec()).root(),
        },
    )
}

#[test]
fn mint_and_transfer_conserve() {
    let mut w = world();
    let (minter, a, b) = (person(), person(), person());
    let s = mint_to(&mut w, cash(true), 100, 40, &minter, &a.cred);
    let t = transfer(&a, s, &b.cred);
    assert_eq!(w.view.apply(&t), Ok(Applied::Accepted));
    let coin = w.view.coin(&t.output(0)).unwrap();
    assert_eq!((coin.amount, coin.hops, coin.history.len()), (40, 1, 2));
    check_all(&w.view).unwrap();
}

/// Fault "steal": a transfer signed by someone who doesn't hold the state.
#[test]
fn steal_is_rejected() {
    let mut w = world();
    let (minter, a, thief) = (person(), person(), person());
    let s = mint_to(&mut w, cash(true), 10, 10, &minter, &a.cred);
    let t = transfer(&thief, s, &thief.cred);
    assert_eq!(w.view.apply(&t), Err(Reject::NotHolder(s)));
    // A forged signature in the holder's name fails too.
    let mut forged = transfer(&a, s, &thief.cred);
    forged.sigs[0] = transfer(&thief, s, &thief.cred).sigs[0].clone();
    assert_eq!(w.view.apply(&forged), Err(Reject::BadSignature));
    check_all(&w.view).unwrap();
}

#[test]
fn minting_never_exceeds_budget() {
    let mut w = world();
    let minter = person();
    let auth = w.view.genesis().rooting_capability();
    let issue = op(
        &w.root,
        Op::IssueBudget {
            authority: auth,
            schema: cash(true),
            amount: 5,
            to: minter.cred.clone(),
        },
    );
    w.view.apply(&issue).unwrap();
    let too_much = op(
        &minter,
        Op::Mint {
            budget: issue.output(0),
            amount: 6,
            to: minter.cred.clone(),
            change_to: minter.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&too_much), Err(Reject::Unbalanced));
    // Only the rooting capability (or one derived with "issue") can issue.
    let rogue = op(
        &minter,
        Op::IssueBudget {
            authority: auth,
            schema: cash(true),
            amount: 5,
            to: minter.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&rogue), Err(Reject::NotHolder(auth)));
    conservation(&w.view).unwrap();
}

#[test]
fn split_and_merge_conserve_and_respect_divisibility() {
    let mut w = world();
    let (minter, a, b) = (person(), person(), person());
    let s = mint_to(&mut w, cash(true), 100, 30, &minter, &a.cred);
    let bad = op(
        &a,
        Op::Split {
            state: s,
            parts: vec![(20, b.cred.clone()), (20, a.cred.clone())],
            receipt: Hash([0; 32]),
        },
    );
    assert_eq!(w.view.apply(&bad), Err(Reject::Unbalanced));
    let split = op(
        &a,
        Op::Split {
            state: s,
            parts: vec![(10, a.cred.clone()), (20, a.cred.clone())],
            receipt: Hash([0; 32]),
        },
    );
    assert_eq!(w.view.apply(&split), Ok(Applied::Accepted));
    let merge = op(
        &a,
        Op::Merge {
            states: vec![split.output(0), split.output(1)],
            to: b.cred.clone(),
            receipt: Hash([0; 32]),
        },
    );
    assert_eq!(w.view.apply(&merge), Ok(Applied::Accepted));
    assert_eq!(w.view.coin(&merge.output(0)).unwrap().amount, 30);
    check_all(&w.view).unwrap();

    // A non-divisible schema allows only zero-value splits.
    let mut w2 = world();
    let c = mint_to(&mut w2, cash(false), 1, 1, &minter, &a.cred);
    let halves = op(
        &a,
        Op::Split {
            state: c,
            parts: vec![(0, a.cred.clone()), (1, a.cred.clone())],
            receipt: Hash([0; 32]),
        },
    );
    assert_eq!(w2.view.apply(&halves), Ok(Applied::Accepted));
    check_all(&w2.view).unwrap();
}

/// Proof of means: a zero-value split re-holds the full amount and leaves a
/// zero-value part as a receipt of possession; nothing moves.
#[test]
fn zero_value_split_proves_means() {
    let mut w = world();
    let (minter, poster, worker) = (person(), person(), person());
    let s = mint_to(&mut w, cash(true), 100, 50, &minter, &poster.cred);
    let terms = Receipt::Node(vec![("public".into(), Receipt::leaf(b"pay 50".to_vec()))]);
    let proof = op(
        &poster,
        Op::Split {
            state: s,
            parts: vec![(50, poster.cred.clone()), (0, worker.cred.clone())],
            receipt: terms.root(),
        },
    );
    assert_eq!(w.view.apply(&proof), Ok(Applied::Accepted));
    assert_eq!(w.view.coin(&proof.output(0)).unwrap().holder, poster.cred);
    assert_eq!(w.view.coin(&proof.output(1)).unwrap().amount, 0);
    check_all(&w.view).unwrap();
}

#[test]
fn per_holder_limit() {
    let mut w = world();
    let (minter, a) = (person(), person());
    let auth = w.view.genesis().rooting_capability();
    let issue = op(
        &w.root,
        Op::IssueBudget {
            authority: auth,
            schema: cash(true),
            amount: 5_000,
            to: minter.cred.clone(),
        },
    );
    w.view.apply(&issue).unwrap();
    let big = op(
        &minter,
        Op::Mint {
            budget: issue.output(0),
            amount: 1_001,
            to: a.cred.clone(),
            change_to: minter.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&big), Err(Reject::OverPerHolder));
}

/// Kernel invariant 6 with faults "noevidence", "flagrecipient" and
/// "positiononly": m spends the same coin at two sites; after merge the
/// first-seen spend stands, evidence names m and only m, and honest holders
/// downstream of either fork are never flagged.
#[test]
fn offline_double_spend_is_detected_and_names_only_the_signer() {
    let mut w = world();
    let (minter, m, a, b, c, d) = (person(), person(), person(), person(), person(), person());
    let s = mint_to(&mut w, cash(true), 10, 10, &minter, &m.cred);
    let mut site_a = w.view.clone();
    let mut site_b = w.view.clone();

    let to_a = transfer(&m, s, &a.cred);
    let to_b = transfer(&m, s, &b.cred);
    assert_eq!(site_a.apply(&to_a), Ok(Applied::Accepted));
    assert_eq!(site_b.apply(&to_b), Ok(Applied::Accepted));
    // Honest holders pass the coin on at each site: same position, different signers.
    assert_eq!(
        site_a.apply(&transfer(&a, to_a.output(0), &c.cred)),
        Ok(Applied::Accepted)
    );
    assert_eq!(
        site_b.apply(&transfer(&b, to_b.output(0), &d.cred)),
        Ok(Applied::Accepted)
    );

    let new = site_a.merge_from(&site_b);
    assert_eq!(new, vec![s]);
    site_b.merge_from(&site_a);

    let honest: BTreeSet<_> = [&a, &b, &c, &d, &minter]
        .iter()
        .map(|p| p.cred.clone())
        .collect();
    for v in [&site_a, &site_b] {
        assert_eq!(v.flagged(), [m.cred.clone()].into_iter().collect());
        no_false_flag(v, &honest).unwrap();
        detected(v).unwrap();
        conservation(v).unwrap();
    }
    // First seen wins locally: each site keeps its own fork.
    assert!(site_a.coins_held_by(&c.cred).next().is_some());
    assert!(site_b.coins_held_by(&d.cred).next().is_some());
}

/// Fault "fakeevidence": evidence that isn't two signed uses by one holder is refused.
#[test]
fn forged_evidence_is_refused() {
    let mut w = world();
    let (minter, m, a, b) = (person(), person(), person(), person());
    let s = mint_to(&mut w, cash(true), 10, 10, &minter, &m.cred);
    let mut site = w.view.clone();
    let mut other = w.view.clone();
    site.apply(&transfer(&m, s, &a.cred)).unwrap();
    other.apply(&transfer(&m, s, &b.cred)).unwrap();
    site.merge_from(&other);
    let real = site.evidence().next().unwrap().clone();
    assert!(verify_evidence(&DevScheme, &real));

    let mut blame_a = real.clone();
    blame_a.signer = a.cred.clone();
    assert!(!verify_evidence(&DevScheme, &blame_a));
    let mut same_twice = real.clone();
    same_twice.second = same_twice.first.clone();
    assert!(!verify_evidence(&DevScheme, &same_twice));
    let mut fresh = w.view.clone();
    assert!(!fresh.import_evidence(&blame_a));
    assert!(fresh.import_evidence(&real));
}

/// A double mint across a partition is a double use of the budget state.
#[test]
fn double_mint_offline_is_detected() {
    let mut w = world();
    let (minter, a, b) = (person(), person(), person());
    let auth = w.view.genesis().rooting_capability();
    let issue = op(
        &w.root,
        Op::IssueBudget {
            authority: auth,
            schema: cash(true),
            amount: 10,
            to: minter.cred.clone(),
        },
    );
    w.view.apply(&issue).unwrap();
    let (mut x, mut y) = (w.view.clone(), w.view.clone());
    x.apply(&op(
        &minter,
        Op::Mint {
            budget: issue.output(0),
            amount: 10,
            to: a.cred.clone(),
            change_to: minter.cred.clone(),
        },
    ))
    .unwrap();
    y.apply(&op(
        &minter,
        Op::Mint {
            budget: issue.output(0),
            amount: 10,
            to: b.cred.clone(),
            change_to: minter.cred.clone(),
        },
    ))
    .unwrap();
    x.merge_from(&y);
    assert_eq!(x.flagged(), [minter.cred.clone()].into_iter().collect());
    conservation(&x).unwrap();
}

#[test]
fn derive_only_narrows() {
    let mut w = world();
    let deputy = person();
    let auth = w.view.genesis().rooting_capability();
    let wider: BTreeSet<String> = [rights::ISSUE, rights::CREATE_SCOPE, "rule-the-world"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let d = op(
        &w.root,
        Op::Derive {
            parent: auth,
            rights: wider,
            to: deputy.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&d), Err(Reject::Widening));
    let narrower: BTreeSet<String> = [rights::ISSUE.to_string()].into_iter().collect();
    let d = op(
        &w.root,
        Op::Derive {
            parent: auth,
            rights: narrower,
            to: deputy.cred.clone(),
        },
    );
    assert_eq!(w.view.apply(&d), Ok(Applied::Accepted));
    // The deputy can issue but not create scopes.
    let scope = op(
        &deputy,
        Op::CreateScope {
            parent: w.view.genesis().root_scope(),
            rules: ScopeRules::default(),
            authority: d.output(0),
        },
    );
    assert_eq!(
        w.view.apply(&scope),
        Err(Reject::MissingRight(rights::CREATE_SCOPE))
    );
}

#[test]
fn child_scope_is_never_looser() {
    let mut w = world();
    let auth = w.view.genesis().rooting_capability();
    let root = w.view.genesis().root_scope();
    let strict = ScopeRules {
        senders: [Hash([1; 32])].into_iter().collect(),
        ..Default::default()
    };
    let s1 = op(
        &w.root,
        Op::CreateScope {
            parent: root,
            rules: strict.clone(),
            authority: auth,
        },
    );
    assert_eq!(w.view.apply(&s1), Ok(Applied::Accepted));
    let loose = op(
        &w.root,
        Op::CreateScope {
            parent: s1.output(0),
            rules: ScopeRules::default(),
            authority: auth,
        },
    );
    assert_eq!(w.view.apply(&loose), Err(Reject::LooserScope));
    let same = op(
        &w.root,
        Op::CreateScope {
            parent: s1.output(0),
            rules: strict,
            authority: auth,
        },
    );
    assert_eq!(w.view.apply(&same), Ok(Applied::Accepted));
}

/// Kernel invariant 2 for messages: a scope that requires a capability
/// refuses senders without one.
#[test]
fn send_needs_consent() {
    let mut w = world();
    let (member, stranger) = (person(), person());
    let auth = w.view.genesis().rooting_capability();
    let root = w.view.genesis().root_scope();
    let member_schema = Hash([7; 32]);
    let s = op(
        &w.root,
        Op::CreateScope {
            parent: root,
            rules: ScopeRules {
                senders: [member_schema].into_iter().collect(),
                ..Default::default()
            },
            authority: auth,
        },
    );
    w.view.apply(&s).unwrap();
    let msg = |p: &Person, presenting| {
        op(
            p,
            Op::Send {
                scope: s.output(0),
                presenting,
                body: b"hello".to_vec(),
                receipt: Hash([0; 32]),
            },
        )
    };
    assert_eq!(
        w.view.apply(&msg(&stranger, None)),
        Err(Reject::NotAllowedToSend)
    );
    assert_eq!(
        w.view.apply(&msg(&member, Some(auth))),
        Err(Reject::NotAllowedToSend)
    );
    let _ = member;
}

#[test]
fn receipts_reveal_branch_by_branch() {
    let r = Receipt::Node(vec![
        ("public".into(), Receipt::leaf(b"price 12".to_vec())),
        ("parties".into(), Receipt::leaf(b"terms".to_vec())),
        (
            "private".into(),
            Receipt::Node(vec![("address".into(), Receipt::leaf(b"12 Elm".to_vec()))]),
        ),
    ]);
    let public = r.reveal(&["public"]).unwrap();
    assert_eq!(public.root(), r.root());
    let addr = r.reveal(&["private", "address"]).unwrap();
    assert_eq!(addr.root(), r.root());
    assert!(r.reveal(&["nope"]).is_none());
    // Two receipts with the same data differ: every leaf is salted.
    assert_ne!(
        Receipt::leaf(b"x".to_vec()).root(),
        Receipt::leaf(b"x".to_vec()).root()
    );
}

#[test]
fn replay_is_idempotent() {
    let mut w = world();
    let (minter, a) = (person(), person());
    let s = mint_to(&mut w, cash(true), 10, 10, &minter, &a.cred);
    let t = transfer(&a, s, &minter.cred);
    assert_eq!(w.view.apply(&t), Ok(Applied::Accepted));
    assert_eq!(w.view.apply(&t), Ok(Applied::Duplicate));
    check_all(&w.view).unwrap();
}
