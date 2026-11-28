//! Swaps with the town: expired coins come back at once, coins tainted by a
//! revoked group are held and then paid, and cheats are refused.

use pave_board::node::{Node, PendingJoin};
use pave_board::swap::{SwapOutcome, Verdict, SWAP_HOLD};
use pave_kernel::Op;
use pave_protocol::{cheat_list, gossip, Refusal};
use std::collections::BTreeSet;

fn join(town: &mut Node, name: &str, class: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, class, credits).unwrap();
    let mut p = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    refill(town, &mut p);
    p
}

fn refill(town: &mut Node, p: &mut Node) {
    let t = town
        .answer_refill(&p.refill_request(&town.refill_terms().unwrap(), 8).unwrap())
        .unwrap();
    p.take_tickets(t);
}

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle(), b.bundle());
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
    a.outbox.clear();
    b.outbox.clear();
    let (sa, sb) = (a.standings(), b.standings());
    b.absorb_standings(sa);
    a.absorb_standings(sb);
}

fn gossip_to(from: &Node, to: &mut Node) {
    let hints = gossip::hints(&from.view, &from.know, &from.carries());
    gossip::absorb_hints(&mut to.know, &hints);
    let wants = gossip::wants(&to.view, &to.know, &to.carries(), &to.watch());
    let proofs = gossip::serve(&from.view, &from.know, &from.carries(), &wants);
    gossip::absorb(&mut to.view, &mut to.know, proofs);
}

/// The whole swap, in process. Returns the outcome.
fn swap(
    town: &mut Node,
    p: &mut Node,
    state: pave_kernel::Hash,
) -> Result<(pave_kernel::Credential, SwapOutcome), String> {
    let q = town.quote(&p.quote_request(state, &cheat_list(&town.view))?)?;
    let req = p.swap_request(&q)?;
    let to = req.to.clone();
    let out = town.answer_swap(&req)?;
    Ok((to, out))
}

#[test]
fn swaps() {
    let dir = std::env::temp_dir().join(format!("pave-swap-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = join(&mut town, "alice", "hardware", &dir, &[100]);
    let mut bob = join(&mut town, "bob", "hardware", &dir, &[20]);
    let mut carol = join(&mut town, "carol", "software", &dir, &[20, 20]);

    // Carol pays Bob honestly, before anything goes wrong.
    let carols = carol.my_coins();
    let to_bob = carol
        .spend(carols[0].state, bob.receive().unwrap())
        .unwrap();
    meet(&mut carol, &mut bob);
    assert_eq!(bob.check(&to_bob), Ok(()));

    // 1. Tainted: the town revokes Carol's enrollment group. Bob's coin from
    //    her was issued within the window, so recipients refuse it offline;
    //    the swapper holds it, then pays once the hold is over.
    town.roll_epoch([carol.group].into_iter().collect(), BTreeSet::new())
        .unwrap();
    gossip_to(&town, &mut bob);
    refill(&mut town, &mut bob);
    assert!(matches!(bob.check(&to_bob), Err(Refusal::Revoked { .. })));
    let (owed, out) = swap(&mut town, &mut bob, to_bob).unwrap();
    let SwapOutcome::Held { until } = out else {
        panic!("expected a hold, got {out:?}")
    };
    assert!(
        matches!(town.collect_swap(&owed).unwrap(), SwapOutcome::Held { .. }),
        "not before the hold is over"
    );
    for _ in 0..SWAP_HOLD {
        town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    }
    let _ = until;
    let out = town.collect_swap(&owed).unwrap();
    let fresh = bob.take_swap(&out).unwrap().unwrap();
    gossip_to(&town, &mut bob);
    assert_eq!(bob.check(&fresh), Ok(()));

    // 2. Expired: Alice's credit passes its hard expiry (8 epochs from mint).
    for _ in 0..8 {
        town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    }
    gossip_to(&town, &mut alice);
    let old = alice.my_coins()[0].state;
    assert!(matches!(
        alice.check(&old),
        Err(Refusal::Expired { .. }) | Err(Refusal::CoinExpired { .. })
    ));
    refill(&mut town, &mut alice); // fresh tickets to receive the new coin on
    let quote = town.quote(&alice.quote_request(old, &[]).unwrap()).unwrap();
    assert_eq!(quote.verdict, Verdict::Pay);
    assert!(quote.verify(alice.view.scheme()));
    let req = alice.swap_request(&quote).unwrap();
    let out = town.answer_swap(&req).unwrap();
    let fresh = alice.take_swap(&out).unwrap().unwrap();
    assert_eq!(alice.check(&fresh), Ok(()));
    assert_eq!(alice.my_coins().iter().map(|c| c.amount).sum::<u64>(), 100);
    // Every payout is paired with a public retirement of the same amount.
    let SwapOutcome::Paid { retire, mint, .. } = &out else {
        panic!()
    };
    assert!(matches!(retire.op, Op::Retire { .. }));
    assert!(matches!(mint.op, Op::Mint { amount: 100, .. }));
    // The coin can't be swapped twice.
    assert!(alice.quote_request(old, &[]).is_err());

    // 3. A cheat is refused: Carol double-spends, the evidence reaches the
    //    town, and she can't prove she isn't the cheat for any coin.
    let other = carol.my_coins()[0].state;
    let first = carol.cheat(other, alice.receive().unwrap()).unwrap();
    meet(&mut carol, &mut alice);
    carol.cheat(other, bob.receive().unwrap()).unwrap();
    meet(&mut carol, &mut bob);
    meet(&mut alice, &mut bob);
    meet(&mut alice, &mut town);
    assert!(!cheat_list(&town.view).is_empty());
    assert!(carol.quote_request(first, &cheat_list(&town.view)).is_err());
    // Asking with an empty list only gets the list back.
    let q = carol.quote_request(other, &[]).ok().map(|r| town.quote(&r));
    if let Some(Ok(q)) = q {
        assert!(matches!(
            q.verdict,
            Verdict::NeedStanding(_) | Verdict::Refuse(_)
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
