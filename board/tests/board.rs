//! The work-board story in process, on Briolette v1 credentials: wallets
//! meeting by swapping bundles, as phones would.

use pave_board::board::{jobs, Status};
use pave_board::node::Node;
use pave_protocol::gossip;
use pave_protocol::{check, Policy, Refusal};
use std::collections::BTreeSet;

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

/// Two-tier gossip from `from` to `to`, in process.
fn gossip_to(from: &Node, to: &mut Node) {
    let hints = gossip::hints(&from.view, &from.know, &from.carries());
    gossip::absorb_hints(&mut to.know, &hints);
    let wants = gossip::wants(&to.view, &to.know, &to.carries(), &to.watch());
    let proofs = gossip::serve(&from.view, &from.know, &from.carries(), &wants);
    gossip::absorb(&mut to.view, &mut to.know, proofs);
}

#[test]
fn the_whole_story_on_ecdaa() {
    let dir = std::env::temp_dir().join(format!("pave-board-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = join(&mut town, "alice", &dir, &[100]);
    let mut bob = join(&mut town, "bob", &dir, &[20]);
    let mut carol = join(&mut town, "carol", &dir, &[20, 20]);
    meet(&mut alice, &mut bob);
    meet(&mut alice, &mut carol);

    // The job.
    let job = alice.post("Fix the fence", 30).unwrap();
    meet(&mut alice, &mut bob);
    bob.reply(job, "Saturday").unwrap();
    meet(&mut alice, &mut bob);
    let worker = jobs(&alice.view, &alice.town.board)[&job].replies[0].0.clone();
    alice.accept(job, worker).unwrap();
    assert!(alice.pay(job).is_err(), "can't pay before the work is done");
    meet(&mut alice, &mut bob);
    assert!(alice.done(job).is_err(), "only the accepted worker marks done");
    bob.done(job).unwrap();
    meet(&mut alice, &mut bob);
    let payment = alice.pay(job).unwrap();
    meet(&mut alice, &mut bob);
    assert_eq!(jobs(&bob.view, &bob.town.board)[&job].status, Status::Paid);
    assert_eq!(bob.check(&payment), Ok(()));
    assert_eq!(bob.my_coins().iter().map(|c| c.amount).sum::<u64>(), 50);
    assert_eq!(alice.my_coins().iter().map(|c| c.amount).sum::<u64>(), 70);

    // Unlinkable: every credential alice used is distinct.
    let alice_signers: BTreeSet<_> = alice.view.records().iter().filter(|r| alice.mine.contains(&r.signer)).map(|r| &r.signer).collect();
    assert!(alice_signers.len() >= 2);

    // The double spend.
    let coins = carol.my_coins();
    let (coin, other) = (coins[0].state, coins[1].state);
    let to_bob = carol.cheat(coin, bob.receive().unwrap()).unwrap();
    meet(&mut carol, &mut bob);
    carol.cheat(coin, alice.receive().unwrap()).unwrap();
    meet(&mut carol, &mut alice);
    assert!(alice.view.flagged().is_empty() && bob.view.flagged().is_empty(), "nobody can tell yet");
    meet(&mut alice, &mut bob);
    for n in [&alice, &bob] {
        let flagged = n.view.flagged();
        assert_eq!(flagged.len(), 1);
        assert_eq!(n.group_of(flagged.iter().next().unwrap()), Some(carol.group), "evidence leads to carol's group only");
    }
    assert_eq!(bob.check(&to_bob), Err(Refusal::KnownCheat));

    // Carol's other coin is held under an unlinkable credential, but alice
    // now knows of a cheat, so she asks the sender to prove it isn't one.
    // Carol can't, under any credential. No town, no revocation list.
    let paid_alice = carol.spend(other, alice.receive().unwrap()).unwrap();
    meet(&mut carol, &mut alice);
    assert!(carol.standings().is_empty(), "the cheat has no standing to give");
    assert!(matches!(alice.check(&paid_alice), Err(Refusal::NoStanding(_))));

    // An honest payer proves it without being linked to anything.
    let bobs = bob.my_coins();
    let from_bob = bob.spend(bobs[0].state, alice.receive().unwrap()).unwrap();
    meet(&mut bob, &mut alice);
    assert_eq!(alice.check(&from_bob), Ok(()));

    // The town can still revoke carol's ticket group, for recipients that
    // haven't met the evidence; the epoch reaches alice by gossip.
    meet(&mut bob, &mut town);
    town.roll_epoch([carol.group].into_iter().collect()).unwrap();
    gossip_to(&town, &mut alice);
    let carol_cred = alice.view.coin(&paid_alice).unwrap().history[0].clone();
    let no_standing = Policy { require_standing: false, ..alice.policy() };
    assert!(matches!(check(&alice.view, &alice.know, &paid_alice, &carol_cred, &no_standing), Err(Refusal::Revoked { group, .. }) if group == carol.group));

    // Tickets refill from the town, in the asker's group.
    let before = bob.pool.len();
    let (creds, by, sig) = bob.refill_request(4).unwrap();
    let t = town.answer_refill(&creds, &by, &sig).unwrap();
    assert!(t.iter().all(|t| t.ticket.group == bob.group));
    assert_eq!(bob.take_tickets(t), 4);
    assert_eq!(bob.pool.len(), before + 4);

    // Saved state replays to the same wallet.
    alice.save().unwrap();
    let again = Node::load(&alice.path).unwrap();
    assert_eq!(again.my_coins(), alice.my_coins());
    assert_eq!(again.view.flagged(), alice.view.flagged());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Enroll the way a wallet does: its key stays on its side.
fn join(town: &mut Node, name: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    use pave_scheme_briolette::{join_nonce, PendingKey};
    let (pending, req) = PendingKey::generate(&join_nonce());
    let e = town.enroll(&req, credits).unwrap();
    Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap()
}
