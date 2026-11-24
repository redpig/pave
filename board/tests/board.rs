//! The work-board story in process: two wallets meeting by swapping bundles.

use pave_board::board::{jobs, Status};
use pave_board::node::Node;
use pave_protocol::Refusal;

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle(), b.bundle());
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
    a.outbox.clear();
    b.outbox.clear();
}

#[test]
fn post_accept_done_pay_then_catch_a_double_spend() {
    let dir = std::env::temp_dir().join(format!("pave-board-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = town.enroll("alice", &dir.join("alice"), 100).unwrap();
    let mut bob = town.enroll("bob", &dir.join("bob"), 20).unwrap();
    let mut carol = town.enroll("carol", &dir.join("carol"), 20).unwrap();
    meet(&mut alice, &mut bob);
    meet(&mut alice, &mut carol);

    let job = alice.post("Fix the fence", 30).unwrap();
    meet(&mut alice, &mut bob);
    bob.reply(job, "Saturday").unwrap();
    meet(&mut alice, &mut bob);
    alice.accept(job, bob.me.clone()).unwrap();
    assert!(alice.pay(job).is_err(), "can't pay before the work is done");
    meet(&mut alice, &mut bob);
    alice.done(job).unwrap(); // anyone can say it; only the worker's counts
    assert_eq!(jobs(&alice.view, &alice.town.board)[&job].status, Status::Accepted);
    bob.done(job).unwrap();
    meet(&mut alice, &mut bob);
    let payment = alice.pay(job).unwrap();
    meet(&mut alice, &mut bob);
    assert_eq!(jobs(&bob.view, &bob.town.board)[&job].status, Status::Paid);
    assert_eq!(bob.check(&payment), Ok(()));
    assert_eq!(bob.my_coins().iter().map(|c| c.amount).sum::<u64>(), 50);

    let coin = carol.my_coins()[0].state;
    let to_bob = carol.cheat(coin, bob.me.clone()).unwrap();
    meet(&mut carol, &mut bob);
    carol.cheat(coin, alice.me.clone()).unwrap();
    meet(&mut carol, &mut alice);
    assert!(alice.view.flagged().is_empty() && bob.view.flagged().is_empty(), "nobody can tell yet");
    meet(&mut alice, &mut bob);
    for n in [&alice, &bob] {
        assert_eq!(n.view.flagged(), [carol.me.clone()].into_iter().collect());
    }
    assert_eq!(bob.check(&to_bob), Err(Refusal::KnownCheat));
    let _ = std::fs::remove_dir_all(&dir);
}
