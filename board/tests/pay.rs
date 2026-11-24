//! The payment handshake, in process: only the coin's provenance travels,
//! the payer checks the payee's ticket, cheats are refused, and a payment
//! whose acknowledgment was lost completes on a resend.

use pave_board::node::{Node, PendingJoin};
use pave_board::pay::{PayVerdict, Prefix};
use std::collections::BTreeSet;

fn join(town: &mut Node, name: &str, class: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, class, credits).unwrap();
    let mut p = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    let t = town.answer_refill(&p.refill_request(&town.refill_terms().unwrap(), 8).unwrap()).unwrap();
    p.take_tickets(t);
    p
}

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle_for(&b.have()), b.bundle_for(&a.have()));
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
    a.outbox.clear();
    b.outbox.clear();
    let (sa, sb) = (a.standings(), b.standings());
    b.absorb_standings(sa);
    a.absorb_standings(sb);
}

/// The handshake between two wallets, in process. Returns the records sent.
fn pay(payer: &mut Node, payee: &mut Node, amount: u64) -> Result<usize, String> {
    let inv = payee.invoice(amount, "test")?;
    payer.check_invoice(&inv)?;
    let offer = payer.offer(&inv)?;
    let lacks: Vec<Prefix> = payee.lacks(&offer);
    let mut p = payer.propose(&offer, &lacks, &pave_protocol::cheat_list(&payer.view))?;
    let sent = p.records.len();
    let mut v = payee.judge(&p);
    if let PayVerdict::NeedStanding(list) = v {
        p = payer.propose(&offer, &[], &list)?;
        v = payee.judge(&p);
    }
    if v != PayVerdict::Accept {
        return Err(format!("{v:?}"));
    }
    let rec = payer.pay_invoice(&inv, offer.state)?;
    let ack = payee.take_payment(&rec)?;
    payer.confirm(&rec, &ack)?;
    Ok(sent)
}

#[test]
fn payments() {
    let dir = std::env::temp_dir().join(format!("pave-pay-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = join(&mut town, "alice", "hardware", &dir, &[100]);
    let mut bob = join(&mut town, "bob", "software", &dir, &[]);
    let mut carol = join(&mut town, "carol", "hardware", &dir, &[20, 20]);

    // A payment sends only the coin's provenance the payee lacks.
    let first = pay(&mut alice, &mut bob, 30).unwrap();
    assert!(first > 0);
    assert_eq!(bob.my_coins().iter().map(|c| c.amount).sum::<u64>(), 30);
    assert_eq!(alice.my_coins().iter().map(|c| c.amount).sum::<u64>(), 70);
    let again = pay(&mut alice, &mut bob, 20).unwrap();
    assert!(again < first + 2, "the second payment reuses what bob has ({again} vs {first})");
    assert!(alice.pending.is_empty());

    // The payer checks the payee's ticket: bob's class can receive at most
    // 50 in one coin.
    let inv = bob.invoice(60, "too much").unwrap();
    assert!(alice.check_invoice(&inv).unwrap_err().contains("can't receive"));

    // Lost acknowledgment: the payer keeps the payment pending; resending
    // the same record gets the same answer, never a second payment.
    let inv = bob.invoice(10, "flaky link").unwrap();
    alice.check_invoice(&inv).unwrap();
    let offer = alice.offer(&inv).unwrap();
    let lacks = bob.lacks(&offer);
    let p = alice.propose(&offer, &lacks, &[]).unwrap();
    assert_eq!(bob.judge(&p), PayVerdict::Accept);
    let rec = alice.pay_invoice(&inv, offer.state).unwrap();
    let _lost = bob.take_payment(&rec).unwrap();
    assert_eq!(alice.pending.len(), 1);
    let ack = bob.re_ack(&rec).unwrap();
    alice.confirm(&rec, &ack).unwrap();
    assert!(alice.pending.is_empty());
    assert!(bob.take_payment(&rec).is_err(), "the invoice is settled");

    // A cheat is refused: carol double-spends, bob learns of it, and her
    // other coin can't get through the handshake.
    let coins = carol.my_coins();
    let to_a = alice.receive().unwrap();
    carol.cheat(coins[0].state, to_a).unwrap();
    meet(&mut carol, &mut alice);
    let to_b = bob.receive().unwrap();
    carol.cheat(coins[0].state, to_b).unwrap();
    meet(&mut carol, &mut bob);
    meet(&mut alice, &mut bob);
    assert!(!pave_protocol::cheat_list(&bob.view).is_empty());
    let err = pay(&mut carol, &mut bob, 20).unwrap_err();
    assert!(err.contains("known cheat") || err.contains("NoStanding") || err.contains("Refuse"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}
