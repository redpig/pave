//! First-round funding, a counterparty's terms for filers, the appeal
//! window, and settling a filer's deposit.

use pave_board::board::{contractor, BoardMsg, Trade};
use pave_board::dispute::{terms_bytes, Answer, Filing};
use pave_board::node::{Node, PendingJoin};
use pave_kernel::hash::hash_of;
use pave_kernel::Scheme;
use pave_protocol::gossip;
use std::collections::BTreeSet;

fn join(town: &mut Node, name: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", credits).unwrap();
    let mut n = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    for _ in 0..2 {
        let t = town.answer_refill(&n.refill_request(&town.refill_terms().unwrap(), 16).unwrap()).unwrap();
        n.take_tickets(t);
    }
    n
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

fn tick(town: &mut Node, all: &mut [&mut Node]) {
    town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    for p in all.iter_mut() {
        let hints = gossip::hints(&town.view, &town.know, &town.carries());
        gossip::absorb_hints(&mut p.know, &hints);
        let wants = gossip::wants(&p.view, &p.know, &p.carries(), &p.watch());
        let proofs = gossip::serve(&town.view, &town.know, &town.carries(), &wants);
        gossip::absorb(&mut p.view, &mut p.know, proofs);
    }
}

fn sync(town: &mut Node, all: &mut [&mut Node]) {
    for _ in 0..2 {
        for n in all.iter_mut() {
            n.sync_with(town);
        }
    }
}

fn balance(n: &Node) -> u64 {
    n.my_coins().iter().map(|c| c.amount).sum()
}

/// Offer, wait out the window, and have the drawn arbiter rule.
fn decide(town: &mut Node, arbs: &mut [Node], others: &mut [&mut Node], d: pave_kernel::Hash, answer: Answer) {
    for a in arbs.iter_mut() {
        a.sync_with(town);
        a.offer_to_arbitrate(d).unwrap();
        a.sync_with(town);
    }
    for _ in 0..2 {
        let mut all: Vec<&mut Node> = others.iter_mut().map(|x| &mut **x).collect();
        all.extend(arbs.iter_mut());
        tick(town, &mut all);
    }
    let mut all: Vec<&mut Node> = others.iter_mut().map(|x| &mut **x).collect();
    all.extend(arbs.iter_mut());
    sync(town, &mut all);
    let i = (0..arbs.len()).find(|i| arbs[*i].arbitrate(d, answer.clone()).is_ok()).expect("someone drawn");
    arbs[i].sync_with(town);
    for o in others.iter_mut() {
        o.sync_with(town);
    }
}

#[test]
fn terms_and_funding() {
    let dir = std::env::temp_dir().join(format!("pave-terms-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut prov = join(&mut town, "prov", &dir, &[100]);
    let mut zoe = join(&mut town, "zoe", &dir, &[50]);
    let mut mallory = join(&mut town, "mallory", &dir, &[]);
    let mut arbs: Vec<Node> = (0..2).map(|i| join(&mut town, &format!("arb{i}"), &dir, &[])).collect();
    let prov_id = contractor(&prov.trade_key().unwrap());
    let q = "was it delivered?";
    let subject = |n: u8| hash_of("test/subject", &n);

    // The provider publishes terms: from filers who've lost to it once, 5.
    prov.publish_terms(1, 5).unwrap();
    // Mallory publishes "terms" for the provider without its trade key: ignored.
    let fake_key = prov.trade.clone().unwrap();
    let (mine, pay_to) = (mallory.receive().unwrap(), mallory.receive().unwrap());
    let sig = mallory.view.scheme().sign(&mallory.key, &mine, &terms_bytes(0, 40, &pay_to), None);
    let fake = BoardMsg::Terms { min_losses: 0, deposit: 40, pay_to, trade: Trade { key: fake_key, sig } };
    let mc = mallory.receive().unwrap();
    mallory.compose(&mallory.town.jobs.scope.clone(), &mc, fake.kind(), Some(prov_id), fake.encode(), None).unwrap();
    sync(&mut town, &mut [&mut prov, &mut zoe, &mut mallory]);
    assert_eq!(zoe.terms_for(&prov_id).map(|t| (t.min_losses, t.deposit)), Some((1, 5)));

    // ── First round, no losses yet: no filer deposit. The provider funds it.
    let d1 = zoe.open_dispute(Filing::new(subject(1), q, false, 1, 2).against(prov_id)).unwrap();
    sync(&mut town, &mut [&mut prov, &mut zoe]);
    prov.fund_dispute(d1).unwrap();
    sync(&mut town, &mut [&mut prov, &mut zoe]);
    let d = &prov.disputes().0[&d1];
    assert!(d.deposit.is_some() && d.funder.is_some() && d.filer_deposit.is_none());
    assert!(prov.pay_arbiters(d1).unwrap_err().contains("escrow"));
    decide(&mut town, &mut arbs, &mut [&mut prov, &mut zoe], d1, Answer::Yes);
    assert_eq!(zoe.disputes().0[&d1].outcome, Some(Answer::Yes), "zoe lost");
    meet(&mut prov, &mut town);
    assert_eq!(town.release_escrow(d1).unwrap().len(), 1, "the panelist is paid from the provider's deposit");

    // Appeals have a window: three epochs on, an appeal is too late.
    for _ in 0..3 {
        let mut all: Vec<&mut Node> = vec![&mut prov, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
    }
    let late = zoe.open_dispute(Filing::new(subject(1), q, false, 3, 4).appeal_of(d1)).unwrap();
    sync(&mut town, &mut [&mut prov, &mut zoe]);
    assert!(!prov.disputes().0.contains_key(&late), "an appeal after the window is ignored");

    // ── Zoe has lost once to the provider, so its terms ask her for 5. A
    // filing without it is ignored; her wallet pays it when it files.
    assert_eq!(zoe.my_losses(&prov_id), 1);
    let bare = zoe.file(Filing::new(subject(2), q, false, 1, 0).against(prov_id), 0, None, None).unwrap();
    let before = balance(&zoe);
    let d2 = zoe.open_dispute(Filing::new(subject(2), q, false, 1, 0).against(prov_id)).unwrap();
    assert_eq!(balance(&zoe), before - 5);
    sync(&mut town, &mut [&mut prov, &mut zoe]);
    let ds = prov.disputes().0;
    assert!(!ds.contains_key(&bare));
    assert!(ds[&d2].filer_deposit.is_some(), "the 5 is in escrow");
    // Zoe wins this one. The deposit waits until the chain is settled.
    decide(&mut town, &mut arbs, &mut [&mut prov, &mut zoe], d2, Answer::No);
    meet(&mut zoe, &mut town);
    assert!(town.release_escrow(d2).is_err(), "not settled: it may still be appealed");
    for _ in 0..3 {
        let mut all: Vec<&mut Node> = vec![&mut prov, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
    }
    assert_eq!(town.release_escrow(d2).unwrap().len(), 1);
    meet(&mut town, &mut zoe);
    assert_eq!(balance(&zoe), before, "she won: her 5 came back");

    // ── She files again (still one loss) and loses: her 5 goes to the provider.
    let d3 = zoe.open_dispute(Filing::new(subject(3), q, false, 1, 0).against(prov_id)).unwrap();
    sync(&mut town, &mut [&mut prov, &mut zoe]);
    assert!(prov.disputes().0[&d3].filer_deposit.is_some());
    decide(&mut town, &mut arbs, &mut [&mut prov, &mut zoe], d3, Answer::Yes);
    for _ in 0..3 {
        let mut all: Vec<&mut Node> = vec![&mut prov, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
    }
    meet(&mut zoe, &mut town);
    let prov_before = balance(&prov);
    assert_eq!(town.release_escrow(d3).unwrap().len(), 1);
    meet(&mut town, &mut prov);
    assert_eq!(balance(&prov), prov_before + 5);
    assert_eq!(zoe.my_losses(&prov_id), 2);
    let _ = std::fs::remove_dir_all(&dir);
}
