//! Delivery without a signature, and disputes about it: code and drop
//! deliveries, disputes as jobs with panels nobody picks, appeals that
//! cost more and need better arbiters, reputation from upheld rulings,
//! referral to an outside authority.

use pave_board::board::contractor;
use pave_board::dispute::{liability, Answer, DisputeRecord, Filing};
use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::{Delivery, Mode};
use pave_kernel::hash::hash_of;
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

/// Everyone sends queued posts and fetches the boards.
fn sync(town: &mut Node, all: &mut [&mut Node]) {
    for _ in 0..2 {
        for n in all.iter_mut() {
            n.sync_with(town);
        }
    }
}

/// Hear the town's latest epochs.
fn hear(town: &Node, p: &mut Node) {
    let hints = gossip::hints(&town.view, &town.know, &town.carries());
    gossip::absorb_hints(&mut p.know, &hints);
    let wants = gossip::wants(&p.view, &p.know, &p.carries(), &p.watch());
    let proofs = gossip::serve(&town.view, &town.know, &town.carries(), &wants);
    gossip::absorb(&mut p.view, &mut p.know, proofs);
}

/// The next epoch, heard by everyone.
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

fn balance(n: &Node) -> u64 {
    n.my_coins().iter().map(|c| c.amount).sum()
}

#[test]
fn disputes() {
    let dir = std::env::temp_dir().join(format!("pave-dispute-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut shop = join(&mut town, "shop", &dir, &[100]);
    let mut ana = join(&mut town, "ana", &dir, &[50]);
    let mut zoe = join(&mut town, "zoe", &dir, &[50]);
    let mut stranger = join(&mut town, "stranger", &dir, &[]);
    let mut arbs: Vec<Node> = (0..7).map(|i| join(&mut town, &format!("arb{i}"), &dir, &[])).collect();
    let to = shop.receive().unwrap();
    town.issue_parcel_budget(to, 10).unwrap();
    // Ana is the courier, under a trade key: disputes about her deliveries name her.
    let ana_id = contractor(&ana.trade_key().unwrap());
    meet(&mut shop, &mut town);

    // ── A code delivery: Zoe has no wallet at the door, only the code.
    let (m, code) = shop.ship_with("medicine", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3, Mode::Code).unwrap();
    let code = code.unwrap();
    shop.hand_off(&m.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m).unwrap();
    ana.deliver_by_code(&m, "wrong").unwrap();
    meet(&mut ana, &mut shop);
    assert_eq!(shop.delivery(&m), Delivery::NotDelivered, "the shop checks the code");
    assert_eq!(ana.delivery(&m), Delivery::Unverified, "the courier can't");
    ana.deliver_by_code(&m, &code).unwrap();
    meet(&mut ana, &mut shop);
    assert_eq!(shop.delivery(&m), Delivery::Delivered("code"));
    assert_eq!(shop.pay_couriers(&m).unwrap().len(), 1);
    meet(&mut shop, &mut ana);
    assert_eq!(balance(&ana), 53);

    // ── A drop, disputed by the addressee.
    let zoe_at = zoe.receive().unwrap();
    let (m2, _) = shop.ship_with("groceries", "dn5bpsb", "dn5bpth", zoe_at.clone(), 3, Mode::Drop { window: 2 }).unwrap();
    shop.hand_off(&m2.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m2).unwrap();
    let photo = hash_of("pave/parcel/photo", &("salt", "porch photo"));
    ana.drop_off(&m2, "dn5bpth", photo).unwrap();
    meet(&mut ana, &mut shop);
    sync(&mut town, &mut [&mut shop, &mut ana, &mut zoe]);
    let e = shop.epoch();
    assert_eq!(shop.delivery(&m2), Delivery::Pending(e + 2));
    meet(&mut ana, &mut zoe);
    let q = "was it delivered?";
    let d0 = zoe.open_dispute(Filing::new(m2.parcel, q, false, 1, 2).against(ana_id).party(zoe_at)).unwrap();
    sync(&mut town, &mut [&mut shop, &mut ana, &mut zoe]);
    assert_eq!(shop.delivery(&m2), Delivery::Disputed);

    // Two arbiters offer; the panel of one is drawn, not chosen.
    for a in arbs.iter_mut().take(2) {
        a.sync_with(&mut town);
        a.offer_to_arbitrate(d0).unwrap();
        a.sync_with(&mut town);
    }
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
        tick(&mut town, &mut all);
        sync(&mut town, &mut all);
    }
    let (ds, _) = shop.disputes();
    let panel = ds[&d0].panel.clone().unwrap();
    assert_eq!(panel.len(), 1);
    let first = (0..2).find(|i| arbs[*i].contractor() == Some(panel[0].1)).unwrap();
    let other = 1 - first;
    assert!(arbs[other].arbitrate(d0, Answer::Yes).unwrap_err().contains("panel"));
    arbs[first].arbitrate(d0, Answer::No).unwrap();
    arbs[first].sync_with(&mut town);
    // The arbiter who wasn't drawn posts a ruling anyway: it doesn't count.
    let others = shop.disputes().0[&d0].offers.iter().find(|(_, k)| Some(*k) == arbs[other].contractor()).unwrap().0.clone();
    let msg = pave_board::board::BoardMsg::Ruling { dispute: d0, answer: Answer::Yes };
    let scope = arbs[other].town.jobs.scope;
    arbs[other].compose(&scope, &others, msg.kind(), Some(d0), msg.encode(), None).unwrap();
    arbs[other].sync_with(&mut town);
    sync(&mut town, &mut [&mut shop, &mut ana, &mut zoe]);
    assert_eq!(shop.disputes().0[&d0].outcome, Some(Answer::No));
    assert_eq!(shop.delivery(&m2), Delivery::NotDelivered);
    assert!(shop.pay_couriers(&m2).is_err());
    // The first round is funded by the side disputed: the courier.
    assert_eq!(ana.pay_arbiters(d0).unwrap().len(), 1);
    assert!(ana.pay_arbiters(d0).unwrap().is_empty(), "once");
    meet(&mut ana, &mut arbs[first]);
    assert_eq!(balance(&arbs[first]), 2);

    // ── Ana appeals, and pays for a bigger, better-paid panel. Appeals that
    // don't escalate are ignored.
    assert!(ana.open_dispute(Filing::new(m2.parcel, q, true, 2, 4).appeal_of(d0)).is_err(), "her wallet won't file one");
    assert!(ana.open_dispute(Filing::new(m2.parcel, q, true, 3, 3).appeal_of(d0)).is_err());
    // Filed anyway, even with a deposit matching its terms, readers ignore it.
    let dep = ana.deposit_for(&m2.parcel, 1, 2, 4, &Some(d0)).unwrap();
    let bad_panel = ana.file(Filing::new(m2.parcel, q, true, 2, 4).appeal_of(d0), 1, Some(Box::new(dep))).unwrap();
    // So is one whose deposit was made for other terms, even if it covers these.
    let other_terms = ana.deposit_for(&m2.parcel, 1, 5, 4, &Some(d0)).unwrap();
    let mismatched = ana.file(Filing::new(m2.parcel, q, true, 3, 4).appeal_of(d0), 1, Some(Box::new(other_terms))).unwrap();
    // An appeal with pay and no deposit is ignored too.
    let bad_pay = ana.file(Filing::new(m2.parcel, q, true, 3, 4).appeal_of(d0), 1, None).unwrap();
    // The real appeal: paid upfront into escrow.
    let d1 = ana.open_dispute(Filing::new(m2.parcel, q, true, 3, 4).appeal_of(d0)).unwrap();
    // A second appeal reusing that deposit is ignored: a deposit pays once.
    let sub = ana.outgoing.iter().find(|x| x.record.id() == d1).unwrap().clone();
    let Some(pave_board::board::BoardMsg::Dispute { deposit, .. }) = pave_board::board::BoardMsg::decode(&sub.content) else { panic!() };
    let reused = ana.file(Filing::new(m2.parcel, q, true, 3, 4).appeal_of(d0), 1, deposit).unwrap();
    ana.sync_with(&mut town);
    for a in arbs.iter_mut().take(5) {
        a.sync_with(&mut town);
        a.offer_to_arbitrate(d1).unwrap();
        a.sync_with(&mut town);
    }
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
        tick(&mut town, &mut all);
        sync(&mut town, &mut all);
    }
    let (ds, _) = shop.disputes();
    assert!(!ds.contains_key(&bad_panel) && !ds.contains_key(&bad_pay) && !ds.contains_key(&reused) && !ds.contains_key(&mismatched));
    let panel1: Vec<_> = ds[&d1].panel.clone().unwrap().into_iter().map(|(_, k)| k).collect();
    assert_eq!(panel1.len(), 3);
    assert!(!panel1.contains(&panel[0].1), "an arbiter who ruled below doesn't sit on the appeal");
    let on: Vec<usize> = (0..5).filter(|i| arbs[*i].contractor().is_some_and(|k| panel1.contains(&k))).collect();
    arbs[on[0]].arbitrate(d1, Answer::Yes).unwrap();
    arbs[on[1]].arbitrate(d1, Answer::Yes).unwrap();
    arbs[on[2]].arbitrate(d1, Answer::No).unwrap();
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
        all.extend(arbs.iter_mut());
        sync(&mut town, &mut all);
    }
    let (ds, scores) = shop.disputes();
    assert_eq!(ds[&d1].outcome, Some(Answer::Yes));
    assert_eq!(shop.delivery(&m2), Delivery::Delivered("ruled"));
    assert_eq!(shop.pay_couriers(&m2).unwrap().len(), 1);
    assert!(ana.pay_arbiters(d1).unwrap_err().contains("escrow"));
    // The town releases the escrow to the panel once it's decided.
    meet(&mut ana, &mut town);
    let before: Vec<u64> = on.iter().map(|i| balance(&arbs[*i])).collect();
    assert_eq!(town.release_escrow(d1).unwrap().len(), 3);
    assert!(town.release_escrow(d1).is_err(), "once");
    for (j, i) in on.iter().enumerate() {
        meet(&mut town, &mut arbs[*i]);
        assert_eq!(balance(&arbs[*i]), before[j] + 4);
    }
    // Loser pays, as computed: Zoe lost and never escalated, so she owes the
    // first round's 2 of the 14 the winning side paid.
    let ds = shop.disputes().0;
    assert_eq!(liability(&ds, &d0), Some(pave_board::dispute::Liability { loser: false, paid_by_winner: 14, owed: 2 }));
    // Records: Ana sees one filer, by pseudonym, who filed against her and
    // lost; and her own record counts that one person.
    let (filers, hers) = shop.dispute_records(&ana_id);
    assert_eq!(filers.values().cloned().collect::<Vec<_>>(), vec![DisputeRecord { filed: 1, won: 0, lost: 1, referred: 0 }]);
    assert_eq!(hers, DisputeRecord { filed: 1, won: 1, lost: 0, referred: 0 });
    // Reputation follows the final outcome: overturned -1, upheld +1.
    let ids: Vec<_> = arbs.iter().map(|a| a.contractor()).collect();
    let k = |i: usize| ids[i].unwrap();
    assert_eq!(scores[&k(first)], -1);
    assert_eq!((scores[&k(on[0])], scores[&k(on[1])], scores[&k(on[2])]), (1, 1, -1));

    // ── Reputation gates the tiers. On a new drop, a volunteer panel (no
    // pay) rules, and the appeal needs arbiters scoring at least 0: the
    // overturned arbiter offers and isn't drawn.
    let (m3, _) = shop.ship_with("tools", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3, Mode::Drop { window: 2 }).unwrap();
    shop.hand_off(&m3.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m3).unwrap();
    ana.drop_off(&m3, "dn5bpth", photo).unwrap();
    let addressee = m3.addressee.clone();
    meet(&mut ana, &mut zoe);
    let d2 = zoe.open_dispute(Filing::new(m3.parcel, q, false, 1, 0).against(ana_id).party(addressee)).unwrap();
    sync(&mut town, &mut [&mut shop, &mut ana, &mut zoe]);
    arbs[5].sync_with(&mut town);
    arbs[5].offer_to_arbitrate(d2).unwrap();
    arbs[5].sync_with(&mut town);
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
        tick(&mut town, &mut all);
        sync(&mut town, &mut all);
    }
    arbs[5].arbitrate(d2, Answer::Yes).unwrap();
    arbs[5].sync_with(&mut town);
    zoe.sync_with(&mut town);
    let d3 = zoe.open_dispute(Filing::new(m3.parcel, q, false, 3, 1).appeal_of(d2)).unwrap();
    zoe.sync_with(&mut town);
    for i in [first, on[0], on[1], 6] {
        arbs[i].sync_with(&mut town);
        arbs[i].offer_to_arbitrate(d3).unwrap();
        arbs[i].sync_with(&mut town);
    }
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
        tick(&mut town, &mut all);
        sync(&mut town, &mut all);
    }
    let panel3: Vec<_> = shop.disputes().0[&d3].panel.clone().unwrap().into_iter().map(|(_, k)| k).collect();
    assert!(!panel3.contains(&k(first)), "an arbiter with a negative score can't sit at tier 1");
    assert_eq!(panel3.len(), 3);

    // ── Referral: the appeal panel hands it to small claims court. Pave
    // holds the parcel; the outside result is the outside's.
    let on3: Vec<usize> = (0..7).filter(|i| arbs[*i].contractor().is_some_and(|c| panel3.contains(&c))).collect();
    arbs[on3[0]].arbitrate(d3, Answer::Refer("small claims".into())).unwrap();
    arbs[on3[1]].arbitrate(d3, Answer::Refer("small claims court".into())).unwrap();
    arbs[on3[2]].arbitrate(d3, Answer::Yes).unwrap();
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
        all.extend(arbs.iter_mut());
        sync(&mut town, &mut all);
    }
    assert!(matches!(shop.delivery(&m3), Delivery::Referred(_)));
    assert!(shop.pay_couriers(&m3).is_err());
    assert!(zoe.open_dispute(Filing::new(m3.parcel, q, false, 5, 2).appeal_of(d3)).is_err());
    let dep = zoe.deposit_for(&m3.parcel, 2, 5, 2, &Some(d3)).unwrap();
    let d4 = zoe.file(Filing::new(m3.parcel, q, false, 5, 2).appeal_of(d3), 2, Some(Box::new(dep))).unwrap();
    zoe.sync_with(&mut town);
    shop.sync_with(&mut town);
    assert!(!shop.disputes().0.contains_key(&d4), "a referral can't be appealed inside pave");
    assert_eq!(liability(&shop.disputes().0, &d2), None, "a referral settles no costs");

    // ── A stranger's dispute holds nothing, even staffed and ruled against
    // delivery, and neither does a party's that nobody staffs: the drop
    // settles after its window.
    let (m5, _) = shop.ship_with("flowers", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3, Mode::Drop { window: 2 }).unwrap();
    shop.hand_off(&m5.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m5).unwrap();
    ana.drop_off(&m5, "dn5bpth", photo).unwrap();
    meet(&mut ana, &mut shop);
    meet(&mut ana, &mut zoe);
    // A wallet behind on epochs can't post: the host keeps time, so nobody
    // backdates a drop note or a dispute.
    stranger.sync_with(&mut town);
    stranger.open_dispute(Filing::new(m5.parcel, q, false, 1, 0)).unwrap();
    assert!(stranger.sync_with(&mut town).refused[0].contains("epoch"));
    hear(&town, &mut stranger);
    let ds5 = stranger.open_dispute(Filing::new(m5.parcel, q, false, 1, 0)).unwrap();
    zoe.open_dispute(Filing::new(m5.parcel, q, false, 1, 0).against(ana_id).party(m5.addressee.clone())).unwrap();
    sync(&mut town, &mut [&mut shop, &mut ana, &mut zoe, &mut stranger]);
    assert_eq!(shop.delivery(&m5), Delivery::Disputed, "zoe's dispute holds while it may be staffed");
    arbs[6].sync_with(&mut town);
    arbs[6].offer_to_arbitrate(ds5).unwrap();
    arbs[6].sync_with(&mut town);
    {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe, &mut stranger, &mut arbs[6]];
        tick(&mut town, &mut all);
        tick(&mut town, &mut all);
        sync(&mut town, &mut all);
    }
    arbs[6].arbitrate(ds5, Answer::No).unwrap();
    arbs[6].sync_with(&mut town);
    shop.sync_with(&mut town);
    assert_eq!(shop.disputes().0[&ds5].outcome, Some(Answer::No));
    assert_eq!(shop.delivery(&m5), Delivery::Delivered("drop"));

    // Zoe filed three times against Ana, under one pseudonym with her: one
    // lost, one referred, one lapsed. Against anyone else she'd be unrelated.
    let (filers, hers) = shop.dispute_records(&ana_id);
    assert_eq!(filers.values().cloned().collect::<Vec<_>>(), vec![DisputeRecord { filed: 3, won: 0, lost: 1, referred: 1 }]);
    assert_eq!(hers, DisputeRecord { filed: 1, won: 1, lost: 0, referred: 1 });

    // Codes and manifests survive a restart.
    shop.save().unwrap();
    let again = Node::load(&shop.path).unwrap();
    assert_eq!(again.delivery(&again.parcels[&m.parcel]), Delivery::Delivered("code"));
    let _ = std::fs::remove_dir_all(&dir);
}
