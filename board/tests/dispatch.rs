//! A co-op's dispatch: members carry its parcels under shift keys, capped
//! per member per day by a day pseudonym; bans outlast the day; a parcel on
//! a lost phone is reminted, layered on a lineage coin so reminting twice
//! is a double spend.

use pave_board::dispatch::{DayCard, Dispatch, MemberCard, SHIFT_SLOTS};
use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::{Delivery, Manifest};
use pave_kernel::Scheme;

fn join(town: &mut Node, name: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", credits).unwrap();
    let mut n = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    let t = town.answer_refill(&n.refill_request(&town.refill_terms().unwrap(), 16).unwrap()).unwrap();
    n.take_tickets(t);
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

fn member(town: &mut Node, d: &Dispatch) -> MemberCard {
    let (pending, req) = MemberCard::start();
    let reply = town.add_member(&d.id, &req).unwrap();
    MemberCard::finish(d, pending, &reply).unwrap()
}

/// Check in for today and keep the day credential.
fn check_in(town: &mut Node, n: &Node, d: &Dispatch, card: &MemberCard) -> Result<DayCard, String> {
    let terms = town.shift_terms(&d.id)?;
    let (pending, req) = n.check_in(d, card, &terms)?;
    let c = town.answer_check_in(&req)?;
    Node::day_card(d, terms.0, pending, &c)
}

/// Check in and get `k` shift keys.
fn shift(town: &mut Node, n: &mut Node, d: &Dispatch, card: &MemberCard, k: usize) -> Result<(), String> {
    let day = check_in(town, n, d, card)?;
    shift_with(town, n, d, card, &day, k)
}

fn shift_with(town: &mut Node, n: &mut Node, d: &Dispatch, card: &MemberCard, day: &DayCard, k: usize) -> Result<(), String> {
    let terms = town.shift_terms(&d.id)?;
    let req = n.shift_request(d, card, day, &terms, k)?;
    let t = town.answer_shift(&req)?;
    n.take_shift(d, t)
}

/// `from` hands a parcel to a shift key of `to`, who takes it.
fn carry(from: &mut Node, to: &mut Node, d: &Dispatch, m: &Manifest) -> Result<(), String> {
    let at = to.shift_key(d).ok_or("no shift key")?;
    from.learn_ticket(to.present(&at).unwrap())?;
    meet(from, to);
    from.hand_off(&m.parcel, at)?;
    meet(from, to);
    to.take_parcel(m).map(|_| ())
}

#[test]
fn dispatch() {
    let dir = std::env::temp_dir().join(format!("pave-dispatch-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut shop = join(&mut town, "shop", &dir, &[100]);
    let mut ana = join(&mut town, "ana", &dir, &[]);
    let mut ben = join(&mut town, "ben", &dir, &[]);
    let mut cat = join(&mut town, "cat", &dir, &[]);
    let mut zoe = join(&mut town, "zoe", &dir, &[]);
    let to = shop.receive().unwrap();
    town.issue_parcel_budget(to, 20).unwrap();
    for _ in 0..1 {
        let t = town.answer_refill(&shop.refill_request(&town.refill_terms().unwrap(), 16).unwrap()).unwrap();
        shop.take_tickets(t);
    }
    meet(&mut shop, &mut town);

    // The co-op runs a dispatch. Checking in is the count: one pseudonym per
    // member per day, so a second check-in (a new phone) counts once.
    let d = town.open_dispatch("Pine Co-op").unwrap();
    let (ca, cb) = (member(&mut town, &d), member(&mut town, &d));
    let today = pave_board::dispatch::today();
    let ana_day = check_in(&mut town, &ana, &d, &ca).unwrap();
    assert_eq!(town.couriers(&d.id, today).unwrap(), 1);
    shift(&mut town, &mut ben, &d, &cb, 4).unwrap();
    assert_eq!(town.couriers(&d.id, today).unwrap(), 2);
    check_in(&mut town, &ana, &d, &ca).unwrap();
    assert_eq!(town.couriers(&d.id, today).unwrap(), 2, "Ana again: linked, counted once");

    // Shift requests use slots: a courier's first few a day can't be linked
    // to each other; past them they're served, and linked to an earlier one.
    let linked = |t: &Node| t.operator.as_ref().unwrap().dispatches[&d.id].requests.linked();
    let before = linked(&town);
    for _ in 0..SHIFT_SLOTS {
        shift_with(&mut town, &mut ana, &d, &ca, &ana_day, 2).unwrap();
    }
    assert_eq!(linked(&town), before, "within the slots: unlinked");
    shift_with(&mut town, &mut ana, &d, &ca, &ana_day, 2).unwrap();
    assert_eq!(linked(&town), before + 1, "past them: served, and linked");
    let terms = town.shift_terms(&d.id).unwrap();
    let mut bad = ana.shift_request(&d, &ca, &ana_day, &terms, 1).unwrap();
    bad.slot = SHIFT_SLOTS;
    assert!(town.answer_shift(&bad).unwrap_err().contains("slots"));

    // A member who didn't check in today gets no shift keys: a day
    // credential from another dispatch doesn't verify here.
    let other = town.open_dispatch("Other Co-op").unwrap();
    let mut dee = join(&mut town, "dee", &dir, &[]);
    let cd = member(&mut town, &d);
    let cd_other = member(&mut town, &other);
    let wrong_day = check_in(&mut town, &dee, &other, &cd_other).unwrap();
    assert!(shift_with(&mut town, &mut dee, &d, &cd, &wrong_day, 1).unwrap_err().contains("check in"));

    // Cat isn't a member: a card for another dispatch's roll doesn't verify.
    let cc = member(&mut town, &other);
    let forged = MemberCard { dispatch: d.id, key: cc.key.clone() };
    assert!(shift(&mut town, &mut cat, &d, &forged, 1).unwrap_err().contains("member"));

    // A dispatched parcel goes only to shift keys.
    let zoe_at = zoe.receive().unwrap();
    let m = shop.ship("thai takeout", "dn5bpsb", "dn5bpth", zoe_at.clone(), 3).unwrap();
    let m = shop.name_dispatch(&m.parcel, d.clone()).unwrap();
    let plain = cat.receive().unwrap();
    meet(&mut shop, &mut cat);
    assert!(shop.hand_off(&m.parcel, plain).unwrap_err().contains("shift ticket"));
    carry(&mut shop, &mut ana, &d, &m).unwrap();
    carry(&mut ana, &mut ben, &d, &m).unwrap();
    meet(&mut ben, &mut zoe);
    ben.hand_off(&m.parcel, zoe_at.clone()).unwrap();
    meet(&mut ben, &mut zoe);
    zoe.confirm_delivery(&m).unwrap();
    meet(&mut zoe, &mut shop);
    assert_eq!(shop.pay_couriers(&m).unwrap().len(), 2, "Ana and Ben, at their shift keys");

    // A ban outlasts the day: Ben is ruled out by a key he took under. His
    // later shift requests need standing against it, and his issued keys
    // are revoked on the dispatch's own ticks, so nobody takes from him and
    // he takes nothing.
    let ben_day = check_in(&mut town, &ben, &d, &cb).unwrap();
    let bens_key = shop.custody(&m).steps.iter().filter_map(|s| if let pave_board::parcel::Step::Take { by } = s { Some(by.clone()) } else { None }).nth(1).unwrap();
    town.rule_courier(&d.id, &bens_key).unwrap();
    assert!(shift(&mut town, &mut ben, &d, &cb, 1).unwrap_err().contains("ruled"));
    // Asking on the terms from before the ruling doesn't help, for shift
    // keys on the day credential he already has or for checking in again.
    let stale = (today, vec![]);
    let req = ben.shift_request(&d, &cb, &ben_day, &stale, 1).unwrap();
    assert!(town.answer_shift(&req).unwrap_err().contains("ruled"));
    let (_, again) = ben.check_in(&d, &cb, &stale).unwrap();
    assert!(town.answer_check_in(&again).unwrap_err().contains("ruled"));
    meet(&mut ben, &mut town);
    let m2 = shop.ship("books", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3).unwrap();
    let m2 = shop.name_dispatch(&m2.parcel, d.clone()).unwrap();
    assert!(carry(&mut shop, &mut ben, &d, &m2).unwrap_err().contains("Revoked"));

    // A courier's wallet that skips the gate and hands a parcel to a
    // non-member's key: the shop pays only the dispatched couriers.
    let zoe_at5 = zoe.receive().unwrap();
    let m5 = shop.ship("lamp", "dn5bpsb", "dn5bpth", zoe_at5.clone(), 3).unwrap();
    let m5 = shop.name_dispatch(&m5.parcel, d.clone()).unwrap();
    carry(&mut shop, &mut ana, &d, &m5).unwrap();
    let held = ana.view.unspent().find(|c| c.origin == m5.parcel).unwrap().clone();
    let cat_at = cat.receive().unwrap();
    let s = ana.view.scheme().clone();
    let skip = pave_kernel::sign(&s, &ana.key, &held.holder, pave_kernel::Op::Transfer { state: held.state, to: cat_at, receipt: pave_board::parcel::handoff_receipt(&m5.hash(), held.hops + 1) });
    ana.view.apply(&skip).unwrap();
    meet(&mut ana, &mut cat);
    cat.parcels.insert(m5.parcel, m5.clone());
    cat.hand_off(&m5.parcel, zoe_at5).unwrap();
    meet(&mut cat, &mut zoe);
    zoe.confirm_delivery(&m5).unwrap();
    meet(&mut zoe, &mut shop);
    meet(&mut ana, &mut shop);
    meet(&mut cat, &mut shop);
    assert_eq!(shop.pay_couriers(&m5).unwrap().len(), 1, "Ana, not Cat");

    // ── A lost phone. Ana takes a parcel, then loses the phone; she still
    // has the package and its label code. On her new phone (her member card
    // restored) she gets a shift key and the shop remints the parcel to it.
    let zoe_at = zoe.receive().unwrap();
    let m3 = shop.ship("flowers", "dn5bpsb", "dn5bpth", zoe_at.clone(), 3).unwrap();
    let m3 = shop.name_dispatch(&m3.parcel, d.clone()).unwrap();
    shift(&mut town, &mut dee, &d, &cd, 4).unwrap();
    carry(&mut shop, &mut dee, &d, &m3).unwrap();
    carry(&mut dee, &mut ana, &d, &m3).unwrap();
    let mut ana2 = join(&mut town, "ana2", &dir, &[]);
    let code = shop.label_code(&m3.parcel).unwrap().clone();
    shift(&mut town, &mut ana2, &d, &ca, 2).unwrap();
    let new_at = ana2.shift_key(&d).expect("a shift key on the new phone");
    shop.learn_ticket(ana2.present(&new_at).unwrap()).unwrap();
    meet(&mut shop, &mut ana2);
    assert!(shop.remint_parcel(&m3, "wrong", new_at.clone()).unwrap_err().contains("label"));
    let m3b = shop.remint_parcel(&m3, &code, new_at.clone()).unwrap();
    assert_eq!((m3b.replaces, m3b.generation, m3b.lineage), (Some(m3.parcel), 1, m3.lineage));
    assert!(shop.remint_parcel(&m3, &code, new_at).unwrap_err().contains("already"));
    assert_eq!(shop.delivery(&m3), Delivery::Replaced(Some(m3b.parcel)));
    meet(&mut shop, &mut ana2);
    ana2.take_parcel(&m3b).unwrap();
    meet(&mut ana2, &mut zoe);
    ana2.hand_off(&m3b.parcel, zoe_at.clone()).unwrap();
    meet(&mut ana2, &mut zoe);
    zoe.confirm_delivery(&m3b).unwrap();
    meet(&mut zoe, &mut shop);
    meet(&mut dee, &mut shop);
    assert_eq!(shop.pay_couriers(&m3b).unwrap().len(), 2, "Dee on the old token, up to the remint; Ana's new key");

    // Whoever has the old phone tries to pass the old token on. A courier
    // who has heard of the remint refuses it as void: the lineage moved
    // past its generation.
    let mut found = ana;
    let finder_key_holder = &mut dee;
    let at = finder_key_holder.shift_key(&d).unwrap();
    found.learn_ticket(finder_key_holder.present(&at).unwrap()).unwrap();
    meet(&mut found, finder_key_holder);
    found.hand_off(&m3.parcel, at).unwrap();
    meet(&mut found, finder_key_holder);
    meet(finder_key_holder, &mut shop);
    assert!(finder_key_holder.take_parcel(&m3).unwrap_err().contains("void"));
    // The shop never pays the old token's later hops.
    assert!(shop.pay_couriers(&m3).is_err());

    // Reminting one generation twice is one lineage state used twice: kernel
    // evidence, and takers refuse the parcel.
    let m4 = shop.ship("tools", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3).unwrap();
    let m4 = shop.name_dispatch(&m4.parcel, d.clone()).unwrap();
    let mut ana3 = ana2;
    shift(&mut town, &mut ana3, &d, &ca, 3).unwrap();
    carry(&mut shop, &mut ana3, &d, &m4).unwrap();
    let code4 = shop.label_code(&m4.parcel).unwrap().clone();
    let k1 = ana3.shift_key(&d).unwrap();
    shop.learn_ticket(ana3.present(&k1).unwrap()).unwrap();
    meet(&mut shop, &mut ana3);
    let m4b = shop.remint_parcel(&m4, &code4, k1).unwrap();
    let lineage = shop.view.unspent().find(|c| Some(c.origin) == m4.lineage).unwrap().clone();
    let first = shop.view.records().iter().find(|r| r.output(0) == lineage.state).unwrap().clone();
    let pave_kernel::Op::Transfer { state, .. } = first.op.clone() else { panic!() };
    let s = shop.view.scheme().clone();
    let held_by = shop.view.records().iter().find(|r| r.output(0) == state).map(|r| match &r.op { pave_kernel::Op::Mint { to, .. } => to.clone(), _ => r.signer.clone() }).unwrap();
    let twice = pave_kernel::sign(&s, &shop.key, &held_by, pave_kernel::Op::Transfer { state, to: s.credential(&shop.key), receipt: pave_board::parcel::remint_receipt(&m4.parcel, &pave_kernel::hash::Hash([9; 32])) });
    let _ = ana3.view.apply(&first);
    let _ = ana3.view.apply(&twice);
    assert!(ana3.reminted_twice(&m4b));
    meet(&mut shop, &mut ana3);
    assert!(ana3.take_parcel(&m4b).unwrap_err().contains("twice"));
    let _ = (cat, ben, found);
    let _ = std::fs::remove_dir_all(&dir);
}
