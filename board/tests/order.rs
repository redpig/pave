//! An order end to end: a restaurant that keeps its own ordering system
//! (a mock of Toast here), a customer, a delivery co-op with its dispatch,
//! and a courier. Pave carries only the order's binding, the payment, the
//! parcel and the pay; the order itself stays with the restaurant.

use pave_board::dispatch::{DayCard, Dispatch, MemberCard};
use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::{Delivery, Manifest};
use pave_board::pay::{PayVerdict, Prefix};
use pave_board::profile::{value, Params, Profile};

const ORDERS: &str = include_str!("../../profiles/orders.json");
const PARCELS: &str = include_str!("../../profiles/parcels.json");

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

fn balance(n: &Node) -> u64 {
    n.my_coins().iter().map(|c| c.amount).sum()
}

/// Pay an invoice in process, as two wallets would over a link.
fn pay(payer: &mut Node, payee: &mut Node, inv: &pave_board::pay::Invoice) -> pave_kernel::Record {
    payer.check_invoice(inv).unwrap();
    let offer = payer.offer(inv).unwrap();
    let lacks: Vec<Prefix> = payee.lacks(&offer);
    let mut p = payer.propose(&offer, &lacks, &pave_protocol::cheat_list(&payer.view)).unwrap();
    let mut v = payee.judge(&p);
    if let PayVerdict::NeedStanding(list) = v {
        p = payer.propose(&offer, &[], &list).unwrap();
        v = payee.judge(&p);
    }
    assert_eq!(v, PayVerdict::Accept);
    let rec = payer.pay_invoice(inv, offer.state).unwrap();
    let ack = payee.take_payment(&rec).unwrap();
    payer.confirm(&rec, &ack).unwrap();
    rec
}

/// The restaurant's adapter: its system's status for a parcel, from the
/// parcel's custody as the profile describes it.
fn toast_status(n: &Node, parcels: &Profile, m: &Manifest) -> &'static str {
    let (steps, _) = n.walk(parcels, "custody", &[("manifest".to_string(), value(m))].into_iter().collect()).unwrap();
    match steps.last().map(|s| s.label.as_str()) {
        Some("retired") => "DELIVERED",
        Some("take") if steps.len() > 1 => "PICKED_UP",
        _ => "READY",
    }
}

#[test]
fn an_order_end_to_end() {
    let dir = std::env::temp_dir().join(format!("pave-order-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (orders, parcels) = (Profile::from_json(ORDERS).unwrap(), Profile::from_json(PARCELS).unwrap());
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut cafe = join(&mut town, "cafe", &dir, &[]);
    let mut cust = join(&mut town, "cust", &dir, &[3000]);
    let mut coop = join(&mut town, "coop", &dir, &[]);
    let mut ana = join(&mut town, "ana", &dir, &[]);
    let budget = cafe.receive().unwrap();
    town.issue_parcel_budget(budget, 50).unwrap();
    meet(&mut cafe, &mut town);

    // The co-op delivers for the cafe: its dispatch, and Ana as a member who
    // checked in today with shift keys.
    let d: Dispatch = town.open_dispatch("Pine Co-op").unwrap();
    let (pending, req) = MemberCard::start();
    let card = MemberCard::finish(&d, pending, &town.add_member(&d.id, &req).unwrap()).unwrap();
    let terms = town.shift_terms(&d.id).unwrap();
    let (pending, ci) = ana.check_in(&d, &card, &terms).unwrap();
    let day: DayCard = Node::day_card(&d, terms.0, pending, &town.answer_check_in(&ci).unwrap()).unwrap();
    let req = ana.shift_request(&d, &card, &day, &terms, 4).unwrap();
    let t = town.answer_shift(&req).unwrap();
    ana.take_shift(&d, t).unwrap();
    let provider = coop.receive().unwrap();

    // Amounts are cents of test credit.
    // 1. The customer orders on the cafe's own site. Its system keeps the
    //    order; pave sees only its hash.
    let toast_order = br#"{"guid":"7d1c","items":[{"name":"pho","qty":2}],"total":2400,"deliveryFee":500,"address":"12 Elm St"}"#;
    let order_hash = pave_board::bulletin::content_hash(toast_order);
    let cafe_id = cafe.identity("public").unwrap();
    let deliver_to = cust.receive().unwrap();
    let params: Params = [
        ("restaurant", value(&cafe_id)),
        ("order", value(&order_hash)),
        ("total", value(&2400u64)),
        ("delivery", value(&500u64)),
        ("to_cell", value(&"dn5bpth")),
        ("deliver_to", value(&deliver_to)),
        ("provider", value(&Some(provider.clone()))),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let binding = orders.build("order", &params).unwrap();
    let binding_hash = orders.hash("order", &binding).unwrap();

    // 2. The cafe's adapter checks the binding against its own order and
    //    invoices it: the payment will commit to the binding.
    let field = |k: &str| binding.as_map().unwrap().iter().find(|(f, _)| f.as_text() == Some(k)).unwrap().1.clone();
    assert_eq!(field("order"), value(&order_hash), "the order is the one in its system");
    assert_eq!(field("total"), value(&2400u64));
    let paid = orders.receipt_of("paid", &[("order".to_string(), binding.clone())].into_iter().collect()).unwrap();
    let inv = cafe.invoice_for(2400, paid).unwrap();

    // 3. The customer pays.
    let payment = pay(&mut cust, &mut cafe, &inv);
    assert!(matches!(payment.op, pave_kernel::Op::Split { receipt, .. } if receipt == paid));

    // 4. The cafe ships a parcel about the order to the customer's key, with
    //    the co-op as provider and its dispatch named.
    let m = cafe.ship("order", "dn5bpsb", "dn5bpth", deliver_to.clone(), 400).unwrap();
    cafe.name_about(&m.parcel, binding_hash).unwrap();
    cafe.name_provider(&m.parcel, provider.clone()).unwrap();
    let m = cafe.name_dispatch(&m.parcel, d.clone()).unwrap();
    assert_eq!((m.about, &m.addressee, m.provider.as_ref()), (Some(binding_hash), &deliver_to, Some(&provider)));
    assert_eq!(toast_status(&cafe, &parcels, &m), "READY");

    // 5. Ana picks it up: the cafe hands it to her shift key, she takes it.
    let at = ana.shift_key(&d).unwrap();
    cafe.learn_ticket(ana.present(&at).unwrap()).unwrap();
    meet(&mut cafe, &mut ana);
    cafe.hand_off(&m.parcel, at).unwrap();
    meet(&mut cafe, &mut ana);
    ana.take_parcel(&m).unwrap();
    meet(&mut ana, &mut cafe);
    assert_eq!(toast_status(&cafe, &parcels, &m), "PICKED_UP");

    // 6. Ana delivers; the customer confirms from the parcels description.
    meet(&mut ana, &mut cust);
    ana.hand_off(&m.parcel, deliver_to.clone()).unwrap();
    meet(&mut ana, &mut cust);
    cust.act(&parcels, "confirm", &[("manifest".to_string(), value(&m))].into_iter().collect()).unwrap();
    meet(&mut cust, &mut cafe);
    assert_eq!(cafe.delivery(&m), Delivery::Delivered("signed"));
    assert_eq!(toast_status(&cafe, &parcels, &m), "DELIVERED");

    // 7. The cafe pays the co-op its delivery fee, once; the co-op pays Ana.
    let fee = cafe.pay_provider(&m, 500).unwrap();
    assert!(cafe.pay_provider(&m, 500).is_err(), "once");
    meet(&mut cafe, &mut coop);
    coop.parcels.insert(m.parcel, m.clone());
    meet(&mut ana, &mut coop);
    meet(&mut cust, &mut coop);
    assert!(coop.view.coin(&fee).is_some());
    assert_eq!(coop.pay_couriers(&m).unwrap().len(), 1);
    meet(&mut coop, &mut ana);

    // Where the money went, in cents of test credit: the customer paid $24.00
    // ($19 of food and a $5 delivery fee); the cafe kept $19; the co-op kept
    // $1 of its $5; Ana earned $4. Nobody else took a cut.
    assert_eq!(balance(&cust), 600);
    assert_eq!(balance(&cafe), 1900);
    assert_eq!(balance(&coop), 100);
    assert_eq!(balance(&ana), 400);
    let _ = std::fs::remove_dir_all(&dir);
}
