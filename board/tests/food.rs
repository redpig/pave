//! Food delivery end to end, by an accountable courier: a restaurant that
//! keeps its own ordering system (a mock of Toast here), a customer, a
//! co-op with its dispatch, and a courier the co-op vetted and badged. Pave
//! carries the order's binding, the payment, custody of the bag and the
//! pay; the order and the address stay with the restaurant and the courier.

use pave_board::dispatch::{DayCard, MemberCard};
use pave_board::board::{contractor, Known};
use pave_board::bulletin::purpose;
use pave_board::food::{Delivered, DeliveryVouch, Outcome};
use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::Delivery;
use pave_board::pay::{Invoice, PayVerdict, Prefix};
use pave_board::profile::{value, Params, Profile};

const ORDERS: &str = include_str!("../../profiles/orders.json");
const FOOD: &str = include_str!("../../profiles/food.json");

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

fn pay(payer: &mut Node, payee: &mut Node, inv: &Invoice) {
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
}

/// A parcel's custody records as `n` has them: its mint and every spend.
fn chain(n: &Node, m: &pave_board::parcel::Manifest) -> Vec<pave_kernel::Record> {
    let mut out: Vec<_> = n.view.creator(&m.parcel).into_iter().cloned().collect();
    let mut state = m.parcel;
    while let Some(r) = n.view.spender(&state) {
        out.push(r.clone());
        state = r.output(0);
    }
    out
}

/// Post a delivery vouch as `signer` without the wallet's own checks,
/// carrying the records `records` has.
fn raw_vouch(n: &mut Node, records: Vec<pave_kernel::Record>, signer: &pave_kernel::Credential, m: &pave_board::parcel::Manifest, who: pave_kernel::hash::Hash) {
    let v = DeliveryVouch { manifest: m.clone(), records, note: "raw".into() };
    let scope = n.town.jobs.scope;
    n.compose(&scope, signer, "delivery vouch", Some(who), pave_kernel::hash::encode(&v), Some(purpose(&scope, "vouch", &who))).unwrap();
}

fn kv(pairs: &[(&str, ciborium::Value)]) -> Params {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

fn field(v: &ciborium::Value, k: &str) -> ciborium::Value {
    v.as_map().unwrap().iter().find(|(f, _)| f.as_text() == Some(k)).unwrap().1.clone()
}

#[test]
fn food_by_an_accountable_courier() {
    let dir = std::env::temp_dir().join(format!("pave-food-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (orders, food) = (Profile::from_json(ORDERS).unwrap(), Profile::from_json(FOOD).unwrap());
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut cafe = join(&mut town, "cafe", &dir, &[]);
    let mut cust = join(&mut town, "cust", &dir, &[3000]);
    let mut coop = join(&mut town, "coop", &dir, &[1000]);
    let mut ana = join(&mut town, "ana", &dir, &[]);
    let mut bea = join(&mut town, "bea", &dir, &[]);
    let budget = cafe.receive().unwrap();
    town.issue_parcel_budget(budget, 50).unwrap();
    meet(&mut cafe, &mut town);

    // The co-op vets Ana outside pave (who she is, insurance) and badges her
    // stable identity key as courier-47. Bea is a member with no badge.
    let d = town.open_dispatch("Pine Co-op").unwrap();
    let ana_id = ana.identity("courier").unwrap();
    let badge = town.issue_badge(&d.id, "courier-47", &ana_id).unwrap();
    ana.take_badge(&d, badge).unwrap();
    let provider = coop.receive().unwrap();

    // Amounts are cents of test credit. The customer orders on the cafe's
    // own site; its system keeps the order and the address. The binding
    // carries the order's hash, a commitment to the address, and a deadline.
    let toast_order = br#"{"guid":"7d1c","items":[{"name":"pho","qty":2}],"total":2400,"deliveryFee":500}"#;
    let (address, salt) = ("12 Elm St", value(&serde_bytes::ByteBuf::from(vec![7u8; 16])));
    let address_commit = orders.receipt_of("address", &kv(&[("salt", salt.clone()), ("address", value(&address))])).unwrap();
    let due = pave_board::bulletin::now() + 45 * 60;
    let deliver_to = cust.receive().unwrap();
    let cafe_id = cafe.identity("public").unwrap();
    let binding = orders
        .build("order", &kv(&[("restaurant", value(&cafe_id)), ("order", value(&pave_board::bulletin::content_hash(toast_order))), ("total", value(&2400u64)), ("delivery", value(&500u64)), ("to_cell", value(&"dn5bpth")), ("address", value(&address_commit)), ("deliver_to", value(&deliver_to)), ("provider", value(&Some(provider.clone()))), ("due", value(&due))]))
        .unwrap();
    let order = orders.hash("order", &binding).unwrap();

    // The cafe invoices; the customer's payment commits to the binding.
    let paid = orders.receipt_of("paid", &kv(&[("order", binding.clone())])).unwrap();
    let inv = cafe.invoice_for(2400, paid).unwrap();
    pay(&mut cust, &mut cafe, &inv);

    // The cafe bags the order (the seal sticker carries the label code) and
    // ships it about the order, with the co-op and its dispatch named.
    let m = cafe.ship("order", "dn5bpsb", "dn5bpth", deliver_to.clone(), 400).unwrap();
    cafe.name_about(&m.parcel, order).unwrap();
    cafe.name_provider(&m.parcel, provider.clone()).unwrap();
    let m = cafe.name_dispatch(&m.parcel, d.clone()).unwrap();
    let mp = kv(&[("manifest", value(&m))]);
    let to = |k: &pave_kernel::Credential| {
        let mut p = mp.clone();
        p.insert("to".into(), value(k));
        p
    };

    // Only a badged courier picks it up: not Bea, a member who checked in
    // today and holds the dispatch's shift keys, but has no badge.
    let (pending, req) = MemberCard::start();
    let card = MemberCard::finish(&d, pending, &town.add_member(&d.id, &req).unwrap()).unwrap();
    let terms = town.shift_terms(&d.id).unwrap();
    let (pending, ci) = bea.check_in(&d, &card, &terms).unwrap();
    let day: DayCard = Node::day_card(&d, terms.0, pending, &town.answer_check_in(&ci).unwrap()).unwrap();
    let req = bea.shift_request(&d, &card, &day, &terms, 2).unwrap();
    let t = town.answer_shift(&req).unwrap();
    bea.take_shift(&d, t).unwrap();
    let bea_key = bea.shift_key(&d).unwrap();
    let bea_ticket = bea.present(&bea_key).unwrap();
    assert_eq!(d.badge_of(cafe.view.scheme(), &bea_ticket), None, "a shift ticket isn't a badge");
    cafe.learn_ticket(bea_ticket).unwrap();
    meet(&mut cafe, &mut bea);
    assert!(cafe.act(&food, "hand_off", &to(&bea_key)).unwrap_err().contains("AnyOf"));
    // The co-op offers the delivery as a job for badged couriers, under the
    // provider key the manifest names. A job about this bag from anyone
    // else, even one some stranger accepts, assigns nobody.
    let pickup_by = pave_board::bulletin::now() + 15 * 60;
    let stray = cust.post_about("Deliver a parcel", 400, Some(Known::Badge(d.roster.clone())), Some(m.parcel), None).unwrap();
    assert!(cust.offer_delivery(&m, 400, pickup_by).unwrap_err().contains("provider"));
    let gig = coop.offer_delivery(&m, 400, pickup_by).unwrap();
    for n in [&mut coop, &mut cust, &mut ana, &mut cafe] {
        n.sync_with(&mut town);
    }
    // Ana replies to both, anonymously; the co-op accepts her on her badge.
    // The stranger accepts her too, which assigns nothing.
    ana.reply(stray, "me").unwrap();
    ana.reply(gig, "5 min away").unwrap();
    for n in [&mut ana, &mut cust] {
        n.sync_with(&mut town);
    }
    let w = cust.jobs()[&stray].replies[0].0.clone();
    cust.accept_shown(stray, w, ana.show_known(stray).unwrap()).unwrap();
    for n in [&mut ana, &mut coop, &mut cust] {
        n.sync_with(&mut town);
    }
    assert_eq!(cafe.assigned_courier(&m), None);
    let w = coop.jobs()[&gig].replies[0].0.clone();
    coop.accept_shown(gig, w, ana.show_known(gig).unwrap()).unwrap();
    coop.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert_eq!(cafe.assigned_courier(&m), Some(ana_id.clone()));
    // At the counter Ana shows her badge; the cafe checks it and knows which
    // courier this is, and the co-op knows who.
    let shown = ana.present(&ana_id).unwrap();
    assert_eq!(d.badge_of(cafe.view.scheme(), &shown).as_deref(), Some("courier-47"));
    cafe.learn_ticket(shown).unwrap();
    meet(&mut cafe, &mut ana);
    cafe.act(&food, "hand_off", &to(&ana_id)).unwrap();
    meet(&mut cafe, &mut ana);
    // The address goes to Ana only now, off the record; she checks it
    // against the binding's commitment.
    let given = orders.receipt_of("address", &kv(&[("salt", salt.clone()), ("address", value(&address))])).unwrap();
    assert_eq!(value(&given), field(&binding, "address"));
    assert_ne!(value(&orders.receipt_of("address", &kv(&[("salt", salt.clone()), ("address", value(&"14 Elm St"))])).unwrap()), field(&binding, "address"));
    ana.act(&food, "take", &mp).unwrap();
    // The record names the accountable courier: the take stays on her badge key.
    meet(&mut ana, &mut cafe);
    let (steps, holder) = cafe.walk(&food, "custody", &mp).unwrap();
    assert_eq!((steps.last().unwrap().label.as_str(), holder.as_ref()), ("take", Some(&ana_id)));

    // Ana delivers; the customer checks the seal, confirms, and posts that
    // it arrived. The board's clock is the time witness.
    meet(&mut ana, &mut cust);
    ana.act(&food, "hand_off", &to(&deliver_to)).unwrap();
    meet(&mut ana, &mut cust);
    cust.act(&food, "confirm", &mp).unwrap();
    // Ana can't say it was delivered on time for the customer: only a note
    // from the key it was delivered to counts.
    let jobs = ana.town.jobs.scope;
    let claim = pave_kernel::hash::encode(&Delivered { order, seal_ok: true });
    // (Her badge key can't post at all: that would replace the badge.)
    assert!(ana.compose(&jobs, &ana_id, "delivered", Some(order), claim.clone(), None).unwrap_err().contains("another clerk"));
    let other = ana.receive().unwrap();
    ana.compose(&jobs, &other, "delivered", Some(order), claim, None).unwrap();
    ana.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert_eq!(cafe.food_outcome(&m, order, due), Outcome::Pending);
    let seal = cafe.label_code(&m.parcel).unwrap().clone();
    cust.note_delivered(&m, order, &seal).unwrap();
    cust.sync_with(&mut town);
    cafe.sync_with(&mut town);
    meet(&mut cust, &mut cafe);
    assert_eq!(cafe.delivery(&m), Delivery::Delivered("signed"));
    let Outcome::OnTime { at } = cafe.food_outcome(&m, order, due) else { panic!("{:?}", cafe.food_outcome(&m, order, due)) };
    // Against an earlier deadline the same note is late, by the board's clock.
    assert_eq!(cafe.food_outcome(&m, order, at - 60), Outcome::Late { at, by: 60 });

    // Ana marks the job done. The co-op pays the job with a vouch, a coin
    // Ana holds, once custody shows her key delivered it: not on her word.
    ana.done(gig).unwrap();
    for n in [&mut ana, &mut coop] {
        n.sync_with(&mut town);
    }
    assert!(coop.pay_delivery(&m, "fast").unwrap_err().contains("custody"));
    // The cafe pays the co-op its fee, and the co-op hears the custody.
    cafe.pay_provider(&m, 500).unwrap();
    meet(&mut cafe, &mut coop);
    coop.pay_delivery(&m, "fast").unwrap();
    coop.parcels.insert(m.parcel, m.clone());
    assert!(coop.pay_couriers(&m).unwrap_err().contains("delivery job"), "not paid twice");
    meet(&mut coop, &mut ana);
    assert_eq!((balance(&cust), balance(&cafe), balance(&coop), balance(&ana)), (600, 1900, 1000 - 400 + 500, 400));
    coop.sync_with(&mut town);
    bea.sync_with(&mut town);
    let (rep, vouches) = bea.reputation(&contractor(&ana_id));
    assert_eq!((rep.get("delivery"), vouches[0].known_by.is_none()), (Some(&1), true));
    // A second offer of the same bag from the co-op leaves it unassigned.
    coop.offer_delivery(&m, 400, pickup_by).unwrap();
    coop.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert!(cafe.delivery_job(&m).is_none());

    // A seal that doesn't match is a broken seal, whatever the time.
    let m2 = cafe.ship("order", "dn5bpsb", "dn5bpth", deliver_to.clone(), 400).unwrap();
    let m2 = cafe.name_dispatch(&m2.parcel, d.clone()).unwrap();
    let mp2 = kv(&[("manifest", value(&m2))]);
    let order2 = pave_kernel::hash::Hash([2; 32]);
    let mut p2 = mp2.clone();
    p2.insert("to".into(), value(&ana_id));
    cafe.act(&food, "hand_off", &p2).unwrap();
    meet(&mut cafe, &mut ana);
    ana.act(&food, "take", &mp2).unwrap();
    meet(&mut ana, &mut cust);
    let mut p2 = mp2.clone();
    p2.insert("to".into(), value(&deliver_to));
    ana.act(&food, "hand_off", &p2).unwrap();
    meet(&mut ana, &mut cust);
    cust.act(&food, "confirm", &mp2).unwrap();
    cust.note_delivered(&m2, order2, "wrong").unwrap();
    cust.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert!(matches!(cafe.food_outcome(&m2, order2, due), Outcome::SealBroken { .. }));

    // The customer vouches for the courier who brought the first order, in
    // the thread of her badge key. Bea, who never saw these parcels, checks
    // it from the records the vouch carries.
    let who = contractor(&ana_id);
    assert!(ana.vouch_delivery(&m, "me").unwrap_err().contains("addressee"));
    cust.vouch_delivery(&m, "hot, and quick").unwrap();
    cust.vouch_delivery(&m, "again").unwrap();
    // Ana vouches for her own second delivery under another key: not the
    // addressee's, so it doesn't count.
    let rs = chain(&cust, &m2);
    raw_vouch(&mut ana, rs, &other, &m2, who);
    for n in [&mut cust, &mut ana, &mut bea] {
        n.sync_with(&mut town);
    }
    let (people, vouches) = bea.delivery_vouches(&who);
    assert_eq!((people, vouches.len(), vouches[0].note.as_str()), (1, 1, "hot, and quick"), "one parcel counts once");
    // A second delivery to the same customer adds a vouch, not a person.
    cust.vouch_delivery(&m2, "fine").unwrap();
    cust.sync_with(&mut town);
    bea.sync_with(&mut town);
    assert_eq!((bea.delivery_vouches(&who).0, bea.delivery_vouches(&who).1.len()), (1, 2));

    // Two vouches that don't count: in Ana's thread for a bag the cafe
    // handed over itself, and for one Ana handed over that the customer
    // hasn't confirmed.
    let ship = |cafe: &mut Node| {
        let m = cafe.ship("order", "dn5bpsb", "dn5bpth", deliver_to.clone(), 400).unwrap();
        cafe.name_dispatch(&m.parcel, d.clone()).unwrap()
    };
    let with = |m: &pave_board::parcel::Manifest, to: Option<&pave_kernel::Credential>| {
        let mut p = kv(&[("manifest", value(m))]);
        if let Some(k) = to {
            p.insert("to".into(), value(k));
        }
        p
    };
    let direct = ship(&mut cafe);
    cafe.act(&food, "hand_off", &with(&direct, Some(&deliver_to))).unwrap();
    meet(&mut cafe, &mut cust);
    cust.act(&food, "confirm", &with(&direct, None)).unwrap();
    let rs = chain(&cafe, &direct).into_iter().chain(chain(&cust, &direct)).collect();
    raw_vouch(&mut cust, rs, &deliver_to, &direct, who);
    let open = ship(&mut cafe);
    cafe.act(&food, "hand_off", &with(&open, Some(&ana_id))).unwrap();
    meet(&mut cafe, &mut ana);
    ana.act(&food, "take", &with(&open, None)).unwrap();
    meet(&mut ana, &mut cust);
    ana.act(&food, "hand_off", &with(&open, Some(&deliver_to))).unwrap();
    meet(&mut ana, &mut cust);
    assert!(cust.vouch_delivery(&open, "early").unwrap_err().contains("not delivered"));
    let rs = chain(&cafe, &open).into_iter().chain(chain(&cust, &open)).collect();
    raw_vouch(&mut cust, rs, &deliver_to, &open, who);
    cust.sync_with(&mut town);
    bea.sync_with(&mut town);
    // A reader needs the shipper's budget history, as any record, to check
    // a bag's mint: Bea hears it from the cafe.
    meet(&mut bea, &mut cafe);
    assert_eq!(bea.delivery_vouches(&who).1.len(), 2);

    // A no-show. The co-op offers a bag, accepts Ana, and she doesn't come
    // by the pickup deadline (here, already past). The co-op releases the
    // job and offers the bag again; Bea, now badged too, takes the job.
    let bea_badge_key = bea.trade_key().unwrap();
    let b = town.issue_badge(&d.id, "courier-52", &bea_badge_key).unwrap();
    bea.take_badge(&d, b).unwrap();
    let m5 = cafe.ship("order", "dn5bpsb", "dn5bpth", deliver_to.clone(), 400).unwrap();
    cafe.name_provider(&m5.parcel, provider.clone()).unwrap();
    let m5 = cafe.name_dispatch(&m5.parcel, d.clone()).unwrap();
    let past = pave_board::bulletin::now() - 60;
    let gig5 = coop.offer_delivery(&m5, 400, past).unwrap();
    for n in [&mut coop, &mut ana, &mut bea, &mut cafe] {
        n.sync_with(&mut town);
    }
    ana.reply(gig5, "on my way").unwrap();
    ana.sync_with(&mut town);
    coop.sync_with(&mut town);
    let w = coop.jobs()[&gig5].replies[0].0.clone();
    coop.accept_shown(gig5, w, ana.show_known(gig5).unwrap()).unwrap();
    coop.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert_eq!(cafe.assigned_courier(&m5), Some(ana_id.clone()));
    coop.release_delivery(&m5).unwrap();
    coop.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert_eq!(cafe.assigned_courier(&m5), None);
    let again = coop.offer_delivery(&m5, 400, past).unwrap();
    for n in [&mut coop, &mut bea, &mut cafe] {
        n.sync_with(&mut town);
    }
    bea.reply(again, "close by").unwrap();
    bea.sync_with(&mut town);
    coop.sync_with(&mut town);
    let w = coop.jobs()[&again].replies[0].0.clone();
    coop.accept_shown(again, w, bea.show_known(again).unwrap()).unwrap();
    coop.sync_with(&mut town);
    cafe.sync_with(&mut town);
    assert_eq!(cafe.assigned_courier(&m5), Some(bea_badge_key.clone()));

    // Bea takes the bag and goes quiet. It's on her badge key, so releasing
    // her is refused: that's a dispute, and the co-op knows who she is. The
    // cafe refunds the customer meanwhile.
    cafe.learn_ticket(bea.present(&bea_badge_key).unwrap()).unwrap();
    let mut p5 = kv(&[("manifest", value(&m5))]);
    p5.insert("to".into(), value(&bea_badge_key));
    cafe.act(&food, "hand_off", &p5).unwrap();
    meet(&mut cafe, &mut bea);
    bea.act(&food, "take", &kv(&[("manifest", value(&m5))])).unwrap();
    meet(&mut bea, &mut coop);
    assert!(coop.release_delivery(&m5).unwrap_err().contains("dispute"));
    let order5 = pave_kernel::hash::Hash([5; 32]);
    let refund = orders.receipt_of("refund", &kv(&[("order", value(&order5))])).unwrap();
    assert_eq!(cust.received(&refund), 0);
    cafe.refund(&m5, 900, refund).unwrap();
    meet(&mut cafe, &mut cust);
    assert_eq!(cust.received(&refund), 900);

    // The co-op revokes Ana's badge: the cafe won't hand her another order,
    // and a bag she still held couldn't be taken under it.
    town.revoke_badge(&d.id, "courier-47").unwrap();
    meet(&mut cafe, &mut town);
    let m3 = cafe.ship("order", "dn5bpsb", "dn5bpth", deliver_to.clone(), 400).unwrap();
    let m3 = cafe.name_dispatch(&m3.parcel, d.clone()).unwrap();
    let mut p3 = kv(&[("manifest", value(&m3))]);
    p3.insert("to".into(), value(&ana_id));
    assert!(cafe.act(&food, "hand_off", &p3).unwrap_err().contains("AnyOf"));
    let _ = std::fs::remove_dir_all(&dir);
}
