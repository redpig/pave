//! A pickup at the counter over an in-person link: the cafe shows a QR
//! invite, the courier scans it, and the badge, the meet and the bag go
//! over the radio, sealed. Then the same over QR frames alone, and the
//! attacks a nearby phone could try.

use pave_board::link::{frames, Frames, Invite, Link, Radio, Side, FRAME_BYTES};
use pave_board::node::{Bundle, Have, Node, PendingJoin};
use pave_board::profile::{value, Params, Profile};
use pave_kernel::hash::encode;
use rand::seq::SliceRandom;

const FOOD: &str = include_str!("../../profiles/food.json");

fn join(town: &mut Node, name: &str, dir: &std::path::Path) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", &[]).unwrap();
    let mut n = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    let t = town
        .answer_refill(&n.refill_request(&town.refill_terms().unwrap(), 16).unwrap())
        .unwrap();
    n.take_tickets(t);
    n
}

fn de<T: serde::de::DeserializeOwned>(b: &[u8]) -> T {
    ciborium::from_reader(b).unwrap()
}

/// A meet over a link: each side sends what it has, then what the other
/// lacks. `carry` moves one sealed message from one side to the other: the
/// radio, or QR frames.
fn meet(
    a: &mut Node,
    la: &mut Link,
    b: &mut Node,
    lb: &mut Link,
    carry: &mut impl FnMut(&[u8], &mut Link) -> (String, Vec<u8>),
) {
    let (_, hb) = carry(&lb.seal("have", &encode(&b.have())), la);
    let (_, ha) = carry(&la.seal("have", &encode(&a.have())), lb);
    let (_, from_a) = carry(
        &la.seal("bundle", &encode(&a.bundle_for(&de::<Have>(&hb)))),
        lb,
    );
    let (_, from_b) = carry(
        &lb.seal("bundle", &encode(&b.bundle_for(&de::<Have>(&ha)))),
        la,
    );
    b.absorb_bundle(&de::<Bundle>(&from_a));
    a.absorb_bundle(&de::<Bundle>(&from_b));
    a.outbox.clear();
    b.outbox.clear();
}

fn kv(pairs: &[(&str, ciborium::Value)]) -> Params {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn pickup_over_a_link() {
    let dir = std::env::temp_dir().join(format!("pave-link-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let food = Profile::from_json(FOOD).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut cafe = join(&mut town, "cafe", &dir);
    let mut ana = join(&mut town, "ana", &dir);
    let mut cust = join(&mut town, "cust", &dir);
    let budget = cafe.receive().unwrap();
    town.issue_parcel_budget(budget, 5).unwrap();
    let d = town.open_dispatch("Pine Co-op").unwrap();
    let ana_id = ana.identity("courier").unwrap();
    let badge = town.issue_badge(&d.id, "courier-47", &ana_id).unwrap();
    ana.take_badge(&d, badge).unwrap();
    // The cafe and Ana hear the town's records the usual way, online.
    for n in [&mut cafe, &mut ana] {
        let (bt, bn) = (town.bundle_for(&n.have()), n.bundle_for(&town.have()));
        n.absorb_bundle(&bt);
        town.absorb_bundle(&bn);
    }
    let to = cust.receive().unwrap();
    let m = cafe.ship("order", "dn5bpsb", "dn5bpth", to, 400).unwrap();
    let m = cafe.name_dispatch(&m.parcel, d.clone()).unwrap();

    // At the counter the cafe's tablet shows an invite; Ana scans it.
    let inv = Invite::new(
        vec![Radio::WifiAware("pave".into()), Radio::Ble([7; 16])],
        120,
    );
    let code = inv.to_qr();
    assert!(
        code.len() < 200,
        "the invite fits a small QR code: {} chars",
        code.len()
    );
    let scanned = Invite::from_qr(&code).unwrap();
    let (mut lc, mut la) = (
        Link::new(&inv, Side::Shower),
        Link::new(&scanned, Side::Scanner),
    );
    let mut radio = |sealed: &[u8], to: &mut Link| to.open(sealed).unwrap();

    // Over the radio: Ana shows her badge, they meet, the cafe hands her
    // the bag, and they meet again so she has the handoff.
    let shown = la.seal("badge", &encode(&ana.present(&ana_id).unwrap()));
    let (kind, t) = lc.open(&shown).unwrap();
    let t: pave_protocol::SignedTicket = de(&t);
    assert_eq!(
        (kind.as_str(), d.badge_of(cafe.view.scheme(), &t).as_deref()),
        ("badge", Some("courier-47"))
    );
    cafe.learn_ticket(t).unwrap();
    meet(&mut cafe, &mut lc, &mut ana, &mut la, &mut radio);
    let mut p = kv(&[("manifest", value(&m))]);
    p.insert("to".into(), value(&ana_id));
    cafe.act(&food, "hand_off", &p).unwrap();
    meet(&mut cafe, &mut lc, &mut ana, &mut la, &mut radio);
    ana.act(&food, "take", &kv(&[("manifest", value(&m))]))
        .unwrap();

    // What a nearby phone can't do. Without the code it can't read or forge.
    let other = Invite::new(vec![], 120);
    let mut eve = Link::new(&other, Side::Shower);
    let msg = la.seal("hello", b"from ana");
    assert!(eve.open(&msg).is_err());
    let mut forger = Link::new(&other, Side::Scanner);
    let forged = forger.seal("hello", b"from eve");
    assert!(lc
        .open(&forged)
        .unwrap_err()
        .contains("not from the other side"));
    // Noise gets the same answer as a forgery, however it fails to parse.
    for junk in [vec![], vec![0xff; 40], vec![0xff; 400]] {
        assert_eq!(
            lc.open(&junk).unwrap_err(),
            "not from the other side of this link"
        );
    }
    // A replay, a reflection back to Ana, an altered byte: all refused.
    assert_eq!(lc.open(&msg).unwrap().1, b"from ana");
    assert!(lc.open(&msg).unwrap_err().contains("out of order"));
    let mine = lc.seal("hello", b"from the cafe");
    let mut copy = Link::new(&inv, Side::Shower);
    for _ in 0..4 {
        copy.seal("skip", b"");
    }
    assert!(
        copy.open(&mine).is_err(),
        "a side can't open its own messages"
    );
    let mut bent = mine.clone();
    *bent.last_mut().unwrap() ^= 1;
    assert!(la.open(&bent).is_err());
    assert_eq!(la.open(&mine).unwrap().1, b"from the cafe");
    // Reflected straight back to the phone that sealed it, on a fresh link
    // where its sequence number lines up.
    let fresh = Invite::new(vec![], 120);
    let mut shower = Link::new(&fresh, Side::Shower);
    let first = shower.seal("hello", b"mine");
    assert!(
        shower.open(&first).is_err(),
        "a reflected message is refused"
    );
    // A stale code is refused.
    let mut old = Invite::new(vec![], 0);
    old.expires -= 1;
    assert!(Invite::from_qr(&old.to_qr())
        .unwrap_err()
        .contains("expired"));

    // No radio: the same exchange in QR frames, each message shown as a
    // loop of codes and scanned in any order, with repeats, beside frames
    // from someone else's link.
    let m2 = cafe
        .ship("order", "dn5bpsb", "dn5bpth", cust.receive().unwrap(), 400)
        .unwrap();
    let m2 = cafe.name_dispatch(&m2.parcel, d.clone()).unwrap();
    let inv = Invite::new(vec![], 120);
    let (mut lc, mut la) = (
        Link::new(&inv, Side::Shower),
        Link::new(&Invite::from_qr(&inv.to_qr()).unwrap(), Side::Scanner),
    );
    let noise = frames(other.token, &eve.seal("x", &[1; 900]), FRAME_BYTES);
    let mut shown_frames = 0;
    let mut camera = |sealed: &[u8], to: &mut Link| {
        let mut loop_ = frames(to.token(), sealed, FRAME_BYTES);
        shown_frames += loop_.len();
        let again = loop_.clone();
        loop_.extend(again);
        loop_.extend(noise.clone());
        loop_.shuffle(&mut rand::thread_rng());
        let mut got = Frames::new(to.token());
        let whole = loop_
            .iter()
            .find_map(|f| got.add(f).unwrap())
            .expect("every frame was shown");
        to.open(&whole).unwrap()
    };
    meet(&mut cafe, &mut lc, &mut ana, &mut la, &mut camera);
    let mut p = kv(&[("manifest", value(&m2))]);
    p.insert("to".into(), value(&ana_id));
    cafe.act(&food, "hand_off", &p).unwrap();
    meet(&mut cafe, &mut lc, &mut ana, &mut la, &mut camera);
    ana.act(&food, "take", &kv(&[("manifest", value(&m2))]))
        .unwrap();
    assert!(shown_frames > 4);
    let _ = std::fs::remove_dir_all(&dir);
}
