//! A profile as data: wallets that run the parcel profile from its JSON
//! description carry parcels with wallets that run its Rust code, and both
//! read the same custody.

use pave_board::dispatch::{DayCard, Dispatch, MemberCard};
use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::{parcel_schema, Manifest, Step};
use pave_board::profile::{value, Params, Profile};

const PARCELS: &str = include_str!("../../profiles/parcels.json");

fn join(town: &mut Node, name: &str, dir: &std::path::Path) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", &[100]).unwrap();
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

/// Check in and get `k` shift keys, through dispatch's Rust code.
fn shift(town: &mut Node, n: &mut Node, d: &Dispatch, card: &MemberCard, k: usize) {
    let terms = town.shift_terms(&d.id).unwrap();
    let (pending, req) = n.check_in(d, card, &terms).unwrap();
    let c = town.answer_check_in(&req).unwrap();
    let day: DayCard = Node::day_card(d, terms.0, pending, &c).unwrap();
    let req = n.shift_request(d, card, &day, &terms, k).unwrap();
    let t = town.answer_shift(&req).unwrap();
    n.take_shift(d, t).unwrap();
}

fn params(kv: &[(&str, ciborium::Value)]) -> Params {
    kv.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

#[test]
fn parcels_from_a_description() {
    let dir = std::env::temp_dir().join(format!("pave-profile-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = Profile::from_json(PARCELS).unwrap();
    assert_eq!(p.schemas["parcel"].schema, parcel_schema(), "the description names the profile's schema");

    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut shop = join(&mut town, "shop", &dir);
    let mut ben = join(&mut town, "ben", &dir);
    let mut ana = join(&mut town, "ana", &dir);
    let mut zoe = join(&mut town, "zoe", &dir);
    let to = shop.receive().unwrap();
    town.issue_parcel_budget(to, 10).unwrap();
    meet(&mut shop, &mut town);

    // The layout is the Rust manifest exactly: built from the same fields
    // it is the same CBOR, so it hashes the same.
    let rust = shop.ship("soup", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3).unwrap();
    let fields = |m: &Manifest| params(&[("parcel", value(&m.parcel)), ("what", value(&m.what)), ("from_cell", value(&m.from_cell)), ("to_cell", value(&m.to_cell)), ("addressee", value(&m.addressee)), ("pay_per_hop", value(&m.pay_per_hop)), ("label", value(&m.label)), ("lineage", value(&m.lineage))]);
    let built = p.build("manifest", &fields(&rust)).unwrap();
    assert_eq!(built, value(&rust));
    assert_eq!(p.hash("manifest", &built).unwrap(), rust.hash());
    // A field of the wrong type is refused.
    let mut wrong = fields(&rust);
    wrong.insert("what".into(), value(&7u32));
    assert!(p.build("manifest", &wrong).unwrap_err().contains("what"));

    // The shop ships from the description: two mints from its budget (the
    // token and the lineage), then the manifest.
    let parcel = shop.act(&p, "mint", &Params::new()).unwrap().output(0);
    let lineage = shop.act(&p, "mint", &Params::new()).unwrap().output(0);
    let zoe_at = zoe.receive().unwrap();
    let m = p
        .build("manifest", &params(&[("parcel", value(&parcel)), ("what", value(&"bread")), ("from_cell", value(&"dn5bpsb")), ("to_cell", value(&"dn5bpth")), ("addressee", value(&zoe_at)), ("pay_per_hop", value(&3u64)), ("lineage", value(&Some(lineage)))]))
        .unwrap();
    let manifest: Manifest = m.deserialized().unwrap();
    let mp = params(&[("manifest", m.clone())]);

    // Shop (from the description) hands it to Ben, who runs the Rust
    // profile and takes it: the receipt is the one his code expects.
    let ben_at = ben.receive().unwrap();
    meet(&mut shop, &mut ben);
    let mut hp = mp.clone();
    hp.insert("to".into(), value(&ben_at));
    shop.act(&p, "hand_off", &hp).unwrap();
    meet(&mut shop, &mut ben);
    ben.take_parcel(&manifest).unwrap();

    // Ben (Rust) hands it to Ana, who takes it from the description.
    let ana_at = ana.receive().unwrap();
    meet(&mut ben, &mut ana);
    ben.hand_off(&manifest.parcel, ana_at).unwrap();
    meet(&mut ben, &mut ana);
    ana.act(&p, "take", &mp).unwrap();
    // Only the addressee confirms: Ana holds it, and isn't.
    assert!(ana.act(&p, "confirm", &mp).unwrap_err().contains("HolderIs"));
    // Taking twice, or with another manifest, doesn't: the handoff's receipt
    // commits to this manifest and this hop.
    assert!(ana.act(&p, "take", &mp).is_err());

    // Ana hands it to Zoe, the addressee, who confirms from the description.
    // Only the addressee can.
    meet(&mut ana, &mut zoe);
    let mut hp = mp.clone();
    hp.insert("to".into(), value(&zoe_at));
    ana.act(&p, "hand_off", &hp).unwrap();
    meet(&mut ana, &mut zoe);
    let mut other = fields(&manifest);
    other.insert("what".into(), value(&"cake"));
    let forged = params(&[("manifest", p.build("manifest", &other).unwrap())]);
    assert!(zoe.act(&p, "take", &forged).unwrap_err().contains("CreatedWith"));
    zoe.act(&p, "confirm", &mp).unwrap();

    // Both read the same custody: the description's walk and the Rust code.
    meet(&mut zoe, &mut shop);
    meet(&mut ana, &mut shop);
    meet(&mut ben, &mut shop);
    let (steps, holder) = shop.walk(&p, "custody", &mp).unwrap();
    let labels: Vec<&str> = steps.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["handoff", "take", "handoff", "take", "handoff", "retired"]);
    assert_eq!(holder, None);
    let c = shop.custody(&manifest);
    assert!(c.delivered);
    let rust_labels: Vec<&str> = c.steps.iter().map(|s| match s { Step::Handoff { .. } => "handoff", Step::Take { .. } => "take", Step::Retired { .. } => "retired", _ => "other" }).collect();
    assert_eq!(labels, rust_labels);

    // Receipts an app can show: what the shipper's payments commit to.
    let ben_key = c.steps.iter().find_map(|s| if let Step::Handoff { from, .. } = s { Some(from.clone()) } else { None }).unwrap();
    assert_eq!(p.receipt_of("shipping", &params(&[("parcel", value(&parcel))])).unwrap(), pave_board::parcel::shipping_receipt(&parcel));
    assert_eq!(p.receipt_of("pay", &params(&[("parcel", value(&parcel)), ("courier", value(&ben_key))])).unwrap(), pave_board::parcel::pay_receipt(&parcel, &ben_key));

    // A take runs the acceptance check: a parcel handed to a key with no
    // ticket is refused even though its receipt matches.
    let parcel2 = shop.act(&p, "mint", &Params::new()).unwrap().output(0);
    let m2 = p.build("manifest", &params(&[("parcel", value(&parcel2)), ("what", value(&"jam")), ("from_cell", value(&"a")), ("to_cell", value(&"b")), ("addressee", value(&zoe_at)), ("pay_per_hop", value(&1u64))])).unwrap();
    let bare = pave_kernel::Scheme::credential(zoe.view.scheme(), &zoe.key);
    zoe.mine.insert(bare.clone());
    let mut hp = params(&[("manifest", m2.clone())]);
    hp.insert("to".into(), value(&bare));
    shop.act(&p, "hand_off", &hp).unwrap();
    meet(&mut shop, &mut zoe);
    assert!(zoe.act(&p, "take", &params(&[("manifest", m2)])).unwrap_err().contains("Ticket"));

    // And the shop's Rust code pays the couriers of a parcel it shipped from
    // the description: Ben and Ana.
    shop.parcels.insert(manifest.parcel, manifest.clone());
    assert_eq!(shop.pay_couriers(&manifest).unwrap().len(), 2);

    // ── A dispatched parcel, with the rules the description now carries:
    // handoffs go only to shift keys, a take goes under one with the
    // dispatch's clerk trusted, and a reminted token is void.
    let d = town.open_dispatch("Pine Co-op").unwrap();
    let (ca, cb) = (member(&mut town, &d), member(&mut town, &d));
    shift(&mut town, &mut ana, &d, &ca, 4);
    shift(&mut town, &mut ben, &d, &cb, 4);
    let m3 = shop.ship("tools", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3).unwrap();
    let m3 = shop.name_dispatch(&m3.parcel, d.clone()).unwrap();
    let mp3 = params(&[("manifest", value(&m3))]);
    let hand = |to: &pave_kernel::Credential| {
        let mut hp = mp3.clone();
        hp.insert("to".into(), value(to));
        hp
    };
    // Not to a key without the dispatch's shift ticket.
    let plain = ben.receive().unwrap();
    meet(&mut shop, &mut ben);
    assert!(shop.act(&p, "hand_off", &hand(&plain)).unwrap_err().contains("IfPresent"));
    // To Ana's shift key, which she shows with its ticket; she takes it from
    // the description, under another of her shift keys.
    let ana_at = ana.shift_key(&d).unwrap();
    shop.learn_ticket(ana.present(&ana_at).unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    shop.act(&p, "hand_off", &hand(&ana_at)).unwrap();
    meet(&mut shop, &mut ana);
    let keys = ana.shift_keys.len();
    ana.act(&p, "take", &mp3).unwrap();
    assert_eq!(ana.shift_keys.len(), keys - 1, "taken under a shift key");
    // Ana loses her phone; the shop (Rust) remints the parcel to Ben. The
    // old token Ana's phone holds is void: whoever passes it on, a courier
    // who has heard of the remint won't take it.
    let code = shop.label_code(&m3.parcel).unwrap().clone();
    let ben_at = ben.shift_key(&d).unwrap();
    shop.learn_ticket(ben.present(&ben_at).unwrap()).unwrap();
    meet(&mut shop, &mut ben);
    shop.remint_parcel(&m3, &code, ben_at).unwrap();
    let ben_old = ben.shift_key(&d).unwrap();
    ana.learn_ticket(ben.present(&ben_old).unwrap()).unwrap();
    meet(&mut ana, &mut ben);
    ana.act(&p, "hand_off", &hand(&ben_old)).unwrap();
    meet(&mut ana, &mut ben);
    meet(&mut shop, &mut ben);
    assert!(ben.act(&p, "take", &mp3).unwrap_err().contains("LineageCurrent"));
    let _ = std::fs::remove_dir_all(&dir);
}
