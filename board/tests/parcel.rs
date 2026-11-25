//! Packages: custody as a coin, handed courier to courier offline, taken
//! with an acknowledgment only the taker can sign, delivered when the
//! addressee retires it, and paid per hop.

use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::Step;

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
    // As real meets do: proofs that the credentials each sent from aren't known cheats.
    let (sa, sb) = (a.standings(), b.standings());
    b.absorb_standings(sa);
    a.absorb_standings(sb);
}

fn balance(n: &Node) -> u64 {
    n.my_coins().iter().map(|c| c.amount).sum()
}

#[test]
fn parcels() {
    let dir = std::env::temp_dir().join(format!("pave-parcel-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut shop = join(&mut town, "shop", &dir, &[100]);
    let mut ana = join(&mut town, "ana", &dir, &[]);
    let mut ben = join(&mut town, "ben", &dir, &[]);
    let mut dan = join(&mut town, "dan", &dir, &[]);
    let mut zoe = join(&mut town, "zoe", &dir, &[]);

    // The town gives the shop a budget of parcels.
    assert!(shop.ship("x", "a", "b", zoe.receive().unwrap(), 3).is_err(), "no budget yet");
    let to = shop.receive().unwrap();
    town.issue_parcel_budget(to, 10).unwrap();
    meet(&mut shop, &mut town);

    // Zoe orders and gives the shop the credential to deliver to.
    let zoe_at = zoe.receive().unwrap();
    let m = shop.ship("thai takeout", "dn5bpsb", "dn5bpth", zoe_at.clone(), 3).unwrap();

    // Shop → Ana → Ben → Zoe, each handoff offline, each courier taking it.
    let ana_at = ana.receive().unwrap();
    shop.hand_off(&m.parcel, ana_at).unwrap();
    meet(&mut shop, &mut ana);
    // A courier checks the manifest against the handoff.
    let mut lie = m.clone();
    lie.pay_per_hop = 30;
    assert!(ana.take_parcel(&lie).unwrap_err().contains("manifest"));
    ana.take_parcel(&m).unwrap();
    assert!(shop.pay_couriers(&m).unwrap_err().contains("not delivered"));

    let ben_at = ben.receive().unwrap();
    ana.hand_off(&m.parcel, ben_at).unwrap();
    meet(&mut ana, &mut ben);
    ben.take_parcel(&m).unwrap();
    // A courier can't confirm delivery: only the addressee's credential can.
    assert!(ben.confirm_delivery(&m).unwrap_err().contains("addressee"));
    ben.hand_off(&m.parcel, zoe_at.clone()).unwrap();
    meet(&mut ben, &mut zoe);
    zoe.confirm_delivery(&m).unwrap();

    // The confirmation travels back like any record.
    meet(&mut zoe, &mut ben);
    meet(&mut ben, &mut ana);
    meet(&mut ana, &mut shop);
    let c = shop.custody(&m);
    assert!(c.delivered && c.holder.is_none());
    let kinds: Vec<&str> = c.steps.iter().map(|s| match s { Step::Handoff { .. } => "handoff", Step::Take { .. } => "take", Step::Retired { .. } => "retired", Step::Closed { .. } => "closed" }).collect();
    assert_eq!(kinds, ["handoff", "take", "handoff", "take", "handoff", "retired"]);
    assert_eq!(c.steps.last(), Some(&Step::Retired { by: zoe_at }));

    // The shop pays each courier per hop, once.
    assert_eq!(shop.pay_couriers(&m).unwrap().len(), 2);
    assert!(shop.pay_couriers(&m).unwrap().is_empty(), "never twice");
    meet(&mut shop, &mut ana);
    meet(&mut shop, &mut ben);
    assert_eq!((balance(&ana), balance(&ben), balance(&shop)), (3, 3, 94));

    // A second parcel: Ana hands it to Ben and also to Dan. Using one state
    // twice is the kernel's evidence; once Ben and Dan meet, both can show
    // it, and the shop won't pay Ana for it.
    let zoe_at = zoe.receive().unwrap();
    let m3 = shop.ship("flowers", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3).unwrap();
    shop.hand_off(&m3.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m3).unwrap();
    let m2 = shop.ship("groceries", "dn5bpsb", "dn5bpth", zoe_at.clone(), 3).unwrap();
    shop.hand_off(&m2.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    let state = ana.take_parcel(&m2).unwrap();
    ana.hand_off(&m2.parcel, ben.receive().unwrap()).unwrap();
    meet(&mut ana, &mut ben);
    ben.take_parcel(&m2).unwrap();
    ana.cheat(state, dan.receive().unwrap()).unwrap();
    meet(&mut ana, &mut dan);
    assert!(dan.take_parcel(&m2).is_err(), "and it doesn't match the manifest anyway");
    meet(&mut ben, &mut dan);
    assert_eq!(ben.view.flagged().len(), 1);
    assert_eq!(dan.view.flagged(), ben.view.flagged());
    // Ben now won't take a parcel from Ana, under any credential she uses.
    ana.hand_off(&m3.parcel, ben.receive().unwrap()).unwrap();
    meet(&mut ana, &mut ben);
    assert!(ben.take_parcel(&m3).unwrap_err().contains("NoStanding"), "she can't prove she isn't the cheat");
    ben.hand_off(&m2.parcel, zoe_at).unwrap();
    meet(&mut ben, &mut zoe);
    zoe.confirm_delivery(&m2).unwrap();
    meet(&mut zoe, &mut ben);
    meet(&mut ben, &mut shop);
    assert!(shop.custody(&m2).delivered);
    assert_eq!(shop.pay_couriers(&m2).unwrap().len(), 1, "ben is paid; ana isn't");

    // A courier who retires a parcel himself hasn't delivered it, and the
    // shop owes nobody for it.
    let m4 = shop.ship("tools", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3).unwrap();
    shop.hand_off(&m4.parcel, dan.receive().unwrap()).unwrap();
    meet(&mut shop, &mut dan);
    dan.take_parcel(&m4).unwrap();
    let coin = dan.view.unspent().find(|c| c.origin == m4.parcel).unwrap().clone();
    let rec = pave_kernel::sign(dan.view.scheme(), &dan.key, &coin.holder, pave_kernel::Op::Retire { state: coin.state });
    dan.view.apply(&rec).unwrap();
    meet(&mut dan, &mut shop);
    let c = shop.custody(&m4);
    assert!(c.holder.is_none() && !c.delivered);
    assert!(shop.pay_couriers(&m4).is_err());

    // Manifests survive a restart.
    shop.save().unwrap();
    let again = Node::load(&shop.path).unwrap();
    assert!(again.custody(&again.parcels[&m.parcel]).delivered);
    let _ = std::fs::remove_dir_all(&dir);
}
