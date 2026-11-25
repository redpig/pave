//! Evidence for panels. A courier drops a parcel at the wrong porch and
//! photographs it; the addressee disputes with a picture of her own house,
//! a street-view image and the city's tax-assessor photo. The panelist's
//! wallet checks what it can and lays the pictures side by side. Only the
//! panel sees them.

use pave_board::dispute::{Answer, Filing};
use pave_board::evidence::{Check, Evidence};
use pave_board::node::{Node, PendingJoin};
use pave_board::parcel::{Delivery, Mode};
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

/// A JPEG's structure: a header, Exif with a location, a C2PA manifest,
/// and "pixels" standing in for the picture.
fn jpeg(pixels: &str, exif: &str) -> Vec<u8> {
    let seg = |marker: u8, payload: &[u8]| {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    };
    let mut v = vec![0xFF, 0xD8];
    v.extend(seg(0xE0, b"JFIF\0"));
    v.extend(seg(0xE1, format!("Exif\0\0{exif}").as_bytes()));
    v.extend(seg(0xEB, b"JP\0jumb c2pa: captured by camera app"));
    v.extend(seg(0xDA, b"scan"));
    v.extend_from_slice(pixels.as_bytes());
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
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

#[test]
fn evidence() {
    let dir = std::env::temp_dir().join(format!("pave-evidence-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut shop = join(&mut town, "shop", &dir, &[100]);
    let mut ana = join(&mut town, "ana", &dir, &[30]);
    let mut zoe = join(&mut town, "zoe", &dir, &[30]);
    let mut stranger = join(&mut town, "stranger", &dir, &[]);
    let mut arbs: Vec<Node> = (0..2).map(|i| join(&mut town, &format!("arb{i}"), &dir, &[])).collect();
    let to = shop.receive().unwrap();
    town.issue_parcel_budget(to, 10).unwrap();
    meet(&mut shop, &mut town);
    let q = "was it delivered?";

    // ── The courier leaves it at the wrong porch, with a photo of it.
    let zoe_at = zoe.receive().unwrap();
    let (m, _) = shop.ship_with("books", "dn5bpsb", "dn5bpth", zoe_at.clone(), 3, Mode::Drop { window: 2 }).unwrap();
    shop.hand_off(&m.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m).unwrap();
    let wrong_porch = jpeg("blue door, white railing, number 125", "GPS 36.1621,-86.7812 2026-11-24T14:02");
    ana.drop_off_photo(&m, "dn5bpth", &wrong_porch).unwrap();
    meet(&mut ana, &mut shop);
    meet(&mut ana, &mut zoe);

    // Zoe disputes, and shows her own house and two public records.
    let d = zoe.open_dispute(Filing::new(m.parcel, q, false, 1, 0).party(zoe_at.clone())).unwrap();
    // Her picture is shown without its metadata; she keeps the original.
    let my_door = jpeg("red door, brick steps, number 123", "GPS 36.1624,-86.7809 2026-11-24T18:30");
    zoe.submit_image(m.parcel, "my front door", &my_door, true, Some(zoe_at.clone())).unwrap();
    zoe.submit_evidence(m.parcel, &Evidence::Reference { source: "street view".into(), url: "https://maps.example/123-pine".into(), caption: "123 Pine St, 2025".into(), image: b"JPEG: red door, number 123".to_vec() }, Some(zoe_at.clone())).unwrap();
    zoe.submit_evidence(m.parcel, &Evidence::Reference { source: "city tax assessor".into(), url: "https://assessor.example/parcel/123-pine".into(), caption: "123 Pine St".into(), image: b"JPEG: brick house, red door".to_vec() }, Some(zoe_at.clone())).unwrap();
    zoe.submit_evidence(m.parcel, &Evidence::Statement { text: "That photo is 125, two doors down. Mine is 123, red door.".into() }, Some(zoe_at.clone())).unwrap();
    // The courier shows custody and the photo it committed to at the drop,
    // and then a different photo it took later, of the right door.
    ana.submit_parcel_evidence(&m, Some("left at the door of the address")).unwrap();
    let later_shot = jpeg("red door, number 123", "GPS 36.1624,-86.7809 2026-11-26T09:00");
    let later = Evidence::DropPhoto { image: later_shot.clone(), commitment: pave_board::evidence::photo_commitment(b"any salt", &later_shot) };
    let ana_cred = ana.parties(&m).into_iter().find(|c| ana.mine.contains(c));
    ana.submit_evidence(m.parcel, &later, ana_cred).unwrap();
    // A submission with a forged signature is refused by the host.
    let mut forged = ana.evidence_out[0].clone();
    forged.bytes.push(0);
    assert!(town.host_evidence(&forged).is_err());
    for p in [&mut zoe, &mut ana, &mut shop, &mut stranger] {
        p.sync_with(&mut town);
    }

    // Everyone sees what was submitted, and by whom; nobody sees it.
    let notes = stranger.evidence_notes(&m.parcel);
    let kinds: Vec<&str> = notes.iter().map(|(k, _, _)| k.as_str()).collect();
    assert_eq!(kinds, ["image", "reference", "reference", "statement", "custody", "photo", "statement", "photo"]);
    assert!(stranger.ask_evidence(&m.parcel).is_err(), "not on a panel");

    // The panel is drawn; only the panelist gets the evidence.
    for a in arbs.iter_mut() {
        a.sync_with(&mut town);
        a.offer_to_arbitrate(d).unwrap();
        a.sync_with(&mut town);
    }
    for _ in 0..2 {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe, &mut stranger];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
    }
    for a in arbs.iter_mut() {
        a.sync_with(&mut town);
    }
    let drawn = (0..2).find(|i| arbs[*i].ask_evidence(&m.parcel).is_ok()).unwrap();
    assert!(arbs[1 - drawn].ask_evidence(&m.parcel).is_err(), "offered but not drawn");
    let ask = arbs[drawn].ask_evidence(&m.parcel).unwrap();
    // A request signed by someone else's credential is refused, and so is
    // a properly signed one from a stranger.
    let mut stolen = ask.clone();
    stolen.panelist = stranger.receive().unwrap();
    assert!(town.answer_evidence(&stolen).is_err());
    let own = stranger.receive().unwrap();
    assert!(town.answer_evidence(&stranger.ask_evidence_as(&m.parcel, &own)).is_err());
    // Naming the panelist's credential doesn't help without its key.
    assert!(town.answer_evidence(&stranger.ask_evidence_as(&m.parcel, &ask.panelist)).is_err());
    // Zoe, who opened the dispute, sees the courier's photo, so she can answer it.
    zoe.sync_with(&mut town);
    let hers = town.answer_evidence(&zoe.ask_evidence(&m.parcel).unwrap()).unwrap();
    assert!(hers.iter().any(|e| e.evidence().is_some_and(|x| x.kind() == "photo")));
    let given = town.answer_evidence(&ask).unwrap();
    assert_eq!(given.len(), 8);

    // The panelist's wallet works it out from the records and checks what
    // it can. The photo is the one committed at the drop, at the right
    // cell: so the question is the door, and the pictures are side by side.
    let ex = arbs[drawn].examine_parcel(&m.parcel, &given);
    assert_eq!(ex.custody, ["handoff shipper → courier 1", "take by courier 1", "closed by courier 1"]);
    assert_eq!((ex.photo_matches.clone(), ex.cell_matches.clone(), ex.code_matches.clone()), (Check::Yes, Check::Yes, Check::Unknown));
    let pics: Vec<(String, String, bool)> = ex.pictures.iter().map(|p| (p.label.clone(), p.from.clone(), p.committed_at_drop)).collect();
    assert_eq!(pics.len(), 5);
    assert!(pics.contains(&("drop photo".into(), "courier 1".into(), true)));
    assert!(pics.contains(&("drop photo".into(), "courier 1".into(), false)), "the later photo wasn't the one committed at the drop");
    assert!(pics.contains(&("my front door".into(), "addressee".into(), false)));
    assert!(pics.contains(&("city tax assessor: 123 Pine St".into(), "addressee".into(), false)));
    // What the panel sees of the drop photo is the stripped copy: no location.
    let shown = &ex.pictures.iter().find(|p| p.committed_at_drop).unwrap().bytes;
    assert_eq!(*shown, pave_board::media::strip_metadata(&wrong_porch));
    assert!(pave_board::media::metadata_kinds(shown).is_empty());
    assert!(ex.pictures.iter().all(|p| p.original == Check::Unknown), "no originals revealed yet");
    assert!(ex.exhibits.iter().any(|e| e.kind == "statement" && e.from == "addressee" && e.detail.contains("two doors down")));
    // What the panel was given is exactly what was noted in public.
    let noted: BTreeSet<_> = notes.iter().map(|(_, h, _)| *h).collect();
    assert_eq!(noted, given.iter().map(|e| e.hash()).collect());

    // Ana reveals her original, to show where and when it was taken; Zoe
    // reveals hers. Each is checked against its commitment and shown with
    // the metadata it carries. A made-up "original" matches nothing.
    let ana_cred = ana.parties(&m).into_iter().find(|c| ana.mine.contains(c));
    ana.reveal_originals(&m.parcel, ana_cred).unwrap();
    zoe.reveal_originals(&m.parcel, Some(zoe_at.clone())).unwrap();
    zoe.submit_evidence(m.parcel, &Evidence::Original { salt: b"guess".to_vec(), original: jpeg("red door", "GPS made up") }, Some(zoe_at.clone())).unwrap();
    ana.sync_with(&mut town);
    zoe.sync_with(&mut town);
    let given = town.answer_evidence(&arbs[drawn].ask_evidence(&m.parcel).unwrap()).unwrap();
    let ex = arbs[drawn].examine_parcel(&m.parcel, &given);
    let orig = ex.pictures.iter().find(|p| p.label == "original of drop photo").unwrap();
    assert_eq!((orig.original.clone(), orig.committed_at_drop, orig.bytes.clone()), (Check::Yes, true, wrong_porch.clone()));
    assert_eq!(orig.metadata, ["Exif", "C2PA (JUMBF)"]);
    assert_eq!(ex.pictures.iter().find(|p| p.label == "drop photo" && p.committed_at_drop).unwrap().original, Check::Yes);
    let door = ex.pictures.iter().find(|p| p.label == "original of my front door").unwrap();
    assert_eq!((door.original.clone(), door.from.as_str()), (Check::Yes, "addressee"));
    assert!(ex.pictures.iter().any(|p| p.label == "an original that matches nothing shown" && p.original == Check::No));

    // The panelist compares the doors and rules: not delivered.
    arbs[drawn].arbitrate(d, Answer::No).unwrap();
    arbs[drawn].sync_with(&mut town);
    shop.sync_with(&mut town);
    assert_eq!(shop.delivery(&m), Delivery::NotDelivered);

    // An old request isn't honored once the epoch has moved on.
    for _ in 0..2 {
        let mut all: Vec<&mut Node> = vec![&mut shop];
        tick(&mut town, &mut all);
    }
    assert!(town.answer_evidence(&ask).is_err());

    // ── A code delivery: the courier closed with a wrong code and says it
    // was delivered. The shop's evidence reveals the code; the panelist's
    // wallet checks the courier's closing against it.
    for p in [&mut ana, &mut zoe, &mut stranger] {
        let mut all: Vec<&mut Node> = vec![p];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
    }
    let (m2, _) = shop.ship_with("medicine", "dn5bpsb", "dn5bpth", zoe.receive().unwrap(), 3, Mode::Code).unwrap();
    shop.hand_off(&m2.parcel, ana.receive().unwrap()).unwrap();
    meet(&mut shop, &mut ana);
    ana.take_parcel(&m2).unwrap();
    ana.deliver_by_code(&m2, "000000x").unwrap();
    meet(&mut ana, &mut shop);
    let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana, &mut zoe];
    all.extend(arbs.iter_mut());
    tick(&mut town, &mut all);
    let d2 = ana.open_dispute(Filing::new(m2.parcel, q, true, 1, 0)).unwrap();
    shop.submit_parcel_evidence(&m2, None).unwrap();
    for p in [&mut ana, &mut shop] {
        p.sync_with(&mut town);
    }
    for a in arbs.iter_mut() {
        a.sync_with(&mut town);
        a.offer_to_arbitrate(d2).unwrap();
        a.sync_with(&mut town);
    }
    for _ in 0..2 {
        let mut all: Vec<&mut Node> = vec![&mut shop, &mut ana];
        all.extend(arbs.iter_mut());
        tick(&mut town, &mut all);
    }
    for a in arbs.iter_mut() {
        a.sync_with(&mut town);
    }
    let drawn = (0..2).find(|i| arbs[*i].ask_evidence(&m2.parcel).is_ok()).unwrap();
    let given = town.answer_evidence(&arbs[drawn].ask_evidence(&m2.parcel).unwrap()).unwrap();
    let ex = arbs[drawn].examine_parcel(&m2.parcel, &given);
    assert_eq!(ex.code_matches, Check::No, "the courier's closing doesn't commit to the shop's code");
    assert!(ex.exhibits.iter().any(|e| e.kind == "code" && e.from == "shipper"));

    // Held evidence survives a restart of the host.
    town.save().unwrap();
    assert_eq!(Node::load(&town.path).unwrap().held_evidence[&m.parcel].len(), 11);
    let _ = std::fs::remove_dir_all(&dir);
}
