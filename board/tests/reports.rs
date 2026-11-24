//! Civic reports: one count per person per issue, permits from mirrored
//! city data, rulings that stop a reporter without unmasking them, held
//! publication, forwarding and clearing.

use pave_board::node::{Node, PendingJoin};
use pave_board::report::{cell, IssueKey, PermitStatus, PublishedPermit, ReportMsg, CELL_PRECISION};
use pave_kernel::{Op, Scheme};
use pave_protocol::gossip;
use pave_scheme_briolette::BrioletteV1;
use std::collections::BTreeSet;

fn join(town: &mut Node, name: &str, class: &str, dir: &std::path::Path) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, class, &[]).unwrap();
    Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap()
}

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle_for(&b.have()), b.bundle_for(&a.have()));
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
}

/// Epochs only: gossip never carries messages.
fn epochs_from(from: &Node, to: &mut Node) {
    let hints = gossip::hints(&from.view, &from.know, &from.carries());
    gossip::absorb_hints(&mut to.know, &hints);
    let wants = gossip::wants(&to.view, &to.know, &to.carries(), &to.watch());
    let proofs = gossip::serve(&from.view, &from.know, &from.carries(), &wants);
    gossip::absorb(&mut to.view, &mut to.know, proofs);
}

/// The next epoch, so held reports go out.
fn tick(town: &mut Node, people: &mut [&mut Node]) {
    town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    for p in people.iter_mut() {
        epochs_from(town, p);
        p.release_reports();
    }
}

/// The pseudonym on a report record.
fn nym_of(view: &Node, id: &pave_kernel::Hash) -> Vec<u8> {
    let rec = view.view.messages().iter().find(|r| r.id() == *id).unwrap();
    let Op::Send { body, .. } = &rec.op else { panic!() };
    let Some(ReportMsg::Report { endorsement, .. }) = ReportMsg::decode(body) else { panic!() };
    BrioletteV1 { group_public_key: vec![] }.nym(&endorsement.sig).unwrap()
}

#[test]
fn reports() {
    let dir = std::env::temp_dir().join(format!("pave-reports-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = join(&mut town, "alice", "hardware", &dir);
    let mut bob = join(&mut town, "bob", "software", &dir);
    let mut carol = join(&mut town, "carol", "hardware", &dir);
    let mut dave = join(&mut town, "dave", "hardware", &dir);

    // The mirror signs in the city's published permits.
    let (permitted, blocked) = ((36.1530, -86.7840), (36.1600, -86.7800));
    let published = vec![PublishedPermit { source: "sample".into(), id: "ROW-1".into(), kind: "sidewalk closure".into(), lat: permitted.0, lon: permitted.1, start: "2026-11-01".into(), end: "2026-11-30".into() }];
    assert_eq!(town.mirror_permits(&published).unwrap(), 1);
    assert_eq!(town.mirror_permits(&published).unwrap(), 0, "mirroring is idempotent");
    let permit_id = town.view.messages().iter().find(|r| r.signer == town.town.mirror).unwrap().id();

    // Alice reports a blocked sidewalk. Her wallet holds it until the next epoch.
    let key = IssueKey { category: "sidewalk blocked".into(), cell: cell(blocked.0, blocked.1, CELL_PRECISION), opened: "2026-11-24".into() };
    let issue = alice.report(key.clone(), "2026-11-24", "fencing across the whole sidewalk, no signs", None).unwrap();
    assert!(alice.issues().is_empty());
    assert_eq!(alice.unpublished.len(), 1);
    meet(&mut alice, &mut town);
    assert!(town.issues().is_empty(), "held reports don't travel");
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut alice, &mut town);
    let i = &town.issues()[&issue];
    assert_eq!((i.reporters, i.permit.clone()), (1, PermitStatus::None));

    // Bob corroborates; Alice reporting again, under a fresh credential,
    // still counts once.
    meet(&mut bob, &mut town);
    bob.corroborate(&issue, "2026-11-24", "still there at noon").unwrap();
    alice.report(key.clone(), "2026-11-24", "and again", None).unwrap();
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut alice, &mut town);
    meet(&mut bob, &mut town);
    let i = &town.issues()[&issue];
    assert_eq!(i.reporters, 2, "one person, one count");
    assert_eq!(i.classes.get("software"), Some(&1));
    let alice_reports: Vec<_> = town.reports_on(&issue).into_iter().filter(|id| alice.view.messages().iter().any(|r| r.id() == *id)).collect();
    // Alice's two reports share a pseudonym on this issue...
    let nyms: BTreeSet<_> = alice_reports.iter().map(|id| nym_of(&town, id)).collect();
    assert_eq!(nyms.len(), 1);

    // ...and her report on another issue has an unrelated one.
    let other_key = IssueKey { category: "sidewalk blocked".into(), cell: cell(permitted.0, permitted.1, CELL_PRECISION), opened: "2026-11-24".into() };
    let other = alice.report(other_key, "2026-11-24", "closed, with a permit sign", None).unwrap();
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut alice, &mut town);
    let other_nym = nym_of(&town, &town.reports_on(&other)[0]);
    assert!(!nyms.contains(&other_nym));
    // That one is covered by the mirrored permit.
    assert_eq!(town.issues()[&other].permit, PermitStatus::Found(permit_id));

    // A reply pointing to a permit counts only if the permit covers the issue.
    meet(&mut carol, &mut town);
    carol.reply_issue(&issue, "we have a permit", Some(permit_id)).unwrap();
    carol.forward_issue(&issue, "311", "SR-2026-118823").unwrap();
    meet(&mut carol, &mut town);
    let i = &town.issues()[&issue];
    assert_eq!(i.permit, PermitStatus::None, "that permit is for another block");
    assert_eq!(i.forwarded, vec![("311".to_string(), "SR-2026-118823".to_string())]);

    // Only the mirror's permits and the moderator's rulings count.
    let cred = alice.view.scheme().credential(&alice.key);
    for msg in [
        ReportMsg::Permit { source: "forged".into(), source_id: "X".into(), kind: "sidewalk closure".into(), cell: key.cell.clone(), start: "2026-11-01".into(), end: "2026-12-31".into() },
        ReportMsg::Ruling { report: town.reports_on(&issue)[0], malicious: true, epoch: 0 },
    ] {
        let rec = pave_kernel::sign(alice.view.scheme(), &alice.key, &cred, Op::Send { scope: alice.town.reports, presenting: None, body: msg.encode(), receipt: pave_kernel::Hash([0; 32]) });
        town.view.apply(&rec).unwrap();
    }
    let i = &town.issues()[&issue];
    assert_eq!((i.permit.clone(), i.reporters), (PermitStatus::None, 2));

    // Clearing counts each person once.
    meet(&mut dave, &mut town);
    dave.clear_issue(&issue).unwrap();
    dave.clear_issue(&issue).unwrap();
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut dave, &mut town);
    assert_eq!(town.issues()[&issue].cleared, 1);

    // A malicious report: Carol invents one, the moderator rules it, and
    // it stops counting. Her later reports need standing against the ruling,
    // which she can't produce, while everyone else can.
    let fake = IssueKey { category: "sidewalk blocked".into(), cell: cell(36.17, -86.79, CELL_PRECISION), opened: "2026-11-24".into() };
    let fake_issue = carol.report(fake.clone(), "2026-11-24", "made up", None).unwrap();
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut carol, &mut town);
    assert_eq!(town.issues()[&fake_issue].reporters, 1);
    let fake_report = town.reports_on(&fake_issue)[0];
    town.rule(fake_report, true).unwrap();
    let i = &town.issues()[&fake_issue];
    assert_eq!((i.reporters, i.discounted), (0, 1));

    // Carol hears of the next epoch but not of the ruling, and reports
    // again. Her standing doesn't cover a ruling older than her report, so
    // it doesn't count, and nothing about it says who she is.
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    let again = carol.report(key.clone(), "2026-11-25", "still blocked", None).unwrap();
    assert_eq!(again, issue);
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut carol, &mut town);
    let i = &town.issues()[&issue];
    assert_eq!((i.reporters, i.discounted), (2, 1));
    // Once she knows of the ruling, her wallet can't produce standing at all.
    assert!(carol.report(key.clone(), "2026-11-25", "again", None).unwrap_err().contains("ruled"));
    // Everyone else still can.
    meet(&mut bob, &mut town);
    bob.report(fake.clone(), "2026-11-25", "I don't see anything here", None).unwrap();
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    meet(&mut bob, &mut town);
    assert_eq!(town.issues()[&fake_issue].reporters, 1, "bob's report counts");
    let _ = std::fs::remove_dir_all(&dir);
}
