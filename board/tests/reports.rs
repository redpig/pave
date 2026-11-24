//! Civic reports on a board the town hosts: one count per person per issue,
//! permits from mirrored city data, rulings that stop a reporter without
//! unmasking them, forwarding and clearing.

use pave_board::bulletin::{content_hash, Post, Submission};
use pave_board::node::{Node, PendingJoin};
use pave_board::report::{cell, IssueKey, PermitStatus, PublishedPermit, ReportMsg, CELL_PRECISION};
use pave_kernel::{Hash, Op, Scheme};
use pave_protocol::gossip;
use pave_scheme_briolette::BrioletteV1;
use std::collections::BTreeSet;

fn join(town: &mut Node, name: &str, class: &str, dir: &std::path::Path) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, class, &[]).unwrap();
    Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap()
}

/// The next epoch, heard by everyone through gossip.
fn tick(town: &mut Node, people: &mut [&mut Node]) {
    town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    for p in people.iter_mut() {
        let hints = gossip::hints(&town.view, &town.know, &town.carries());
        gossip::absorb_hints(&mut p.know, &hints);
        let wants = gossip::wants(&p.view, &p.know, &p.carries(), &p.watch());
        let proofs = gossip::serve(&town.view, &town.know, &town.carries(), &wants);
        gossip::absorb(&mut p.view, &mut p.know, proofs);
    }
}

/// The pseudonym on a report post.
fn nym_of(n: &Node, id: &Hash) -> Vec<u8> {
    let copy = n.copy(&n.town.reports.scope).unwrap();
    let item = copy.items().into_iter().find(|i| i.id == *id).unwrap();
    BrioletteV1 { group_public_key: vec![] }.nym(&item.post.endorsement.unwrap().sig).unwrap()
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
    let permit_id = town.copy(&town.town.reports.scope).unwrap().items()[0].id;

    // Alice reports a blocked sidewalk. It waits in her queue until she
    // syncs with the board, then goes straight to it.
    let key = IssueKey { category: "sidewalk blocked".into(), cell: cell(blocked.0, blocked.1, CELL_PRECISION), opened: "2026-11-24".into() };
    let issue = alice.report(key.clone(), "2026-11-24", "fencing across the whole sidewalk, no signs", None).unwrap();
    assert_eq!(alice.outgoing.len(), 1);
    assert!(town.issues().is_empty());
    let s = alice.sync_with(&mut town);
    assert_eq!((s.sent, s.refused.len()), (1, 0));
    assert!(alice.outgoing.is_empty());
    let i = &town.issues()[&issue];
    assert_eq!((i.reporters, i.permit.clone()), (1, PermitStatus::None));
    // Alice holds the host's receipt, so dropping her post later is provable.
    let alice_post = town.reports_on(&issue)[0];
    assert!(alice.copy(&alice.town.reports.scope).unwrap().receipts.contains_key(&alice_post));
    // A receipt is the host's word for one post: it doesn't stand for another,
    // and nobody but the host can make one.
    alice.report(key.clone(), "2026-11-24", "queued", None).unwrap();
    let queued = alice.outgoing[0].clone();
    let r = alice.copy(&alice.town.reports.scope).unwrap().receipts[&alice_post].clone();
    assert!(alice.posted(&queued, &r).is_err());
    let mut fake_receipt = r.clone();
    fake_receipt.post = queued.record.id();
    fake_receipt.content = content_hash(&queued.content);
    assert!(alice.posted(&queued, &fake_receipt).is_err());
    alice.refused(&queued).unwrap();

    // Bob corroborates; Alice reporting again, under a fresh credential,
    // still counts once.
    bob.sync_with(&mut town);
    bob.corroborate(&issue, "2026-11-24", "still there at noon").unwrap();
    alice.report(key.clone(), "2026-11-24", "and again", None).unwrap();
    alice.sync_with(&mut town);
    bob.sync_with(&mut town);
    let i = &town.issues()[&issue];
    assert_eq!(i.reporters, 2, "one person, one count");
    assert_eq!(i.classes.get("software"), Some(&1));
    let alice_reports: Vec<Hash> = alice.copy(&alice.town.reports.scope).unwrap().receipts.keys().copied().collect();
    assert_eq!(alice_reports.len(), 2);
    // Alice's two reports share a pseudonym on this issue...
    let nyms: BTreeSet<_> = alice_reports.iter().map(|id| nym_of(&town, id)).collect();
    assert_eq!(nyms.len(), 1);

    // ...and her report on another issue has an unrelated one.
    let other_key = IssueKey { category: "sidewalk blocked".into(), cell: cell(permitted.0, permitted.1, CELL_PRECISION), opened: "2026-11-24".into() };
    let other = alice.report(other_key, "2026-11-24", "closed, with a permit sign", None).unwrap();
    alice.sync_with(&mut town);
    let other_nym = nym_of(&town, &town.reports_on(&other)[0]);
    assert!(!nyms.contains(&other_nym));
    // That one is covered by the mirrored permit.
    assert_eq!(town.issues()[&other].permit, PermitStatus::Found(permit_id));

    // A reply pointing to a permit counts only if the permit covers the issue.
    carol.sync_with(&mut town);
    carol.reply_issue(&issue, "we have a permit", Some(permit_id)).unwrap();
    carol.forward_issue(&issue, "311", "SR-2026-118823").unwrap();
    carol.sync_with(&mut town);
    let i = &town.issues()[&issue];
    assert_eq!(i.permit, PermitStatus::None, "that permit is for another block");
    assert_eq!(i.forwarded, vec![("311".to_string(), "SR-2026-118823".to_string())]);

    // Only the mirror's permits and the moderator's rulings count.
    let cred = alice.view.scheme().credential(&alice.key);
    for msg in [ReportMsg::Permit { source: "forged".into(), source_id: "X".into(), kind: "sidewalk closure".into(), cell: key.cell.clone(), start: "2026-11-01".into(), end: "2026-12-31".into() }, ReportMsg::Ruling { report: town.reports_on(&issue)[0], malicious: true }] {
        alice.compose(&alice.town.reports.scope.clone(), &cred, msg.kind(), None, msg.encode(), None).unwrap();
    }
    assert_eq!(alice.sync_with(&mut town).sent, 2, "the host takes them; they just don't count");
    let i = &town.issues()[&issue];
    assert_eq!((i.permit.clone(), i.reporters), (PermitStatus::None, 2));

    // The host refuses content that doesn't match its binding, or a forged
    // endorsement; a reader drops such posts from any copy.
    let mut bad = town.copy(&town.town.reports.scope).unwrap().submissions()[1].clone();
    bad.content.push(0);
    assert!(town.host_post(&bad).unwrap_err().contains("hash"));
    let mut forged = town.copy(&town.town.reports.scope).unwrap().submissions().into_iter().find(|s| s.post().unwrap().endorsement.is_some()).unwrap();
    let Op::Send { body, .. } = &mut forged.record.op else { panic!() };
    let mut post = Post::decode(body).unwrap();
    post.epoch += 1;
    *body = post.encode();
    let forged = Submission { record: pave_kernel::sign(alice.view.scheme(), &alice.key, &cred, forged.record.op.clone()), content: forged.content };
    assert!(town.host_post(&forged).unwrap_err().contains("endorsement"));
    assert_eq!(dave.absorb_posts(&dave.town.reports.scope.clone(), &[bad]), 0);

    // A report filed under a thread other than its issue's would carry a
    // second pseudonym for the same person. It doesn't count.
    let msg = ReportMsg::Report { key: key.clone(), observed: "2026-11-24".into(), note: "sneaky".into(), photo: None };
    let ruled = pave_board::report::ruled(alice.copy(&alice.town.reports.scope).unwrap(), &alice.town.classes);
    alice.compose(&alice.town.reports.scope.clone(), &cred, "report", Some(Hash([7; 32])), msg.encode(), Some(&ruled)).unwrap();
    alice.sync_with(&mut town);
    assert_eq!(town.issues()[&issue].reporters, 2);

    // Clearing counts each person once. Two clearings have the same
    // content, and a receipt for one doesn't stand for the other.
    dave.sync_with(&mut town);
    dave.clear_issue(&issue).unwrap();
    dave.sync_with(&mut town);
    dave.clear_issue(&issue).unwrap();
    let second = dave.outgoing[0].clone();
    let first = dave.copy(&dave.town.reports.scope).unwrap().receipts.values().next().unwrap().clone();
    assert_eq!(first.content, content_hash(&second.content));
    assert!(dave.posted(&second, &first).is_err());
    dave.sync_with(&mut town);
    assert_eq!(town.issues()[&issue].cleared, 1);

    // A malicious report: Carol invents one, the moderator rules it, and
    // it stops counting. Her later reports need standing against the ruling,
    // which she can't produce, while everyone else can.
    let fake = IssueKey { category: "sidewalk blocked".into(), cell: cell(36.17, -86.79, CELL_PRECISION), opened: "2026-11-24".into() };
    let fake_issue = carol.report(fake.clone(), "2026-11-24", "made up", None).unwrap();
    carol.sync_with(&mut town);
    assert_eq!(town.issues()[&fake_issue].reporters, 1);
    let fake_report = town.reports_on(&fake_issue)[0];
    town.rule(fake_report, true).unwrap();
    let i = &town.issues()[&fake_issue];
    assert_eq!((i.reporters, i.discounted), (0, 1));

    // Carol hears of the next epoch but reports from a stale copy, without
    // the ruling. Her standing doesn't cover a ruling older than her report,
    // so it doesn't count, and nothing about it says who she is.
    tick(&mut town, &mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    let again = carol.report(key.clone(), "2026-11-25", "still blocked", None).unwrap();
    assert_eq!(again, issue);
    carol.sync_with(&mut town);
    let i = &town.issues()[&issue];
    assert_eq!((i.reporters, i.discounted), (2, 1));
    // Once she has the ruling, her wallet can't produce standing at all.
    assert!(carol.report(key.clone(), "2026-11-25", "again", None).unwrap_err().contains("ruled"));
    // Everyone else still can.
    bob.sync_with(&mut town);
    bob.report(fake.clone(), "2026-11-25", "I don't see anything here", None).unwrap();
    bob.sync_with(&mut town);
    assert_eq!(town.issues()[&fake_issue].reporters, 1, "bob's report counts");

    // Any copy can serve readers, and a reader checks everything it gets:
    // Dave fetches from Bob's copy and sees the same board.
    let scope = dave.town.reports.scope;
    let posts = bob.posts_since(&scope, &dave.board_have(&scope));
    dave.absorb_posts(&scope, &posts);
    assert_eq!(dave.issues()[&issue].reporters, town.issues()[&issue].reporters);

    // Reports never travel between wallets: meeting carries value, epochs
    // and evidence, and a wallet drops board posts slipped into a bundle.
    let mut b = alice.bundle();
    b.records.push(town.copy(&scope).unwrap().submissions()[0].record.clone());
    let mut erin = join(&mut town, "erin", "hardware", &dir);
    erin.absorb_bundle(&b);
    assert!(erin.view.messages().iter().all(|r| !matches!(&r.op, Op::Send { scope: s, .. } if *s == scope)));
    assert!(erin.issues().is_empty());

    // Saved state keeps the copy and its receipts.
    alice.save().unwrap();
    let again = Node::load(&alice.path).unwrap();
    assert_eq!(again.issues()[&issue].reporters, alice.issues()[&issue].reporters);
    assert_eq!(again.copy(&scope).unwrap().receipts.len(), alice.copy(&scope).unwrap().receipts.len());
    let _ = std::fs::remove_dir_all(&dir);
}
