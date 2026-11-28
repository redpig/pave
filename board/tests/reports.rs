//! Civic reports on a board the town hosts: one count per person per issue,
//! permits from mirrored city data, rulings that stop a reporter without
//! unmasking them, forwarding and clearing.

use pave_board::bulletin::{purpose, Clock};
use pave_board::node::{Node, PendingJoin};
use pave_board::report::{
    cell, IssueKey, PermitStatus, PublishedPermit, ReportMsg, CELL_PRECISION,
};
use pave_kernel::{Hash, Op, Scheme};
use pave_protocol::gossip;
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

/// The pseudonym on a report post: its ticket's tag.
fn nym_of(n: &Node, id: &Hash) -> Vec<u8> {
    let copy = n.copy(&n.town.reports.scope).unwrap();
    let item = copy.items().into_iter().find(|i| i.id == *id).unwrap();
    item.tag.unwrap().nym.clone()
}

/// A fresh key for a wallet.
fn erin_key(n: &Node) -> pave_kernel::Credential {
    n.view.scheme().credential(&n.key)
}

/// Alice's posts in her own copy, as the server took them.
fn taken(n: &Node) -> Vec<pave_board::bulletin::Submission> {
    n.copy(&n.town.reports.scope)
        .unwrap()
        .submissions()
        .into_iter()
        .filter(|s| n.mine.contains(&s.record.signer))
        .collect()
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
    let published = vec![PublishedPermit {
        source: "sample".into(),
        id: "ROW-1".into(),
        kind: "sidewalk closure".into(),
        lat: permitted.0,
        lon: permitted.1,
        start: "2026-11-01".into(),
        end: "2026-11-30".into(),
    }];
    assert_eq!(town.mirror_permits(&published).unwrap(), 1);
    assert_eq!(
        town.mirror_permits(&published).unwrap(),
        0,
        "mirroring is idempotent"
    );
    let permit_id = town.copy(&town.town.reports.scope).unwrap().items()[0].id;

    // Alice reports a blocked sidewalk. It waits in her queue until she
    // syncs with the board, then goes straight to it.
    let key = IssueKey {
        category: "sidewalk blocked".into(),
        cell: cell(blocked.0, blocked.1, CELL_PRECISION),
        opened: "2026-11-24".into(),
    };
    let issue = alice
        .report(
            key.clone(),
            "2026-11-24",
            "fencing across the whole sidewalk, no signs",
            None,
        )
        .unwrap();
    assert_eq!(alice.outgoing.len(), 1);
    assert!(town.issues().is_empty());
    let s = alice.sync_with(&mut town);
    assert_eq!((s.sent, s.refused.len()), (1, 0));
    assert!(alice.outgoing.is_empty());
    let i = &town.issues()[&issue];
    assert_eq!((i.reporters, i.permit.clone()), (1, PermitStatus::None));
    // Her post is her token's transfer to the server, and the server's
    // retire of that token is its word that it took it, so dropping her post
    // later is provable.
    let mine = taken(&alice);
    assert_eq!(mine.len(), 1);
    let retire = mine[0].taken.clone().unwrap();
    assert_eq!(retire.signer, town.town.reports.host);
    assert_eq!(
        retire.op,
        Op::Retire {
            state: mine[0].record.output(0)
        }
    );
    // The retire stands for that post's token, not another's.
    alice
        .report(key.clone(), "2026-11-24", "queued", None)
        .unwrap();
    let queued = alice.outgoing[0].clone();
    let terms = town.token_terms().unwrap();
    let req = alice
        .token_request(&terms, std::slice::from_ref(&queued.signer), queued.count)
        .unwrap();
    let grant = town.answer_tokens(&req).unwrap();
    alice.take_grant(grant).unwrap();
    let sub = alice
        .sign_post(&queued, &town.board_clock(&queued.board).unwrap())
        .unwrap();
    assert!(alice.posted(&sub, &retire).is_err());
    alice.refused(&queued.name()).unwrap();

    let scope_r = alice.town.reports.scope;
    // Bob corroborates; Alice reporting again, under a fresh credential,
    // still counts once.
    bob.sync_with(&mut town);
    bob.corroborate(&issue, "2026-11-24", "still there at noon")
        .unwrap();
    alice
        .report(key.clone(), "2026-11-24", "and again", None)
        .unwrap();
    alice.sync_with(&mut town);
    bob.sync_with(&mut town);
    let i = &town.issues()[&issue];
    assert_eq!(i.reporters, 2, "one person, one count");
    assert_eq!(i.classes.get("software"), Some(&1));
    let alice_reports: Vec<Hash> = taken(&alice).iter().map(|s| s.name()).collect();
    assert_eq!(alice_reports.len(), 2);
    // Alice's two reports share a pseudonym on this issue...
    let nyms: BTreeSet<_> = alice_reports.iter().map(|id| nym_of(&town, id)).collect();
    assert_eq!(nyms.len(), 1);

    // ...and her report on another issue has an unrelated one.
    let other_key = IssueKey {
        category: "sidewalk blocked".into(),
        cell: cell(permitted.0, permitted.1, CELL_PRECISION),
        opened: "2026-11-24".into(),
    };
    let other = alice
        .report(other_key, "2026-11-24", "closed, with a permit sign", None)
        .unwrap();
    alice.sync_with(&mut town);
    let other_nym = nym_of(&town, &town.reports_on(&other)[0]);
    assert!(!nyms.contains(&other_nym));
    // That one is covered by the mirrored permit.
    assert_eq!(town.issues()[&other].permit, PermitStatus::Found(permit_id));

    // A reply pointing to a permit counts only if the permit covers the issue.
    carol.sync_with(&mut town);
    carol
        .reply_issue(&issue, "we have a permit", Some(permit_id))
        .unwrap();
    carol
        .forward_issue(&issue, "311", "SR-2026-118823")
        .unwrap();
    carol.sync_with(&mut town);
    let i = &town.issues()[&issue];
    assert_eq!(
        i.permit,
        PermitStatus::None,
        "that permit is for another block"
    );
    assert_eq!(
        i.forwarded,
        vec![("311".to_string(), "SR-2026-118823".to_string())]
    );

    // Only the mirror's permits and the moderator's rulings count.
    let cred = alice.view.scheme().credential(&alice.key);
    for msg in [
        ReportMsg::Permit {
            source: "forged".into(),
            source_id: "X".into(),
            kind: "sidewalk closure".into(),
            cell: key.cell.clone(),
            start: "2026-11-01".into(),
            end: "2026-12-31".into(),
        },
        ReportMsg::Ruling {
            report: town.reports_on(&issue)[0],
            malicious: true,
        },
    ] {
        alice
            .compose(
                &alice.town.reports.scope.clone(),
                &cred,
                msg.kind(),
                None,
                msg.encode(),
                None,
            )
            .unwrap();
    }
    assert_eq!(
        alice.sync_with(&mut town).sent,
        2,
        "the host takes them; they just don't count"
    );
    let i = &town.issues()[&issue];
    assert_eq!((i.permit.clone(), i.reporters), (PermitStatus::None, 2));

    // A server or reader refuses content that doesn't match the binding, or
    // a binding changed after signing; a token can't be used twice, at this
    // server or another; and a server takes only its own clock.
    let mut bad = town.copy(&town.town.reports.scope).unwrap().submissions()[1].clone();
    bad.content.push(0);
    assert_eq!(
        dave.absorb_posts(&dave.town.reports.scope.clone(), std::slice::from_ref(&bad)),
        0
    );
    let mut changed = town.copy(&town.town.reports.scope).unwrap().submissions()[1].clone();
    changed.post.kind = "cleared".into();
    assert!(town.host_post(&changed).unwrap_err().contains("this post"));
    assert_eq!(
        dave.absorb_posts(&dave.town.reports.scope.clone(), &[changed]),
        0
    );
    let again = town.copy(&town.town.reports.scope).unwrap().submissions()[1].clone();
    assert!(
        town.host_post(&pave_board::bulletin::Submission {
            taken: None,
            ..again
        })
        .is_err(),
        "one token, one post"
    );
    alice
        .report(key.clone(), "2026-11-24", "late", None)
        .unwrap();
    let late = alice.outgoing.pop().unwrap();
    let req = alice
        .token_request(
            &town.token_terms().unwrap(),
            std::slice::from_ref(&late.signer),
            late.count,
        )
        .unwrap();
    alice.take_grant(town.answer_tokens(&req).unwrap()).unwrap();
    let now = town.board_clock(&late.board).unwrap();
    let stale = alice
        .sign_post(
            &late,
            &Clock {
                clock: now.clock - 3600,
                ..now
            },
        )
        .unwrap();
    assert!(town.host_post(&stale).unwrap_err().contains("clock"));
    let behind = alice.sign_post(
        &late,
        &Clock {
            epoch: now.epoch + 5,
            ..now
        },
    );
    assert!(behind.is_err(), "one token, one signature");
    alice
        .report(key.clone(), "2026-11-24", "early", None)
        .unwrap();
    let early = alice.outgoing.pop().unwrap();
    let req = alice
        .token_request(
            &town.token_terms().unwrap(),
            std::slice::from_ref(&early.signer),
            early.count,
        )
        .unwrap();
    alice.take_grant(town.answer_tokens(&req).unwrap()).unwrap();
    let ahead = alice
        .sign_post(
            &early,
            &Clock {
                epoch: now.epoch + 5,
                ..now
            },
        )
        .unwrap();
    assert!(town.host_post(&ahead).unwrap_err().contains("epoch"));

    // A tag is the mint's word: a request signed for one purpose can't
    // claim another.
    let terms = town.token_terms().unwrap();
    let fresh = alice.view.scheme().credential(&alice.key);
    let mut req = alice
        .token_request(&terms, std::slice::from_ref(&fresh), Some(Hash([1; 32])))
        .unwrap();
    req.body.purpose = Some(Hash([2; 32]));
    assert!(town.answer_tokens(&req).is_err());
    let mut req = alice
        .token_request(&terms, std::slice::from_ref(&fresh), Some(Hash([1; 32])))
        .unwrap();
    req.also = alice
        .token_request(&terms, std::slice::from_ref(&fresh), Some(Hash([2; 32])))
        .unwrap()
        .also;
    assert!(town
        .answer_tokens(&req)
        .unwrap_err()
        .contains("extra signature"));

    // Only the board mint's tokens post: a budget of the same schema under
    // the root's own capability makes tokens no server or reader takes.
    let op = town.operator.clone().unwrap();
    let s = town.view.scheme().clone();
    let rogue = pave_kernel::sign(
        &s,
        &op.root,
        &op.root_cred,
        Op::IssueBudget {
            authority: town.town.genesis.rooting_capability(),
            schema: pave_board::bulletin::post_schema(),
            amount: 1,
            to: op.root_cred.clone(),
        },
    );
    let token = pave_kernel::sign(
        &s,
        &op.root,
        &op.root_cred,
        Op::Mint {
            budget: rogue.output(0),
            amount: 1,
            to: fresh.clone(),
            change_to: op.root_cred.clone(),
        },
    );
    alice.view.apply(&rogue).unwrap();
    alice.view.apply(&token).unwrap();
    alice
        .compose(
            &scope_r,
            &fresh,
            "reply",
            Some(issue),
            b"rogue".to_vec(),
            None,
        )
        .unwrap();
    let d = alice.outgoing.pop().unwrap();
    let mut rogue_sub = alice
        .sign_post(&d, &town.board_clock(&scope_r).unwrap())
        .unwrap();
    assert!(town
        .host_post(&rogue_sub)
        .unwrap_err()
        .contains("another mint"));
    rogue_sub.taken = Some(pave_kernel::sign(
        &s,
        &town.key,
        &town.town.reports.host,
        Op::Retire {
            state: rogue_sub.record.output(0),
        },
    ));
    assert_eq!(
        dave.absorb_posts(&scope_r, &[rogue_sub]),
        0,
        "nor does a reader, even if the server took it"
    );

    // A report filed under a thread other than its issue's would carry a
    // second pseudonym for the same person. It doesn't count.
    let msg = ReportMsg::Report {
        key: key.clone(),
        observed: "2026-11-24".into(),
        note: "sneaky".into(),
        photo: None,
    };
    let scope = alice.town.reports.scope;
    alice
        .compose(
            &scope,
            &cred,
            "report",
            Some(Hash([7; 32])),
            msg.encode(),
            Some(purpose(&scope, "report", &Hash([7; 32]))),
        )
        .unwrap();
    // Nor does one counted for another issue.
    let fresh = alice.view.scheme().credential(&alice.key);
    alice
        .compose(
            &scope,
            &fresh,
            "report",
            Some(issue),
            msg.encode(),
            Some(purpose(&scope, "report", &other)),
        )
        .unwrap();
    alice.sync_with(&mut town);
    assert_eq!(town.issues()[&issue].reporters, 2);

    // Bob reports again, signed with his contacts identity. Alice, whom he
    // gave it to, sees he's among the reporters; Carol doesn't. The count
    // doesn't change: he was already counted.
    let bobs = bob.identity("contacts").unwrap();
    alice.add_contact("bob", bobs).unwrap();
    bob.report_as(
        key.clone(),
        "2026-11-24",
        "it's me, Bob",
        None,
        Some("contacts"),
    )
    .unwrap();
    bob.sync_with(&mut town);
    alice.sync_with(&mut town);
    carol.sync_with(&mut town);
    assert_eq!(alice.issues()[&issue].known_by, vec!["bob".to_string()]);
    assert!(carol.issues()[&issue].known_by.is_empty());
    assert_eq!(
        carol.issues()[&issue].identified.len(),
        1,
        "carol sees one identified, unnamed reporter"
    );
    assert_eq!(alice.issues()[&issue].reporters, 2);

    // Clearing counts each person once. Two clearings have the same
    // content and different names.
    dave.sync_with(&mut town);
    dave.clear_issue(&issue).unwrap();
    dave.sync_with(&mut town);
    dave.clear_issue(&issue).unwrap();
    dave.sync_with(&mut town);
    let clearings: BTreeSet<Hash> = taken(&dave).iter().map(|s| s.name()).collect();
    assert_eq!(clearings.len(), 2);
    assert_eq!(town.issues()[&issue].cleared, 1);

    // A malicious report: Carol invents one, the moderator rules it, and
    // it stops counting. Carol had asked for two tokens for that key.
    let fake = IssueKey {
        category: "sidewalk blocked".into(),
        cell: cell(36.17, -86.79, CELL_PRECISION),
        opened: "2026-11-24".into(),
    };
    let ck = carol.view.scheme().credential(&carol.key);
    let fake_purpose = purpose(&scope, "report", &fake.id());
    let req = carol
        .token_request(
            &town.token_terms().unwrap(),
            &[ck.clone(), ck.clone()],
            Some(fake_purpose),
        )
        .unwrap();
    carol.take_grant(town.answer_tokens(&req).unwrap()).unwrap();
    let made_up = ReportMsg::Report {
        key: fake.clone(),
        observed: "2026-11-24".into(),
        note: "made up".into(),
        photo: None,
    };
    carol
        .compose(
            &scope,
            &ck,
            "report",
            Some(fake.id()),
            made_up.encode(),
            Some(fake_purpose),
        )
        .unwrap();
    let s = carol.sync_with(&mut town);
    assert_eq!(
        (s.sent, s.refused.len()),
        (1, 0),
        "no new request: she held a tagged token"
    );
    let fake_issue = fake.id();
    assert_eq!(town.issues()[&fake_issue].reporters, 1);
    let fake_report = town.reports_on(&fake_issue)[0];
    town.rule(fake_report, true).unwrap();
    let i = &town.issues()[&fake_issue];
    assert_eq!((i.reporters, i.discounted), (0, 1));

    // A wallet that ignores the ruling and asks on the terms from before it
    // is refused by the mint.
    let before = pave_board::bulletin::TokenTerms {
        ruled: vec![],
        ..town.token_terms().unwrap()
    };
    let fresh_c = carol.view.scheme().credential(&carol.key);
    let stale_req = carol
        .token_request(&before, std::slice::from_ref(&fresh_c), None)
        .unwrap();
    assert!(town
        .answer_tokens(&stale_req)
        .unwrap_err()
        .contains("ruled"));
    // The ruling puts her tag on the mint's list: she can't get tokens any
    // more, for anything, since she can't show standing against it, and
    // nothing about that says who she is.
    carol.sync_with(&mut town);
    carol
        .report(key.clone(), "2026-11-25", "still blocked", None)
        .unwrap();
    let s = carol.sync_with(&mut town);
    assert!(s.refused.iter().any(|e| e.contains("ruled")), "{s:?}");
    // At the next roll its ticket group is revoked, which stops the other
    // token she already held.
    let group = town.copy(&scope).unwrap().group(&fake_report).unwrap();
    tick(
        &mut town,
        &mut [&mut alice, &mut bob, &mut carol, &mut dave],
    );
    assert!(town.operator.as_ref().unwrap().revoked.contains_key(&group));
    carol
        .compose(
            &scope,
            &ck,
            "report",
            Some(fake.id()),
            made_up.encode(),
            Some(fake_purpose),
        )
        .unwrap();
    let s = carol.sync_with(&mut town);
    assert!(s.refused.iter().any(|e| e.contains("Revoked")), "{s:?}");
    assert_eq!(town.issues()[&issue].reporters, 2);
    // Everyone else still can.
    bob.sync_with(&mut town);
    bob.report(
        fake.clone(),
        "2026-11-25",
        "I don't see anything here",
        None,
    )
    .unwrap();
    bob.sync_with(&mut town);
    assert_eq!(
        town.issues()[&fake_issue].reporters,
        1,
        "bob's report counts"
    );

    // Any copy can serve readers, and a reader checks everything it gets:
    // Dave fetches from Bob's copy and sees the same board.
    let scope = dave.town.reports.scope;
    let posts = bob.posts_since(&scope, &dave.board_have(&scope));
    dave.absorb_posts(&scope, &posts);
    assert_eq!(
        dave.issues()[&issue].reporters,
        town.issues()[&issue].reporters
    );
    // A copy can serve the board but can't add to it: a validly signed post
    // the server never took has no retire, and readers drop it.
    assert_eq!(dave.absorb_posts(&scope, std::slice::from_ref(&sub)), 0);
    let mut stolen = sub.clone();
    stolen.taken = town.copy(&scope).unwrap().submissions()[0].taken.clone();
    assert_eq!(
        dave.absorb_posts(&scope, &[stolen]),
        0,
        "nor with another post's retire"
    );

    // A counted post gets a token tagged for its purpose even if its key
    // already holds an untagged one, so it counts.
    let third = IssueKey {
        category: "streetlight out".into(),
        cell: cell(36.15, -86.78, CELL_PRECISION),
        opened: "2026-11-25".into(),
    };
    let dk = dave.view.scheme().credential(&dave.key);
    let req = dave
        .token_request(
            &town.token_terms().unwrap(),
            std::slice::from_ref(&dk),
            None,
        )
        .unwrap();
    dave.take_grant(town.answer_tokens(&req).unwrap()).unwrap();
    let out = ReportMsg::Report {
        key: third.clone(),
        observed: "2026-11-25".into(),
        note: "dark all night".into(),
        photo: None,
    };
    dave.compose(
        &scope,
        &dk,
        "report",
        Some(third.id()),
        out.encode(),
        Some(purpose(&scope, "report", &third.id())),
    )
    .unwrap();
    dave.sync_with(&mut town);
    assert_eq!(town.issues()[&third.id()].reporters, 1);

    // Token requests aren't refused for a count. A wallet's first
    // TOKEN_SLOTS requests in an epoch can't be linked to each other; each
    // one after reuses a slot, so the mint sees it is the same holder as an
    // earlier request, still without knowing who.
    let mut fay = join(&mut town, "fay", "hardware", &dir);
    let terms = town.token_terms().unwrap();
    let linked = |t: &Node| t.operator.as_ref().unwrap().tokens.linked();
    let before = linked(&town);
    for _ in 0..pave_board::bulletin::TOKEN_SLOTS {
        let c = erin_key(&fay);
        let req = fay.token_request(&terms, &[c], None).unwrap();
        town.answer_tokens(&req).unwrap();
    }
    assert_eq!(linked(&town), before, "within the slots: unlinked");
    let c = erin_key(&fay);
    let req = fay.token_request(&terms, &[c], None).unwrap();
    assert_eq!(req.slot, 0);
    town.answer_tokens(&req).unwrap();
    assert_eq!(linked(&town), before + 1, "past them: served, and linked");
    let mut bad = fay.token_request(&terms, &[erin_key(&fay)], None).unwrap();
    bad.slot = pave_board::bulletin::TOKEN_SLOTS;
    assert!(town.answer_tokens(&bad).unwrap_err().contains("slots"));

    // Posts and post tokens never travel between wallets: meeting carries
    // value, epochs and evidence. Alice's bundle leaves out her tokens, and
    // a wallet drops token records slipped into one.
    let mut b = alice.bundle();
    assert!(b.records.iter().all(|r| !alice.post_record(r)));
    let theirs = town.copy(&scope).unwrap().submissions()[0].clone();
    b.records.extend(theirs.provenance.iter().cloned());
    b.records.push(theirs.record.clone());
    let mut erin = join(&mut town, "erin", "hardware", &dir);
    erin.absorb_bundle(&b);
    assert!(erin.view.coin(&theirs.record.output(0)).is_none());
    assert!(erin.issues().is_empty());

    // Saved state keeps the copy.
    alice.save().unwrap();
    let again = Node::load(&alice.path).unwrap();
    assert_eq!(
        again.issues()[&issue].reporters,
        alice.issues()[&issue].reporters
    );
    assert_eq!(taken(&again).len(), taken(&alice).len());
    let _ = std::fs::remove_dir_all(&dir);
}
