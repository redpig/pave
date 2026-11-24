//! Vouches: a reputational commitment that rides on a real payment. The
//! vouch coin goes to the contractor with the pay; the vouch is posted in
//! the contractor's thread and counts each person once per job type.

use pave_board::board::{contractor, vouch_receipt, BoardMsg, Status};
use pave_board::node::{Node, PendingJoin};
use pave_kernel::{Hash, Op, Record};

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
}

/// Post, reply, accept and finish a job; return its id once it's Done.
fn job_done(town: &mut Node, poster: &mut Node, worker: &mut Node, title: &str, as_contractor: bool) -> Hash {
    let job = poster.post(title, 10).unwrap();
    poster.sync_with(town);
    worker.sync_with(town);
    if as_contractor {
        worker.reply_as_contractor(job, "can do").unwrap();
    } else {
        worker.reply(job, "can do").unwrap();
    }
    worker.sync_with(town);
    poster.sync_with(town);
    let w = poster.jobs()[&job].replies[0].0.clone();
    poster.accept(job, w).unwrap();
    poster.sync_with(town);
    worker.sync_with(town);
    worker.done(job).unwrap();
    worker.sync_with(town);
    poster.sync_with(town);
    job
}

#[test]
fn vouches() {
    let dir = std::env::temp_dir().join(format!("pave-vouch-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = join(&mut town, "alice", &dir, &[100]);
    let mut carol = join(&mut town, "carol", &dir, &[100]);
    let mut bob = join(&mut town, "bob", &dir, &[]);
    let mut mallory = join(&mut town, "mallory", &dir, &[100]);

    // Bob replies as a contractor; Alice pays and vouches for fencing.
    let job = job_done(&mut town, &mut alice, &mut bob, "Fix the fence", true);
    let who = bob.contractor().unwrap();
    assert_eq!(alice.jobs()[&job].contractors.values().next(), Some(&who));
    alice.pay_and_vouch(job, "fencing", "on time, tidy", Some("neighbors")).unwrap();
    // The pay and the vouch coin go straight to Bob, like any payment.
    meet(&mut alice, &mut bob);
    // Bob now holds the payment record, and tries posting the vouch himself
    // before Alice's arrives. Only the job's poster can vouch.
    let payment = bob.view.records().iter().find(|r| matches!(&r.op, Op::Split { receipt, .. } if *receipt == vouch_receipt(&job, &who, "fencing"))).unwrap().clone();
    let selfie = BoardMsg::Vouch { job, category: "fencing".into(), note: "I'm great".into(), payment, by: None };
    let bk = bob.receive().unwrap();
    bob.compose(&bob.town.jobs.scope.clone(), &bk, selfie.kind(), Some(who), selfie.encode(), Some(&[])).unwrap();
    bob.sync_with(&mut town);
    alice.sync_with(&mut town);
    bob.sync_with(&mut town);
    assert_eq!(bob.jobs()[&job].status, Status::Paid);
    let (counts, vouches) = bob.reputation(&who);
    assert_eq!(counts.get("fencing"), Some(&1));
    let coin = vouches[0].coin;
    assert_eq!(bob.vouch_coins(), vec![coin], "bob holds the vouch coin");
    assert_eq!(bob.view.coin(&coin).unwrap().amount, 0);
    assert_eq!(bob.check(&coin), Ok(()), "it checks like money");
    assert_eq!(bob.my_coins().iter().map(|c| c.amount).sum::<u64>(), 10, "and isn't money");

    // Alice hiring Bob again counts once; Carol hiring him counts too.
    let job2 = job_done(&mut town, &mut alice, &mut bob, "Fix the gate", true);
    alice.pay_and_vouch(job2, "fencing", "again", Some("neighbors")).unwrap();
    alice.sync_with(&mut town);
    let job3 = job_done(&mut town, &mut carol, &mut bob, "New fence", true);
    carol.pay_and_vouch(job3, "fencing", "great", None).unwrap();
    carol.sync_with(&mut town);
    bob.sync_with(&mut town);
    let (counts, vouches) = bob.reputation(&who);
    assert_eq!((counts.get("fencing"), vouches.len()), (Some(&2), 3), "three jobs, two people");

    // Alice vouched with the stable credential she shares with her
    // neighbors; Carol vouched anonymously. Dave was given Alice's: he sees
    // her two vouches as hers. Mallory wasn't: she sees one unnamed person
    // behind both, and can't say who. The counts are the same for everyone.
    let mut dave = join(&mut town, "dave", &dir, &[]);
    let neighbors = alice.stable("neighbors").unwrap();
    dave.add_contact("alice", neighbors.clone()).unwrap();
    dave.sync_with(&mut town);
    mallory.sync_with(&mut town);
    let (dc, dv) = dave.reputation(&who);
    assert_eq!(dv.iter().filter(|v| v.known_by.as_deref() == Some("alice")).count(), 2);
    let (mc, mv) = mallory.reputation(&who);
    assert!(mv.iter().all(|v| v.known_by.is_none()));
    assert_eq!(mv.iter().filter(|v| v.by.as_ref() == Some(&neighbors)).count(), 2, "linkable, not named");
    assert_eq!(mv.iter().filter(|v| v.by.is_none()).count(), 1, "carol's is anonymous");
    assert_eq!(dc, mc);
    // Dave, now holding Alice's stable credential, can't sign as her: he
    // pays for his own job with her credential attached, and it shows as
    // nobody's.
    // (Dave has no credit, so Carol plays him: she knows Alice's credential too.)
    carol.add_contact("alice", neighbors.clone()).unwrap();
    let job8 = job_done(&mut town, &mut carol, &mut bob, "Gate latch", true);
    carol.pay_and_vouch(job8, "fencing", "", Some("mine")).unwrap();
    let q = carol.outgoing.iter().find(|s| s.post().unwrap().kind == "vouch").unwrap().clone();
    carol.refused(&q).unwrap();
    let Some(BoardMsg::Vouch { payment, .. }) = BoardMsg::decode(&q.content) else { panic!() };
    // Copy Alice's own signature and credential from her vouch on the first job.
    let alice_poster = dave.jobs()[&job].poster.clone();
    let t = dave
        .copy(&dave.town.jobs.scope)
        .unwrap()
        .items()
        .into_iter()
        .filter(|i| *i.signer == alice_poster)
        .find_map(|i| match BoardMsg::decode(i.content) {
            Some(BoardMsg::Vouch { job: j, by: Some(t), .. }) if j == job => Some(t),
            _ => None,
        })
        .unwrap();
    assert_eq!(t.key, neighbors);
    let poster = carol.jobs()[&job8].poster.clone();
    let forged = BoardMsg::Vouch { job: job8, category: "fencing".into(), note: "".into(), payment, by: Some(t) };
    carol.compose(&carol.town.jobs.scope.clone(), &poster, forged.kind(), Some(who), forged.encode(), Some(&[])).unwrap();
    carol.sync_with(&mut town);
    dave.sync_with(&mut town);
    let (_, dv) = dave.reputation(&who);
    assert_eq!(dv.iter().filter(|v| v.known_by.as_deref() == Some("alice")).count(), 2, "only Alice can sign as Alice");
    assert_eq!(dv.iter().filter(|v| v.job == job8 && v.by.is_none()).count(), 1, "the vouch still counts, as nobody's");
    // Contacts and stable credentials survive a restart.
    dave.save().unwrap();
    assert_eq!(Node::load(&dave.path).unwrap().reputation(&who).1.iter().filter(|v| v.known_by.is_some()).count(), 2);
    alice.save().unwrap();
    assert_eq!(Node::load(&alice.path).unwrap().stable["neighbors"], neighbors);

    // Vouches can't be had without opting in: a plain reply gets none.
    let job4 = job_done(&mut town, &mut carol, &mut bob, "Paint", false);
    assert!(carol.pay_and_vouch(job4, "painting", "", None).unwrap_err().contains("contractor"));

    // Mallory can't make vouches for Bob that count:
    // - posting one for a job that isn't hers;
    let rec: Record = carol.view.records().iter().find(|r| matches!(&r.op, Op::Split { parts, .. } if parts.len() >= 2 && parts[1].0 == 0 && parts[0].0 == 10)).unwrap().clone();
    let fake = BoardMsg::Vouch { job: job3, category: "plumbing".into(), note: "fake".into(), payment: rec.clone(), by: None };
    let mk = mallory.receive().unwrap();
    mallory.compose(&mallory.town.jobs.scope.clone(), &mk, fake.kind(), Some(who), fake.encode(), Some(&[])).unwrap();
    // - or replaying a real payment under another job type, with the poster's key she doesn't have;
    // - or naming Bob's contractor id in her own reply without his trade key.
    let job5 = mallory.post("Help", 10).unwrap();
    mallory.sync_with(&mut town);
    let mut forged = BoardMsg::Reply { job: job5, note: "it's bob".into(), trade: None };
    if let BoardMsg::Reply { trade, .. } = &mut forged {
        let other = carol.trade_key().unwrap();
        let sig = pave_kernel::Scheme::sign(carol.view.scheme(), &carol.key, &other, b"not the trade bytes", None);
        *trade = Some(pave_board::board::Trade { key: bob.trade_key().unwrap(), sig });
    }
    let mc = mallory.receive().unwrap();
    mallory.compose(&mallory.town.jobs.scope.clone(), &mc, forged.kind(), Some(job5), forged.encode(), None).unwrap();
    mallory.sync_with(&mut town);
    assert!(mallory.jobs()[&job5].contractors.is_empty(), "a trade claim needs the trade key's signature");
    bob.sync_with(&mut town);
    let (counts, vouches) = bob.reputation(&who);
    assert_eq!((counts.get("fencing"), counts.get("plumbing"), vouches.len()), (Some(&2), None, 4));

    // A vouch's payment must commit to its job type: relabeling fails.
    // Carol pays for a new job with a fencing vouch, then swaps her queued
    // vouch for one saying roofing. The payment commits to fencing.
    let job6 = job_done(&mut town, &mut carol, &mut bob, "Fence repair", true);
    carol.pay_and_vouch(job6, "fencing", "", None).unwrap();
    let queued = carol.outgoing.iter().find(|s| s.post().unwrap().kind == "vouch").unwrap().clone();
    carol.refused(&queued).unwrap();
    let Some(BoardMsg::Vouch { payment, .. }) = BoardMsg::decode(&queued.content) else { panic!() };
    let relabeled = BoardMsg::Vouch { job: job6, category: "roofing".into(), note: "".into(), payment, by: None };
    let poster = carol.jobs()[&job6].poster.clone();
    carol.compose(&carol.town.jobs.scope.clone(), &poster, relabeled.kind(), Some(who), relabeled.encode(), Some(&[])).unwrap();
    carol.sync_with(&mut town);
    bob.sync_with(&mut town);
    assert_eq!(bob.reputation(&who).0.get("roofing"), None);

    // Carol hires Mallory, who didn't reply as a contractor, and tries to
    // credit the job to Bob with a payment that names him.
    let scope = carol.town.jobs.scope;
    let job7 = job_done(&mut town, &mut carol, &mut mallory, "Haul", false);
    let j = carol.jobs()[&job7].clone();
    let worker = j.worker.clone().unwrap();
    let c = carol.my_coins()[0].clone();
    let parts = vec![(10, worker.clone()), (0, worker), (c.amount - 10, carol.receive().unwrap())];
    let rec = pave_kernel::sign(carol.view.scheme(), &carol.key, &c.holder, Op::Split { state: c.state, parts, receipt: vouch_receipt(&job7, &who, "fencing") });
    carol.view.apply(&rec).unwrap();
    let paid = BoardMsg::Paid { job: job7, payment: rec.output(0) };
    carol.compose(&scope, &j.poster, paid.kind(), Some(job7), paid.encode(), None).unwrap();
    let v = BoardMsg::Vouch { job: job7, category: "fencing".into(), note: "".into(), payment: rec, by: None };
    carol.compose(&scope, &j.poster, v.kind(), Some(who), v.encode(), Some(&[])).unwrap();
    carol.sync_with(&mut town);
    bob.sync_with(&mut town);
    assert_eq!(bob.jobs()[&job7].status, Status::Paid);
    let (counts, vouches) = bob.reputation(&who);
    assert_eq!((counts.get("fencing"), vouches.len()), (Some(&2), 4), "only the four honest vouches count");

    // Anyone reading the board sees the same reputation, and contractor ids
    // come from trade keys alone.
    mallory.sync_with(&mut town);
    assert_eq!(mallory.reputation(&who).0, bob.reputation(&who).0);
    assert_eq!(contractor(&bob.trade.clone().unwrap()), who);

    // The trade key survives a restart.
    bob.save().unwrap();
    assert_eq!(Node::load(&bob.path).unwrap().contractor(), Some(who));
    let _ = std::fs::remove_dir_all(&dir);
}
