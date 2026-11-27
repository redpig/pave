//! Jobs given only to someone known. Replies are anonymous; the replier a
//! poster picks shows its stable pseudonym (its trade key) before the job is
//! given, and for a lifeguard job, the town lifeguard roster's badge on that
//! key. Vouches build one reputation on the key, across jobs and posters,
//! from before it was badged and after.

use pave_board::board::{contractor, BoardMsg, Known, Shown, Status, Trade};
use pave_board::node::{Node, PendingJoin};
use pave_kernel::{Hash, Scheme};

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

fn sync(town: &mut Node, ns: &mut [&mut Node]) {
    for n in ns.iter_mut() {
        n.sync_with(town);
    }
    for n in ns.iter_mut() {
        n.sync_with(town);
    }
}

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle_for(&b.have()), b.bundle_for(&a.have()));
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
}

/// The poster's view of who replied, by reply order.
fn repliers(n: &Node, job: &Hash) -> Vec<pave_kernel::Credential> {
    n.jobs()[job].replies.iter().map(|(c, _)| c.clone()).collect()
}

#[test]
fn lifeguards_are_known_before_the_job() {
    let dir = std::env::temp_dir().join(format!("pave-known-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut pool = join(&mut town, "pool", &dir, &[100]);
    let mut camp = join(&mut town, "camp", &dir, &[100]);
    let mut ana = join(&mut town, "ana", &dir, &[]);
    let mut bea = join(&mut town, "bea", &dir, &[]);

    // First, a job that needs only a stable pseudonym: the camp wants to see
    // who it hires, not a certificate. Ana replies anonymously, then shows
    // her trade key, and the work counts toward it.
    let key = ana.trade_key().unwrap();
    let helper = camp.post_known("Swim lesson helper", 20, Known::Stable).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    ana.reply(helper, "happy to").unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    let w = repliers(&camp, &helper)[0].clone();
    assert!(camp.accept(helper, w.clone()).unwrap_err().contains("must be known"));
    camp.accept_shown(helper, w, ana.show_known(helper).unwrap()).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    ana.done(helper).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    camp.pay_and_vouch(helper, "swim", "patient", None).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana, &mut pool]);
    assert_eq!(pool.reputation(&contractor(&key)).0.get("swim"), Some(&1));

    // The town's lifeguard roster checks certification and age outside
    // pave, and badges that same key as guard-12: her record carries over.
    // Bea isn't certified.
    let d = town.open_dispatch("Lifeguards").unwrap();
    let badge = town.issue_badge(&d.id, "guard-12", &key).unwrap();
    ana.take_badge(&d, badge).unwrap();
    let guard = Known::Badge(d.clone());

    let job = pool.post_known("Lifeguard, Saturday 10-4", 40, guard.clone()).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut bea]);
    assert_eq!(ana.jobs()[&job].known, Some(guard.clone()));
    // Both reply anonymously: nothing in a reply links to a badge.
    bea.reply(job, "free Saturday").unwrap();
    ana.reply(job, "free Saturday").unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut bea]);
    let r = repliers(&pool, &job);
    assert_eq!(r.len(), 2);
    assert!(!r.contains(&key) && pool.jobs()[&job].contractors.is_empty());
    let ana_w = r.iter().find(|c| ana.mine.contains(*c)).unwrap().clone();
    let bea_w = r.iter().find(|c| bea.mine.contains(*c)).unwrap().clone();

    // The pool can't just give it to someone: the job needs a badge.
    assert!(pool.accept(job, bea_w.clone()).unwrap_err().contains("must be known"));
    assert!(bea.show_known(job).unwrap_err().contains("no badge"));
    // Ana's badge, signed for Bea's reply, isn't Bea's; nor is Ana's ticket
    // with Bea's own key signing for her.
    let shown = ana.show_known(job).unwrap();
    assert!(pool.accept_shown(job, bea_w.clone(), shown.clone()).is_err());
    let bea_key = bea.trade_key().unwrap();
    let sig = bea.view.scheme().sign(&bea.key, &bea_key, &pave_board::board::trade_bytes(&job, &bea_w), None);
    let mixed = Shown { ticket: shown.ticket.clone(), trade: Trade { key: bea_key, sig } };
    assert!(pool.accept_shown(job, bea_w.clone(), mixed).is_err());
    // A badge from another roster (the swim club's) isn't a lifeguard badge.
    let club = town.open_dispatch("Swim club").unwrap();
    let bea_key = bea.trade_key().unwrap();
    let other = town.issue_badge(&club.id, "swim-3", &bea_key).unwrap();
    let sig = bea.view.scheme().sign(&bea.key, &bea_key, &pave_board::board::trade_bytes(&job, &bea_w), None);
    let wrong_roster = Shown { ticket: Some(other), trade: Trade { key: bea_key, sig } };
    assert!(pool.accept_shown(job, bea_w.clone(), wrong_roster).is_err());
    pool.accept_shown(job, ana_w.clone(), shown.clone()).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut bea]);
    let j = bea.jobs()[&job].clone();
    assert_eq!((j.status, j.known_as.as_deref()), (Status::Accepted, Some("guard-12")));
    assert_eq!(j.contractors.get(&ana_w), Some(&contractor(&key)), "the work counts toward the badge key");

    // Readers ignore an accept for a badged job without a good badge, even
    // from the poster with a good assignment.
    let job2 = pool.post_known("Lifeguard, Sunday 10-4", 40, guard.clone()).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut bea]);
    bea.reply(job2, "Sunday works").unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut bea]);
    let w2 = repliers(&pool, &job2)[0].clone();
    let j2 = pool.jobs()[&job2].clone();
    let s = pool.view.scheme().clone();
    let state = pave_board::board::job_state(&j2.means);
    let rec = pave_kernel::sign(&s, &pool.key, &j2.poster, pave_kernel::Op::Transfer { state, to: w2.clone(), receipt: pave_board::board::accept_receipt(&job2, &w2) });
    for badge in [None, Some(Box::new(shown.clone()))] {
        let msg = BoardMsg::Accept { job: job2, worker: w2.clone(), assignment: Some(rec.clone()), badge };
        pool.compose(&pool.town.jobs.scope.clone(), &j2.poster, msg.kind(), msg.job(), msg.encode(), None).unwrap();
    }
    sync(&mut town, &mut [&mut pool, &mut bea]);
    assert_eq!(bea.jobs()[&job2].status, Status::Open);

    // Ana works the shift and the pool pays and vouches: the vouch goes to
    // her badge key's thread.
    ana.done(job).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana]);
    pool.pay_and_vouch(job, "lifeguard", "on time, sharp", None).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut camp]);
    assert_eq!(camp.reputation(&contractor(&key)).0.get("lifeguard"), Some(&1));

    // A camp posts another badged job. Ana replies under a fresh key again,
    // shows the same badge, and her reputation grows on the same stable id.
    let job3 = camp.post_known("Lifeguard, swim lessons", 30, guard.clone()).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    ana.reply(job3, "I can").unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    let w3 = repliers(&camp, &job3)[0].clone();
    assert_ne!(w3, ana_w, "replies don't link to each other");
    camp.accept_shown(job3, w3, ana.show_known(job3).unwrap()).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    ana.done(job3).unwrap();
    sync(&mut town, &mut [&mut camp, &mut ana]);
    camp.pay_and_vouch(job3, "lifeguard", "great with kids", None).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana, &mut camp]);
    let rep = pool.reputation(&contractor(&key)).0;
    assert_eq!((rep.get("lifeguard"), rep.get("swim")), (Some(&2), Some(&1)));

    // The roster revokes guard-12: a poster who has heard won't accept her.
    town.revoke_badge(&d.id, "guard-12").unwrap();
    meet(&mut pool, &mut town);
    let job4 = pool.post_known("Lifeguard, next Saturday", 40, guard.clone()).unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana]);
    ana.reply(job4, "again?").unwrap();
    sync(&mut town, &mut [&mut pool, &mut ana]);
    let w4 = repliers(&pool, &job4)[0].clone();
    assert!(pool.accept_shown(job4, w4, ana.show_known(job4).unwrap()).unwrap_err().contains("revoked"));
    let _ = std::fs::remove_dir_all(&dir);
}
