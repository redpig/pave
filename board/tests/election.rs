//! A municipal election: the basename is the election, not the epoch, and
//! the election keeps its own clock. Legal time limits, not system ones.

use pave_board::bulletin::now;
use pave_board::election::{Election, VoterCard};
use pave_board::node::{Node, PendingJoin};
use pave_kernel::{Credential, Scheme};
use std::collections::BTreeMap;

fn join(town: &mut Node, name: &str, dir: &std::path::Path) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", &[]).unwrap();
    Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap()
}

/// Register a voter on a district's roll: the key is made on the voter's side.
fn register(town: &mut Node, e: &Election, district: &str) -> VoterCard {
    let (pending, req) = VoterCard::start();
    let reply = town.register_voter(&e.id, district, &req).unwrap();
    VoterCard::finish(e, district, pending, &reply).unwrap()
}

/// Ask for a vote coin under a fresh key and keep it. Returns the key.
fn collect(town: &mut Node, v: &mut Node, e: &Election, card: &VoterCard) -> Result<Credential, String> {
    let cred = v.view.scheme().credential(&v.key);
    let req = v.vote_request(e, card, &cred);
    let g = town.answer_vote(&req)?;
    v.take_vote(e, &g)?;
    Ok(cred)
}

fn vote(town: &mut Node, v: &mut Node, e: &Election, district: &str, cred: &Credential, choice: &str) -> Result<(), String> {
    let at = town.booth_clock(&e.id)?;
    let sub = v.cast_vote(e, district, cred, choice, &at)?;
    town.accept_vote(&e.id, &sub).map(|_| ())
}

fn votes(t: &BTreeMap<String, pave_board::election::Count>, d: &str, c: &str) -> usize {
    t[d].votes.get(c).copied().unwrap_or(0)
}

#[test]
fn election() {
    let dir = std::env::temp_dir().join(format!("pave-election-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut people: Vec<Node> = ["alice", "bob", "carol", "dave", "erin"].iter().map(|n| join(&mut town, n, &dir)).collect();
    let [alice, bob, carol, dave, erin] = &mut people[..] else { panic!() };

    // A council election: two districts, a legal window of an hour, and no
    // voting again once a vote is cast.
    let t = now();
    let e = town.open_election("council 2026", &["d1", "d2"], &["Ruiz", "Okafor"], t - 60, t + 3600, false).unwrap();
    let (ca, cb, cc, cd) = (register(&mut town, &e, "d1"), register(&mut town, &e, "d1"), register(&mut town, &e, "d2"), register(&mut town, &e, "d1"));

    // Alice, Bob and Carol collect vote coins and vote at their booths.
    let ka = collect(&mut town, alice, &e, &ca).unwrap();
    vote(&mut town, alice, &e, "d1", &ka, "Ruiz").unwrap();
    let kb = collect(&mut town, bob, &e, &cb).unwrap();
    vote(&mut town, bob, &e, "d1", &kb, "Okafor").unwrap();
    let kc = collect(&mut town, carol, &e, &cc).unwrap();
    // A coin is good only at its own district's booth.
    assert!(vote(&mut town, carol, &e, "d1", &kc, "Ruiz").unwrap_err().contains("district"));
    let kc2 = collect(&mut town, carol, &e, &cc).unwrap();
    vote(&mut town, carol, &e, "d2", &kc2, "Ruiz").unwrap();

    // One coin, one vote: the same ballot again is refused, and so is a
    // second coin for a voter who already voted, since this election
    // doesn't allow voting again. The basename links her at the mint.
    let again = town.ballots(&e.id).unwrap().0[0].clone();
    let dup = town.accept_vote(&e.id, &pave_board::bulletin::Submission { taken: None, ..again });
    assert!(dup.unwrap_err().contains("spent"));
    assert!(collect(&mut town, alice, &e, &ca).unwrap_err().contains("already voted"));
    // Someone not on a roll gets nothing: a card for another election's
    // roll doesn't verify here.
    let other = town.open_election("school board 2026", &["d1"], &["Yes", "No"], t - 60, t + 3600, false).unwrap();
    let stranger = register(&mut town, &other, "d1");
    let forged = VoterCard { election: e.id, district: "d1".into(), key: stranger.key.clone() };
    assert!(collect(&mut town, erin, &e, &forged).unwrap_err().contains("roll"));

    // Dave loses his phone before voting. He comes back to the mint inside
    // the window and gets a new coin; the old one's group is revoked on the
    // election's own clock, which ticked once, while the town's epochs didn't
    // move.
    let town_epoch = town.epoch();
    let tick = |n: &Node| pave_protocol::head(&n.view, &e.sequence).unwrap().number;
    let before = tick(&town);
    let lost = dave.view.scheme().credential(&dave.key);
    let old_req = dave.vote_request(&e, &cd, &lost);
    dave.take_vote(&e, &town.answer_vote(&old_req).unwrap()).unwrap();
    let kd = collect(&mut town, dave, &e, &cd).unwrap();
    assert_eq!((tick(&town), town.epoch()), (before + 1, town_epoch));
    // Whoever found the phone can't vote with the old coin...
    assert!(vote(&mut town, dave, &e, "d1", &lost, "Okafor").unwrap_err().contains("Revoked"));
    // ...or replay Dave's old request to revoke his new one.
    assert!(town.answer_vote(&old_req).unwrap_err().contains("old request"));
    vote(&mut town, dave, &e, "d1", &kd, "Ruiz").unwrap();

    // Time limits are legal: when the window closes nobody collects or
    // votes, and when a court extends it, they can again.
    let ce = register(&mut town, &e, "d2");
    town.set_window(&e.id, t - 60, now() - 1).unwrap();
    assert!(collect(&mut town, erin, &e, &ce).unwrap_err().contains("window"));
    town.set_window(&e.id, t - 60, now() + 600).unwrap();
    let ke = collect(&mut town, erin, &e, &ce).unwrap();
    town.set_window(&e.id, t - 60, now() - 1).unwrap();
    assert!(vote(&mut town, erin, &e, "d2", &ke, "Okafor").unwrap_err().contains("window"));
    town.set_window(&e.id, t - 60, now() + 600).unwrap();
    // A ballot signed while the window was open and sent after it closed is
    // refused too: the law's window is when the booth takes it.
    let at = town.booth_clock(&e.id).unwrap();
    let late = erin.cast_vote(&e, "d2", &ke, "Okafor", &at).unwrap();
    town.set_window(&e.id, t - 60, now() - 1).unwrap();
    assert!(town.accept_vote(&e.id, &late).unwrap_err().contains("window"));
    town.set_window(&e.id, t - 60, now() + 600).unwrap();
    town.accept_vote(&e.id, &late).unwrap();

    // Anyone can tally from the published ballots.
    let e = town.election(&e.id).unwrap();
    let (ballots, revoked) = town.ballots(&e.id).unwrap();
    let r = alice.tally(&e, &ballots, &revoked).unwrap();
    assert_eq!((votes(&r, "d1", "Ruiz"), votes(&r, "d1", "Okafor"), votes(&r, "d2", "Ruiz"), votes(&r, "d2", "Okafor")), (2, 1, 1, 1));
    // A ballot's pseudonym is per election: Carol's differs from hers in
    // another election, and no ballot carries a roll credential.
    let nym_in = |e: &Election, n: &Node, card: &VoterCard| {
        let req = n.vote_request(e, card, &n.view.scheme().credential(&n.key));
        pave_scheme_briolette::BrioletteV1 { group_public_key: vec![] }.nym(&req.sig).unwrap()
    };
    let same_key = VoterCard { election: other.id, district: "d1".into(), key: cc.key.clone() };
    assert_ne!(nym_in(&e, carol, &cc), nym_in(&other, carol, &same_key), "the same key, unrelated across elections");
    assert_eq!(nym_in(&e, carol, &cc), nym_in(&e, carol, &cc), "stable for the whole election");

    // ── An election that allows voting again: the later vote counts, so a
    // voter pressed to vote one way can vote again in private.
    let t = now();
    let open = town.open_election("ballot measure", &["d1"], &["Yes", "No"], t - 60, t + 3600, true).unwrap();
    let cf = register(&mut town, &open, "d1");
    let k1 = collect(&mut town, alice, &open, &cf).unwrap();
    vote(&mut town, alice, &open, "d1", &k1, "Yes").unwrap();
    let k2 = collect(&mut town, alice, &open, &cf).unwrap();
    vote(&mut town, alice, &open, "d1", &k2, "No").unwrap();
    let cg = register(&mut town, &open, "d1");
    let kg = collect(&mut town, bob, &open, &cg).unwrap();
    vote(&mut town, bob, &open, "d1", &kg, "Yes").unwrap();
    let (ballots, revoked) = town.ballots(&open.id).unwrap();
    let r = carol.tally(&open, &ballots, &revoked).unwrap();
    assert_eq!((votes(&r, "d1", "Yes"), votes(&r, "d1", "No"), r["d1"].revoked), (1, 1, 1));
    // A reader who never heard the revocation (or a booth that took the
    // first vote before hearing it) still counts Alice once: her newest
    // ticket wins.
    let r = carol.tally(&open, &ballots, &BTreeMap::new()).unwrap();
    assert_eq!((votes(&r, "d1", "Yes"), votes(&r, "d1", "No"), r["d1"].replaced), (1, 1, 1));
    // In whatever order the ballots arrive.
    let reversed: Vec<_> = ballots.iter().rev().cloned().collect();
    let r = carol.tally(&open, &reversed, &BTreeMap::new()).unwrap();
    assert_eq!((votes(&r, "d1", "Yes"), votes(&r, "d1", "No")), (1, 1));
    // A forged ballot doesn't count: changed after the booth took it.
    let mut bad = ballots.clone();
    bad[2].content = b"No".to_vec();
    let r = carol.tally(&open, &bad, &revoked).unwrap();
    assert_eq!(votes(&r, "d1", "Yes") + votes(&r, "d1", "No"), 1);

    // The authority's state survives a restart.
    let again = Node::load(&town.path).unwrap();
    assert_eq!(again.ballots(&open.id).unwrap().0.len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}
