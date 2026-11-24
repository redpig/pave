//! Protocol tests, each mirroring a property or fault in the TLA+ models
//! (CivicSequences, CivicGossip, CivicTiered). See formal/TRACEABILITY.md.

use ed25519_dalek::SigningKey;
use pave_kernel::scheme::DevScheme;
use pave_kernel::*;
use pave_protocol::accept::ancestry;
use pave_protocol::gossip::{self, compressed_frames, decode_frame, PACKET_BYTES};
use pave_protocol::*;
use std::collections::BTreeSet;

struct P {
    key: SigningKey,
    cred: Credential,
}
fn person() -> P {
    let key = DevScheme::keygen();
    let cred = DevScheme.credential(&key);
    P { key, cred }
}

/// One site: a view plus what its wallets know.
#[derive(Clone)]
struct Site {
    view: View<DevScheme>,
    know: Knowledge,
}

struct World {
    root: P,
    clerk_x: P,
    clerk_y: P,
    minter: P,
    seq_x: Hash,
    seq_y: Hash,
    cash_budget: Hash,
    site: Site,
}

fn cash() -> Schema {
    Schema {
        label: "test credit".into(),
        divisible: true,
        soft_expiry: Some(2),
        hard_expiry: Some(4),
        offline_transfers: Some(3),
        max_per_holder: None,
        sequence: None,
    }
}

fn apply(site: &mut Site, rec: &Record) {
    assert_eq!(site.view.apply(rec), Ok(Applied::Accepted), "{:?}", rec.op);
}

fn start_sequence(site: &mut Site, root: &P, clerk: &P, label: &str) -> Hash {
    let auth = site.view.genesis().rooting_capability();
    let issue = sign(&DevScheme, &root.key, &root.cred, Op::IssueBudget { authority: auth, schema: epoch_schema(label), amount: 1, to: clerk.cred.clone() });
    apply(site, &issue);
    let mint = sign(&DevScheme, &clerk.key, &clerk.cred, Op::Mint { budget: issue.output(0), amount: 1, to: clerk.cred.clone(), change_to: clerk.cred.clone() });
    apply(site, &mint);
    mint.output(0)
}

fn world() -> World {
    let (root, clerk_x, clerk_y, minter) = (person(), person(), person(), person());
    let genesis = Genesis { label: "test town".into(), root_rules: ScopeRules::default(), rooting: root.cred.clone() };
    let mut site = Site { view: View::new(DevScheme, genesis), know: Knowledge::default() };
    let seq_x = start_sequence(&mut site, &root, &clerk_x, "x");
    let seq_y = start_sequence(&mut site, &root, &clerk_y, "y");
    let auth = site.view.genesis().rooting_capability();
    let issue = sign(&DevScheme, &root.key, &root.cred, Op::IssueBudget { authority: auth, schema: cash(), amount: 1_000, to: minter.cred.clone() });
    apply(&mut site, &issue);
    World { root, clerk_x, clerk_y, minter, seq_x, seq_y, cash_budget: issue.output(0), site }
}

impl World {
    fn policy(&self) -> Policy {
        Policy::wallet([(self.clerk_x.cred.clone(), self.seq_x), (self.clerk_y.cred.clone(), self.seq_y)].into_iter().collect())
    }
    fn clerk(&self, seq: Hash) -> &P {
        if seq == self.seq_x { &self.clerk_x } else { &self.clerk_y }
    }
    /// A clerk issues `p` a ticket at its sequence's current epoch.
    fn ticket(&mut self, p: &P, seq: Hash, group: u32) {
        let epoch = head(&self.site.view, &seq).unwrap().number;
        let clerk = self.clerk(seq);
        let t = SignedTicket::issue(&DevScheme, &clerk.key, &clerk.cred, Ticket { credential: p.cred.clone(), sequence: seq, epoch, group, max_spend: None });
        assert!(self.site.know.add_ticket(&DevScheme, t));
    }
    fn mint_to(&mut self, p: &P, amount: u64) -> Hash {
        let m = sign(&DevScheme, &self.minter.key, &self.minter.cred, Op::Mint { budget: self.cash_budget, amount, to: p.cred.clone(), change_to: self.minter.cred.clone() });
        apply(&mut self.site, &m);
        self.cash_budget = m.output(1);
        m.output(0)
    }
}

/// Roll a sequence one epoch on `site`, revoking `revoked` groups.
fn roll_on(site: &mut Site, clerk: &P, seq: Hash, revoked: &[u32]) -> Record {
    let h = head(&site.view, &seq).unwrap();
    let coin = site.view.coin(&h.state).unwrap().clone();
    let data = EpochData { sequence: seq, number: h.number + 1, revoked_groups: revoked.iter().copied().collect() };
    let rec = roll(&DevScheme, &clerk.key, &clerk.cred, &coin, &clerk.cred, &data);
    apply(site, &rec);
    assert!(site.know.add_epoch_data(&site.view, data));
    rec
}

fn pay(site: &mut Site, from: &P, state: Hash, to: &P) -> Hash {
    let rec = sign(&DevScheme, &from.key, &from.cred, Op::Transfer { state, to: to.cred.clone(), receipt: Hash([0; 32]) });
    apply(site, &rec);
    rec.output(0)
}

#[test]
fn epochs_roll_and_commit_their_data() {
    let mut w = world();
    assert_eq!(head(&w.site.view, &w.seq_x).unwrap().number, 0);
    roll_on(&mut w.site, &w.clerk_x, w.seq_x, &[]);
    roll_on(&mut w.site, &w.clerk_x, w.seq_x, &[3]);
    let h = head(&w.site.view, &w.seq_x).unwrap();
    assert_eq!(h.number, 2);
    let d = &w.site.know.epoch_data[&h.data.unwrap()];
    assert_eq!((d.number, d.revoked_groups.contains(&3)), (2, true));
    // Data a roll didn't commit to is refused (fault "forge" for epoch data).
    let fake = EpochData { sequence: w.seq_x, number: 2, revoked_groups: BTreeSet::new() };
    assert!(!w.site.know.add_epoch_data(&w.site.view, fake));
}

/// `EpochDetected` / fault `noepochevidence`, and `honestrepeat`: two versions
/// of one epoch are the issuer using one state twice, whether it cheated or
/// restored from a backup.
#[test]
fn epoch_equivocation_is_a_kernel_conflict() {
    let w = world();
    let (mut a, mut b) = (w.site.clone(), w.site.clone());
    roll_on(&mut a, &w.clerk_x, w.seq_x, &[]);
    roll_on(&mut b, &w.clerk_x, w.seq_x, &[9]);
    a.view.merge_from(&b.view);
    assert_eq!(a.view.flagged(), [w.clerk_x.cred.clone()].into_iter().collect());
    assert_eq!(head(&a.view, &w.seq_x).unwrap().number, 1, "first seen wins");
}

/// `HonestAcceptsInDate` / fault `ignoreexpiry`, and the witness: the kernel
/// itself moves an expired coin; honoring expiry is the recipient's policy.
#[test]
fn recipients_honor_soft_expiry_and_the_kernel_doesnt() {
    let mut w = world();
    let (a, b) = (person(), person());
    w.ticket(&a, w.seq_x, 1);
    w.ticket(&b, w.seq_x, 1);
    let coin = w.mint_to(&a, 10);
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &a.cred, &w.policy()), Ok(()));
    roll_on(&mut w.site, &w.clerk_x, w.seq_x, &[]);
    roll_on(&mut w.site, &w.clerk_x, w.seq_x, &[]);
    assert!(matches!(check(&w.site.view, &w.site.know, &coin, &a.cred, &w.policy()), Err(Refusal::Expired { issued: 0, now: 2, .. })));
    let mut lax = w.policy();
    lax.honor_expiry = false;
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &a.cred, &lax), Ok(()));
    pay(&mut w.site, &a, coin, &b); // the kernel moves it anyway
}

/// Fault `latestonly`: a coin's history holds tickets from two clerks that
/// roll at different rates. The newest ticket is in date, an older one from
/// the faster clerk has expired, so the coin is refused.
#[test]
fn every_ticket_is_checked_against_its_own_sequence() {
    let mut w = world();
    let (a, b, c) = (person(), person(), person());
    w.ticket(&a, w.seq_y, 1);
    let coin = w.mint_to(&a, 10);
    roll_on(&mut w.site, &w.clerk_x, w.seq_x, &[]);
    w.ticket(&b, w.seq_x, 1); // newer ticket, from the other clerk
    w.ticket(&c, w.seq_x, 1);
    let coin = pay(&mut w.site, &a, coin, &b);
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &b.cred, &w.policy()), Ok(()));
    roll_on(&mut w.site, &w.clerk_y, w.seq_y, &[]);
    roll_on(&mut w.site, &w.clerk_y, w.seq_y, &[]);
    let r = check(&w.site.view, &w.site.know, &coin, &b.cred, &w.policy());
    assert_eq!(r, Err(Refusal::Expired { credential: a.cred.clone(), issued: 0, now: 2 }));
}

/// Fault `nolimit`.
#[test]
fn transfer_limit_is_honored() {
    let mut w = world();
    let ps: Vec<P> = (0..5).map(|_| person()).collect();
    for p in &ps {
        w.ticket(p, w.seq_x, 1);
    }
    let mut coin = w.mint_to(&ps[0], 10);
    for i in 0..3 {
        assert_eq!(check(&w.site.view, &w.site.know, &coin, &ps[i].cred, &w.policy()), Ok(()));
        coin = pay(&mut w.site, &ps[i], coin, &ps[i + 1]);
    }
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &ps[3].cred, &w.policy()), Err(Refusal::OverTransferLimit));
}

#[test]
fn revoked_groups_are_refused_per_issuer() {
    let mut w = world();
    let a = person();
    w.ticket(&a, w.seq_x, 42);
    let coin = w.mint_to(&a, 10);
    roll_on(&mut w.site, &w.clerk_y, w.seq_y, &[42]); // another issuer's list doesn't apply
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &a.cred, &w.policy()), Ok(()));
    roll_on(&mut w.site, &w.clerk_x, w.seq_x, &[42]);
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &a.cred, &w.policy()), Err(Refusal::Revoked { credential: a.cred.clone(), group: 42 }));
}

/// `HonestNoKnownCheat` / fault `ignoreevidence`.
#[test]
fn known_cheats_are_refused() {
    let mut w = world();
    let (m, a, b) = (person(), person(), person());
    for p in [&m, &a, &b] {
        w.ticket(p, w.seq_x, 1);
    }
    let coin = w.mint_to(&m, 10);
    let coin2 = w.mint_to(&m, 5);
    let (mut s1, mut s2) = (w.site.clone(), w.site.clone());
    pay(&mut s1, &m, coin, &a);
    pay(&mut s2, &m, coin, &b);
    s1.view.merge_from(&s2.view);
    assert_eq!(check(&s1.view, &s1.know, &coin2, &m.cred, &w.policy()), Err(Refusal::KnownCheat));
}

/// Fault `forge` for tickets: untrusted clerks and tampered tickets.
#[test]
fn tickets_must_come_from_a_trusted_clerk() {
    let mut w = world();
    let (a, rogue) = (person(), person());
    let coin = w.mint_to(&a, 10);
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &a.cred, &w.policy()), Err(Refusal::NoTicket(a.cred.clone())));
    let t = SignedTicket::issue(&DevScheme, &rogue.key, &rogue.cred, Ticket { credential: a.cred.clone(), sequence: w.seq_x, epoch: 0, group: 1, max_spend: None });
    w.site.know.add_ticket(&DevScheme, t.clone());
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &a.cred, &w.policy()), Err(Refusal::UntrustedClerk(rogue.cred.clone())));
    let mut tampered = SignedTicket::issue(&DevScheme, &w.clerk_x.key, &w.clerk_x.cred, t.ticket.clone());
    tampered.ticket.epoch = 99;
    assert!(!w.site.know.add_ticket(&DevScheme, tampered));
}

#[test]
fn compressed_frames_fit_a_packet() {
    let w = world();
    let mut hints: Vec<Hint> = (0..6u8).map(|i| Hint::head(&Hash([i; 32]), 7, &Hash([i + 1; 32]))).collect();
    hints.extend((0..3u8).map(|i| Hint::fork(&Hash([100 + i; 32]))));
    let frames = compressed_frames(&hints);
    assert_eq!(frames.len(), 1, "6 heads and 3 fork hints fit one packet");
    assert!(frames.iter().all(|f| f.len() <= PACKET_BYTES));
    let back: Vec<Hint> = frames.iter().flat_map(|f| decode_frame(f).unwrap()).collect();
    assert_eq!(back, hints);
    let _ = w;
}

/// `KnownIsSigned` / fault `hintepoch`: a false head hint triggers a request,
/// nobody can prove it, and the known epoch never moves.
#[test]
fn false_head_hints_never_advance_an_epoch() {
    let mut w = world();
    let a = person();
    w.ticket(&a, w.seq_x, 1);
    let coin = w.mint_to(&a, 10);
    let relies: BTreeSet<Hash> = [w.seq_x, w.seq_y].into_iter().collect();
    let peer = w.site.clone();
    let mut me = w.site.clone();
    gossip::absorb_hints(&mut me.know, &[Hint::head(&w.seq_x, 99, &Hash([7; 32]))]);
    let wants = gossip::wants(&me.view, &me.know, &relies, &BTreeSet::new());
    assert_eq!(wants.len(), 1);
    let proofs = gossip::serve(&peer.view, &peer.know, &relies, &wants);
    assert!(proofs.is_empty());
    gossip::absorb(&mut me.view, &mut me.know, proofs);
    assert_eq!(head(&me.view, &w.seq_x).unwrap().number, 0);
    assert_eq!(check(&me.view, &me.know, &coin, &a.cred, &w.policy()), Ok(()));
}

/// Fault `trusthint`, and the witness `NoFalseHintDelay`: a false fork hint
/// flags no one; it can only hold off one coin for a recipient who waits.
#[test]
fn false_fork_hints_only_delay() {
    let mut w = world();
    let (a, b) = (person(), person());
    w.ticket(&a, w.seq_x, 1);
    w.ticket(&b, w.seq_x, 1);
    let coin = w.mint_to(&a, 10);
    let coin = pay(&mut w.site, &a, coin, &b);
    let ancestor = *ancestry(&w.site.view, &coin).iter().find(|s| **s != coin).unwrap();
    gossip::absorb_hints(&mut w.site.know, &[Hint::fork(&ancestor)]);
    assert!(w.site.view.flagged().is_empty());
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &b.cred, &w.policy()), Ok(()));
    let mut careful = w.policy();
    careful.wait_on_hints = true;
    assert_eq!(check(&w.site.view, &w.site.know, &coin, &b.cred, &careful), Err(Refusal::HintPending(ancestor)));
}

/// `HintsSuffice` / fault `notrigger`: evidence and a newer epoch at A reach C
/// through B, who relays only hints. C's wants go unanswered by B and are
/// answered by A, after which C holds the same proofs A does.
#[test]
fn hints_suffice_across_a_relay() {
    let mut w = world();
    let (m, a, b) = (person(), person(), person());
    for p in [&m, &a, &b] {
        w.ticket(p, w.seq_x, 1);
    }
    let coin = w.mint_to(&m, 10);
    let base = w.site.clone();
    let (mut site_a, mut fork) = (base.clone(), base.clone());
    pay(&mut site_a, &m, coin, &a);
    pay(&mut fork, &m, coin, &b);
    site_a.view.merge_from(&fork.view);
    roll_on(&mut site_a, &w.clerk_x, w.seq_x, &[1]);
    let (mut site_b, mut site_c) = (base.clone(), base.clone());

    let relies: BTreeSet<Hash> = [w.seq_x].into_iter().collect();
    // Compressed: A -> B -> C.
    let ha = gossip::hints(&site_a.view, &site_a.know, &relies);
    gossip::absorb_hints(&mut site_b.know, &ha);
    let hb = gossip::hints(&site_b.view, &site_b.know, &relies);
    gossip::absorb_hints(&mut site_c.know, &hb);

    // C holds the forked coin's ancestor? It watches m's coin state.
    let watch: BTreeSet<Hash> = [coin].into_iter().collect();
    let wants = gossip::wants(&site_c.view, &site_c.know, &relies, &watch);
    assert_eq!(wants.len(), 2, "one for the epoch, one for the evidence");
    assert!(gossip::serve(&site_b.view, &site_b.know, &relies, &wants).is_empty(), "B can't prove a hint");
    let proofs = gossip::serve(&site_a.view, &site_a.know, &relies, &wants);
    // Fault `gossiprecords`: the only records served are epoch rolls.
    for p in &proofs {
        if let Proof::Records(recs) = p {
            for r in recs {
                assert!(matches!(r.op, Op::Transfer { .. }));
                assert_eq!(r.signer, w.clerk_x.cred, "only the clerk's epoch rolls travel");
            }
        }
    }
    println!("extended proofs: {} B", gossip::proof_bytes(&proofs));
    gossip::absorb(&mut site_c.view, &mut site_c.know, proofs);

    assert_eq!(site_c.view.flagged(), site_a.view.flagged());
    assert_eq!(head(&site_c.view, &w.seq_x), head(&site_a.view, &w.seq_x));
    // C now refuses a's ticket group as A's epoch revoked it.
    assert!(gossip::wants(&site_c.view, &site_c.know, &relies, &watch).is_empty(), "quiet once proofs arrive");
    let _ = (&w.root, &w.minter);
}

/// Fault `nostanding`: once a recipient knows of a cheat, a sender must show
/// it isn't one. Honest senders can; the cheat can't, under any credential.
/// (Unlinkable credentials, where this matters most, are exercised with
/// Briolette ECDAA in the board tests.)
#[test]
fn senders_show_standing_once_cheats_are_known() {
    let mut w = world();
    let (m, a, b, h) = (person(), person(), person(), person());
    for p in [&m, &a, &b, &h] {
        w.ticket(p, w.seq_x, 1);
    }
    let coin = w.mint_to(&m, 10);
    let honest_coin = w.mint_to(&h, 7);
    let mut site = w.site.clone();
    // No cheats known: no proof needed.
    let to_a = pay(&mut site, &h, honest_coin, &a);
    assert_eq!(check(&site.view, &site.know, &to_a, &h.cred, &w.policy()), Ok(()));

    let (mut s1, mut s2) = (site.clone(), site.clone());
    pay(&mut s1, &m, coin, &a);
    pay(&mut s2, &m, coin, &b);
    s1.view.merge_from(&s2.view);
    let list = cheat_list(&s1.view);
    assert_eq!(list.len(), 1);

    // Now the honest sender needs standing, and has it.
    let policy = w.policy();
    assert_eq!(check(&s1.view, &s1.know, &to_a, &h.cred, &policy), Err(Refusal::NoStanding(h.cred.clone())));
    let st = Standing::prove(&DevScheme, &h.key, &h.cred, &list).unwrap();
    assert!(s1.know.add_standing(&DevScheme, st.clone()));
    assert!(!s1.know.add_standing(&DevScheme, st), "no gain, not replaced");
    assert_eq!(check(&s1.view, &s1.know, &to_a, &h.cred, &policy), Ok(()));

    // The cheat can't prove it, and a forged one doesn't verify.
    assert!(Standing::prove(&DevScheme, &m.key, &m.cred, &list).is_none());
    let forged = Standing { credential: m.cred.clone(), cheats: list.clone(), proof: vec![] };
    assert!(!s1.know.add_standing(&DevScheme, forged));

    // A standing that predates a newer cheat doesn't cover it.
    let (m2, c) = (person(), person());
    w.ticket(&m2, w.seq_x, 1);
    w.ticket(&c, w.seq_x, 1);
    let coin3 = w.mint_to(&m2, 3);
    let mut s3 = s1.clone();
    s3.view.merge_from(&w.site.view);
    let (mut s4, mut s5) = (s3.clone(), s3.clone());
    pay(&mut s4, &m2, coin3, &a);
    pay(&mut s5, &m2, coin3, &c);
    s4.view.merge_from(&s5.view);
    assert_eq!(check(&s4.view, &s4.know, &to_a, &h.cred, &policy), Err(Refusal::NoStanding(h.cred.clone())));

    // Mutation `nostanding`: without the rule the old standing is never asked for.
    let lax = Policy { require_standing: false, ..policy };
    assert_eq!(check(&s4.view, &s4.know, &to_a, &h.cred, &lax), Ok(()));
}

/// Fault `nocap`: a ticket's `max_spend` bounds what one coin may carry to or
/// from it.
#[test]
fn ticket_caps_are_honored() {
    let mut w = world();
    let (m, a, small) = (person(), person(), person());
    w.ticket(&m, w.seq_x, 1);
    w.ticket(&a, w.seq_x, 1);
    let epoch = head(&w.site.view, &w.seq_x).unwrap().number;
    let t = SignedTicket::issue(&DevScheme, &w.clerk_x.key, &w.clerk_x.cred, Ticket { credential: small.cred.clone(), sequence: w.seq_x, epoch, group: 2, max_spend: Some(50) });
    assert!(w.site.know.add_ticket(&DevScheme, t));
    let big = w.mint_to(&m, 80);
    let ok = w.mint_to(&m, 40);
    let policy = w.policy();
    let mut site = w.site.clone();
    let to_small = pay(&mut site, &m, big, &small);
    assert_eq!(check(&site.view, &site.know, &to_small, &m.cred, &policy), Err(Refusal::OverMaxSpend { credential: small.cred.clone(), amount: 80, max: 50 }));
    let fine = pay(&mut site, &m, ok, &small);
    assert_eq!(check(&site.view, &site.know, &fine, &m.cred, &policy), Ok(()));
    // And from it: the capped holder can't pass on more than its cap.
    let onward = pay(&mut site, &small, to_small, &a);
    assert!(matches!(check(&site.view, &site.know, &onward, &small.cred, &policy), Err(Refusal::OverMaxSpend { .. })));
    let lax = Policy { honor_ticket_caps: false, ..policy };
    assert_eq!(check(&site.view, &site.know, &onward, &small.cred, &lax), Ok(()));
}
