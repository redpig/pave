//! Disputes as jobs on the job board, with appeals and arbiter reputation.
//!
//! - **A dispute is a job.** Anyone may open one about a subject (a parcel,
//!   a job) with a yes-or-no question, a tier, a panel size and the pay per
//!   arbiter. Pay may be zero: volunteers moderate too.
//! - **Arbiters offer.** An arbiter replies to the dispute under its trade
//!   key, as a contractor replies to a job. Any wallet can arbitrate,
//!   including one an AI agent drives; a panel of agents is just a panel.
//! - **Neither party picks the panel.** Once the offer window closes, the
//!   panel is the eligible offers with the lowest hash of (dispute,
//!   contractor). Eligible means not having ruled earlier on the subject,
//!   and enough reputation for the tier.
//! - **Rulings.** Each panelist answers yes, no, or refer: hand the matter
//!   to an outside authority, such as small claims court. A majority of the
//!   panel decides.
//! - **Appeals.** Anyone may dispute a decided dispute, and pays for it:
//!   one tier up, at least two more panelists, at least double the pay per
//!   arbiter. The highest decided tier is final. A referral is final too:
//!   pave holds the subject and the outside result is the outside's.
//! - **Reputation.** An arbiter scores +1 for every ruling that agrees with
//!   the final outcome and -1 for every one overturned. Tier t needs a score
//!   of at least t - 1, so reputation is what gets an arbiter onto better
//!   paid panels. A dispute's eligibility counts only disputes opened
//!   before it, so nothing about a dispute shapes its own panel.
//! - **Sides and records.** A dispute says what its filer claims (yes or
//!   no) and may name its counterparty, a contractor. Then the filer
//!   endorses it with the counterparty as basename: one pseudonym per
//!   person per counterparty, so a provider sees each filer's record with
//!   it ("filed 5, lost 5") without learning who they are, and the
//!   counterparty's own record counts distinct people.
//! - **Escrow.** An appeal with pay is paid upfront: a deposit to the
//!   town's escrow credential, whose receipt commits to the appeal's terms.
//!   Once the appeal is decided or lapses, the town pays each panelist who
//!   ruled and refunds the rest, by retiring the deposit and minting.
//! - **First rounds.** The side the filer disputes may fund a first round
//!   upfront, into the same escrow; the rest comes back to the funder.
//! - **Terms for filers.** A counterparty may publish terms, signed by its
//!   trade key: from filers who have lost to it at least so many times, a
//!   deposit. A first-round filing that meets the terms and lacks the
//!   deposit is ignored. Once the chain is settled, the deposit goes back
//!   to the filer if it won, and to the counterparty if it lost.
//! - **Who owes whom.** [`liability`] works out loser-pays for a subject
//!   once it is final: the losing side owes what the winning side paid,
//!   capped at the first round's cost if the loser never escalated. It is
//!   computed, not enforced. See the example in spec/disputes.md.

use crate::board::{contractor, trade_bytes, BoardMsg};
use crate::bulletin::{endorser, Copy};
use crate::node::{apply_ok, Class, Node};
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Op, Record, Scheme};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Epochs after a dispute opens during which arbiters may offer.
pub const OFFER_EPOCHS: u32 = 1;

/// Epochs after a dispute is decided during which it may be appealed. After
/// that, with nothing open, its chain is settled.
pub const APPEAL_EPOCHS: u32 = 2;

/// Epochs after the offer window a panel has to decide. A dispute nobody
/// staffs, or a panel that doesn't decide, lapses: it holds nothing.
pub const RULING_EPOCHS: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Answer {
    Yes,
    No,
    /// Hand it to an outside authority, named here.
    Refer(String),
}

impl Answer {
    /// Referrals agree with each other whatever authority they name.
    fn class(&self) -> u8 {
        match self {
            Answer::Yes => 0,
            Answer::No => 1,
            Answer::Refer(_) => 2,
        }
    }
}

/// The score an arbiter needs for a tier.
pub fn min_score(tier: u32) -> i64 {
    tier as i64 - 1
}

pub fn pay_receipt(dispute: &Hash, arbiter: &Hash) -> Hash {
    hash_of("pave/dispute/pay", &(dispute, arbiter))
}

/// The receipt an appeal's escrow deposit commits to: its terms.
pub fn escrow_receipt(subject: &Hash, tier: u32, panel: u32, pay_each: u64, appeal_of: &Option<Hash>) -> Hash {
    hash_of("pave/dispute/escrow", &(subject, tier, panel, pay_each, appeal_of))
}

pub fn filer_deposit_receipt(subject: &Hash, against: &Hash, amount: u64) -> Hash {
    hash_of("pave/dispute/filer-deposit", &(subject, against, amount))
}

pub fn terms_bytes(min_losses: u32, deposit: u64, pay_to: &Credential) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/dispute/terms/v0", min_losses, deposit, pay_to))
}

/// A counterparty's terms for filers against it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    /// Filers with at least this many losses against it owe a deposit.
    pub min_losses: u32,
    pub deposit: u64,
    /// Where a lost deposit goes.
    pub pay_to: Credential,
}

/// Whether an appeal escalates enough over the dispute it appeals.
pub fn escalates(prior: &Dispute, subject: &Hash, tier: u32, panel: u32, pay_each: u64) -> bool {
    prior.subject == *subject && prior.outcome.is_some() && !matches!(prior.outcome, Some(Answer::Refer(_))) && tier == prior.tier + 1 && panel >= prior.panel_size + 2 && pay_each >= prior.pay_each.saturating_mul(2)
}

/// What a filing says. See [`Node::open_dispute`].
#[derive(Clone, Debug)]
pub struct Filing {
    pub subject: Hash,
    pub question: String,
    /// The answer the filer argues for.
    pub claim: bool,
    /// The counterparty, a contractor, if any: the filer then endorses the
    /// dispute, and both sides' records count it.
    pub against: Option<Hash>,
    pub panel: u32,
    pub pay_each: u64,
    pub appeal_of: Option<Hash>,
    /// A credential this wallet holds that makes it a party, such as a
    /// parcel's addressee; else a fresh one.
    pub party: Option<Credential>,
}

impl Filing {
    /// A first-round filing: what it's about, the question, the answer the
    /// filer argues for, and the panel and its pay.
    pub fn new(subject: Hash, question: &str, claim: bool, panel: u32, pay_each: u64) -> Self {
        Filing { subject, question: question.into(), claim, against: None, panel, pay_each, appeal_of: None, party: None }
    }
    pub fn against(mut self, contractor: Hash) -> Self {
        self.against = Some(contractor);
        self
    }
    pub fn appeal_of(mut self, dispute: Hash) -> Self {
        self.appeal_of = Some(dispute);
        self
    }
    pub fn party(mut self, cred: Credential) -> Self {
        self.party = Some(cred);
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Dispute {
    pub id: Hash,
    pub subject: Hash,
    pub question: String,
    pub tier: u32,
    pub panel_size: u32,
    pub pay_each: u64,
    pub appeal_of: Option<Hash>,
    pub opener: Credential,
    pub epoch: u32,
    pub claim: bool,
    pub against: Option<Hash>,
    /// The filer's pseudonym with the counterparty, if it endorsed.
    pub filer: Option<Vec<u8>>,
    /// The escrow deposit's state: an appeal's, or a funded first round's.
    pub deposit: Option<Hash>,
    /// Who funded a first round, if it was funded; its refund goes there.
    pub funder: Option<Credential>,
    /// A filer's deposit the counterparty's terms required, and where it
    /// goes if the filer loses.
    pub filer_deposit: Option<(Hash, Credential)>,
    /// The epoch of the ruling that decided it.
    pub decided_at: Option<u32>,
    /// Offers in the window: the offering credential and its contractor.
    pub offers: Vec<(Credential, Hash)>,
    /// Set once the window has closed and enough eligible arbiters offered.
    pub panel: Option<Vec<(Credential, Hash)>>,
    /// Panelists' rulings, by contractor.
    pub rulings: BTreeMap<Hash, Answer>,
    /// The majority answer, once there is one.
    pub outcome: Option<Answer>,
    /// Undecided past its deadline, or never staffed.
    pub lapsed: bool,
}

struct Raw {
    id: Hash,
    epoch: u32,
    opener: Credential,
    subject: Hash,
    question: String,
    tier: u32,
    panel: u32,
    pay_each: u64,
    appeal_of: Option<Hash>,
    claim: bool,
    against: Option<Hash>,
    filer: Option<Vec<u8>>,
    deposit: Option<Hash>,
    filer_deposit: Option<Box<Record>>,
    position: usize,
}

/// Whether `rec` is a deposit to `escrow` of at least `amount` with this
/// receipt, validly signed. Returns the deposit's state.
fn deposit_ok(s: &crate::node::S, rec: &Record, escrow: &Credential, amount: u64, want: &Hash) -> Option<Hash> {
    let (state, outs, receipt) = match &rec.op {
        Op::Transfer { state, receipt, .. } => (state, vec![], receipt),
        Op::Split { state, parts, receipt } => (state, parts.clone(), receipt),
        _ => return None,
    };
    if receipt != want || rec.sigs.len() != 1 || !s.verify(&rec.signer, &rec.op.signing_bytes(), Some(state.as_bytes()), &rec.sigs[0]) {
        return None;
    }
    match &rec.op {
        // A whole-coin transfer: its amount isn't in the record, so only a
        // split, which states amounts, counts as a deposit.
        Op::Transfer { .. } => None,
        _ => outs.iter().position(|(a, to)| to == escrow && *a >= amount).map(|i| rec.output(i as u32)),
    }
}

/// Every dispute on the job board as a copy has it at epoch `now`, and
/// each arbiter's score.
pub fn disputes(copy: &Copy, classes: &BTreeMap<String, Class>, now: u32) -> (BTreeMap<Hash, Dispute>, BTreeMap<Hash, i64>) {
    let s = copy.scheme();
    let escrow = copy.info.role("escrow").cloned();
    let mut used_deposits: BTreeSet<Hash> = BTreeSet::new();
    let mut raws: Vec<Raw> = vec![];
    let mut offers: BTreeMap<Hash, Vec<(Credential, Hash, u32)>> = BTreeMap::new();
    let mut rulings: BTreeMap<Hash, Vec<(Credential, Answer, u32)>> = BTreeMap::new();
    let mut funds: BTreeMap<Hash, Vec<(Credential, Record)>> = BTreeMap::new();
    let mut terms: BTreeMap<Hash, Vec<(usize, Terms)>> = BTreeMap::new();
    for (position, item) in copy.items().into_iter().enumerate() {
        match BoardMsg::decode(item.content) {
            Some(BoardMsg::Terms { min_losses, deposit, pay_to, trade }) if item.post.kind == "terms" && item.post.thread == Some(contractor(&trade.key)) => {
                if s.verify(&trade.key, &terms_bytes(min_losses, deposit, &pay_to), None, &trade.sig) {
                    terms.entry(contractor(&trade.key)).or_default().push((position, Terms { min_losses, deposit, pay_to }));
                }
            }
            Some(BoardMsg::Fund { dispute, deposit }) if item.post.kind == "fund" && item.post.thread == Some(dispute) => {
                funds.entry(dispute).or_default().push((item.signer.clone(), *deposit));
            }
            Some(BoardMsg::Dispute { subject, question, claim, against, tier, panel, pay_each, appeal_of, deposit, filer_deposit }) if item.post.kind == "dispute" && item.post.thread == against => {
                // Naming a counterparty means endorsing: one pseudonym per
                // person per counterparty.
                let filer = match against {
                    Some(_) => match endorser(classes, &copy.info.scope, &item.post) {
                        Some((_, nym)) => Some(nym),
                        None => continue,
                    },
                    None => None,
                };
                // An appeal with pay needs its deposit, used once.
                let deposit = match (&appeal_of, pay_each, &deposit, &escrow) {
                    (None, _, _, _) | (_, 0, _, _) => None,
                    (Some(_), _, Some(rec), Some(esc)) => {
                        let want = escrow_receipt(&subject, tier, panel, pay_each, &appeal_of);
                        match deposit_ok(s, rec, esc, pay_each.saturating_mul(panel as u64), &want) {
                            Some(d) if used_deposits.insert(d) => Some(d),
                            _ => continue,
                        }
                    }
                    _ => continue,
                };
                raws.push(Raw { id: item.id, epoch: item.post.epoch, opener: item.signer.clone(), subject, question, tier, panel, pay_each, appeal_of, claim, against, filer, deposit, filer_deposit, position });
            }
            Some(BoardMsg::Reply { job, trade: Some(t), .. }) if item.post.thread == Some(job) => {
                if s.verify(&t.key, &trade_bytes(&job, item.signer), None, &t.sig) {
                    offers.entry(job).or_default().push((item.signer.clone(), contractor(&t.key), item.post.epoch));
                }
            }
            Some(BoardMsg::Ruling { dispute, answer }) if item.post.kind == "ruling" && item.post.thread == Some(dispute) => {
                rulings.entry(dispute).or_default().push((item.signer.clone(), answer, item.post.epoch));
            }
            _ => {}
        }
    }

    // Disputes in board order; each one's panel counts only those before it.
    let mut out: BTreeMap<Hash, Dispute> = BTreeMap::new();
    let mut order: Vec<Hash> = vec![];
    for r in raws {
        let scores = score(&out, &order);
        // An appeal must follow a decided dispute on the same subject, a
        // tier up, with a bigger panel and at least double the pay.
        // ...within the appeal window after it was decided.
        let valid = match r.appeal_of.and_then(|a| out.get(&a)) {
            None => r.appeal_of.is_none() && r.tier == 0 && r.panel >= 1,
            Some(p) => escalates(p, &r.subject, r.tier, r.panel, r.pay_each) && p.decided_at.is_some_and(|at| r.epoch <= at + APPEAL_EPOCHS),
        };
        if !valid {
            continue;
        }
        // A first round against a counterparty whose terms ask this filer
        // for a deposit needs it.
        let mut filer_deposit = None;
        if let (0, Some(c), Some(nym)) = (r.tier, &r.against, &r.filer) {
            let t = terms.get(c).and_then(|ts| ts.iter().rev().find(|(p, _)| *p < r.position)).map(|(_, t)| t.clone());
            if let Some(t) = t {
                let lost = records(&out, c).0.get(nym).map_or(0, |x| x.lost);
                if lost >= t.min_losses as usize && t.deposit > 0 {
                    let want = filer_deposit_receipt(&r.subject, c, t.deposit);
                    let ok = match (&r.filer_deposit, &escrow) {
                        (Some(rec), Some(esc)) => deposit_ok(s, rec, esc, t.deposit, &want).filter(|d| used_deposits.insert(*d)),
                        _ => None,
                    };
                    match ok {
                        Some(d) => filer_deposit = Some((d, t.pay_to.clone())),
                        None => continue,
                    }
                }
            }
        }
        // A first round may be funded upfront by anyone, normally the side disputed.
        let (mut deposit, mut funder) = (r.deposit, None);
        if r.tier == 0 && r.pay_each > 0 {
            if let Some(esc) = &escrow {
                let want = escrow_receipt(&r.subject, 0, r.panel, r.pay_each, &None);
                for (who, rec) in funds.get(&r.id).into_iter().flatten() {
                    if let Some(d) = deposit_ok(s, rec, esc, r.pay_each.saturating_mul(r.panel as u64), &want).filter(|d| used_deposits.insert(*d)) {
                        deposit = Some(d);
                        funder = Some(who.clone());
                        break;
                    }
                }
            }
        }
        let earlier: BTreeSet<Hash> = order.iter().filter_map(|d| out.get(d)).filter(|d| d.subject == r.subject).flat_map(|d| d.panel.iter().flatten().map(|(_, c)| *c)).collect();
        let window: Vec<(Credential, Hash)> = offers.get(&r.id).into_iter().flatten().filter(|(_, _, e)| *e <= r.epoch + OFFER_EPOCHS).map(|(c, k, _)| (c.clone(), *k)).collect();
        let mut seen = BTreeSet::new();
        let mut eligible: Vec<(Credential, Hash)> = window
            .iter()
            .filter(|(_, k)| !earlier.contains(k) && (r.tier == 0 || scores.get(k).copied().unwrap_or(0) >= min_score(r.tier)))
            .filter(|(_, k)| seen.insert(*k))
            .cloned()
            .collect();
        eligible.sort_by_key(|(_, k)| hash_of("pave/dispute/draw", &(r.id, k)));
        let panel = (now > r.epoch + OFFER_EPOCHS && eligible.len() >= r.panel as usize).then(|| eligible[..r.panel as usize].to_vec());
        let mut by: BTreeMap<Hash, Answer> = BTreeMap::new();
        let mut decided_at = None;
        if let Some(p) = &panel {
            for (cred, answer, at) in rulings.get(&r.id).into_iter().flatten() {
                if let Some((_, k)) = p.iter().find(|(c, _)| c == cred) {
                    by.entry(*k).or_insert_with(|| answer.clone());
                    if decided_at.is_none() && majority(&by, r.panel).is_some() {
                        decided_at = Some(*at);
                    }
                }
            }
        }
        let outcome = majority(&by, r.panel);
        let lapsed = outcome.is_none() && (now > r.epoch + OFFER_EPOCHS + RULING_EPOCHS || (now > r.epoch + OFFER_EPOCHS && panel.is_none()));
        order.push(r.id);
        out.insert(r.id, Dispute {
            id: r.id,
            subject: r.subject,
            question: r.question,
            tier: r.tier,
            panel_size: r.panel,
            pay_each: r.pay_each,
            appeal_of: r.appeal_of,
            opener: r.opener,
            epoch: r.epoch,
            claim: r.claim,
            against: r.against,
            filer: r.filer,
            deposit,
            funder,
            filer_deposit,
            decided_at,
            offers: window,
            panel,
            rulings: by,
            outcome,
            lapsed,
        });
    }
    let scores = score(&out, &order);
    (out, scores)
}

fn majority(by: &BTreeMap<Hash, Answer>, panel: u32) -> Option<Answer> {
    let mut counts: BTreeMap<u8, (usize, Answer)> = BTreeMap::new();
    for a in by.values() {
        counts.entry(a.class()).or_insert((0, a.clone())).0 += 1;
    }
    counts.into_values().find(|(n, _)| *n * 2 > panel as usize).map(|(_, a)| a)
}

/// Whether a chain is settled at epoch `now`: nothing in it is still being
/// decided, and its top dispute is past its appeal window (or a referral).
pub fn settled(disputes: &BTreeMap<Hash, Dispute>, root: &Hash, now: u32) -> bool {
    let chain: Vec<&Dispute> = disputes.values().filter(|d| root_of(disputes, d) == *root).collect();
    if chain.iter().any(|d| d.outcome.is_none() && !d.lapsed) {
        return false;
    }
    match chain.iter().filter(|d| d.outcome.is_some()).max_by_key(|d| d.tier) {
        None => true,
        Some(top) => matches!(top.outcome, Some(Answer::Refer(_))) || top.decided_at.is_some_and(|at| now > at + APPEAL_EPOCHS),
    }
}

/// The final outcome on a subject: the decided dispute of the highest tier.
pub fn final_outcome(disputes: &BTreeMap<Hash, Dispute>, subject: &Hash) -> Option<Answer> {
    disputes.values().filter(|d| d.subject == *subject && d.outcome.is_some()).max_by_key(|d| d.tier).and_then(|d| d.outcome.clone())
}

/// Whether a subject has a dispute still open: undecided and not lapsed.
/// A profile decides whose disputes count (a parcel counts its parties').
pub fn open_dispute(disputes: &BTreeMap<Hash, Dispute>, subject: &Hash) -> bool {
    disputes.values().any(|d| d.subject == *subject && d.outcome.is_none() && !d.lapsed)
}

/// A party's dispute record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DisputeRecord {
    pub filed: usize,
    pub won: usize,
    pub lost: usize,
    pub referred: usize,
}

/// The first-round dispute an appeal chain starts from.
pub fn root_of(disputes: &BTreeMap<Hash, Dispute>, d: &Dispute) -> Hash {
    let mut id = d.id;
    while let Some(p) = disputes.get(&id).and_then(|x| x.appeal_of) {
        id = p;
    }
    id
}

/// A chain's final outcome: its decided dispute of the highest tier.
pub fn chain_outcome(disputes: &BTreeMap<Hash, Dispute>, root: &Hash) -> Option<Answer> {
    disputes.values().filter(|d| root_of(disputes, d) == *root && d.outcome.is_some()).max_by_key(|d| d.tier).and_then(|d| d.outcome.clone())
}

/// Whether the filer of `d` won, lost or neither, by its chain's final outcome.
fn result(disputes: &BTreeMap<Hash, Dispute>, d: &Dispute) -> Option<Option<bool>> {
    match chain_outcome(disputes, &root_of(disputes, d))? {
        Answer::Yes => Some(Some(d.claim)),
        Answer::No => Some(Some(!d.claim)),
        Answer::Refer(_) => Some(None),
    }
}

/// Records with a counterparty: each filer's (by its pseudonym with that
/// counterparty) and the counterparty's own, counting distinct filers.
pub fn records(disputes: &BTreeMap<Hash, Dispute>, against: &Hash) -> (BTreeMap<Vec<u8>, DisputeRecord>, DisputeRecord) {
    let mut filers: BTreeMap<Vec<u8>, DisputeRecord> = BTreeMap::new();
    let mut theirs: BTreeMap<Vec<u8>, (bool, bool, bool)> = BTreeMap::new();
    for d in disputes.values().filter(|d| d.against.as_ref() == Some(against)) {
        let Some(nym) = &d.filer else { continue };
        let r = filers.entry(nym.clone()).or_default();
        r.filed += 1;
        let t = theirs.entry(nym.clone()).or_default();
        match result(disputes, d) {
            Some(Some(true)) => {
                r.won += 1;
                t.0 = true;
            }
            Some(Some(false)) => {
                r.lost += 1;
                t.1 = true;
            }
            Some(None) => {
                r.referred += 1;
                t.2 = true;
            }
            None => {}
        }
    }
    // The counterparty lost to each filer who won against it at least once.
    let mut c = DisputeRecord { filed: theirs.len(), ..Default::default() };
    for (won, lost, referred) in theirs.values() {
        c.lost += *won as usize;
        c.won += *lost as usize;
        c.referred += *referred as usize;
    }
    (filers, c)
}

/// Loser-pays for a subject, once final.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Liability {
    /// The losing side's claim.
    pub loser: bool,
    /// What the winning side paid for panels.
    pub paid_by_winner: u64,
    /// What the loser owes the winner: all of it if the loser escalated,
    /// else capped at the first round's cost.
    pub owed: u64,
}

/// Who owes whom on an appeal chain, given its first-round dispute. The
/// first round is funded by the side the filer disputes (its counterparty,
/// such as the provider); each appeal by its appellant. Referrals settle
/// nothing: each side keeps its costs.
pub fn liability(disputes: &BTreeMap<Hash, Dispute>, root: &Hash) -> Option<Liability> {
    let win = match chain_outcome(disputes, root)? {
        Answer::Yes => true,
        Answer::No => false,
        Answer::Refer(_) => return None,
    };
    let chain: Vec<&Dispute> = disputes.values().filter(|d| root_of(disputes, d) == *root && (d.outcome.is_some() || d.lapsed)).collect();
    let cost = |d: &Dispute| d.pay_each.saturating_mul(d.panel_size as u64);
    let mut paid_by_winner = 0u64;
    let mut first = 0u64;
    let mut loser_escalated = false;
    for d in &chain {
        // Who funded this round, by side.
        let payer = if d.tier == 0 { !d.claim } else { d.claim };
        if d.tier == 0 {
            first = cost(d);
        }
        if payer == win {
            paid_by_winner += cost(d);
        } else if d.tier > 0 {
            loser_escalated = true;
        }
    }
    let owed = if loser_escalated { paid_by_winner } else { paid_by_winner.min(first) };
    Some(Liability { loser: !win, paid_by_winner, owed })
}

fn score(out: &BTreeMap<Hash, Dispute>, order: &[Hash]) -> BTreeMap<Hash, i64> {
    let mut scores: BTreeMap<Hash, i64> = BTreeMap::new();
    for d in order.iter().filter_map(|id| out.get(id)) {
        let Some(fin) = chain_outcome(out, &root_of(out, d)) else { continue };
        for (k, a) in &d.rulings {
            *scores.entry(*k).or_default() += if a.class() == fin.class() { 1 } else { -1 };
        }
    }
    scores
}

impl Node {
    /// The job board's disputes now, and each arbiter's score.
    pub fn disputes(&self) -> (BTreeMap<Hash, Dispute>, BTreeMap<Hash, i64>) {
        self.copy(&self.town.jobs.scope).map(|c| disputes(c, &self.town.classes, self.epoch())).unwrap_or_default()
    }

    /// Open a dispute, or appeal one with `appeal_of`. An appeal must
    /// escalate, and one with pay is paid upfront into escrow. Returns the
    /// dispute's id.
    pub fn open_dispute(&mut self, f: Filing) -> Result<Hash, String> {
        let tier = match f.appeal_of {
            None => 0,
            Some(a) => {
                let ds = self.disputes().0;
                let prior = ds.get(&a).ok_or("unknown dispute to appeal")?;
                if !escalates(prior, &f.subject, prior.tier + 1, f.panel, f.pay_each) {
                    return Err("an appeal needs a decided dispute, two more panelists and at least double the pay".into());
                }
                prior.tier + 1
            }
        };
        let deposit = if f.appeal_of.is_some() && f.pay_each > 0 { Some(Box::new(self.deposit_for(&f.subject, tier, f.panel, f.pay_each, &f.appeal_of)?)) } else { None };
        // If the counterparty's terms ask this wallet for a deposit, pay it.
        // Its record is by its pseudonym, which only an endorsement shows,
        // so pay whenever the terms could apply and losses are on record.
        let filer_deposit = match (tier, f.against) {
            (0, Some(c)) => match self.terms_for(&c) {
                Some(t) if t.deposit > 0 && self.my_losses(&c) >= t.min_losses as usize => Some(Box::new(self.deposit_to_escrow(t.deposit, filer_deposit_receipt(&f.subject, &c, t.deposit))?)),
                _ => None,
            },
            _ => None,
        };
        self.file(f, tier, deposit, filer_deposit)
    }

    /// The latest terms a counterparty has published.
    pub fn terms_for(&self, against: &Hash) -> Option<Terms> {
        let copy = self.copy(&self.town.jobs.scope).ok()?;
        copy.items().into_iter().rev().find_map(|i| match BoardMsg::decode(i.content) {
            Some(BoardMsg::Terms { min_losses, deposit, pay_to, trade }) if contractor(&trade.key) == *against && i.post.thread == Some(*against) && copy.scheme().verify(&trade.key, &terms_bytes(min_losses, deposit, &pay_to), None, &trade.sig) => Some(Terms { min_losses, deposit, pay_to }),
            _ => None,
        })
    }

    /// Counterparty: publish terms for filers against it, under its trade key.
    pub fn publish_terms(&mut self, min_losses: u32, deposit: u64) -> Result<Hash, String> {
        let key = self.trade_key()?;
        let pay_to = self.receive()?;
        let sig = self.view.scheme().sign(&self.key, &key, &terms_bytes(min_losses, deposit, &pay_to), None);
        let me = contractor(&key);
        let msg = BoardMsg::Terms { min_losses, deposit, pay_to, trade: crate::board::Trade { key, sig } };
        let signer = self.fresh()?;
        let scope = self.town.jobs.scope;
        self.compose(&scope, &signer, msg.kind(), Some(me), msg.encode(), None)
    }

    /// How many disputes this wallet has lost against a counterparty, by
    /// its own pseudonym with it.
    pub fn my_losses(&self, against: &Hash) -> usize {
        let ds = self.disputes().0;
        ds.values().filter(|d| d.against.as_ref() == Some(against) && self.mine.contains(&d.opener)).filter(|d| matches!(result(&ds, d), Some(Some(false)))).count()
    }

    /// Fund a first-round dispute upfront, into escrow. Anyone may; normally
    /// it's the side disputed, which funds the first round.
    pub fn fund_dispute(&mut self, dispute: Hash) -> Result<Hash, String> {
        let d = self.disputes().0.remove(&dispute).ok_or("unknown dispute")?;
        if d.tier != 0 || d.pay_each == 0 {
            return Err("only a paid first round is funded".into());
        }
        let rec = self.deposit_to_escrow(d.pay_each.saturating_mul(d.panel_size as u64), escrow_receipt(&d.subject, 0, d.panel_size, d.pay_each, &None))?;
        let msg = BoardMsg::Fund { dispute, deposit: Box::new(rec) };
        let signer = self.fresh()?;
        let scope = self.town.jobs.scope;
        self.compose(&scope, &signer, msg.kind(), Some(dispute), msg.encode(), None)
    }

    /// Post a filing as given, without checking it escalates.
    pub fn file(&mut self, f: Filing, tier: u32, deposit: Option<Box<Record>>, filer_deposit: Option<Box<Record>>) -> Result<Hash, String> {
        let me = match f.party {
            Some(c) if self.mine.contains(&c) => c,
            Some(_) => return Err("this wallet doesn't hold that credential".into()),
            None => self.fresh()?,
        };
        let msg = BoardMsg::Dispute { subject: f.subject, question: f.question, claim: f.claim, against: f.against, tier, panel: f.panel, pay_each: f.pay_each, appeal_of: f.appeal_of, deposit, filer_deposit };
        let scope = self.town.jobs.scope;
        let endorse: Option<&[crate::bulletin::Cheat]> = if f.against.is_some() { Some(&[]) } else { None };
        self.compose(&scope, &me, msg.kind(), f.against, msg.encode(), endorse)
    }

    /// Pay an appeal's panel upfront: a split of one coin with
    /// `panel * pay_each` to the town's escrow credential, its receipt
    /// committing to the appeal's terms.
    pub fn deposit_for(&mut self, subject: &Hash, tier: u32, panel: u32, pay_each: u64, appeal_of: &Option<Hash>) -> Result<Record, String> {
        self.deposit_to_escrow(pay_each.saturating_mul(panel as u64), escrow_receipt(subject, tier, panel, pay_each, appeal_of))
    }

    /// Split `amount` off one coin to the town's escrow credential.
    pub fn deposit_to_escrow(&mut self, amount: u64, receipt: Hash) -> Result<Record, String> {
        let escrow = self.town.jobs.role("escrow").ok_or("this town has no escrow")?.clone();
        let coin = self.my_coins().into_iter().find(|c| c.amount > amount).ok_or("no single coin covers the deposit with change")?;
        let change = self.fresh()?;
        let rec = self.signed(&coin.holder, Op::Split { state: coin.state, parts: vec![(amount, escrow), (coin.amount - amount, change)], receipt })?;
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec)
    }

    /// Town: release what a dispute holds in escrow. A panel deposit, once
    /// the dispute is decided or lapses: each panelist who ruled gets its
    /// pay, and whoever paid in (the appellant or the funder) the rest. A
    /// filer's deposit, once the chain is settled: back to the filer if it
    /// won or nothing was decided, else to the counterparty. Deposits must
    /// have reached the town's view. Returns the coins minted.
    pub fn release_escrow(&mut self, dispute: Hash) -> Result<Vec<Hash>, String> {
        let (ds, _) = self.disputes();
        let d = ds.get(&dispute).ok_or("unknown dispute")?.clone();
        let now = self.epoch();
        let mut pays: Vec<(Credential, u64)> = vec![];
        let mut retire: Vec<Hash> = vec![];
        if let Some(state) = d.deposit.filter(|s| self.view.coin(s).is_some()) {
            if d.outcome.is_some() || d.lapsed {
                let amount = self.view.coin(&state).unwrap().amount;
                let panel: Vec<(Credential, u64)> = d.panel.clone().unwrap_or_default().into_iter().filter(|(_, k)| d.rulings.contains_key(k)).map(|(c, _)| (c, d.pay_each)).collect();
                let rest = amount - panel.iter().map(|(_, a)| a).sum::<u64>();
                pays.extend(panel);
                if rest > 0 {
                    pays.push((d.funder.clone().unwrap_or(d.opener.clone()), rest));
                }
                retire.push(state);
            }
        }
        if let Some((state, pay_to)) = d.filer_deposit.clone().filter(|(s, _)| self.view.coin(s).is_some()) {
            if settled(&ds, &dispute, now) {
                let amount = self.view.coin(&state).unwrap().amount;
                let lost = matches!((chain_outcome(&ds, &dispute), d.claim), (Some(Answer::Yes), false) | (Some(Answer::No), true));
                pays.push((if lost { pay_to } else { d.opener.clone() }, amount));
                retire.push(state);
            }
        }
        if retire.is_empty() {
            return Err("nothing to release yet (still being decided, already released, or not yet seen here)".into());
        }
        let s = self.view.scheme().clone();
        for state in retire {
            let holder = self.view.coin(&state).unwrap().holder.clone();
            let r = pave_kernel::sign(&s, &self.key, &holder, Op::Retire { state });
            let r = self.guard(r)?;
            apply_ok(&mut self.view, &r)?;
        }
        let mut out = vec![];
        for (to, amount) in pays {
            let op = self.operator.as_ref().ok_or("only the town releases escrow")?;
            let mint = pave_kernel::sign(&s, &op.minter, &op.minter_cred, Op::Mint { budget: op.cash_budget, amount, to, change_to: op.minter_cred.clone() });
            let mint = self.guard(mint)?;
            self.operator.as_mut().unwrap().cash_budget = mint.output(1);
            apply_ok(&mut self.view, &mint)?;
            out.push(mint.output(0));
        }
        self.save()?;
        Ok(out)
    }

    /// Records with a counterparty: each filer's, by pseudonym, and its own.
    pub fn dispute_records(&self, against: &Hash) -> (BTreeMap<Vec<u8>, DisputeRecord>, DisputeRecord) {
        records(&self.disputes().0, against)
    }

    /// Offer to arbitrate a dispute, under this wallet's trade key.
    pub fn offer_to_arbitrate(&mut self, dispute: Hash) -> Result<Hash, String> {
        self.reply_as_contractor(dispute, "")
    }

    /// Rule on a dispute this wallet is a panelist on.
    pub fn arbitrate(&mut self, dispute: Hash, answer: Answer) -> Result<Hash, String> {
        let d = self.disputes().0.remove(&dispute).ok_or("unknown dispute")?;
        let panel = d.panel.ok_or("the panel isn't set yet")?;
        let (cred, _) = panel.into_iter().find(|(c, _)| self.mine.contains(c)).ok_or("this wallet isn't on the panel")?;
        let msg = BoardMsg::Ruling { dispute, answer };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &cred, msg.kind(), Some(dispute), msg.encode(), None)
    }

    /// Pay each panelist who ruled on a first-round dispute, once. Its
    /// funder is the side the filer disputes, such as the provider; appeals
    /// are paid from escrow instead ([`Node::release_escrow`]).
    pub fn pay_arbiters(&mut self, dispute: Hash) -> Result<Vec<Hash>, String> {
        let d = self.disputes().0.remove(&dispute).ok_or("unknown dispute")?;
        if d.deposit.is_some() {
            return Err("this dispute's panel is paid from escrow".into());
        }
        let mut out = vec![];
        for (cred, k) in d.panel.unwrap_or_default() {
            if !d.rulings.contains_key(&k) || d.pay_each == 0 {
                continue;
            }
            let receipt = pay_receipt(&dispute, &k);
            let paid = self.view.records().iter().any(|r| matches!(&r.op, pave_kernel::Op::Transfer { receipt: x, .. } | pave_kernel::Op::Split { receipt: x, .. } if *x == receipt));
            if !paid {
                out.push(self.pay_to(cred, d.pay_each, receipt)?);
            }
        }
        Ok(out)
    }
}
