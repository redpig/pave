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

use crate::board::{contractor, trade_bytes, BoardMsg};
use crate::bulletin::Copy;
use crate::node::Node;
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Scheme};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Epochs after a dispute opens during which arbiters may offer.
pub const OFFER_EPOCHS: u32 = 1;

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
}

/// Every dispute on the job board as a copy has it at epoch `now`, and
/// each arbiter's score.
pub fn disputes(copy: &Copy, now: u32) -> (BTreeMap<Hash, Dispute>, BTreeMap<Hash, i64>) {
    let s = copy.scheme();
    let mut raws: Vec<Raw> = vec![];
    let mut offers: BTreeMap<Hash, Vec<(Credential, Hash, u32)>> = BTreeMap::new();
    let mut rulings: BTreeMap<Hash, Vec<(Credential, Answer)>> = BTreeMap::new();
    for item in copy.items() {
        match BoardMsg::decode(item.content) {
            Some(BoardMsg::Dispute { subject, question, tier, panel, pay_each, appeal_of }) if item.post.kind == "dispute" && item.post.thread.is_none() => {
                raws.push(Raw { id: item.id, epoch: item.post.epoch, opener: item.signer.clone(), subject, question, tier, panel, pay_each, appeal_of });
            }
            Some(BoardMsg::Reply { job, trade: Some(t), .. }) if item.post.thread == Some(job) => {
                if s.verify(&t.key, &trade_bytes(&job, item.signer), None, &t.sig) {
                    offers.entry(job).or_default().push((item.signer.clone(), contractor(&t.key), item.post.epoch));
                }
            }
            Some(BoardMsg::Ruling { dispute, answer }) if item.post.kind == "ruling" && item.post.thread == Some(dispute) => {
                rulings.entry(dispute).or_default().push((item.signer.clone(), answer));
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
        let valid = match r.appeal_of.and_then(|a| out.get(&a)) {
            None => r.appeal_of.is_none() && r.tier == 0 && r.panel >= 1,
            Some(p) => p.subject == r.subject && p.outcome.is_some() && !matches!(p.outcome, Some(Answer::Refer(_))) && r.tier == p.tier + 1 && r.panel >= p.panel_size + 2 && r.pay_each >= p.pay_each.saturating_mul(2),
        };
        if !valid {
            continue;
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
        if let Some(p) = &panel {
            for (cred, answer) in rulings.get(&r.id).into_iter().flatten() {
                if let Some((_, k)) = p.iter().find(|(c, _)| c == cred) {
                    by.entry(*k).or_insert_with(|| answer.clone());
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

/// The final outcome on a subject: the decided dispute of the highest tier.
pub fn final_outcome(disputes: &BTreeMap<Hash, Dispute>, subject: &Hash) -> Option<Answer> {
    disputes.values().filter(|d| d.subject == *subject && d.outcome.is_some()).max_by_key(|d| d.tier).and_then(|d| d.outcome.clone())
}

/// Whether a subject has a dispute still open: undecided and not lapsed.
/// A profile decides whose disputes count (a parcel counts its parties').
pub fn open_dispute(disputes: &BTreeMap<Hash, Dispute>, subject: &Hash) -> bool {
    disputes.values().any(|d| d.subject == *subject && d.outcome.is_none() && !d.lapsed)
}

fn score(out: &BTreeMap<Hash, Dispute>, order: &[Hash]) -> BTreeMap<Hash, i64> {
    let mut scores: BTreeMap<Hash, i64> = BTreeMap::new();
    for d in order.iter().filter_map(|id| out.get(id)) {
        let Some(fin) = final_outcome(out, &d.subject) else { continue };
        for (k, a) in &d.rulings {
            *scores.entry(*k).or_default() += if a.class() == fin.class() { 1 } else { -1 };
        }
    }
    scores
}

impl Node {
    /// The job board's disputes now, and each arbiter's score.
    pub fn disputes(&self) -> (BTreeMap<Hash, Dispute>, BTreeMap<Hash, i64>) {
        self.copy(&self.town.jobs.scope).map(|c| disputes(c, self.epoch())).unwrap_or_default()
    }

    /// Open a dispute, or appeal one with `appeal_of`, signed as `party`
    /// (a credential this wallet holds that makes it a party to the
    /// subject, such as a parcel's addressee) or a fresh one. The opener
    /// pays the panel. Returns the dispute's id.
    pub fn open_dispute(&mut self, subject: Hash, question: &str, panel: u32, pay_each: u64, appeal_of: Option<Hash>, party: Option<Credential>) -> Result<Hash, String> {
        let tier = match appeal_of {
            None => 0,
            Some(a) => self.disputes().0.get(&a).ok_or("unknown dispute to appeal")?.tier + 1,
        };
        let me = match party {
            Some(c) if self.mine.contains(&c) => c,
            Some(_) => return Err("this wallet doesn't hold that credential".into()),
            None => self.fresh()?,
        };
        let msg = BoardMsg::Dispute { subject, question: question.into(), tier, panel, pay_each, appeal_of };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &me, msg.kind(), None, msg.encode(), None)
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

    /// Opener: pay each panelist who ruled, once.
    pub fn pay_arbiters(&mut self, dispute: Hash) -> Result<Vec<Hash>, String> {
        let d = self.disputes().0.remove(&dispute).ok_or("unknown dispute")?;
        if !self.mine.contains(&d.opener) {
            return Err("only the opener pays the panel".into());
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
