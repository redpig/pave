//! The civic work board: a board (see [`crate::bulletin`]) for jobs.
//!
//! Job posts, replies and status changes are posts the town hosts. A job
//! post carries a proof of means: a zero-value split of the poster's coin
//! that commits to the job's terms. Payment is not a post. It is an ordinary
//! transfer whose receipt commits to the job, and it moves like any coin,
//! offline if need be. The board only shows the poster's claim that it paid.
//!
//! **Vouches.** A worker who wants a reputation replies under a stable trade
//! key, signing over the credential it will be paid at. The poster can then
//! pay with a vouch: the payment record gets a second, zero-value output to
//! the worker, and its receipt commits to the job, the contractor and the
//! job type. That output is the vouch coin. It goes to the contractor with
//! the pay, is held like money and checks like money, offline too. The
//! poster also posts the vouch in the contractor's thread as a counted
//! post for that contractor (see [`crate::bulletin`]), so readers count
//! distinct people per job type without learning who they are, and one
//! person counts once however many jobs they vouch for.
//!
//! **Known before the job.** A job can say its worker must be known
//! ([`Known`]): by a stable pseudonym the worker keeps for its line of work
//! (its trade key), or by a badge, a roster's ticket certifying that key
//! (a co-op's [`crate::dispatch::Dispatch`]). Replies stay anonymous. The
//! poster picks one; that replier shows the poster its key, and its badge if
//! the job needs one, signing with the key over the credential it will be
//! paid at; the accept carries it. Readers count the accept only if it
//! shows what the job needs, and vouches for the job go to that key's
//! contractor thread: one reputation, whoever matched the job. A badge adds
//! what a pseudonym can't: someone vouches for who is behind it, so a bad
//! record can't be shed by making a new key.
//!
//! **Known to your contacts.** Like any post, a vouch may be signed with
//! one of the voucher's identities (see [`crate::bulletin`]): contacts who
//! were given it see who vouched; anyone else sees only that one unnamed
//! person vouched for several jobs. Without one, a vouch is anonymous.

use crate::bulletin::{purpose, Copy};
use crate::dispatch::Dispatch;
use pave_protocol::SignedTicket;
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Op, Record, Scheme, Sig};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A worker's opt-in to a reputation: its trade key, and that key's
/// signature over the job and the credential it will be paid at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trade {
    pub key: Credential,
    pub sig: Sig,
}

pub fn trade_bytes(job: &Hash, worker: &Credential) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/board/trade/v0", job, worker))
}

/// How a job's worker must be known before it is given the job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Known {
    /// By a stable pseudonym: the job counts toward it.
    Stable,
    /// By a stable pseudonym this roster badged.
    Badge(Dispatch),
}

/// What a worker shows for a job: its stable key's signature over the job
/// and the credential to be paid, and the roster's ticket on that key if
/// the job needs a badge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shown {
    pub ticket: Option<SignedTicket>,
    pub trade: Trade,
}

/// The contractor a trade key names: the thread its vouches go in.
pub fn contractor(key: &Credential) -> Hash {
    hash_of("pave/board/contractor", key)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardMsg {
    /// `means` is the split record proving the poster holds the pay;
    /// `terms` is the receipt root that split commits to.
    /// `known`: how the worker must be known before it is given the job.
    Post {
        title: String,
        pay: u64,
        means: Hash,
        terms: Hash,
        #[serde(default)]
        known: Option<Box<Known>>,
        /// What the job is about, such as a parcel to deliver.
        #[serde(default)]
        about: Option<Hash>,
    },
    /// `trade` is set when the replier wants vouches for this job.
    Reply { job: Hash, note: String, trade: Option<Trade> },
    /// `assignment` is the poster's transfer of the job's zero-value state
    /// (the second output of its proof of means) to the worker: a job can
    /// be given once, and the worker holds the record.
    Accept {
        job: Hash,
        worker: Credential,
        #[serde(default)]
        assignment: Option<pave_kernel::Record>,
        /// For a job whose worker must be known: what it showed.
        #[serde(default)]
        badge: Option<Box<Shown>>,
    },
    Done { job: Hash },
    Paid { job: Hash, payment: Hash },
    /// A dispute: see [`crate::dispute`].
    Dispute {
        subject: Hash,
        question: String,
        claim: bool,
        against: Option<Hash>,
        tier: u32,
        panel: u32,
        pay_each: u64,
        appeal_of: Option<Hash>,
        /// For an appeal with pay: its escrow deposit.
        deposit: Option<Box<Record>>,
        /// A deposit the counterparty's terms ask of this filer.
        filer_deposit: Option<Box<Record>>,
    },
    /// Funding for a first-round dispute, into escrow.
    Fund { dispute: Hash, deposit: Box<Record> },
    /// A counterparty's terms for filers against it, signed by its trade key.
    Terms { min_losses: u32, deposit: u64, pay_to: Credential, trade: Trade },
    /// A panelist's answer to a dispute.
    Ruling { dispute: Hash, answer: crate::dispute::Answer },
    /// A courier's note on an unattended drop: see [`crate::parcel`].
    Dropped { parcel: Hash, cell: String, photo: Hash },
    /// A courier's note that it took a parcel, signed with an identity.
    Took { parcel: Hash, hop: u32 },
    /// The shipper reminted a parcel to whoever has the package and its
    /// label code: the old token is void.
    /// `roll` is the shipper's move of the parcel's lineage coin.
    Replaced { parcel: Hash, with: Hash, roll: pave_kernel::Record },
    /// Evidence was submitted about a subject: its kind and hash. The
    /// evidence itself goes only to the host, for the panel.
    EvidenceNote { subject: Hash, kind: String, hash: Hash },
    /// In the contractor's thread, from the job's poster: the payment
    /// record, whose second output is the vouch coin.
    Vouch {
        job: Hash,
        category: String,
        note: String,
        payment: Box<Record>,
    },
}

impl BoardMsg {
    pub fn encode(&self) -> Vec<u8> {
        pave_kernel::hash::encode(self)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        ciborium::from_reader(b).ok()
    }
    /// The post kind this message is sent as.
    pub fn kind(&self) -> &'static str {
        match self {
            BoardMsg::Post { .. } => "job",
            BoardMsg::Reply { .. } => "reply",
            BoardMsg::Accept { .. } => "accept",
            BoardMsg::Done { .. } => "done",
            BoardMsg::Paid { .. } => "paid",
            BoardMsg::Vouch { .. } => "vouch",
            BoardMsg::Dispute { .. } => "dispute",
            BoardMsg::Ruling { .. } => "ruling",
            BoardMsg::Dropped { .. } => "dropped",
            BoardMsg::Took { .. } => "took",
            BoardMsg::Replaced { .. } => "replaced",
            BoardMsg::Fund { .. } => "fund",
            BoardMsg::EvidenceNote { .. } => "evidence",
            BoardMsg::Terms { .. } => "terms",
        }
    }
    /// The job a message is about; None for a new job.
    pub fn job(&self) -> Option<Hash> {
        match self {
            BoardMsg::Post { .. } => None,
            BoardMsg::Dispute { against, .. } => *against,
            BoardMsg::Ruling { dispute, .. } => Some(*dispute),
            BoardMsg::Dropped { parcel, .. } | BoardMsg::Took { parcel, .. } | BoardMsg::Replaced { parcel, .. } => Some(*parcel),
            BoardMsg::Fund { dispute, .. } => Some(*dispute),
            BoardMsg::EvidenceNote { subject, .. } => Some(*subject),
            BoardMsg::Terms { trade, .. } => Some(contractor(&trade.key)),
            BoardMsg::Reply { job, .. } | BoardMsg::Accept { job, .. } | BoardMsg::Done { job } | BoardMsg::Paid { job, .. } | BoardMsg::Vouch { job, .. } => Some(*job),
        }
    }
}

/// The receipt a payment for `job` commits to.
pub fn pay_receipt(job: &Hash) -> Hash {
    hash_of("pave/board/pay", job)
}

/// The receipt a payment with a vouch commits to.
pub fn vouch_receipt(job: &Hash, contractor: &Hash, category: &str) -> Hash {
    hash_of("pave/board/vouch/v0", &(job, contractor, category))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Status {
    Open,
    Accepted,
    Done,
    Paid,
    /// The poster gave the job to two workers: two transfers of one state.
    Contested,
}

/// The job's assignment state: the zero-value second output of its proof of means.
pub fn job_state(means: &Hash) -> Hash {
    pave_kernel::hash::hash_of("pave/output", &(means, 1u32))
}

/// What a job's assignment commits to.
pub fn accept_receipt(job: &Hash, worker: &Credential) -> Hash {
    pave_kernel::hash::hash_of("pave/job/accept", &(job, worker))
}

/// Whether `rec` is the poster's transfer of the job's state to `worker`.
fn assigns(copy: &Copy, job: &Job, worker: &Credential, rec: &pave_kernel::Record) -> bool {
    let state = job_state(&job.means);
    rec.signer == job.poster
        && rec.op == pave_kernel::Op::Transfer { state, to: worker.clone(), receipt: accept_receipt(&job.id, worker) }
        && rec.sigs.first().is_some_and(|sig| copy.scheme().verify(&rec.signer, &rec.op.signing_bytes(), Some(state.as_bytes()), sig))
}

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub id: Hash,
    pub title: String,
    pub pay: u64,
    pub poster: Credential,
    pub means: Hash,
    /// How the worker must be known.
    pub known: Option<Known>,
    /// What the job is about.
    pub about: Option<Hash>,
    /// The stable key the accepted worker showed.
    pub known_key: Option<Credential>,
    /// The worker's id on its badge, once accepted.
    pub known_as: Option<String>,
    pub replies: Vec<(Credential, String)>,
    /// Repliers who opted into vouches, and the contractor each named.
    pub contractors: BTreeMap<Credential, Hash>,
    pub worker: Option<Credential>,
    /// The poster's transfer of the job's state to the worker.
    pub assignment: Option<Hash>,
    pub status: Status,
    pub payment: Option<Hash>,
}

/// The board as a copy has it. Only the poster can accept or mark paid,
/// and only the accepted worker can mark done; anything else is ignored, as
/// is any post whose kind or thread doesn't match its content.
pub fn jobs(copy: &Copy) -> BTreeMap<Hash, Job> {
    let mut jobs: BTreeMap<Hash, Job> = BTreeMap::new();
    for item in copy.items() {
        let Some(msg) = BoardMsg::decode(item.content) else { continue };
        if item.post.kind != msg.kind() || matches!(msg, BoardMsg::Vouch { .. }) || item.post.thread != msg.job() {
            continue;
        }
        let (id, signer) = (item.id, item.signer);
        match msg {
            BoardMsg::Post { title, pay, means, known, about, .. } => {
                jobs.insert(id, Job {
                    id,
                    title,
                    pay,
                    poster: signer.clone(),
                    means,
                    known: known.map(|k| *k),
                    about,
                    known_key: None,
                    known_as: None,
                    replies: vec![],
                    contractors: BTreeMap::new(),
                    worker: None,
                    assignment: None,
                    status: Status::Open,
                    payment: None,
                });
            }
            BoardMsg::Reply { job, note, trade } => {
                if let Some(j) = jobs.get_mut(&job) {
                    j.replies.push((signer.clone(), note));
                    if let Some(t) = trade {
                        if copy.scheme().verify(&t.key, &trade_bytes(&job, signer), None, &t.sig) {
                            j.contractors.insert(signer.clone(), contractor(&t.key));
                        }
                    }
                }
            }
            BoardMsg::Accept { job, worker, assignment, badge } => {
                if let Some(j) = jobs.get_mut(&job) {
                    let Some(rec) = assignment.filter(|r| &j.poster == signer && assigns(copy, j, &worker, r)) else { continue };
                    // A job whose worker must be known counts only an accept showing it.
                    let known = match &j.known {
                        None => None,
                        Some(k) => match badge.as_deref().and_then(|b| shown_by(copy.scheme(), k, &job, &worker, b)) {
                            Some(k) => Some(k),
                            None => continue,
                        },
                    };
                    if j.status == Status::Open {
                        if let Some((id, key)) = known {
                            j.known_as = id;
                            j.known_key = Some(key.clone());
                            j.contractors.insert(worker.clone(), contractor(&key));
                        }
                        j.worker = Some(worker);
                        j.assignment = Some(rec.id());
                        j.status = Status::Accepted;
                    } else if j.assignment.is_some_and(|a| a != rec.id()) {
                        // A second transfer of the one state: the poster gave it twice.
                        j.worker = None;
                        j.status = Status::Contested;
                    }
                }
            }
            BoardMsg::Done { job } => {
                if let Some(j) = jobs.get_mut(&job) {
                    if j.worker.as_ref() == Some(signer) && j.status == Status::Accepted {
                        j.status = Status::Done;
                    }
                }
            }
            BoardMsg::Vouch { .. } | BoardMsg::Dispute { .. } | BoardMsg::Ruling { .. } | BoardMsg::Dropped { .. } | BoardMsg::Took { .. } | BoardMsg::Replaced { .. } | BoardMsg::Fund { .. } | BoardMsg::Terms { .. } | BoardMsg::EvidenceNote { .. } => {}
            BoardMsg::Paid { job, payment } => {
                if let Some(j) = jobs.get_mut(&job) {
                    if &j.poster == signer && j.status == Status::Done {
                        j.status = Status::Paid;
                        j.payment = Some(payment);
                    }
                }
            }
        }
    }
    jobs
}

/// The stable key `b` shows, and its badge id when `known` needs a badge,
/// if the key signed for `worker` on `job` and carries what `known` needs.
pub fn shown_by(s: &impl Scheme, known: &Known, job: &Hash, worker: &Credential, b: &Shown) -> Option<(Option<String>, Credential)> {
    if !s.verify(&b.trade.key, &trade_bytes(job, worker), None, &b.trade.sig) {
        return None;
    }
    let id = match known {
        Known::Stable => None,
        Known::Badge(d) => {
            let t = b.ticket.as_ref().filter(|t| t.ticket.credential == b.trade.key)?;
            Some(d.badge_of(s, t)?)
        }
    };
    Some((id, b.trade.key.clone()))
}

/// One vouch that counts.
#[derive(Clone, Debug, Serialize)]
pub struct Vouched {
    pub job: Hash,
    pub category: String,
    pub note: String,
    /// The vouch coin: the payment's second output, held by the worker.
    pub coin: Hash,
    pub class: String,
    /// The stable credential the voucher signed with, if any. Vouches with
    /// the same one are from the same person.
    pub by: Option<Credential>,
    /// The reader's name for it, if the reader was given it.
    pub known_by: Option<String>,
}

/// A contractor's reputation as a copy of the job board has it: by job
/// type, the number of distinct people who paid for work and vouched, and
/// the vouches themselves. A vouch counts only if it comes from the job's
/// poster, the job is paid, the worker named this contractor with its trade
/// key, the payment record is signed and pays the worker with a vouch
/// output whose receipt names this job, contractor and type, and the
/// post counts its author for this contractor. Each job counts once, and each person once per
/// type.
/// `contacts` are the reader's: names for the stable credentials it was given.
pub fn reputation(copy: &Copy, contacts: &BTreeMap<String, Credential>, who: &Hash) -> (BTreeMap<String, usize>, Vec<Vouched>) {
    let jobs = jobs(copy);
    let scope = copy.info.scope;
    let mut seen_jobs: BTreeSet<Hash> = BTreeSet::new();
    let mut people: BTreeMap<String, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut out = vec![];
    for item in copy.items() {
        if item.post.kind != "vouch" || item.post.thread != Some(*who) {
            continue;
        }
        let Some(BoardMsg::Vouch { job, category, note, payment }) = BoardMsg::decode(item.content) else { continue };
        let Some(j) = jobs.get(&job) else { continue };
        let Some(worker) = j.worker.as_ref() else { continue };
        let paid = j.status == Status::Paid && j.payment == Some(payment.output(0));
        let named = j.contractors.get(worker) == Some(who);
        let pays = match &payment.op {
            Op::Split { state, parts, receipt } => {
                parts.len() >= 2
                    && parts[0] == (j.pay, worker.clone())
                    && parts[1] == (0, worker.clone())
                    && *receipt == vouch_receipt(&job, who, &category)
                    && payment.sigs.len() == 1
                    && copy.scheme().verify(&payment.signer, &payment.op.signing_bytes(), Some(state.as_bytes()), &payment.sigs[0])
            }
            _ => false,
        };
        if item.signer != &j.poster || !paid || !named || !pays || !seen_jobs.insert(job) {
            continue;
        }
        let Some((class, nym)) = item.counted(&purpose(&scope, "vouch", who)) else { continue };
        people.entry(category.clone()).or_default().insert(nym);
        let by = item.by.clone();
        let known_by = by.as_ref().and_then(|c| contacts.iter().find(|(_, k)| *k == c).map(|(n, _)| n.clone()));
        out.push(Vouched { job, category, note, coin: payment.output(1), class, by, known_by });
    }
    (people.into_iter().map(|(c, n)| (c, n.len())).collect(), out)
}
