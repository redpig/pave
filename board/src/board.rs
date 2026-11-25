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
//! poster also posts the vouch in the contractor's thread, endorsed with
//! the contractor as basename, so readers count distinct people per job
//! type without learning who they are, and one person counts once however
//! many jobs they vouch for.
//!
//! **Known to your contacts.** Like any post, a vouch may be signed with
//! one of the voucher's identities (see [`crate::bulletin`]): contacts who
//! were given it see who vouched; anyone else sees only that one unnamed
//! person vouched for several jobs. Without one, a vouch is anonymous.

use crate::bulletin::{endorser, Copy};
use crate::node::Class;
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

/// The contractor a trade key names: the thread its vouches go in.
pub fn contractor(key: &Credential) -> Hash {
    hash_of("pave/board/contractor", key)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardMsg {
    /// `means` is the split record proving the poster holds the pay;
    /// `terms` is the receipt root that split commits to.
    Post { title: String, pay: u64, means: Hash, terms: Hash },
    /// `trade` is set when the replier wants vouches for this job.
    Reply { job: Hash, note: String, trade: Option<Trade> },
    Accept { job: Hash, worker: Credential },
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
    },
    /// A panelist's answer to a dispute.
    Ruling { dispute: Hash, answer: crate::dispute::Answer },
    /// A courier's note on an unattended drop: see [`crate::parcel`].
    Dropped { parcel: Hash, cell: String, photo: Hash },
    /// A courier's note that it took a parcel, signed with an identity.
    Took { parcel: Hash, hop: u32 },
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
        }
    }
    /// The job a message is about; None for a new job.
    pub fn job(&self) -> Option<Hash> {
        match self {
            BoardMsg::Post { .. } => None,
            BoardMsg::Dispute { against, .. } => *against,
            BoardMsg::Ruling { dispute, .. } => Some(*dispute),
            BoardMsg::Dropped { parcel, .. } | BoardMsg::Took { parcel, .. } => Some(*parcel),
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
}

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub id: Hash,
    pub title: String,
    pub pay: u64,
    pub poster: Credential,
    pub means: Hash,
    pub replies: Vec<(Credential, String)>,
    /// Repliers who opted into vouches, and the contractor each named.
    pub contractors: BTreeMap<Credential, Hash>,
    pub worker: Option<Credential>,
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
            BoardMsg::Post { title, pay, means, .. } => {
                jobs.insert(id, Job {
                    id,
                    title,
                    pay,
                    poster: signer.clone(),
                    means,
                    replies: vec![],
                    contractors: BTreeMap::new(),
                    worker: None,
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
            BoardMsg::Accept { job, worker } => {
                if let Some(j) = jobs.get_mut(&job) {
                    if &j.poster == signer && j.status == Status::Open {
                        j.worker = Some(worker);
                        j.status = Status::Accepted;
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
            BoardMsg::Vouch { .. } | BoardMsg::Dispute { .. } | BoardMsg::Ruling { .. } | BoardMsg::Dropped { .. } | BoardMsg::Took { .. } => {}
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
/// endorsement checks out. Each job counts once, and each person once per
/// type.
/// `contacts` are the reader's: names for the stable credentials it was given.
pub fn reputation(copy: &Copy, classes: &BTreeMap<String, Class>, contacts: &BTreeMap<String, Credential>, who: &Hash) -> (BTreeMap<String, usize>, Vec<Vouched>) {
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
        let Some((class, nym)) = endorser(classes, &scope, &item.post) else { continue };
        people.entry(category.clone()).or_default().insert(nym);
        let by = item.by.clone();
        let known_by = by.as_ref().and_then(|c| contacts.iter().find(|(_, k)| *k == c).map(|(n, _)| n.clone()));
        out.push(Vouched { job, category, note, coin: payment.output(1), class, by, known_by });
    }
    (people.into_iter().map(|(c, n)| (c, n.len())).collect(), out)
}
