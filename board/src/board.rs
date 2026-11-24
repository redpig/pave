//! The civic work board: a board (see [`crate::bulletin`]) for jobs.
//!
//! Job posts, replies and status changes are posts the town hosts. A job
//! post carries a proof of means: a zero-value split of the poster's coin
//! that commits to the job's terms. Payment is not a post. It is an ordinary
//! transfer whose receipt commits to the job, and it moves like any coin,
//! offline if need be. The board only shows the poster's claim that it paid.

use crate::bulletin::Copy;
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::Credential;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardMsg {
    /// `means` is the split record proving the poster holds the pay;
    /// `terms` is the receipt root that split commits to.
    Post { title: String, pay: u64, means: Hash, terms: Hash },
    Reply { job: Hash, note: String },
    Accept { job: Hash, worker: Credential },
    Done { job: Hash },
    Paid { job: Hash, payment: Hash },
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
        }
    }
    /// The job a message is about; None for a new job.
    pub fn job(&self) -> Option<Hash> {
        match self {
            BoardMsg::Post { .. } => None,
            BoardMsg::Reply { job, .. } | BoardMsg::Accept { job, .. } | BoardMsg::Done { job } | BoardMsg::Paid { job, .. } => Some(*job),
        }
    }
}

/// The receipt a payment for `job` commits to.
pub fn pay_receipt(job: &Hash) -> Hash {
    hash_of("pave/board/pay", job)
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
        if item.post.kind != msg.kind() || item.post.thread != msg.job() {
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
                    worker: None,
                    status: Status::Open,
                    payment: None,
                });
            }
            BoardMsg::Reply { job, note } => {
                if let Some(j) = jobs.get_mut(&job) {
                    j.replies.push((signer.clone(), note));
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
