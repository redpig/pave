//! The civic work board profile.
//!
//! Jobs are messages sent to a board scope. A post carries a proof of means:
//! a zero-value split of the poster's coin that commits to the job's terms.
//! Payment is an ordinary transfer whose receipt commits to the job, so the
//! record of who was paid for what is in the signed history and nowhere else.

use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Op, Scheme, View};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardMsg {
    Post { title: String, pay: u64, means: Hash },
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

/// The board as this view sees it. Only the poster can accept or mark paid,
/// and only the accepted worker can mark done; anything else is ignored.
pub fn jobs<S: Scheme>(view: &View<S>, board: &Hash) -> BTreeMap<Hash, Job> {
    let mut jobs: BTreeMap<Hash, Job> = BTreeMap::new();
    for rec in view.messages() {
        let Op::Send { scope, body, .. } = &rec.op else { continue };
        if scope != board {
            continue;
        }
        let Some(msg) = BoardMsg::decode(body) else { continue };
        match msg {
            BoardMsg::Post { title, pay, means } => {
                jobs.insert(rec.id(), Job {
                    id: rec.id(),
                    title,
                    pay,
                    poster: rec.signer.clone(),
                    means,
                    replies: vec![],
                    worker: None,
                    status: Status::Open,
                    payment: None,
                });
            }
            BoardMsg::Reply { job, note } => {
                if let Some(j) = jobs.get_mut(&job) {
                    j.replies.push((rec.signer.clone(), note));
                }
            }
            BoardMsg::Accept { job, worker } => {
                if let Some(j) = jobs.get_mut(&job) {
                    if j.poster == rec.signer && j.status == Status::Open {
                        j.worker = Some(worker);
                        j.status = Status::Accepted;
                    }
                }
            }
            BoardMsg::Done { job } => {
                if let Some(j) = jobs.get_mut(&job) {
                    if j.worker.as_ref() == Some(&rec.signer) && j.status == Status::Accepted {
                        j.status = Status::Done;
                    }
                }
            }
            BoardMsg::Paid { job, payment } => {
                if let Some(j) = jobs.get_mut(&job) {
                    if j.poster == rec.signer && j.status == Status::Done {
                        j.status = Status::Paid;
                        j.payment = Some(payment);
                    }
                }
            }
        }
    }
    jobs
}
