//! Food delivery's outcomes: what the description in `profiles/food.json`
//! can't say on its own, because it reads more than one record.
//!
//! - **The time witness is the board.** The kernel has no clock, so the
//!   customer's confirmation also goes out as a `delivered` note on the job
//!   board, in the order's thread. The board server stamps every post with
//!   its own clock (see [`crate::bulletin`]), so the note's clock is when it
//!   was delivered, as far as anyone can show.
//! - **The seal.** The bag's tamper seal carries the manifest's label code.
//!   At the door the customer reads it; the note says whether it matched.
//! - **The outcome** compares the note with the order's deadline: on time,
//!   late by so many seconds, or delivered with a broken seal. It is what a
//!   dispute over the order starts from.

use crate::parcel::{label_hash, Manifest};
use pave_kernel::hash::Hash;
use serde::{Deserialize, Serialize};

/// The customer's note on delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivered {
    pub order: Hash,
    pub seal_ok: bool,
}

/// How a food order went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No delivered note from the customer's key yet.
    Pending,
    OnTime { at: u64 },
    Late { at: u64, by: u64 },
    /// Delivered, but the seal's code didn't match the label.
    SealBroken { at: u64 },
}

impl crate::node::Node {
    /// Customer: post that the order arrived, with whether the seal matched,
    /// signed by the key the order was delivered to. Confirm the parcel
    /// first; the note waits for the next sync with the board.
    pub fn note_delivered(&mut self, m: &Manifest, order: Hash, seal: &str) -> Result<Hash, String> {
        let seal_ok = m.label == Some(label_hash(&m.parcel, seal));
        let note = Delivered { order, seal_ok };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &m.addressee, "delivered", Some(order), pave_kernel::hash::encode(&note), None)
    }

    /// Anyone: how the order went, from the board, against its deadline.
    pub fn food_outcome(&self, m: &Manifest, order: Hash, due: u64) -> Outcome {
        let Ok(copy) = self.copy(&self.town.jobs.scope) else { return Outcome::Pending };
        let note = copy.items().into_iter().find_map(|i| {
            let ok = i.post.kind == "delivered" && i.post.thread == Some(order) && *i.signer == m.addressee;
            let d: Delivered = ciborium::from_reader(i.content).ok()?;
            (ok && d.order == order).then_some((i.post.clock, d.seal_ok))
        });
        match note {
            None => Outcome::Pending,
            Some((at, false)) => Outcome::SealBroken { at },
            Some((at, true)) if at > due => Outcome::Late { at, by: at - due },
            Some((at, true)) => Outcome::OnTime { at },
        }
    }
}
