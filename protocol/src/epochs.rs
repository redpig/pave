//! Epoch sequences. See "Standard schemas: Epochs" in `spec/protocol.md`.
//!
//! A sequence is an exclusive capability its issuer holds. Rolling to the next
//! epoch spends the current state and commits to that epoch's data through the
//! transfer's receipt, so two different epochs at one number are the same
//! state used twice: an ordinary kernel conflict. The epoch number is the
//! number of rolls since the sequence was minted (the state's `hops`). The
//! sequence is identified by its capability's origin.

use pave_kernel::hash::hash_of;
use pave_kernel::{sign, Coin, Credential, Hash, Op, Record, Schema, Scheme, View};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The schema epoch sequences use: one indivisible unit, no expiry of its own.
pub fn epoch_schema(label: &str) -> Schema {
    Schema {
        label: format!("epochs: {label}"),
        divisible: false,
        soft_expiry: None,
        hard_expiry: None,
        offline_transfers: None,
        max_per_holder: Some(1),
        sequence: None,
    }
}

/// What an epoch says. Committed by the roll's receipt, so it travels with
/// the signed record and can't be swapped afterward.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochData {
    pub sequence: Hash,
    pub number: u32,
    /// Ticket groups this issuer has revoked, for its own tickets only, each
    /// with the epoch it was revoked in.
    ///
    /// A ticket in a revoked group always stops the coin it is sending or
    /// receiving. Further back in a coin's history, it stops the coin only
    /// if it was issued within the recipient's window before the revocation
    /// (`Policy::revocation_window`): recent hops through a bad group, not
    /// coins that passed through long before the trouble. The window is in
    /// the issuer's own epochs, so an issuer that rolls faster when volume is
    /// high shortens it in wall time without anyone changing a setting.
    pub revoked: BTreeMap<u32, u32>,
}

/// Does a ticket issued in epoch `issued`, in a group revoked in epoch `at`,
/// taint a coin's history under a window of `window` epochs?
pub fn taints(issued: u32, at: u32, window: u32) -> bool {
    issued.saturating_add(window) >= at
}

impl EpochData {
    pub fn hash(&self) -> Hash {
        hash_of("pave/epoch-data", self)
    }
}

/// Roll a sequence: spend the current epoch state, re-holding it under
/// `next` (a fresh credential of the issuer) and committing to `data`.
pub fn roll<S: Scheme>(
    scheme: &S,
    key: &S::HolderKey,
    holder: &Credential,
    current: &Coin,
    next: &Credential,
    data: &EpochData,
) -> Record {
    sign(scheme, key, holder, Op::Transfer { state: current.state, to: next.clone(), receipt: data.hash() })
}

/// The latest epoch of a sequence a view knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub sequence: Hash,
    pub number: u32,
    /// The epoch's state id. Two versions of one epoch have different states.
    pub state: Hash,
    /// The committed epoch data, if this epoch came from a roll.
    pub data: Option<Hash>,
}

/// The head of `sequence` in `view`, from signed records only.
pub fn head<S: Scheme>(view: &View<S>, sequence: &Hash) -> Option<Head> {
    let coin = view.unspent().find(|c| &c.origin == sequence)?;
    let data = match &view.creator(&coin.state)?.op {
        Op::Transfer { receipt, .. } => Some(*receipt),
        _ => None,
    };
    Some(Head { sequence: *sequence, number: coin.hops, state: coin.state, data })
}

/// The records of `sequence` after epoch `have`, oldest first: what a peer
/// at epoch `have` needs to reach this view's head.
pub fn chain_since<S: Scheme>(view: &View<S>, sequence: &Hash, have: u32) -> Vec<Record> {
    let mut out = Vec::new();
    let Some(h) = head(view, sequence) else { return out };
    let mut state = h.state;
    let mut number = h.number;
    while number > have {
        let Some(rec) = view.creator(&state) else { break };
        let Some(prev) = rec.op.consumes().first().copied() else { break };
        out.push(rec.clone());
        state = prev;
        number -= 1;
    }
    out.reverse();
    out
}

/// The record that made epoch `number` in this view, if it has one.
pub fn epoch_record<S: Scheme>(view: &View<S>, sequence: &Hash, number: u32) -> Option<Record> {
    let h = head(view, sequence)?;
    if number > h.number || number == 0 {
        return None;
    }
    chain_since(view, sequence, number - 1).into_iter().next()
}
