//! What a wallet knows beyond its view, and its acceptance policy.
//!
//! The kernel moves anything a holder signs. Whether to *accept* a coin is the
//! recipient's choice: honoring expiry, transfer limits, revocation and
//! evidence. This is the protocol's default policy (`HonestAcceptsInDate` and
//! `HonestNoKnownCheat` in the TLA+ models).

use crate::epochs::{head, EpochData};
use crate::gossip::Hint;
use crate::tickets::SignedTicket;
use pave_kernel::{Credential, Hash, Scheme, View};
use std::collections::{BTreeMap, BTreeSet};

/// A wallet's knowledge beyond its view: tickets it has seen (they travel
/// with a coin's provenance), epoch data, and unverified hints.
#[derive(Clone, Debug, Default)]
pub struct Knowledge {
    pub tickets: BTreeMap<Credential, SignedTicket>,
    pub epoch_data: BTreeMap<Hash, EpochData>,
    pub hints: BTreeSet<Hint>,
}

impl Knowledge {
    /// Keep a ticket only if its clerk's signature verifies.
    pub fn add_ticket<S: Scheme>(&mut self, scheme: &S, t: SignedTicket) -> bool {
        if !t.verify(scheme) {
            return false;
        }
        self.tickets.insert(t.ticket.credential.clone(), t);
        true
    }

    /// Keep epoch data only if a signed roll in `view` commits to it.
    pub fn add_epoch_data<S: Scheme>(&mut self, view: &View<S>, d: EpochData) -> bool {
        let committed = crate::epochs::epoch_record(view, &d.sequence, d.number)
            .is_some_and(|r| matches!(r.op, pave_kernel::Op::Transfer { receipt, .. } if receipt == d.hash()));
        if committed {
            self.epoch_data.insert(d.hash(), d);
        }
        committed
    }
}

/// A recipient's policy. Every field is the recipient's own choice.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Clerks whose tickets count, and the sequence each counts by.
    pub trusted_clerks: BTreeMap<Credential, Hash>,
    pub honor_expiry: bool,
    pub honor_transfer_limit: bool,
    pub refuse_known_cheats: bool,
    /// Hold off a coin offline while an unproven fork hint names its history.
    pub wait_on_hints: bool,
}

impl Policy {
    /// The default wallet policy: honor everything, don't wait on hints.
    pub fn wallet(trusted_clerks: BTreeMap<Credential, Hash>) -> Self {
        Policy { trusted_clerks, honor_expiry: true, honor_transfer_limit: true, refuse_known_cheats: true, wait_on_hints: false }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    UnknownState,
    UnknownSchema,
    KnownCheat,
    OverTransferLimit,
    NoTicket(Credential),
    BadTicket(Credential),
    UntrustedClerk(Credential),
    UnknownSequence(Hash),
    EpochDataMissing(Hash),
    Expired { credential: Credential, issued: u32, now: u32 },
    Revoked { credential: Credential, group: u32 },
    HintPending(Hash),
}

/// Every state in a coin's provenance, from its current state back to mint.
pub fn ancestry<S: Scheme>(view: &View<S>, state: &Hash) -> BTreeSet<Hash> {
    let mut out = BTreeSet::new();
    let mut todo = vec![*state];
    while let Some(s) = todo.pop() {
        if !out.insert(s) {
            continue;
        }
        if let Some(rec) = view.creator(&s) {
            todo.extend(rec.op.consumes());
        }
    }
    out
}

/// Should the holder of `state` be accepted as payment from `sender`?
pub fn check<S: Scheme>(
    view: &View<S>,
    know: &Knowledge,
    state: &Hash,
    sender: &Credential,
    policy: &Policy,
) -> Result<(), Refusal> {
    let coin = view.coin(state).ok_or(Refusal::UnknownState)?;
    let schema = view.schema(&coin.schema).ok_or(Refusal::UnknownSchema)?;

    if policy.refuse_known_cheats && view.flagged().contains(sender) {
        return Err(Refusal::KnownCheat);
    }
    if policy.honor_transfer_limit {
        if let Some(limit) = schema.offline_transfers {
            if coin.hops >= limit {
                return Err(Refusal::OverTransferLimit);
            }
        }
    }

    // Every credential the coin has been held under, each against its own
    // clerk's sequence. Checking only the newest is wrong once clerks roll
    // at different rates (the `latestonly` fault).
    for cred in &coin.history {
        let t = know.tickets.get(cred).ok_or_else(|| Refusal::NoTicket(cred.clone()))?;
        if !t.verify(view.scheme()) {
            return Err(Refusal::BadTicket(cred.clone()));
        }
        let seq = policy.trusted_clerks.get(&t.clerk).ok_or_else(|| Refusal::UntrustedClerk(t.clerk.clone()))?;
        if &t.ticket.sequence != seq {
            return Err(Refusal::BadTicket(cred.clone()));
        }
        let h = head(view, seq).ok_or(Refusal::UnknownSequence(*seq))?;
        if policy.honor_expiry {
            if let Some(soft) = schema.soft_expiry {
                if h.number >= t.ticket.epoch.saturating_add(soft) {
                    return Err(Refusal::Expired { credential: cred.clone(), issued: t.ticket.epoch, now: h.number });
                }
            }
        }
        if let Some(d) = h.data {
            let data = know.epoch_data.get(&d).ok_or(Refusal::EpochDataMissing(d))?;
            if data.revoked_groups.contains(&t.ticket.group) {
                return Err(Refusal::Revoked { credential: cred.clone(), group: t.ticket.group });
            }
        }
    }

    if policy.wait_on_hints {
        let proven: BTreeSet<Hash> = view.evidence().map(|e| e.basename).collect();
        for s in ancestry(view, state) {
            if !proven.contains(&s) && know.hints.contains(&Hint::fork(&s)) {
                return Err(Refusal::HintPending(s));
            }
        }
    }
    Ok(())
}
