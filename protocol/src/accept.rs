//! What a wallet knows beyond its view, and its acceptance policy.
//!
//! The kernel moves anything a holder signs. Whether to *accept* a coin is the
//! recipient's choice: honoring expiry, transfer limits, revocation and
//! evidence. This is the protocol's default policy (`HonestAcceptsInDate` and
//! `HonestNoKnownCheat` in the TLA+ models).
//!
//! Evidence names one credential, but a cheat has many unlinkable ones. So a
//! recipient that knows of cheats asks the sender for its *standing*: a proof
//! that the sending credential's key is none of the cheats' keys. An honest
//! sender proves it without revealing anything else; a cheat can't, under any
//! credential. That stops a cheat everywhere the evidence has reached, with no
//! clerk, no revocation list and no harm to anyone else.

use crate::epochs::{head, EpochData};
use crate::gossip::Hint;
use crate::tickets::SignedTicket;
use pave_kernel::{Credential, Hash, Scheme, View};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// What a standing proof is bound to.
pub const STANDING_CONTEXT: &[u8] = b"pave/standing/v0";

/// Every cheat `view` holds evidence for, as (basename, pseudonym), sorted.
pub fn cheat_list<S: Scheme>(view: &View<S>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let set: BTreeSet<_> = view.evidence().map(|e| e.cheat()).collect();
    set.into_iter().collect()
}

/// A proof that a credential's key is none of `cheats`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standing {
    pub credential: Credential,
    pub cheats: Vec<(Vec<u8>, Vec<u8>)>,
    pub proof: Vec<u8>,
}

impl Standing {
    /// None if the key is one of the cheats.
    pub fn prove<S: Scheme>(scheme: &S, key: &S::HolderKey, credential: &Credential, cheats: &[(Vec<u8>, Vec<u8>)]) -> Option<Self> {
        let proof = scheme.prove_not_cheat(key, credential, cheats, STANDING_CONTEXT)?;
        Some(Standing { credential: credential.clone(), cheats: cheats.to_vec(), proof })
    }

    pub fn verify<S: Scheme>(&self, scheme: &S) -> bool {
        scheme.verify_not_cheat(&self.credential, &self.cheats, STANDING_CONTEXT, &self.proof)
    }

    /// Does this cover every cheat in `list`?
    pub fn covers(&self, list: &[(Vec<u8>, Vec<u8>)]) -> bool {
        list.iter().all(|c| self.cheats.contains(c))
    }
}

/// A wallet's knowledge beyond its view: tickets it has seen (they travel
/// with a coin's provenance), epoch data, and unverified hints.
#[derive(Clone, Debug, Default)]
pub struct Knowledge {
    pub tickets: BTreeMap<Credential, SignedTicket>,
    pub epoch_data: BTreeMap<Hash, EpochData>,
    pub hints: BTreeSet<Hint>,
    /// The best verified standing seen for each credential.
    pub standing: BTreeMap<Credential, Standing>,
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

    /// Keep a standing proof if it verifies and covers more than the one held.
    pub fn add_standing<S: Scheme>(&mut self, scheme: &S, st: Standing) -> bool {
        if let Some(have) = self.standing.get(&st.credential) {
            if st.cheats.len() <= have.cheats.len() || !st.covers(&have.cheats) {
                return false;
            }
        }
        if !st.verify(scheme) {
            return false;
        }
        self.standing.insert(st.credential.clone(), st);
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
    /// Once this recipient knows of any cheat, require the sender's standing.
    pub require_standing: bool,
}

impl Policy {
    /// The default wallet policy: honor everything, don't wait on hints.
    pub fn wallet(trusted_clerks: BTreeMap<Credential, Hash>) -> Self {
        Policy { trusted_clerks, honor_expiry: true, honor_transfer_limit: true, refuse_known_cheats: true, wait_on_hints: false, require_standing: true }
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
    /// The recipient knows of cheats, and the sender hasn't shown it isn't one.
    NoStanding(Credential),
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
    if policy.require_standing {
        let list = cheat_list(view);
        if !list.is_empty() && !know.standing.get(sender).is_some_and(|st| st.covers(&list)) {
            return Err(Refusal::NoStanding(sender.clone()));
        }
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
