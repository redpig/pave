//! Slotted basenames: a budget of unlinkable requests per period, then
//! linkable ones. This is Briolette's ticket-request pattern.
//!
//! A request is signed with (domain, scope, period, slot) as basename, and
//! the mint takes only slots below its budget. Each slot's first use in a
//! period gives a fresh pseudonym, unrelated to the others, so a holder's
//! first `slots` requests can't be linked to each other. A request past the
//! budget has to reuse a slot, so it carries the pseudonym of that slot's
//! earlier request: the mint serves it, and knows it is the same holder as
//! before, still without knowing who. Nothing is refused for a count.
//!
//! A mint that needs to count people (how many distinct couriers today) does
//! it with a request of its own whose basename has no slot: see
//! [`crate::dispatch`].

use pave_kernel::hash::{encode, Hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The basename for one slot of one period.
pub fn basename(domain: &str, scope: &Hash, period: u64, slot: u32) -> Vec<u8> {
    encode(&(domain, scope, period, slot))
}

/// Mint: the pseudonyms seen this period, with how often each was used.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Seen {
    pub period: u64,
    pub uses: BTreeMap<Vec<u8>, u32>,
}

impl Seen {
    /// Note a request's pseudonym: a second use links it to the first.
    pub fn note(&mut self, period: u64, nym: Vec<u8>) {
        if period != self.period {
            self.uses.clear();
            self.period = period;
        }
        *self.uses.entry(nym).or_default() += 1;
    }

    /// Requests this period that were linked to an earlier one.
    pub fn linked(&self) -> u32 {
        self.uses.values().map(|n| n - 1).sum()
    }
}

/// Wallet: the next slot to use, per scope and period.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Slots {
    next: BTreeMap<Hash, (u64, u32)>,
}

impl Slots {
    /// The slot for the next request to `scope` in `period`: unused slots
    /// first, then the earliest again, which links that request to it.
    pub fn take(&mut self, scope: &Hash, period: u64, slots: u32) -> u32 {
        let e = self.next.entry(*scope).or_insert((period, 0));
        if e.0 != period {
            *e = (period, 0);
        }
        let s = e.1;
        e.1 += 1;
        s % slots.max(1)
    }
}
