//! Tickets. See "Standard schemas: Tickets" in `spec/protocol.md`.
//!
//! A ticket binds a holding credential to a clerk's sequence, the epoch it was
//! issued in, a randomized revocation group and optional policy. Value is held
//! under the ticket's credential; transfer is spend. A capability's expiry
//! runs from every ticket in its history, each against its own sequence.

use pave_kernel::hash::encode;
use pave_kernel::{Credential, Hash, Scheme, Sig};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// The holding credential this ticket certifies.
    pub credential: Credential,
    /// The clerk's epoch sequence the ticket counts by.
    pub sequence: Hash,
    /// The epoch it was issued in.
    pub epoch: u32,
    /// Randomized revocation group.
    pub group: u32,
    /// Optional most this ticket may receive in one transfer.
    pub max_spend: Option<u64>,
}

impl Ticket {
    fn signing_bytes(&self) -> Vec<u8> {
        encode(&("pave/ticket/v0", self))
    }
}

/// A ticket signed by its clerk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTicket {
    pub ticket: Ticket,
    pub clerk: Credential,
    pub sig: Sig,
}

impl SignedTicket {
    pub fn issue<S: Scheme>(scheme: &S, clerk_key: &S::HolderKey, clerk: &Credential, ticket: Ticket) -> Self {
        let sig = scheme.sign(clerk_key, clerk, &ticket.signing_bytes(), None);
        SignedTicket { ticket, clerk: clerk.clone(), sig }
    }

    pub fn verify<S: Scheme>(&self, scheme: &S) -> bool {
        scheme.verify(&self.clerk, &self.ticket.signing_bytes(), None, &self.sig)
    }
}
