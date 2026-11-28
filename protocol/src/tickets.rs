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
    /// Optional: the holder's pseudonym for one purpose, which the clerk
    /// checked when it issued the ticket. The same person gets the same tag
    /// for the same purpose and unrelated tags for others, so readers can
    /// count people per purpose without learning who they are.
    #[serde(default)]
    pub tag: Option<Tag>,
}

/// A pseudonym for one purpose: the nym of the holder's access credential
/// signed with that purpose's basename, and the class it showed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tag {
    pub purpose: Hash,
    #[serde(with = "serde_bytes")]
    pub nym: Vec<u8>,
    pub class: String,
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
    pub fn issue<S: Scheme>(
        scheme: &S,
        clerk_key: &S::HolderKey,
        clerk: &Credential,
        ticket: Ticket,
    ) -> Self {
        let sig = scheme.sign(clerk_key, clerk, &ticket.signing_bytes(), None);
        SignedTicket {
            ticket,
            clerk: clerk.clone(),
            sig,
        }
    }

    pub fn verify<S: Scheme>(&self, scheme: &S) -> bool {
        scheme.verify(&self.clerk, &self.ticket.signing_bytes(), None, &self.sig)
    }
}
