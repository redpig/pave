//! The pave protocol, built from the kernel's axioms. See `spec/protocol.md`.
//!
//! - [`epochs`]: epoch sequences as exclusive capabilities; rolling is spending
//! - [`tickets`]: holding credentials certified by a clerk, per sequence
//! - [`accept`]: a wallet's knowledge and its acceptance policy
//! - [`gossip`]: two-tier gossip, compressed hints and extended proofs

pub mod accept;
pub mod epochs;
pub mod gossip;
pub mod tickets;

pub use accept::{cheat_list, check, Knowledge, Policy, Refusal, Standing};
pub use epochs::{epoch_schema, head, roll, EpochData, Head};
pub use gossip::{Hint, Proof, Want};
pub use tickets::{SignedTicket, Tag, Ticket};
