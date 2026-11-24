//! A civic work board on pave, and the node that runs one wallet.
//!
//! - [`board`]: the work-board profile (posts with proof of means, replies,
//!   accept, done, payment committing to the job)
//! - [`node`]: a wallet's view, knowledge and keys, saved as a record log
//! - [`net`]: the peer link (meet, two-tier gossip) over TCP
//! - [`pay`]: the payment handshake, sending only what a payment needs
//! - [`swap`]: old coins in, fresh coins out
//! - [`vault`]: sealing a wallet's state, and making old copies useless

pub mod board;
pub mod net;
pub mod node;
pub mod pay;
pub mod swap;
pub mod vault;
