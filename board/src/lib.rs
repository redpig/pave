//! A civic work board on pave, and the node that runs one wallet.
//!
//! - [`bulletin`]: the board profile: posts to an online host, bound by
//!   hash, with endorsements that count people and receipts from the host
//! - [`board`]: the job board (posts with proof of means, replies, accept,
//!   done; payment is a coin whose receipt commits to the job)
//! - [`node`]: a wallet's view, knowledge and keys, saved as a record log
//! - [`net`]: the peer link (meet, two-tier gossip) over TCP
//! - [`report`]: the civic reports board
//! - [`dispute`]: disputes as jobs, with appeals and arbiter reputation
//! - [`evidence`]: evidence for dispute panels, held by the host and shown only to the panel
//! - [`media`]: image metadata: which kinds a picture carries, and a copy without them
//! - [`nac`]: the network access gate every exposed service asks for
//! - [`parcel`]: packages, with custody as a coin from shipper to addressee
//! - [`pay`]: the payment handshake, sending only what a payment needs
//! - [`swap`]: old coins in, fresh coins out
//! - [`vault`]: sealing a wallet's state, and making old copies useless

pub mod board;
pub mod bulletin;
pub mod dispute;
pub mod evidence;
pub mod media;
pub mod nac;
pub mod net;
pub mod node;
pub mod parcel;
pub mod pay;
pub mod report;
pub mod swap;
pub mod vault;
