//! A civic work board on pave, and the node that runs one wallet.
//!
//! - [`bulletin`]: the board profile: a board is a clerk; a post spends a
//!   token from the board mint at a board server, bound by hash
//! - [`board`]: the job board (posts with proof of means, replies, accept,
//!   done; payment is a coin whose receipt commits to the job)
//! - [`node`]: a wallet's view, knowledge and keys, saved as a record log
//! - [`net`]: the peer link (meet, two-tier gossip) over TCP
//! - [`report`]: the civic reports board
//! - [`dispatch`]: a co-op's dispatch: members, daily caps and bans by a
//!   per-day pseudonym
//! - [`dispute`]: disputes as jobs, with appeals and arbiter reputation
//! - [`food`]: food delivery's outcomes: the board's clock as the time
//!   witness, the tamper seal, lateness
//! - [`election`]: a municipal election: a mint whose basename is the
//!   election and whose clock is its own
//! - [`evidence`]: evidence for dispute panels, held by the host and shown only to the panel
//! - [`media`]: image metadata: which kinds a picture carries, and a copy without them
//! - [`nac`]: the network access gate every exposed service asks for
//! - [`profile`]: profiles as data, which an app loads and acts on
//! - [`request`]: one request type for every mint, from a spec that is data
//! - [`slots`]: slotted basenames: unlinkable requests up to a budget, then
//!   linked ones
//! - [`parcel`]: packages, with custody as a coin from shipper to addressee
//! - [`pay`]: the payment handshake, sending only what a payment needs
//! - [`swap`]: old coins in, fresh coins out
//! - [`vault`]: sealing a wallet's state, and making old copies useless

pub mod board;
pub mod bulletin;
pub mod dispatch;
pub mod dispute;
pub mod election;
pub mod food;
pub mod link;
pub mod evidence;
pub mod media;
pub mod nac;
pub mod net;
pub mod node;
pub mod parcel;
pub mod profile;
pub mod pay;
pub mod report;
pub mod request;
pub mod slots;
pub mod swap;
pub mod vault;
