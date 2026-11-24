//! Two-tier gossip, an optimization. See "Gossip, an optimization in two
//! tiers" in `spec/protocol.md` and `formal/CivicTiered.tla`.
//!
//! - Compressed: hints only, sized to fit one mesh packet. A head hint names a
//!   sequence, an epoch number and the epoch state's prefix; a fork hint names
//!   a prefix of a state used twice. Hints are unverified and never decide
//!   anything.
//! - Extended: proofs, fetched per hint (have/want). Signed epoch records and
//!   their data, and conflict evidence. The receiver's kernel checks every
//!   signature.
//!
//! Gossip never carries transfer records other than epoch rolls, so it
//! carries no transaction graph.

use crate::accept::Knowledge;
use crate::epochs::{chain_since, head, EpochData};
use pave_kernel::{Evidence, Hash, Record, Scheme, View};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Bytes in one Meshtastic packet's payload, roughly.
pub const PACKET_BYTES: usize = 231;
pub const HEAD_HINT_BYTES: usize = 21;
pub const FORK_HINT_BYTES: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Hint {
    Head { sequence: [u8; 8], number: u32, tag: [u8; 8] },
    Fork { state: [u8; 10] },
}

fn prefix<const N: usize>(h: &Hash) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&h.0[..N]);
    out
}

impl Hint {
    pub fn head(sequence: &Hash, number: u32, state: &Hash) -> Self {
        Hint::Head { sequence: prefix(sequence), number, tag: prefix(state) }
    }
    pub fn fork(state: &Hash) -> Self {
        Hint::Fork { state: prefix(state) }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Hint::Head { sequence, number, tag } => {
                out.push(1);
                out.extend_from_slice(sequence);
                out.extend_from_slice(&number.to_be_bytes());
                out.extend_from_slice(tag);
            }
            Hint::Fork { state } => {
                out.push(2);
                out.extend_from_slice(state);
            }
        }
    }
}

/// Pack hints into frames of at most one packet each.
pub fn compressed_frames(hints: &[Hint]) -> Vec<Vec<u8>> {
    let mut frames = vec![Vec::new()];
    for h in hints {
        let mut b = Vec::new();
        h.encode_into(&mut b);
        if frames.last().unwrap().len() + b.len() > PACKET_BYTES {
            frames.push(Vec::new());
        }
        frames.last_mut().unwrap().extend_from_slice(&b);
    }
    frames
}

/// Decode one compressed frame.
pub fn decode_frame(mut b: &[u8]) -> Option<Vec<Hint>> {
    let mut out = Vec::new();
    while let Some((&tag, rest)) = b.split_first() {
        match tag {
            1 if rest.len() >= 20 => {
                out.push(Hint::Head {
                    sequence: rest[..8].try_into().ok()?,
                    number: u32::from_be_bytes(rest[8..12].try_into().ok()?),
                    tag: rest[12..20].try_into().ok()?,
                });
                b = &rest[20..];
            }
            2 if rest.len() >= 10 => {
                out.push(Hint::Fork { state: rest[..10].try_into().ok()? });
                b = &rest[10..];
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The hints this wallet offers: a head for each sequence it carries, a fork
/// hint for each piece of evidence it holds, and hints it has relayed.
pub fn hints<S: Scheme>(view: &View<S>, know: &Knowledge, carries: &BTreeSet<Hash>) -> Vec<Hint> {
    let mut out: BTreeSet<Hint> = know.hints.clone();
    for seq in carries {
        if let Some(h) = head(view, seq) {
            out.insert(Hint::head(seq, h.number, &h.state));
        }
    }
    for e in view.evidence() {
        out.insert(Hint::fork(&e.basename));
    }
    out.into_iter().collect()
}

/// Take in a peer's hints. They're kept only to decide what to ask for.
pub fn absorb_hints(know: &mut Knowledge, hints: &[Hint]) {
    know.hints.extend(hints.iter().copied());
}

/// What a wallet asks a peer for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Want {
    /// The records of a sequence after `have`, up to the hinted epoch.
    Epochs { sequence: [u8; 8], have: u32 },
    /// Evidence for a state matching this prefix.
    Evidence { state: [u8; 10] },
}

/// Per-hint triggers: a newer or different head for a sequence this wallet
/// relies on, or a fork hint naming a state in the history of a coin it
/// holds or is about to accept (`watch`). Everything else waits.
pub fn wants<S: Scheme>(
    view: &View<S>,
    know: &Knowledge,
    relies_on: &BTreeSet<Hash>,
    watch: &BTreeSet<Hash>,
) -> Vec<Want> {
    let mut out = Vec::new();
    let proven: BTreeSet<[u8; 10]> = view.evidence().map(|e| prefix(&e.basename)).collect();
    for h in &know.hints {
        match *h {
            Hint::Head { sequence, number, tag } => {
                let Some(seq) = relies_on.iter().find(|s| prefix::<8>(s) == sequence) else { continue };
                let mine = head(view, seq);
                let have = mine.as_ref().map_or(0, |m| m.number);
                let differs = mine.as_ref().is_some_and(|m| m.number == number && prefix::<8>(&m.state) != tag);
                if number > have || differs {
                    let have = if differs { number.saturating_sub(1) } else { have };
                    let w = Want::Epochs { sequence, have };
                    if !out.contains(&w) {
                        out.push(w);
                    }
                }
            }
            Hint::Fork { state } => {
                if !proven.contains(&state) && watch.iter().any(|s| prefix::<10>(s) == state) {
                    out.push(Want::Evidence { state });
                }
            }
        }
    }
    out
}

/// A proof served in the extended tier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    Records(Vec<Record>),
    EpochData(EpochData),
    Evidence(Box<Evidence>),
}

/// Answer a peer's wants from what this wallet can prove.
pub fn serve<S: Scheme>(view: &View<S>, know: &Knowledge, carries: &BTreeSet<Hash>, wants: &[Want]) -> Vec<Proof> {
    let mut out = Vec::new();
    for w in wants {
        match w {
            Want::Epochs { sequence, have } => {
                let Some(seq) = carries.iter().find(|s| prefix::<8>(s) == *sequence) else { continue };
                let recs = chain_since(view, seq, *have);
                if recs.is_empty() {
                    continue;
                }
                let data: Vec<Proof> = recs
                    .iter()
                    .filter_map(|r| match r.op {
                        pave_kernel::Op::Transfer { receipt, .. } => know.epoch_data.get(&receipt),
                        _ => None,
                    })
                    .map(|d| Proof::EpochData(d.clone()))
                    .collect();
                out.push(Proof::Records(recs));
                out.extend(data);
            }
            Want::Evidence { state } => {
                for e in view.evidence() {
                    if prefix::<10>(&e.basename) == *state {
                        out.push(Proof::Evidence(Box::new(e.clone())));
                    }
                }
            }
        }
    }
    out
}

/// Take in proofs. Records go through the kernel (signatures checked, and a
/// second version of an epoch becomes evidence); epoch data is kept only if a
/// signed roll commits to it; evidence only if it verifies.
pub fn absorb<S: Scheme>(view: &mut View<S>, know: &mut Knowledge, proofs: Vec<Proof>) {
    let mut data = Vec::new();
    for p in proofs {
        match p {
            Proof::Records(recs) => {
                for r in &recs {
                    let _ = view.apply(r);
                }
            }
            Proof::EpochData(d) => data.push(d),
            Proof::Evidence(e) => {
                view.import_evidence(&e);
            }
        }
    }
    for d in data {
        know.add_epoch_data(view, d);
    }
}

/// Bytes a set of proofs takes on the wire, for sizing.
pub fn proof_bytes(proofs: &[Proof]) -> usize {
    pave_kernel::hash::encode(&proofs).len()
}
