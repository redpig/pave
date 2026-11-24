//! Receipts: one root of salted, nested hashes, revealed branch by branch.
//!
//! A message commits to its receipts through a single root. Each leaf has its
//! own salt, so an unrevealed sibling leaks nothing, and a leaf can itself be
//! another receipt's root, so evidence chains without anything on the ledger.

use crate::hash::{hash_bytes, Hash};
use serde::{Deserialize, Serialize};

/// A receipt tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Receipt {
    Leaf { salt: [u8; 16], data: Vec<u8> },
    /// A labelled branch, e.g. "public", "parties", "private".
    Node(Vec<(String, Receipt)>),
}

impl Receipt {
    pub fn leaf(data: impl Into<Vec<u8>>) -> Self {
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        Receipt::Leaf { salt, data: data.into() }
    }

    pub fn root(&self) -> Hash {
        match self {
            Receipt::Leaf { salt, data } => {
                let mut b = salt.to_vec();
                b.extend_from_slice(data);
                hash_bytes("pave/receipt/leaf", &b)
            }
            Receipt::Node(children) => {
                let mut b = Vec::new();
                for (label, child) in children {
                    b.extend_from_slice(&(label.len() as u32).to_be_bytes());
                    b.extend_from_slice(label.as_bytes());
                    b.extend_from_slice(child.root().as_bytes());
                }
                hash_bytes("pave/receipt/node", &b)
            }
        }
    }

    /// Reveal the branch at `path`, hiding every sibling behind its hash.
    pub fn reveal(&self, path: &[&str]) -> Option<Disclosure> {
        match (self, path.split_first()) {
            (r, None) => Some(Disclosure::Revealed(r.clone())),
            (Receipt::Node(children), Some((head, rest))) => {
                let mut out = Vec::new();
                let mut found = false;
                for (label, child) in children {
                    if label == head && !found {
                        out.push((label.clone(), child.reveal(rest)?));
                        found = true;
                    } else {
                        out.push((label.clone(), Disclosure::Hidden(child.root())));
                    }
                }
                found.then_some(Disclosure::Node(out))
            }
            (Receipt::Leaf { .. }, Some(_)) => None,
        }
    }
}

/// A partial reveal of a receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disclosure {
    Hidden(Hash),
    Revealed(Receipt),
    Node(Vec<(String, Disclosure)>),
}

impl Disclosure {
    /// The root this disclosure commits to; compare it with a message's.
    pub fn root(&self) -> Hash {
        match self {
            Disclosure::Hidden(h) => *h,
            Disclosure::Revealed(r) => r.root(),
            Disclosure::Node(children) => {
                let mut b = Vec::new();
                for (label, child) in children {
                    b.extend_from_slice(&(label.len() as u32).to_be_bytes());
                    b.extend_from_slice(label.as_bytes());
                    b.extend_from_slice(child.root().as_bytes());
                }
                hash_bytes("pave/receipt/node", &b)
            }
        }
    }
}
