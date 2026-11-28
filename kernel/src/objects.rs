//! Kernel objects: scopes, capabilities (shared and exclusive), messages, and
//! the signed records that create and move them. See `spec/kernel.md`.

use crate::hash::{hash_of, Hash};
use crate::scheme::{Credential, Sig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A capability's operation rules, chosen from a closed menu. Data, not code.
/// A schema never says who may accept it. The kernel enforces divisibility and
/// the per-holder amount; expiry and the offline-transfer limit are carried
/// for recipients, who decide whether to honor them (protocol layer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    /// Human label; not interpreted.
    pub label: String,
    pub divisible: bool,
    /// Soft and hard expiry, in epochs of `sequence`, counted from each
    /// holding credential in the history. Honoring them is the recipient's
    /// choice; the kernel keeps no time.
    pub soft_expiry: Option<u32>,
    pub hard_expiry: Option<u32>,
    /// Transfers allowed before a swap. Recipient-checked.
    pub offline_transfers: Option<u32>,
    /// The most one capability held under one credential may carry.
    pub max_per_holder: Option<u64>,
    /// The epoch sequence expiry is counted in, if any.
    pub sequence: Option<Hash>,
}

impl Schema {
    /// A schema is identified by the hash of its settings, so it can't change
    /// after creation (kernel invariant 5).
    pub fn id(&self) -> Hash {
        hash_of("pave/schema", self)
    }
}

/// A scope's rules. Scopes hold nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRules {
    /// Schemas a sender must present a shared capability under. Empty means
    /// anyone may send.
    pub senders: BTreeSet<Hash>,
    /// Which schemas count in this scope, and from which roots: (schema, root).
    /// Empty means no restriction.
    pub accepts: BTreeSet<(Hash, Hash)>,
    /// How long it lasts: a reference to a protocol expiry, opaque here.
    pub lifetime: Option<Hash>,
}

impl ScopeRules {
    /// A child is never looser than its parent.
    pub fn within(&self, parent: &ScopeRules) -> bool {
        let senders_ok = parent.senders.is_empty()
            || (!self.senders.is_empty() && self.senders.is_subset(&parent.senders));
        let accepts_ok = parent.accepts.is_empty()
            || (!self.accepts.is_empty() && self.accepts.is_subset(&parent.accepts));
        let lifetime_ok = parent.lifetime.is_none() || self.lifetime == parent.lifetime;
        senders_ok && accepts_ok && lifetime_ok
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub id: Hash,
    pub parent: Option<Hash>,
    pub rules: ScopeRules,
}

/// Rights a shared capability can carry.
pub mod rights {
    pub const CREATE_SCOPE: &str = "create-scope";
    pub const ISSUE: &str = "issue";
}

/// A shared capability: a right to act. Deriving narrows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shared {
    pub id: Hash,
    pub parent: Option<Hash>,
    pub schema: Option<Hash>,
    pub rights: BTreeSet<String>,
    pub holder: Credential,
}

/// What an exclusive capability is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// A resource under a schema: value, time, votes, a certification.
    Value,
    /// A mint right: the budget for minting `Value` under this schema.
    MintBudget,
}

/// The current state of an exclusive capability. Each state is used once:
/// a second use by the same holder is a detectable conflict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    /// This state's id, used as the basename when it is spent.
    pub state: Hash,
    /// The capability this state belongs to: the state it had when minted or
    /// issued. Moves and splits keep it; a merge starts a new one.
    pub origin: Hash,
    pub kind: Kind,
    pub schema: Hash,
    pub amount: u64,
    pub holder: Credential,
    /// Transfers since mint or swap, for the recipient's offline-limit check.
    pub hops: u32,
    /// Every credential this capability has been held under, for the
    /// recipient's expiry check across history.
    pub history: Vec<Credential>,
}

/// The initial state: one root scope and one rooting capability that can
/// create the first scopes and capabilities but not change them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub label: String,
    pub root_rules: ScopeRules,
    pub rooting: Credential,
}

impl Genesis {
    pub fn root_scope(&self) -> Hash {
        hash_of("pave/genesis/scope", self)
    }
    pub fn rooting_capability(&self) -> Hash {
        hash_of("pave/genesis/rooting", self)
    }
}

/// An operation. Each is carried by a signed [`Record`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Scope: create a child, under a shared capability with `create-scope`.
    CreateScope {
        parent: Hash,
        rules: ScopeRules,
        authority: Hash,
    },
    /// Capability: derive a narrower shared capability.
    Derive {
        parent: Hash,
        rights: BTreeSet<String>,
        to: Credential,
    },
    /// Create a mint right (a budget) for a new schema, under `issue`.
    IssueBudget {
        authority: Hash,
        schema: Schema,
        amount: u64,
        to: Credential,
    },
    /// Mint value by spending a budget state; any remainder stays a budget.
    Mint {
        budget: Hash,
        amount: u64,
        to: Credential,
        change_to: Credential,
    },
    /// Move an exclusive capability to be held under another credential.
    Transfer {
        state: Hash,
        to: Credential,
        receipt: Hash,
    },
    /// Divide one state into parts; zero-value parts prove possession.
    Split {
        state: Hash,
        parts: Vec<(u64, Credential)>,
        receipt: Hash,
    },
    /// Combine states of one schema, all held by the signer.
    Merge {
        states: Vec<Hash>,
        to: Credential,
        receipt: Hash,
    },
    /// Remove a state from what is outstanding.
    Retire { state: Hash },
    /// Message: send to a scope, presenting a shared capability if required.
    Send {
        scope: Hash,
        presenting: Option<Hash>,
        body: Vec<u8>,
        receipt: Hash,
    },
}

impl Op {
    /// The exclusive states this operation uses up, in signature order.
    pub fn consumes(&self) -> Vec<Hash> {
        match self {
            Op::Mint { budget, .. } => vec![*budget],
            Op::Transfer { state, .. } | Op::Split { state, .. } | Op::Retire { state } => {
                vec![*state]
            }
            Op::Merge { states, .. } => states.clone(),
            _ => vec![],
        }
    }

    /// The bytes every signature in a record covers.
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::hash::encode(&("pave/op/v0", self))
    }
}

/// A signed operation. Ops that use up exclusive states carry one
/// basename-signature per state (basename = the state id); others carry one
/// plain signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub op: Op,
    pub signer: Credential,
    pub sigs: Vec<Sig>,
}

impl Record {
    pub fn id(&self) -> Hash {
        hash_of("pave/record", self)
    }

    /// The id of output `index` this record creates.
    pub fn output(&self, index: u32) -> Hash {
        hash_of("pave/output", &(self.id(), index))
    }
}

/// Self-certifying proof that one holder used one state twice. Anyone with
/// the scheme can check it; it names only the signer, never a recipient
/// (kernel invariant 6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// The state used twice (the shared basename).
    pub basename: Hash,
    /// The signer's credential and the nym both signatures carry.
    pub signer: Credential,
    #[serde(with = "serde_bytes")]
    pub nym: Vec<u8>,
    pub first: Record,
    pub second: Record,
}

impl Evidence {
    /// The (basename, pseudonym) pair that identifies the cheat's key, for
    /// asking anyone to prove they aren't it (`Scheme::prove_not_cheat`).
    pub fn cheat(&self) -> (Vec<u8>, Vec<u8>) {
        (self.basename.as_bytes().to_vec(), self.nym.clone())
    }
}
