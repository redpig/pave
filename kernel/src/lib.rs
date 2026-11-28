//! The pave kernel.
//!
//! Three objects (scope, capability, message), holding under credentials,
//! schemas as data, receipts, five operations and six invariants. No time, no
//! roles and no code: see `spec/kernel.md`.
//!
//! - [`objects`]: the objects and the signed records that create and move them
//! - [`view`]: applying records to a local view, first seen wins, evidence, merge
//! - [`receipt`]: salted, nested receipt hashes with partial reveal
//! - [`scheme`]: the credential-scheme slot ([`scheme::DevScheme`] for tests)
//! - [`invariants`]: runtime checks named as in the TLA+ models

pub mod hash;
pub mod invariants;
pub mod objects;
pub mod receipt;
pub mod scheme;
pub mod view;

pub use hash::Hash;
pub use objects::{Coin, Evidence, Genesis, Kind, Op, Record, Schema, Scope, ScopeRules, Shared};
pub use scheme::{Credential, Scheme, Sig};
pub use view::{verify_evidence, Applied, Reject, View};

/// Sign an operation as the holder of `signer`: one basename-signature per
/// state it uses up, or one plain signature.
pub fn sign<S: Scheme>(scheme: &S, key: &S::HolderKey, signer: &Credential, op: Op) -> Record {
    let msg = op.signing_bytes();
    let consumes = op.consumes();
    let sigs = if consumes.is_empty() {
        vec![scheme.sign(key, signer, &msg, None)]
    } else {
        consumes
            .iter()
            .map(|s| scheme.sign(key, signer, &msg, Some(s.as_bytes())))
            .collect()
    };
    Record {
        op,
        signer: signer.clone(),
        sigs,
    }
}
