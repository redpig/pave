// DRAFT: not yet checked by Verus (the toolchain wasn't available where this
// was written). Run with `verus verus/spend.rs`.
//
// The security-critical step of `pave-kernel`'s `View::apply`, as a spec-level
// transition: spending one exclusive state. First seen wins; a second use by
// the same holder, with the same pseudonym, becomes evidence naming that
// holder. The lemmas mirror the TLA+ properties Consent, Detected and
// NoFalseFlag (see formal/TRACEABILITY.md).

use vstd::prelude::*;

verus! {

pub type StateId = int;
pub type Signer = int;

pub struct Coin {
    pub holder: Signer,
    pub amount: nat,
}

pub struct Spend {
    pub signer: Signer,
    pub nym: int,
    pub record: int,
}

pub struct Ledger {
    pub unspent: Map<StateId, Coin>,
    pub spent: Map<StateId, Spend>,
    /// Evidence, keyed by the state used twice, naming the signer.
    pub evidence: Map<StateId, Signer>,
}

pub enum Outcome {
    Accepted,
    Conflict,
    Rejected,
}

/// One spend of state `s` by `signer`, carrying pseudonym `nym`, in record `rec`.
/// Signature checks happen before this step and are assumed.
pub open spec fn step(l: Ledger, s: StateId, signer: Signer, nym: int, rec: int) -> (Ledger, Outcome) {
    if l.spent.contains_key(s) {
        let first = l.spent[s];
        if first.signer == signer && first.nym == nym && first.record != rec {
            let ev = if l.evidence.contains_key(s) { l.evidence } else { l.evidence.insert(s, signer) };
            (Ledger { unspent: l.unspent, spent: l.spent, evidence: ev }, Outcome::Conflict)
        } else {
            (l, Outcome::Rejected)
        }
    } else if l.unspent.contains_key(s) && l.unspent[s].holder == signer {
        (
            Ledger {
                unspent: l.unspent.remove(s),
                spent: l.spent.insert(s, Spend { signer, nym, record: rec }),
                evidence: l.evidence,
            },
            Outcome::Accepted,
        )
    } else {
        (l, Outcome::Rejected)
    }
}

/// Evidence only ever names whoever first spent that state, and a state is
/// never both spent and unspent.
pub open spec fn inv(l: Ledger) -> bool {
    &&& forall|s: StateId| #![auto] l.evidence.contains_key(s) ==>
            l.spent.contains_key(s) && l.evidence[s] == l.spent[s].signer
    &&& forall|s: StateId| #![auto] l.unspent.contains_key(s) ==> !l.spent.contains_key(s)
}

proof fn lemma_step_preserves_inv(l: Ledger, s: StateId, signer: Signer, nym: int, rec: int)
    requires inv(l),
    ensures inv(step(l, s, signer, nym, rec).0),
{
}

/// Consent: a spend is accepted only from the state's holder.
proof fn lemma_consent(l: Ledger, s: StateId, signer: Signer, nym: int, rec: int)
    requires step(l, s, signer, nym, rec).1 == Outcome::Accepted,
    ensures l.unspent.contains_key(s) && l.unspent[s].holder == signer,
{
}

/// Detected: a second, different spend by the same holder always leaves
/// evidence for that state.
proof fn lemma_detected(l: Ledger, s: StateId, signer: Signer, nym: int, rec: int)
    requires
        l.spent.contains_key(s),
        l.spent[s].signer == signer,
        l.spent[s].nym == nym,
        l.spent[s].record != rec,
    ensures step(l, s, signer, nym, rec).0.evidence.contains_key(s),
{
}

/// NoFalseFlag: evidence names only someone who spent that state. A recipient
/// never spent it, so a recipient is never named.
proof fn lemma_names_signer(l: Ledger, s: StateId, signer: Signer, nym: int, rec: int)
    requires inv(l),
    ensures
        forall|t: StateId| #![auto] step(l, s, signer, nym, rec).0.evidence.contains_key(t) ==>
            step(l, s, signer, nym, rec).0.spent.contains_key(t)
            && step(l, s, signer, nym, rec).0.evidence[t] == step(l, s, signer, nym, rec).0.spent[t].signer,
{
    lemma_step_preserves_inv(l, s, signer, nym, rec);
}

fn main() {}

} // verus!
