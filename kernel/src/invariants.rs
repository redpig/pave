//! Runtime checks for the kernel invariants, named as in the TLA+ models.
//! See `formal/TRACEABILITY.md` for the mapping from each check to its
//! kernel invariant, TLA+ property and tests.

use crate::hash::Hash;
use crate::objects::Kind;
use crate::scheme::{Credential, Scheme};
use crate::view::{verify_evidence, Applied, View};
use std::collections::{BTreeMap, BTreeSet};

/// Kernel invariant 1, Conservation. Mirrors `OneView` / conservation in
/// `formal/CivicSequences.tla`. Per schema, what is outstanding equals what
/// was minted less what was retired, and minting never exceeds the issued
/// budget.
pub fn conservation<S: Scheme>(v: &View<S>) -> Result<(), String> {
    let mut value: BTreeMap<Hash, u64> = BTreeMap::new();
    let mut budget: BTreeMap<Hash, u64> = BTreeMap::new();
    for c in v.unspent.values() {
        let m = if c.kind == Kind::Value { &mut value } else { &mut budget };
        *m.entry(c.schema).or_default() += c.amount;
    }
    let schemas: BTreeSet<Hash> =
        v.totals.keys().chain(value.keys()).chain(budget.keys()).copied().collect();
    for s in schemas {
        let t = v.totals(&s);
        let val = value.get(&s).copied().unwrap_or(0);
        let bud = budget.get(&s).copied().unwrap_or(0);
        if val + t.retired_value != t.minted {
            return Err(format!("schema {s:?}: outstanding {val} + retired {} != minted {}", t.retired_value, t.minted));
        }
        if bud + t.minted + t.retired_budget != t.issued {
            return Err(format!("schema {s:?}: budget {bud} + minted {} + retired {} != issued {}", t.minted, t.retired_budget, t.issued));
        }
    }
    Ok(())
}

/// Kernel invariant 2, Consent. Mirrors `Consent` in every TLA+ model: every
/// accepted record was signed by the holder of what it moved. Checked by
/// replaying the records into a fresh view: each must be accepted again and
/// the outstanding states must come out the same.
pub fn consent<S: Scheme + Clone>(v: &View<S>) -> Result<(), String> {
    let mut fresh = View::new(v.scheme().clone(), v.genesis().clone());
    for rec in v.records() {
        match fresh.apply(rec) {
            Ok(Applied::Accepted) => {}
            other => return Err(format!("record {:?} replays as {other:?}", rec.id())),
        }
    }
    if fresh.unspent != v.unspent {
        return Err("replay produced different outstanding states".into());
    }
    Ok(())
}

/// Kernel invariant 5, Fixed at creation. Every outstanding capability names
/// a schema this view knows, and a schema's id is the hash of its settings.
pub fn fixed_at_creation<S: Scheme>(v: &View<S>) -> Result<(), String> {
    for (id, s) in &v.schemas {
        if &s.id() != id {
            return Err(format!("schema {id:?} doesn't hash to its id"));
        }
    }
    for c in v.unspent.values() {
        if !v.schemas.contains_key(&c.schema) {
            return Err(format!("state {:?} names an unknown schema", c.state));
        }
    }
    Ok(())
}

/// Kernel invariant 6, Detectable conflict. Mirrors `Detected` and
/// `EpochDetected`: every pair of records this view holds that use the same
/// state under the same signer has evidence, and all evidence verifies.
pub fn detected<S: Scheme>(v: &View<S>) -> Result<(), String> {
    let mut uses: BTreeMap<(Hash, Credential), BTreeSet<Hash>> = BTreeMap::new();
    for rec in v.records.iter().chain(v.conflicts.iter()) {
        for s in rec.op.consumes() {
            uses.entry((s, rec.signer.clone())).or_default().insert(rec.id());
        }
    }
    for ((state, _), recs) in uses {
        if recs.len() > 1 && !v.evidence.contains_key(&state) {
            return Err(format!("state {state:?} used twice without evidence"));
        }
    }
    for ev in v.evidence.values() {
        if !verify_evidence(v.scheme(), ev) {
            return Err(format!("evidence for {:?} doesn't verify", ev.basename));
        }
    }
    Ok(())
}

/// Mirrors `NoFalseFlag`: evidence never names anyone in `honest`.
pub fn no_false_flag<S: Scheme>(v: &View<S>, honest: &BTreeSet<Credential>) -> Result<(), String> {
    match v.flagged().intersection(honest).next() {
        Some(c) => Err(format!("honest {c:?} flagged")),
        None => Ok(()),
    }
}

/// All the checks that need nothing outside the view.
pub fn check_all<S: Scheme + Clone>(v: &View<S>) -> Result<(), String> {
    conservation(v)?;
    consent(v)?;
    fixed_at_creation(v)?;
    detected(v)?;
    Ok(())
}
