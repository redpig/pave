//! A local view: the state one site knows, built by applying signed records.
//!
//! There is no global order. Records made apart, even offline, merge later.
//! Locally the first spend of a state seen wins; a second spend of the same
//! state by the same holder is kept only as [`Evidence`] (kernel invariant 6).

use crate::hash::Hash;
use crate::objects::{rights, Coin, Evidence, Genesis, Kind, Op, Record, Schema, Scope, Shared};
use crate::scheme::{Credential, Scheme};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Why a record was refused. A refused record changes nothing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Reject {
    #[error("bad signature")]
    BadSignature,
    #[error("wrong number of signatures")]
    SignatureCount,
    #[error("signer does not hold {0:?}")]
    NotHolder(Hash),
    #[error("unknown state {0:?} (its provenance hasn't arrived)")]
    UnknownState(Hash),
    #[error("unknown capability {0:?}")]
    UnknownCapability(Hash),
    #[error("unknown scope {0:?}")]
    UnknownScope(Hash),
    #[error("capability lacks the right {0}")]
    MissingRight(&'static str),
    #[error("derived rights exceed the parent's")]
    Widening,
    #[error("child scope is looser than its parent")]
    LooserScope,
    #[error("amounts don't balance")]
    Unbalanced,
    #[error("schema is not divisible")]
    NotDivisible,
    #[error("over the per-holder amount")]
    OverPerHolder,
    #[error("wrong kind of capability")]
    WrongKind,
    #[error("mixed schemas")]
    MixedSchemas,
    #[error("sender lacks a required capability")]
    NotAllowedToSend,
    #[error("malformed operation")]
    Malformed,
}

/// What applying a record did.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// New: its outputs are now known.
    Accepted,
    /// Already known.
    Duplicate,
    /// It reused a state already spent by the same holder. Not applied (first
    /// seen wins); evidence recorded against the signer.
    Conflict(Hash),
}

/// The first spend of a state seen here.
#[derive(Clone, Debug)]
pub struct Spent {
    pub record: Record,
    pub nym: Vec<u8>,
}

/// Running totals per schema, for conservation (kernel invariant 1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub issued: u64,
    pub minted: u64,
    pub retired_value: u64,
    pub retired_budget: u64,
}

#[derive(Clone)]
pub struct View<S: Scheme> {
    scheme: S,
    genesis: Genesis,
    pub(crate) scopes: BTreeMap<Hash, Scope>,
    pub(crate) shared: BTreeMap<Hash, Shared>,
    pub(crate) schemas: BTreeMap<Hash, Schema>,
    pub(crate) unspent: BTreeMap<Hash, Coin>,
    pub(crate) spent: BTreeMap<Hash, Spent>,
    pub(crate) totals: BTreeMap<Hash, Totals>,
    /// Applied records, in the order applied here.
    pub(crate) records: Vec<Record>,
    /// Records refused as conflicts, kept so evidence can be relayed.
    pub(crate) conflicts: Vec<Record>,
    pub(crate) messages: Vec<Record>,
    pub(crate) evidence: BTreeMap<Hash, Evidence>,
    /// Which applied record created each state, as an index into `records`.
    created: BTreeMap<Hash, usize>,
    known: BTreeSet<Hash>,
}

impl<S: Scheme> View<S> {
    pub fn new(scheme: S, genesis: Genesis) -> Self {
        let root = Scope { id: genesis.root_scope(), parent: None, rules: genesis.root_rules.clone() };
        let rooting = Shared {
            id: genesis.rooting_capability(),
            parent: None,
            schema: None,
            rights: [rights::CREATE_SCOPE, rights::ISSUE].iter().map(|s| s.to_string()).collect(),
            holder: genesis.rooting.clone(),
        };
        let mut v = View {
            scheme,
            genesis,
            scopes: BTreeMap::new(),
            shared: BTreeMap::new(),
            schemas: BTreeMap::new(),
            unspent: BTreeMap::new(),
            spent: BTreeMap::new(),
            totals: BTreeMap::new(),
            records: Vec::new(),
            conflicts: Vec::new(),
            messages: Vec::new(),
            evidence: BTreeMap::new(),
            created: BTreeMap::new(),
            known: BTreeSet::new(),
        };
        v.scopes.insert(root.id, root);
        v.shared.insert(rooting.id, rooting);
        v
    }

    pub fn scheme(&self) -> &S {
        &self.scheme
    }
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }
    pub fn coin(&self, state: &Hash) -> Option<&Coin> {
        self.unspent.get(state)
    }
    pub fn coins_held_by<'a>(&'a self, cred: &'a Credential) -> impl Iterator<Item = &'a Coin> {
        self.unspent.values().filter(move |c| &c.holder == cred)
    }
    pub fn shared(&self, id: &Hash) -> Option<&Shared> {
        self.shared.get(id)
    }
    pub fn scope(&self, id: &Hash) -> Option<&Scope> {
        self.scopes.get(id)
    }
    pub fn schema(&self, id: &Hash) -> Option<&Schema> {
        self.schemas.get(id)
    }
    pub fn evidence(&self) -> impl Iterator<Item = &Evidence> {
        self.evidence.values()
    }
    /// The record that created `state`, spent or not.
    pub fn creator(&self, state: &Hash) -> Option<&Record> {
        self.created.get(state).map(|&i| &self.records[i])
    }
    /// The first spend of `state` seen here, if it has been spent.
    pub fn spender(&self, state: &Hash) -> Option<&Record> {
        self.spent.get(state).map(|s| &s.record)
    }
    /// Every outstanding state.
    pub fn unspent(&self) -> impl Iterator<Item = &Coin> {
        self.unspent.values()
    }
    /// Records refused as conflicts, kept so their evidence can be relayed.
    pub fn conflicts(&self) -> &[Record] {
        &self.conflicts
    }
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    pub fn messages(&self) -> &[Record] {
        &self.messages
    }
    pub fn totals(&self, schema: &Hash) -> Totals {
        self.totals.get(schema).cloned().unwrap_or_default()
    }
    /// Signers this view holds evidence against.
    pub fn flagged(&self) -> BTreeSet<Credential> {
        self.evidence.values().map(|e| e.signer.clone()).collect()
    }

    /// Apply one signed record.
    pub fn apply(&mut self, rec: &Record) -> Result<Applied, Reject> {
        let id = rec.id();
        if self.known.contains(&id) {
            return Ok(Applied::Duplicate);
        }
        let consumes = rec.op.consumes();
        let msg = rec.op.signing_bytes();

        // Signatures first: nothing unsigned can count as evidence or input.
        let mut nyms = Vec::with_capacity(consumes.len());
        if consumes.is_empty() {
            if rec.sigs.len() != 1 {
                return Err(Reject::SignatureCount);
            }
            if !self.scheme.verify(&rec.signer, &msg, None, &rec.sigs[0]) {
                return Err(Reject::BadSignature);
            }
        } else {
            if rec.sigs.len() != consumes.len() {
                return Err(Reject::SignatureCount);
            }
            let distinct: BTreeSet<_> = consumes.iter().collect();
            if distinct.len() != consumes.len() {
                return Err(Reject::Malformed);
            }
            for (state, sig) in consumes.iter().zip(&rec.sigs) {
                if !self.scheme.verify(&rec.signer, &msg, Some(state.as_bytes()), sig) {
                    return Err(Reject::BadSignature);
                }
                nyms.push(self.scheme.nym(sig).ok_or(Reject::BadSignature)?);
            }
        }

        // A reused state: first seen wins, the second becomes evidence.
        for (i, state) in consumes.iter().enumerate() {
            if let Some(first) = self.spent.get(state) {
                if first.record.signer != rec.signer || first.nym != nyms[i] {
                    // Someone other than the holder: not a double use, a forgery.
                    return Err(Reject::NotHolder(*state));
                }
                let ev = Evidence {
                    basename: *state,
                    signer: rec.signer.clone(),
                    nym: nyms[i].clone(),
                    first: first.record.clone(),
                    second: rec.clone(),
                };
                self.evidence.entry(*state).or_insert(ev);
                self.known.insert(id);
                self.conflicts.push(rec.clone());
                return Ok(Applied::Conflict(*state));
            }
        }

        let inputs: Vec<Coin> = consumes
            .iter()
            .map(|s| {
                let c = self.unspent.get(s).ok_or(Reject::UnknownState(*s))?;
                if c.holder != rec.signer {
                    return Err(Reject::NotHolder(*s));
                }
                Ok(c.clone())
            })
            .collect::<Result<_, _>>()?;

        let effect = self.effect(rec, &inputs)?;

        // Commit.
        for (state, nym) in consumes.iter().zip(nyms) {
            self.unspent.remove(state);
            self.spent.insert(*state, Spent { record: rec.clone(), nym });
        }
        for coin in effect.coins {
            self.created.insert(coin.state, self.records.len());
            self.unspent.insert(coin.state, coin);
        }
        if let Some(s) = effect.scope {
            self.scopes.insert(s.id, s);
        }
        if let Some(s) = effect.shared {
            self.shared.insert(s.id, s);
        }
        if let Some(s) = effect.schema {
            self.schemas.entry(s.id()).or_insert(s);
        }
        if let Some((schema, delta)) = effect.totals {
            let t = self.totals.entry(schema).or_default();
            t.issued += delta.issued;
            t.minted += delta.minted;
            t.retired_value += delta.retired_value;
            t.retired_budget += delta.retired_budget;
        }
        if effect.message {
            self.messages.push(rec.clone());
        }
        self.known.insert(id);
        self.records.push(rec.clone());
        Ok(Applied::Accepted)
    }

    /// Validate a record against its inputs and compute what it creates.
    /// Pure: changes nothing.
    fn effect(&self, rec: &Record, inputs: &[Coin]) -> Result<Effect, Reject> {
        let mut e = Effect::default();
        match &rec.op {
            Op::CreateScope { parent, rules, authority } => {
                self.authorize(authority, &rec.signer, rights::CREATE_SCOPE)?;
                let p = self.scopes.get(parent).ok_or(Reject::UnknownScope(*parent))?;
                if !rules.within(&p.rules) {
                    return Err(Reject::LooserScope);
                }
                e.scope = Some(Scope { id: rec.output(0), parent: Some(*parent), rules: rules.clone() });
            }
            Op::Derive { parent, rights, to } => {
                let p = self.shared.get(parent).ok_or(Reject::UnknownCapability(*parent))?;
                if p.holder != rec.signer {
                    return Err(Reject::NotHolder(*parent));
                }
                if !rights.is_subset(&p.rights) {
                    return Err(Reject::Widening);
                }
                e.shared = Some(Shared {
                    id: rec.output(0),
                    parent: Some(*parent),
                    schema: p.schema,
                    rights: rights.clone(),
                    holder: to.clone(),
                });
            }
            Op::IssueBudget { authority, schema, amount, to } => {
                self.authorize(authority, &rec.signer, rights::ISSUE)?;
                if *amount == 0 {
                    return Err(Reject::Malformed);
                }
                let sid = schema.id();
                e.coins.push(Coin {
                    state: rec.output(0),
                    origin: rec.output(0),
                    kind: Kind::MintBudget,
                    schema: sid,
                    amount: *amount,
                    holder: to.clone(),
                    hops: 0,
                    history: vec![to.clone()],
                });
                e.schema = Some(schema.clone());
                e.totals = Some((sid, Totals { issued: *amount, ..Default::default() }));
            }
            Op::Mint { amount, to, change_to, .. } => {
                let b = &inputs[0];
                if b.kind != Kind::MintBudget {
                    return Err(Reject::WrongKind);
                }
                if *amount == 0 || *amount > b.amount {
                    return Err(Reject::Unbalanced);
                }
                self.check_per_holder(&b.schema, *amount)?;
                e.coins.push(Coin {
                    state: rec.output(0),
                    origin: rec.output(0),
                    kind: Kind::Value,
                    schema: b.schema,
                    amount: *amount,
                    holder: to.clone(),
                    hops: 0,
                    history: vec![to.clone()],
                });
                if b.amount > *amount {
                    e.coins.push(Coin {
                        state: rec.output(1),
                        origin: b.origin,
                        kind: Kind::MintBudget,
                        schema: b.schema,
                        amount: b.amount - amount,
                        holder: change_to.clone(),
                        hops: 0,
                        history: vec![change_to.clone()],
                    });
                }
                e.totals = Some((b.schema, Totals { minted: *amount, ..Default::default() }));
            }
            Op::Transfer { to, .. } => {
                let c = &inputs[0];
                e.coins.push(moved(c, rec.output(0), c.amount, to));
            }
            Op::Split { parts, .. } => {
                let c = &inputs[0];
                if parts.is_empty() {
                    return Err(Reject::Malformed);
                }
                let mut sum: u64 = 0;
                for (amount, _) in parts {
                    sum = sum.checked_add(*amount).ok_or(Reject::Unbalanced)?;
                    self.check_per_holder(&c.schema, *amount)?;
                }
                if sum != c.amount {
                    return Err(Reject::Unbalanced);
                }
                let nonzero = parts.iter().filter(|(a, _)| *a > 0).count();
                let divisible = self.schemas.get(&c.schema).is_some_and(|s| s.divisible);
                if !divisible && nonzero > 1 {
                    return Err(Reject::NotDivisible);
                }
                for (i, (amount, to)) in parts.iter().enumerate() {
                    e.coins.push(moved(c, rec.output(i as u32), *amount, to));
                }
            }
            Op::Merge { to, .. } => {
                if inputs.len() < 2 {
                    return Err(Reject::Malformed);
                }
                let first = &inputs[0];
                let mut sum: u64 = 0;
                let mut hops = 0;
                let mut history: Vec<Credential> = Vec::new();
                for c in inputs {
                    if c.schema != first.schema {
                        return Err(Reject::MixedSchemas);
                    }
                    if c.kind != first.kind {
                        return Err(Reject::WrongKind);
                    }
                    sum = sum.checked_add(c.amount).ok_or(Reject::Unbalanced)?;
                    hops = hops.max(c.hops);
                    for h in &c.history {
                        if !history.contains(h) {
                            history.push(h.clone());
                        }
                    }
                }
                self.check_per_holder(&first.schema, sum)?;
                if !history.contains(to) {
                    history.push(to.clone());
                }
                e.coins.push(Coin {
                    state: rec.output(0),
                    origin: rec.output(0),
                    kind: first.kind.clone(),
                    schema: first.schema,
                    amount: sum,
                    holder: to.clone(),
                    hops: hops + 1,
                    history,
                });
            }
            Op::Retire { .. } => {
                let c = &inputs[0];
                let delta = match c.kind {
                    Kind::Value => Totals { retired_value: c.amount, ..Default::default() },
                    Kind::MintBudget => Totals { retired_budget: c.amount, ..Default::default() },
                };
                e.totals = Some((c.schema, delta));
            }
            Op::Send { scope, presenting, .. } => {
                let s = self.scopes.get(scope).ok_or(Reject::UnknownScope(*scope))?;
                if !s.rules.senders.is_empty() {
                    let cap = presenting
                        .and_then(|p| self.shared.get(&p))
                        .ok_or(Reject::NotAllowedToSend)?;
                    let ok = cap.holder == rec.signer
                        && cap.schema.is_some_and(|sc| s.rules.senders.contains(&sc));
                    if !ok {
                        return Err(Reject::NotAllowedToSend);
                    }
                }
                e.message = true;
            }
        }
        Ok(e)
    }

    fn authorize(&self, cap: &Hash, signer: &Credential, right: &'static str) -> Result<(), Reject> {
        let c = self.shared.get(cap).ok_or(Reject::UnknownCapability(*cap))?;
        if &c.holder != signer {
            return Err(Reject::NotHolder(*cap));
        }
        if !c.rights.contains(right) {
            return Err(Reject::MissingRight(right));
        }
        Ok(())
    }

    fn check_per_holder(&self, schema: &Hash, amount: u64) -> Result<(), Reject> {
        match self.schemas.get(schema).and_then(|s| s.max_per_holder) {
            Some(max) if amount > max => Err(Reject::OverPerHolder),
            _ => Ok(()),
        }
    }

    /// Accept evidence from elsewhere (gossip). Only self-certifying evidence
    /// is kept: two valid signatures by one holder over one state.
    pub fn import_evidence(&mut self, ev: &Evidence) -> bool {
        if !verify_evidence(&self.scheme, ev) {
            return false;
        }
        self.evidence.entry(ev.basename).or_insert_with(|| ev.clone());
        true
    }

    /// Merge another view's records into this one. Records are applied in the
    /// other's order, so provenance arrives before what depends on it. Where
    /// both views spent the same state, ours stands and the other's becomes
    /// evidence. Returns the basenames with new evidence.
    pub fn merge_from(&mut self, other: &View<S>) -> Vec<Hash> {
        let before: BTreeSet<Hash> = self.evidence.keys().copied().collect();
        for rec in other.records.iter().chain(other.conflicts.iter()) {
            let _ = self.apply(rec);
        }
        for ev in other.evidence.values() {
            self.import_evidence(ev);
        }
        self.evidence.keys().filter(|k| !before.contains(k)).copied().collect()
    }
}

#[derive(Default)]
struct Effect {
    coins: Vec<Coin>,
    scope: Option<Scope>,
    shared: Option<Shared>,
    schema: Option<Schema>,
    totals: Option<(Hash, Totals)>,
    message: bool,
}

fn moved(c: &Coin, state: Hash, amount: u64, to: &Credential) -> Coin {
    let mut history = c.history.clone();
    if history.last() != Some(to) {
        history.push(to.clone());
    }
    Coin {
        state,
        origin: c.origin,
        kind: c.kind.clone(),
        schema: c.schema,
        amount,
        holder: to.clone(),
        hops: c.hops + 1,
        history,
    }
}

/// Check evidence on its own: two different records, both using `basename`,
/// both signed by `signer` with that basename, both carrying `nym`.
pub fn verify_evidence<S: Scheme>(scheme: &S, ev: &Evidence) -> bool {
    if ev.first == ev.second {
        return false;
    }
    [&ev.first, &ev.second].iter().all(|rec| {
        if rec.signer != ev.signer {
            return false;
        }
        let consumes = rec.op.consumes();
        let Some(i) = consumes.iter().position(|s| s == &ev.basename) else {
            return false;
        };
        let Some(sig) = rec.sigs.get(i) else {
            return false;
        };
        scheme.verify(&rec.signer, &rec.op.signing_bytes(), Some(ev.basename.as_bytes()), sig)
            && scheme.nym(sig).as_deref() == Some(ev.nym.as_slice())
    })
}
