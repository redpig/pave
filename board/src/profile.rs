//! Profiles as data: a description an app can load and act on without code
//! for that profile.
//!
//! Every binding and receipt in pave is CBOR, so a profile describes them
//! exactly, and an app that builds the same CBOR computes the same hashes as
//! the profile's own code. A profile names:
//!
//! - **Schemas**, with what each state means.
//! - **Layouts**: the structures it hashes (a manifest, a post binding),
//!   as CBOR maps in field order, each field typed, with a hash domain.
//! - **Receipts**: hash_of(domain, parts), each part an expression.
//! - **Actions**: one kernel operation each (mint from a budget, transfer,
//!   retire), with the state it consumes, its target, its receipt, and what
//!   must hold first.
//! - **Walks**: how to read a state's history back as named steps (a
//!   parcel's custody), by matching each transfer's receipt.
//! - **Requests** (see [`crate::request`]) are already data.
//!
//! What can't be described this way yet (dispatch gating, remint rules,
//! tallies) stays in the profile's code; [`spec/profiles.md`] says how it
//! would come in as a pinned pure function.
//!
//! [`spec/profiles.md`]: ../../spec/profiles.md

use crate::node::{apply_ok, Node};
use ciborium::Value;
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Kind, Op, Record, Schema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A profile, as published.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub version: u32,
    #[serde(default)]
    pub doc: String,
    pub schemas: BTreeMap<String, SchemaDesc>,
    pub layouts: BTreeMap<String, Layout>,
    pub receipts: BTreeMap<String, Receipt>,
    pub actions: BTreeMap<String, Action>,
    #[serde(default)]
    pub walks: BTreeMap<String, Walk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchemaDesc {
    pub meaning: String,
    pub schema: Schema,
}

/// A structure the profile hashes: a CBOR map in field order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Layout {
    pub domain: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: Ty,
    /// The value when the caller gives none, as JSON.
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    #[serde(default)]
    pub doc: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ty {
    Hash,
    Credential,
    Text,
    U32,
    U64,
    /// None or the inner type; None when not given.
    Opt(Box<Ty>),
    /// Any CBOR value: an enum or a nested structure the caller builds.
    Any,
}

/// hash_of(domain, the part) for one part, or of the array of parts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub domain: String,
    pub parts: Vec<Expr>,
}

/// A value an action or receipt computes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expr {
    /// A parameter the caller gives.
    Param(String),
    /// A field of a map value.
    Field { of: Box<Expr>, name: String },
    /// The hash of a value under a layout's domain.
    Hash { layout: String, of: Box<Expr> },
    /// The hop count in context: the state's hops plus the action's offset,
    /// or the hop a walk is at.
    Hop,
}

/// One kernel operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    #[serde(default)]
    pub doc: String,
    pub state: StateSel,
    pub op: OpDesc,
    /// Added to the state's hops to give [`Expr::Hop`].
    #[serde(default)]
    pub hop: u32,
    #[serde(default)]
    pub requires: Vec<Pred>,
    /// Run the ordinary acceptance check on the state first.
    #[serde(default)]
    pub check: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateSel {
    /// An unspent state this wallet holds whose origin is this.
    Held { origin: Expr },
    /// A mint budget of this schema this wallet holds.
    Budget { schema: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpDesc {
    Transfer { to: Target, receipt: String },
    Retire,
    /// Mint one from the budget; the change stays with the budget's key.
    Mint { to: Target },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Param(String),
    /// A fresh ticketed key of this wallet's.
    Fresh,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pred {
    /// The state was made by a transfer carrying this receipt.
    CreatedWith { receipt: String },
    /// The state's holder is this credential.
    HolderIs(Expr),
}

/// Read a state's history as named steps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Walk {
    pub from: Expr,
    pub steps: Vec<WalkStep>,
    /// The label of a retire, which ends the walk.
    pub retire: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalkStep {
    pub receipt: String,
    pub label: String,
}

/// One step a walk found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stepped {
    pub label: String,
    pub signer: Credential,
    pub to: Option<Credential>,
}

pub type Params = BTreeMap<String, Value>;

/// A typed value as CBOR.
pub fn value<T: Serialize>(x: &T) -> Value {
    Value::serialized(x).expect("serializable")
}

fn as_hash(v: &Value) -> Result<Hash, String> {
    v.deserialized().map_err(|_| "not a hash".to_string())
}

fn as_cred(v: &Value) -> Result<Credential, String> {
    v.deserialized().map_err(|_| "not a credential".to_string())
}

fn fits(ty: &Ty, v: &Value) -> bool {
    match (ty, v) {
        (Ty::Hash, Value::Bytes(b)) => b.len() == 32,
        (Ty::Credential, Value::Bytes(_)) | (Ty::Text, Value::Text(_)) | (Ty::Any, _) => true,
        (Ty::U32 | Ty::U64, Value::Integer(_)) => true,
        (Ty::Opt(_), Value::Null) => true,
        (Ty::Opt(t), v) => fits(t, v),
        _ => false,
    }
}

struct Ctx<'a> {
    params: &'a Params,
    hop: u32,
}

impl Profile {
    pub fn from_json(s: &str) -> Result<Profile, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }

    /// Build a layout's value from parameters, checking each field's type.
    pub fn build(&self, layout: &str, params: &Params) -> Result<Value, String> {
        let l = self.layouts.get(layout).ok_or_else(|| format!("no layout {layout}"))?;
        let mut out = vec![];
        for f in &l.fields {
            let v = match (params.get(&f.name), &f.default, &f.ty) {
                (Some(v), _, _) => v.clone(),
                (None, Some(d), _) => value(d),
                (None, None, Ty::Opt(_)) => Value::Null,
                (None, None, _) => return Err(format!("{layout}: no {}", f.name)),
            };
            if !fits(&f.ty, &v) {
                return Err(format!("{layout}: {} isn't a {:?}", f.name, f.ty));
            }
            out.push((Value::Text(f.name.clone()), v));
        }
        Ok(Value::Map(out))
    }

    /// The hash of a value under a layout's domain.
    pub fn hash(&self, layout: &str, v: &Value) -> Result<Hash, String> {
        Ok(hash_of(&self.layouts.get(layout).ok_or_else(|| format!("no layout {layout}"))?.domain, v))
    }

    fn eval(&self, e: &Expr, cx: &Ctx) -> Result<Value, String> {
        Ok(match e {
            Expr::Param(n) => cx.params.get(n).cloned().ok_or_else(|| format!("no parameter {n}"))?,
            Expr::Field { of, name } => match self.eval(of, cx)? {
                Value::Map(m) => m.into_iter().find(|(k, _)| k.as_text() == Some(name)).map(|(_, v)| v).ok_or_else(|| format!("no field {name}"))?,
                _ => return Err(format!("{name}: not a map")),
            },
            Expr::Hash { layout, of } => value(&self.hash(layout, &self.eval(of, cx)?)?),
            Expr::Hop => value(&cx.hop),
        })
    }

    /// A receipt for `params`: what an app shows a payment or a handoff
    /// should commit to.
    pub fn receipt_of(&self, name: &str, params: &Params) -> Result<Hash, String> {
        self.receipt(name, &Ctx { params, hop: 0 })
    }

    fn receipt(&self, name: &str, cx: &Ctx) -> Result<Hash, String> {
        let r = self.receipts.get(name).ok_or_else(|| format!("no receipt {name}"))?;
        let parts = r.parts.iter().map(|p| self.eval(p, cx)).collect::<Result<Vec<_>, _>>()?;
        Ok(match parts.as_slice() {
            [one] => hash_of(&r.domain, one),
            _ => hash_of(&r.domain, &Value::Array(parts)),
        })
    }
}

impl Node {
    /// Run one of a profile's actions with `params`. Returns the record.
    pub fn act(&mut self, p: &Profile, action: &str, params: &Params) -> Result<Record, String> {
        let a = p.actions.get(action).ok_or_else(|| format!("{}: no action {action}", p.name))?;
        let coin = match &a.state {
            StateSel::Held { origin } => {
                let origin = as_hash(&p.eval(origin, &Ctx { params, hop: 0 })?)?;
                self.view.unspent().find(|c| c.origin == origin && self.mine.contains(&c.holder)).cloned().ok_or("this wallet doesn't hold it")?
            }
            StateSel::Budget { schema } => {
                let id = p.schemas.get(schema).ok_or_else(|| format!("no schema {schema}"))?.schema.id();
                self.view.unspent().find(|c| c.kind == Kind::MintBudget && c.schema == id && c.amount > 0 && self.mine.contains(&c.holder)).cloned().ok_or("no budget of that schema")?
            }
        };
        for pred in &a.requires {
            let cx = Ctx { params, hop: coin.hops };
            let ok = match pred {
                Pred::CreatedWith { receipt } => {
                    let want = p.receipt(receipt, &cx)?;
                    matches!(self.view.creator(&coin.state).map(|r| &r.op), Some(Op::Transfer { receipt, .. }) if *receipt == want)
                }
                Pred::HolderIs(e) => coin.holder == as_cred(&p.eval(e, &cx)?)?,
            };
            if !ok {
                return Err(format!("{action}: {pred:?} doesn't hold"));
            }
        }
        if a.check {
            self.check_trusting(&coin.state, &[]).map_err(|r| format!("{r:?}"))?;
        }
        let target = |n: &mut Node, t: &Target| -> Result<Credential, String> {
            match t {
                Target::Param(name) => as_cred(params.get(name).ok_or_else(|| format!("no parameter {name}"))?),
                Target::Fresh => n.fresh(),
            }
        };
        let cx = Ctx { params, hop: coin.hops + a.hop };
        let op = match &a.op {
            OpDesc::Transfer { to, receipt } => Op::Transfer { state: coin.state, to: target(self, to)?, receipt: p.receipt(receipt, &cx)? },
            OpDesc::Retire => Op::Retire { state: coin.state },
            OpDesc::Mint { to } => Op::Mint { budget: coin.state, amount: 1, to: target(self, to)?, change_to: coin.holder.clone() },
        };
        let rec = self.signed(&coin.holder, op)?;
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec)
    }

    /// Read a state's history with one of a profile's walks. Returns the
    /// steps and the current holder, if it's still held.
    pub fn walk(&self, p: &Profile, walk: &str, params: &Params) -> Result<(Vec<Stepped>, Option<Credential>), String> {
        let w = p.walks.get(walk).ok_or_else(|| format!("no walk {walk}"))?;
        let mut state = as_hash(&p.eval(&w.from, &Ctx { params, hop: 0 })?)?;
        let (mut steps, mut hop) = (vec![], 0u32);
        loop {
            if let Some(c) = self.view.coin(&state) {
                return Ok((steps, Some(c.holder.clone())));
            }
            let Some(rec) = self.view.spender(&state) else { return Ok((steps, None)) };
            hop += 1;
            match &rec.op {
                Op::Transfer { to, receipt, .. } => {
                    let cx = Ctx { params, hop };
                    let label = w.steps.iter().find(|s| p.receipt(&s.receipt, &cx).ok() == Some(*receipt)).map_or("other".to_string(), |s| s.label.clone());
                    steps.push(Stepped { label, signer: rec.signer.clone(), to: Some(to.clone()) });
                }
                Op::Retire { .. } => {
                    steps.push(Stepped { label: w.retire.clone(), signer: rec.signer.clone(), to: None });
                    return Ok((steps, None));
                }
                _ => return Ok((steps, None)),
            }
            state = rec.output(0);
        }
    }
}
