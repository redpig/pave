//! Packages: custody as a coin.
//!
//! A package is a parcel coin: one, not divisible, never expiring, with a
//! limit on handoffs. Everything here is ordinary kernel operations.
//!
//! - **Shipping.** The town gives a shipper a parcel budget. Shipping mints
//!   one parcel to the shipper. The parcel's id is its origin state.
//! - **Manifest.** What it is, where from and to, who it is for (the
//!   addressee's credential) and the pay per hop. It travels with the
//!   parcel, hand to hand, and every handoff's receipt commits to its hash.
//! - **Handoff.** The holder transfers the parcel to the next courier's
//!   credential. The courier wants it: holding it is what gets them paid.
//! - **Take.** The courier acknowledges by moving the parcel to a fresh
//!   credential of its own. That record only the courier can sign, so the
//!   giver can show the handoff happened.
//! - **Delivery.** The addressee retires the parcel. Only the addressee's
//!   credential can sign that, so "delivered" can't be claimed by a courier.
//! - **Double handoff.** Handing one parcel to two people is using one
//!   state twice: the kernel's evidence, as for a double spend.
//! - **Pay.** Once it is delivered, the shipper pays the signer of every
//!   handoff after its own, each payment's receipt naming the parcel, and
//!   never a courier caught handing one parcel to two people.

use crate::node::{apply_ok, Node};
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Kind, Op, Schema};
use serde::{Deserialize, Serialize};

/// Most transfers a parcel may make, takes included.
pub const MAX_HOPS: u32 = 32;

pub fn parcel_schema() -> Schema {
    Schema { label: "parcel".into(), divisible: false, soft_expiry: None, hard_expiry: None, offline_transfers: Some(MAX_HOPS), max_per_holder: None, sequence: None }
}

/// What travels with a parcel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub parcel: Hash,
    pub what: String,
    pub from_cell: String,
    pub to_cell: String,
    /// The credential that may confirm delivery.
    pub addressee: Credential,
    pub pay_per_hop: u64,
}

impl Manifest {
    pub fn hash(&self) -> Hash {
        hash_of("pave/parcel/manifest", self)
    }
}

/// The receipt of the transfer that makes `hop`: a handoff to someone else,
/// or a take by the one who received it.
pub fn handoff_receipt(manifest: &Hash, hop: u32) -> Hash {
    hash_of("pave/parcel/handoff", &(manifest, hop))
}

pub fn take_receipt(manifest: &Hash, hop: u32) -> Hash {
    hash_of("pave/parcel/take", &(manifest, hop))
}

pub fn pay_receipt(parcel: &Hash, courier: &Credential) -> Hash {
    hash_of("pave/parcel/pay", &(parcel, courier))
}

/// One step in a parcel's custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Step {
    /// `from` handed it to `to`.
    Handoff { from: Credential, to: Credential },
    /// `by` acknowledged taking it.
    Take { by: Credential },
    /// The holder retired it: delivered, if it was the addressee.
    Retired { by: Credential },
}

#[derive(Clone, Debug, Serialize)]
pub struct Custody {
    pub steps: Vec<Step>,
    /// Who holds it now, if it isn't retired.
    pub holder: Option<Credential>,
    /// Whether the addressee retired it.
    pub delivered: bool,
}

impl Node {
    /// Operator: give a shipper a budget of `count` parcels, held by `to`.
    pub fn issue_parcel_budget(&mut self, to: Credential, count: u64) -> Result<Hash, String> {
        let op = self.operator.as_ref().ok_or("only the town issues parcel budgets")?;
        let rec = pave_kernel::sign(self.view.scheme(), &op.root, &op.root_cred, Op::IssueBudget { authority: self.town.genesis.rooting_capability(), schema: parcel_schema(), amount: count, to });
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec.output(0))
    }

    fn parcel_budget(&self) -> Option<pave_kernel::Coin> {
        self.view.unspent().find(|c| c.kind == Kind::MintBudget && c.schema == self.town.parcels && c.amount > 0 && self.mine.contains(&c.holder)).cloned()
    }

    /// Shipper: mint a parcel and keep its manifest. Returns the manifest,
    /// to hand to the first courier with the parcel.
    pub fn ship(&mut self, what: &str, from_cell: &str, to_cell: &str, addressee: Credential, pay_per_hop: u64) -> Result<Manifest, String> {
        let budget = self.parcel_budget().ok_or("no parcel budget: ask the town for one")?;
        let (me, change) = (self.fresh()?, self.fresh()?);
        let rec = self.signed(&budget.holder, Op::Mint { budget: budget.state, amount: 1, to: me, change_to: change })?;
        apply_ok(&mut self.view, &rec)?;
        let m = Manifest { parcel: rec.output(0), what: what.into(), from_cell: from_cell.into(), to_cell: to_cell.into(), addressee, pay_per_hop };
        self.parcels.insert(m.parcel, m.clone());
        self.save()?;
        Ok(m)
    }

    /// The parcel's current state, if this wallet holds it.
    fn held(&self, parcel: &Hash) -> Result<pave_kernel::Coin, String> {
        self.view.unspent().find(|c| c.origin == *parcel && c.schema == self.town.parcels && self.mine.contains(&c.holder)).cloned().ok_or_else(|| "this wallet doesn't hold that parcel".into())
    }

    /// Hand a parcel this wallet holds to `to`, a credential the next
    /// courier (or the addressee) gave. They meet to carry the record.
    pub fn hand_off(&mut self, parcel: &Hash, to: Credential) -> Result<Hash, String> {
        let m = self.parcels.get(parcel).ok_or("no manifest for that parcel")?.clone();
        let coin = self.held(parcel)?;
        let rec = self.signed(&coin.holder, Op::Transfer { state: coin.state, to, receipt: handoff_receipt(&m.hash(), coin.hops + 1) })?;
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec.output(0))
    }

    /// Courier: take a parcel handed to this wallet. Checks that it is held
    /// here, that the handoff commits to this manifest, and that the coin
    /// passes this wallet's usual checks; then acknowledges by moving it to
    /// a fresh credential of its own.
    pub fn take_parcel(&mut self, m: &Manifest) -> Result<Hash, String> {
        let coin = self.held(&m.parcel)?;
        let creator = self.view.creator(&coin.state).ok_or("unknown parcel state")?.clone();
        match &creator.op {
            Op::Transfer { receipt, .. } if *receipt == handoff_receipt(&m.hash(), coin.hops) => {}
            _ => return Err("that handoff doesn't match the manifest".into()),
        }
        self.check(&coin.state).map_err(|r| format!("{r:?}"))?;
        let me = self.fresh()?;
        let rec = self.signed(&coin.holder, Op::Transfer { state: coin.state, to: me, receipt: take_receipt(&m.hash(), coin.hops + 1) })?;
        apply_ok(&mut self.view, &rec)?;
        self.parcels.insert(m.parcel, m.clone());
        self.save()?;
        Ok(rec.output(0))
    }

    /// Addressee: confirm delivery by retiring the parcel.
    pub fn confirm_delivery(&mut self, m: &Manifest) -> Result<Hash, String> {
        let coin = self.held(&m.parcel)?;
        if coin.holder != m.addressee {
            return Err("only the manifest's addressee confirms delivery".into());
        }
        let rec = self.signed(&coin.holder, Op::Retire { state: coin.state })?;
        apply_ok(&mut self.view, &rec)?;
        self.parcels.insert(m.parcel, m.clone());
        self.save()?;
        Ok(rec.id())
    }

    /// A parcel's custody as this wallet's view has it.
    pub fn custody(&self, m: &Manifest) -> Custody {
        let (mut steps, mut state, mut holder, mut delivered) = (vec![], m.parcel, None, false);
        let mut hop = 0;
        loop {
            if let Some(c) = self.view.coin(&state) {
                holder = Some(c.holder.clone());
                break;
            }
            let Some(rec) = self.view.spender(&state) else { break };
            hop += 1;
            match &rec.op {
                Op::Transfer { receipt, .. } if *receipt == take_receipt(&m.hash(), hop) => steps.push(Step::Take { by: rec.signer.clone() }),
                Op::Transfer { to, receipt, .. } if *receipt == handoff_receipt(&m.hash(), hop) => steps.push(Step::Handoff { from: rec.signer.clone(), to: to.clone() }),
                Op::Retire { .. } => {
                    delivered = rec.signer == m.addressee;
                    steps.push(Step::Retired { by: rec.signer.clone() });
                    break;
                }
                _ => break,
            }
            state = rec.output(0);
        }
        Custody { steps, holder, delivered }
    }

    /// Shipper: pay the signer of every handoff after this wallet's own,
    /// once the addressee has confirmed delivery. Returns the payments.
    pub fn pay_couriers(&mut self, m: &Manifest) -> Result<Vec<Hash>, String> {
        let c = self.custody(m);
        if !c.delivered {
            return Err("not delivered yet".into());
        }
        let couriers: Vec<Credential> = c
            .steps
            .iter()
            .filter_map(|s| match s {
                // Never a courier caught handing one parcel to two people.
                Step::Handoff { from, .. } if !self.mine.contains(from) && !self.view.flagged().contains(from) => Some(from.clone()),
                _ => None,
            })
            .collect();
        let mut out = vec![];
        for courier in couriers {
            let receipt = pay_receipt(&m.parcel, &courier);
            let paid = self.view.records().iter().any(|r| matches!(&r.op, Op::Transfer { receipt: x, .. } | Op::Split { receipt: x, .. } if *x == receipt));
            if paid {
                continue;
            }
            out.push(self.pay_to(courier, m.pay_per_hop, receipt)?);
        }
        Ok(out)
    }

    /// Pay `amount` to `to` from one coin, with change to a fresh credential.
    fn pay_to(&mut self, to: Credential, amount: u64, receipt: Hash) -> Result<Hash, String> {
        let coin = self.my_coins().into_iter().find(|c| c.amount >= amount).ok_or("no single coin covers the pay")?;
        let rec = if coin.amount == amount {
            self.signed(&coin.holder, Op::Transfer { state: coin.state, to, receipt })?
        } else {
            let change = self.fresh()?;
            self.signed(&coin.holder, Op::Split { state: coin.state, parts: vec![(amount, to), (coin.amount - amount, change)], receipt })?
        };
        apply_ok(&mut self.view, &rec)?;
        Ok(rec.output(0))
    }
}
