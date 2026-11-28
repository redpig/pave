//! Ramps: an accountable clerk at the edge of a town that exchanges credit
//! for something outside (spec/ramps.md). This is the pave side, the same
//! whatever is on the other side; `pave-ramp` holds a Bitcoin pool.
//!
//! - **Its own credit.** The town issues each ramp a budget for a schema of
//!   its own, "Pine sats, backed by ramp R", so a ramp that fails hurts
//!   only its own credit.
//! - **Deposits.** The depositor's wallet makes a fresh credential and a
//!   commitment to it, and puts the commitment on the outside system with
//!   the deposit. Once confirmed, the ramp mints the amount to a fresh key
//!   of its own and splits it to the depositor, less the fee to the town,
//!   with a receipt naming the deposit. A deposit credited twice shows as
//!   two receipts naming it.
//! - **Withdrawals.** An ordinary payment to the ramp, against an invoice
//!   whose memo commits to the payout address and amount, so standing, the
//!   cheat list and the acceptance check all apply. The ramp pays out
//!   after the challenge period and retires the credit.
//! - **Audit.** Every view keeps what each schema has minted and retired;
//!   what's outstanding should never exceed what the pool holds.

use crate::node::{apply_ok, Node};
use crate::pay::Invoice;
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Op, Record, Schema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A ramp's backed credit: one unit is one of the outside system's smallest
/// units (a satoshi, a cent).
pub fn ramp_schema(label: &str) -> Schema {
    Schema {
        label: label.into(),
        divisible: true,
        soft_expiry: Some(4),
        hard_expiry: Some(8),
        offline_transfers: Some(5),
        max_per_holder: None,
        sequence: None,
    }
}

/// What the town posts about a ramp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RampInfo {
    pub label: String,
    /// The ramp's credit.
    pub schema: Hash,
    /// The key holding the ramp's budget.
    pub key: Credential,
    /// The town's share of each deposit and withdrawal, in basis points.
    pub fee_bps: u16,
    /// Where fees go: the town's operations key.
    pub treasury: Credential,
    /// The outside system, and the pool's address on it.
    pub chain: String,
    pub pool: String,
    /// Confirmations a deposit needs before it's credited.
    pub min_conf: u32,
}

impl RampInfo {
    pub fn fee(&self, amount: u64) -> u64 {
        amount * self.fee_bps as u64 / 10_000
    }
}

/// What a depositor gives the ramp, beside the deposit itself: the
/// credential to credit and the nonce in its commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositClaim {
    pub to: Credential,
    pub nonce: [u8; 16],
}

/// The commitment a deposit carries on the outside system: 32 bytes.
pub fn deposit_commitment(schema: &Hash, claim: &DepositClaim) -> Hash {
    hash_of(
        "pave/ramp/deposit/v1",
        &[
            schema.0.as_slice(),
            claim.to.0.as_slice(),
            claim.nonce.as_slice(),
        ],
    )
}

/// A confirmed deposit, as the outside system shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    /// Its id there: a txid and output, a transfer reference.
    pub id: String,
    pub amount: u64,
    pub commitment: Hash,
    pub confirmations: u32,
}

/// The receipt on the split that credits `d`.
pub fn deposit_receipt(d: &Deposit) -> Hash {
    hash_of(
        "pave/ramp/credit/v1",
        &[
            d.id.as_bytes(),
            d.commitment.0.as_slice(),
            &d.amount.to_be_bytes(),
        ],
    )
}

/// The memo a withdrawal invoice commits to.
pub fn withdraw_memo(schema: &Hash, address: &str, amount: u64, nonce: &[u8; 16]) -> Hash {
    hash_of(
        "pave/ramp/withdraw/v1",
        &[
            schema.0.as_slice(),
            address.as_bytes(),
            &amount.to_be_bytes(),
            nonce.as_slice(),
        ],
    )
}

/// The receipt on the split that takes the town's fee from a withdrawal.
pub fn withdraw_fee_receipt(paid: &Hash) -> Hash {
    hash_of("pave/ramp/withdraw-fee/v1", &paid.0)
}

/// What the ramp's own records and the view show.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    pub minted: u64,
    pub retired: u64,
    /// Deposit receipts that credited more than once.
    pub double_credits: Vec<Hash>,
}

impl Ledger {
    pub fn outstanding(&self) -> u64 {
        self.minted.saturating_sub(self.retired)
    }
}

impl Node {
    /// Operator: issue a ramp a budget of `amount` units of its own credit,
    /// labelled `label`, to `to`. Returns the schema.
    pub fn issue_ramp_budget(
        &mut self,
        label: &str,
        amount: u64,
        to: Credential,
    ) -> Result<Hash, String> {
        let op = self
            .operator
            .as_ref()
            .ok_or("only the town issues ramp budgets")?;
        let schema = ramp_schema(label);
        let id = schema.id();
        let rec = pave_kernel::sign(
            self.view.scheme(),
            &op.root,
            &op.root_cred,
            Op::IssueBudget {
                authority: self.town.genesis.rooting_capability(),
                schema,
                amount,
                to,
            },
        );
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(id)
    }

    /// Depositor: a fresh credential to be credited, and the commitment to
    /// put on the outside system with the deposit.
    pub fn deposit_claim(&mut self, schema: &Hash) -> Result<(DepositClaim, Hash), String> {
        let to = self.fresh()?;
        let claim = DepositClaim {
            to,
            nonce: rand::random(),
        };
        let c = deposit_commitment(schema, &claim);
        self.save()?;
        Ok((claim, c))
    }

    /// Ramp: credit a confirmed deposit to the claim it commits to. Mints
    /// to a fresh key of the ramp's, then splits it: the depositor's share
    /// and the town's fee, with a receipt naming the deposit. The caller
    /// keeps which deposits it has credited; a second credit shows in the
    /// [`Node::ramp_ledger`] of anyone who sees both.
    pub fn credit_deposit(
        &mut self,
        info: &RampInfo,
        d: &Deposit,
        claim: &DepositClaim,
    ) -> Result<Record, String> {
        if deposit_commitment(&info.schema, claim) != d.commitment {
            return Err("the deposit doesn't commit to this claim".into());
        }
        if d.confirmations < info.min_conf {
            return Err(format!(
                "{} confirmations, {} needed",
                d.confirmations, info.min_conf
            ));
        }
        let budget = self
            .view
            .unspent()
            .find(|c| {
                c.kind == pave_kernel::Kind::MintBudget
                    && c.schema == info.schema
                    && c.amount >= d.amount
                    && self.mine.contains(&c.holder)
            })
            .cloned()
            .ok_or("the ramp's budget can't cover this deposit")?;
        let me = self.fresh()?;
        let mint = self.signed(
            &budget.holder,
            Op::Mint {
                budget: budget.state,
                amount: d.amount,
                to: me.clone(),
                change_to: budget.holder.clone(),
            },
        )?;
        apply_ok(&mut self.view, &mint)?;
        let fee = info.fee(d.amount);
        let mut parts = vec![(d.amount - fee, claim.to.clone())];
        if fee > 0 {
            parts.push((fee, info.treasury.clone()));
        }
        let split = self.signed(
            &me,
            Op::Split {
                state: mint.output(0),
                parts,
                receipt: deposit_receipt(d),
            },
        )?;
        apply_ok(&mut self.view, &split)?;
        self.save()?;
        Ok(split)
    }

    /// Ramp: an invoice for a withdrawal of `amount` to `address`. Returns
    /// it and the nonce its memo commits to.
    pub fn withdraw_invoice(
        &mut self,
        info: &RampInfo,
        address: &str,
        amount: u64,
    ) -> Result<(Invoice, [u8; 16]), String> {
        let nonce: [u8; 16] = rand::random();
        let inv = self.invoice_in(
            info.schema,
            amount,
            withdraw_memo(&info.schema, address, amount, &nonce),
        )?;
        Ok((inv, nonce))
    }

    /// Ramp: retire a coin of its credit once its value has been paid out.
    pub fn retire_paid(&mut self, info: &RampInfo, state: &Hash) -> Result<Record, String> {
        let c = self.view.coin(state).cloned().ok_or("no such coin")?;
        if c.schema != info.schema || !self.mine.contains(&c.holder) {
            return Err("not this ramp's credit, held here".into());
        }
        let rec = self.signed(&c.holder, Op::Retire { state: *state })?;
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec)
    }

    /// Ramp: settle a paid withdrawal once its payout is out: the town's
    /// fee goes to the treasury, and the rest is retired. Returns what was
    /// retired, which is what the payout carried.
    pub fn settle_withdrawal(&mut self, info: &RampInfo, state: &Hash) -> Result<u64, String> {
        let c = self.view.coin(state).cloned().ok_or("no such coin")?;
        if c.schema != info.schema || !self.mine.contains(&c.holder) {
            return Err("not this ramp's credit, held here".into());
        }
        let fee = info.fee(c.amount);
        let rest = if fee == 0 {
            *state
        } else {
            let me = self.fresh()?;
            let split = self.signed(
                &c.holder,
                Op::Split {
                    state: *state,
                    parts: vec![(c.amount - fee, me), (fee, info.treasury.clone())],
                    receipt: withdraw_fee_receipt(state),
                },
            )?;
            apply_ok(&mut self.view, &split)?;
            split.output(0)
        };
        self.retire_paid(info, &rest)?;
        Ok(c.amount - fee)
    }

    /// Anyone: what this view shows of a ramp's credit, minted and retired,
    /// and any deposit credited twice.
    /// The schema a budget state issues, back through the mints that spent
    /// it and left change.
    fn budget_schema(&self, budget: &Hash) -> Option<Hash> {
        let mut at = *budget;
        loop {
            match &self.view.creator(&at)?.op {
                Op::IssueBudget { schema, .. } => return Some(schema.id()),
                Op::Mint { budget, .. } => at = *budget,
                _ => return None,
            }
        }
    }

    pub fn ramp_ledger(&self, schema: &Hash) -> Ledger {
        let t = self.view.totals(schema);
        // A credit is a split straight off a mint of this schema.
        let credits: BTreeMap<Hash, u32> = self
            .view
            .records()
            .iter()
            .filter_map(|r| match &r.op {
                Op::Split { state, receipt, .. }
                    if self.view.creator(state).and_then(|m| match &m.op {
                        Op::Mint { budget, .. } => self.budget_schema(budget),
                        _ => None,
                    }) == Some(*schema) =>
                {
                    Some(*receipt)
                }
                _ => None,
            })
            .fold(BTreeMap::new(), |mut m, r| {
                *m.entry(r).or_default() += 1;
                m
            });
        Ledger {
            minted: t.minted,
            retired: t.retired_value,
            double_credits: credits
                .into_iter()
                .filter(|(_, n)| *n > 1)
                .map(|(r, _)| r)
                .collect(),
        }
    }
}
