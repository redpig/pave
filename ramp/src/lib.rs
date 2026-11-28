//! A pave ramp on Bitcoin (spec/ramps.md): deposits into a Taproot pool
//! become the ramp's own credit in a town, and that credit retired becomes
//! a payout from the pool, co-signed by the town's auditors.
//!
//! - [`pool`]: the pool's Taproot output (ramp and `k` of `n` co-signers,
//!   or the co-signers alone after a long timelock), its spends, and the
//!   `OP_RETURN` formats.
//! - [`chain`]: the [`chain::L1`] a ramp needs, and a chain with regtest's
//!   rules in memory that implements it.
//! - [`Ramp`]: the ramp's side, over a pave wallet (`pave_board::ramp`).
//! - [`Cosigner`]: an auditor's side. It signs a payout only after the
//!   challenge period, for a withdrawal whose payment commits to that
//!   address and amount, in the ramp's credit, with no double spend of the
//!   coin in its view.

pub mod chain;
pub mod pool;

use bitcoin::absolute::LockTime;
use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::schnorr;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, KnownHrp, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use chain::L1;
use pave_board::node::Node;
use pave_board::pay::{Ack, Invoice};
use pave_board::ramp::{withdraw_memo, Deposit, DepositClaim, Ledger, RampInfo};
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Op, Record};
use pool::Pool;
use std::collections::{BTreeMap, BTreeSet};

/// A withdrawal the ramp has invoiced.
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub address: String,
    pub spk: ScriptBuf,
    pub amount: u64,
    pub nonce: [u8; 16],
    pub invoice: Invoice,
    /// The payment, once taken, and the chain height then.
    pub paid: Option<(Record, u64)>,
    pub done: Option<Txid>,
}

/// What a co-signer needs to review a payout.
#[derive(Clone, Debug)]
pub struct Review {
    pub address: String,
    pub amount: u64,
    pub nonce: [u8; 16],
    pub payment: Record,
    /// The chain height when the ramp took the payment.
    pub paid_at: u64,
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
}

/// The hash an epoch's anchor carries: the town's tick head and the ramp's ledger.
pub fn anchor_hash(head: &Hash, ledger: &Ledger) -> [u8; 32] {
    hash_of(
        "pave/ramp/anchor/v1",
        &[
            head.0.as_slice(),
            &ledger.minted.to_be_bytes(),
            &ledger.retired.to_be_bytes(),
        ],
    )
    .0
}

fn regtest_spk(address: &str) -> Result<ScriptBuf, String> {
    Ok(address
        .parse::<Address<_>>()
        .map_err(|e| format!("{e}"))?
        .require_network(Network::Regtest)
        .map_err(|e| format!("{e}"))?
        .script_pubkey())
}

/// The least a Taproot output can carry and still relay.
pub const DUST: u64 = 330;

pub struct Ramp {
    pub info: RampInfo,
    pub pool: Pool,
    key: Keypair,
    fee_key: Keypair,
    credited: BTreeSet<OutPoint>,
    claims: BTreeMap<Hash, DepositClaim>,
    pub withdrawals: Vec<Withdrawal>,
    /// Blocks a withdrawal waits before its payout is co-signed.
    pub challenge: u64,
    /// Sats each payout leaves for the miners, from the withdrawal.
    pub tx_fee: u64,
}

impl Ramp {
    /// Set up a ramp: its keys and pool, and the town's budget for its
    /// credit, issued to `ramp_node`'s key.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        town: &mut Node,
        ramp_node: &mut Node,
        label: &str,
        budget: u64,
        cosigners: Vec<XOnlyPublicKey>,
        threshold: usize,
        fee_bps: u16,
        treasury: pave_kernel::Credential,
        min_conf: u32,
        challenge: u64,
    ) -> Result<Ramp, String> {
        let secp = Secp256k1::new();
        let (key, fee_key) = (
            Keypair::new(&secp, &mut bitcoin::secp256k1::rand::thread_rng()),
            Keypair::new(&secp, &mut bitcoin::secp256k1::rand::thread_rng()),
        );
        let pool = Pool::new(key.x_only_public_key().0, cosigners, threshold, 4320)?;
        let holder = ramp_node.receive()?;
        let schema = town.issue_ramp_budget(label, budget, holder.clone())?;
        let info = RampInfo {
            label: label.into(),
            schema,
            key: holder,
            fee_bps,
            treasury,
            chain: "bitcoin-regtest".into(),
            pool: pool.address(KnownHrp::Regtest).to_string(),
            min_conf,
        };
        Ok(Ramp {
            info,
            pool,
            key,
            fee_key,
            credited: BTreeSet::new(),
            claims: BTreeMap::new(),
            withdrawals: vec![],
            challenge,
            tx_fee: 500,
        })
    }

    /// A depositor hands over the claim its deposit's commitment names.
    pub fn claim(&mut self, commitment: Hash, claim: DepositClaim) {
        self.claims.insert(commitment, claim);
    }

    /// Credit every confirmed deposit with a claim, once each.
    pub fn scan(&mut self, node: &mut Node, chain: &impl L1) -> Result<Vec<Record>, String> {
        let mut out = vec![];
        for d in chain.deposits(&self.pool.script_pubkey()) {
            if self.credited.contains(&d.outpoint) || d.confirmations < self.info.min_conf {
                continue;
            }
            let Some(claim) = self.claims.get(&Hash(d.commitment)) else {
                continue;
            };
            let dep = Deposit {
                id: format!("{}:{}", d.outpoint.txid, d.outpoint.vout),
                amount: d.sats,
                commitment: Hash(d.commitment),
                confirmations: d.confirmations,
            };
            out.push(node.credit_deposit(&self.info, &dep, claim)?);
            self.credited.insert(d.outpoint);
        }
        Ok(out)
    }

    /// Invoice a withdrawal of `amount` to a regtest `address`.
    pub fn request_withdrawal(
        &mut self,
        node: &mut Node,
        address: &str,
        amount: u64,
    ) -> Result<Invoice, String> {
        let spk = regtest_spk(address)?;
        if amount < self.info.fee(amount) + self.tx_fee + DUST {
            return Err("too small to pay out".into());
        }
        let (invoice, nonce) = node.withdraw_invoice(&self.info, address, amount)?;
        self.withdrawals.push(Withdrawal {
            address: address.into(),
            spk,
            amount,
            nonce,
            invoice: invoice.clone(),
            paid: None,
            done: None,
        });
        Ok(invoice)
    }

    /// Take the payment for a withdrawal. The invoice is in this ramp's
    /// credit, so the wallet refuses payment in any other.
    pub fn take_payment(
        &mut self,
        node: &mut Node,
        rec: &Record,
        height: u64,
    ) -> Result<Ack, String> {
        let to = match &rec.op {
            Op::Transfer { to, .. } => to.clone(),
            Op::Split { parts, .. } => parts.first().ok_or("an empty split")?.1.clone(),
            _ => return Err("not a payment".into()),
        };
        let i = self
            .withdrawals
            .iter()
            .position(|w| w.invoice.to == to && w.paid.is_none())
            .ok_or("no withdrawal waiting on that payment")?;
        let ack = node.take_payment(rec)?;
        self.withdrawals[i].paid = Some((rec.clone(), height));
        Ok(ack)
    }

    /// The unsigned payout for withdrawal `i`, and the outputs it spends:
    /// pool outputs in, the recipient's share and change to the pool out.
    pub fn payout(&self, chain: &impl L1, i: usize) -> Result<Review, String> {
        let w = &self.withdrawals[i];
        let (payment, paid_at) = w.paid.clone().ok_or("not paid yet")?;
        let send = w.amount - self.info.fee(w.amount) - self.tx_fee;
        let need = send + self.tx_fee;
        let (mut input, mut prevouts, mut have) = (vec![], vec![], 0u64);
        for (op, o) in chain.unspent(&self.pool.script_pubkey()) {
            if have >= need {
                break;
            }
            have += o.value.to_sat();
            input.push(TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            prevouts.push(o);
        }
        if have < need {
            return Err("the pool can't cover it".into());
        }
        let mut output = vec![TxOut {
            value: Amount::from_sat(send),
            script_pubkey: w.spk.clone(),
        }];
        if have > need {
            output.push(TxOut {
                value: Amount::from_sat(have - need),
                script_pubkey: self.pool.script_pubkey(),
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        };
        Ok(Review {
            address: w.address.clone(),
            amount: w.amount,
            nonce: w.nonce,
            payment,
            paid_at,
            tx,
            prevouts,
        })
    }

    /// The ramp's signatures on a payout, one per input.
    pub fn sign(&self, r: &Review) -> Vec<schnorr::Signature> {
        (0..r.tx.input.len())
            .map(|i| pool::sign(&self.key, &self.pool.sighash(&r.tx, &r.prevouts, i)))
            .collect()
    }

    /// Put the signatures on, broadcast, and settle the credit: the town's
    /// fee to the treasury, the rest retired.
    pub fn complete(
        &mut self,
        node: &mut Node,
        chain: &mut impl L1,
        i: usize,
        mut r: Review,
        cosigned: &[Vec<Option<schnorr::Signature>>],
    ) -> Result<Txid, String> {
        let mine = self.sign(&r);
        for (j, input) in r.tx.input.iter_mut().enumerate() {
            // cosigned[c][j]: co-signer c's signature on input j, if it signed.
            let theirs: Vec<Option<schnorr::Signature>> = (0..self.pool.cosigners.len())
                .map(|c| cosigned.get(c).and_then(|s| s.get(j).copied()).flatten())
                .collect();
            input.witness = self.pool.witness(&mine[j], &theirs);
        }
        let txid = chain.broadcast(r.tx)?;
        let state = r.payment.output(0);
        node.settle_withdrawal(&self.info, &state)?;
        self.withdrawals[i].done = Some(txid);
        Ok(txid)
    }

    /// Where to send sats for the ramp's anchors.
    pub fn fee_spk(&self) -> ScriptBuf {
        pool::key_spk(&self.fee_key)
    }

    /// Anchor `epoch` on the chain: the town's tick head and the ramp's
    /// ledger, paid from the ramp's fee output.
    pub fn anchor(
        &self,
        node: &Node,
        chain: &mut impl L1,
        epoch: u64,
        head: &Hash,
    ) -> Result<Txid, String> {
        let spk = self.fee_spk();
        let (op, o) = chain
            .unspent(&spk)
            .into_iter()
            .next()
            .ok_or("no sats for anchors: fund the fee address")?;
        let change = o
            .value
            .to_sat()
            .checked_sub(300)
            .ok_or("too little for an anchor")?;
        let data = pool::anchor_data(
            epoch,
            &anchor_hash(head, &node.ramp_ledger(&self.info.schema)),
        );
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: spk,
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: pool::op_return(&data),
                },
            ],
        };
        tx.input[0].witness = pool::key_spend(&self.fee_key, &tx, &[o], 0);
        chain.broadcast(tx)
    }
}

/// One of the town's auditors, co-signing the pool.
pub struct Cosigner {
    key: Keypair,
}

impl Default for Cosigner {
    fn default() -> Self {
        Self::new()
    }
}

impl Cosigner {
    pub fn new() -> Cosigner {
        Cosigner {
            key: Keypair::new(
                &Secp256k1::new(),
                &mut bitcoin::secp256k1::rand::thread_rng(),
            ),
        }
    }

    pub fn public(&self) -> XOnlyPublicKey {
        self.key.x_only_public_key().0
    }

    /// Review a payout against this auditor's own view (`node`, its pave
    /// wallet) and sign it if it holds up:
    /// - the challenge period has passed since the ramp took the payment;
    /// - the payment commits to this address and amount, and paid that
    ///   amount in the ramp's credit;
    /// - no double spend of the coin it paid with is in this view;
    /// - the payout sends the recipient its share, from the pool, with any
    ///   change back to it.
    pub fn review(
        &self,
        node: &Node,
        info: &RampInfo,
        pool: &Pool,
        ramp: &Ramp,
        r: &Review,
        height: u64,
    ) -> Result<Vec<schnorr::Signature>, String> {
        if height < r.paid_at + ramp.challenge {
            return Err(format!(
                "the challenge period runs {} more blocks",
                r.paid_at + ramp.challenge - height
            ));
        }
        let (receipt, spent) = match &r.payment.op {
            Op::Transfer { state, receipt, .. } | Op::Split { state, receipt, .. } => {
                (*receipt, *state)
            }
            _ => return Err("not a payment".into()),
        };
        if receipt != withdraw_memo(&info.schema, &r.address, r.amount, &r.nonce) {
            return Err("the payment doesn't commit to this address and amount".into());
        }
        if node
            .view
            .coin(&r.payment.output(0))
            .is_none_or(|c| c.schema != info.schema || c.amount != r.amount)
        {
            return Err(
                "the payment isn't this amount of the ramp's credit, as this auditor sees it"
                    .into(),
            );
        }
        // A conflicting record leaves evidence too; evidence alone arrives by gossip.
        if node.view.evidence().any(|e| e.basename == spent) {
            return Err("the coin this withdrawal paid with was spent twice".into());
        }
        let send = r.amount - info.fee(r.amount) - ramp.tx_fee;
        let spk = regtest_spk(&r.address)?;
        if r.tx
            .output
            .first()
            .is_none_or(|o| o.script_pubkey != spk || o.value.to_sat() != send)
        {
            return Err("the payout doesn't send the recipient its share".into());
        }
        if r.tx
            .output
            .iter()
            .skip(1)
            .any(|o| o.script_pubkey != pool.script_pubkey())
            || r.prevouts
                .iter()
                .any(|o| o.script_pubkey != pool.script_pubkey())
        {
            return Err("the payout spends or pays outside the pool".into());
        }
        Ok((0..r.tx.input.len())
            .map(|i| pool::sign(&self.key, &pool.sighash(&r.tx, &r.prevouts, i)))
            .collect())
    }
}
