//! A chain with regtest's rules, in memory: blocks, confirmations and
//! unspent outputs. Outside wallets pay into it; the ramp and its
//! co-signers spend the pool from it. Spends of the pool are checked by
//! [`Pool::verify_spend`], key-path spends by their signature. It stands in
//! for a bitcoind on regtest behind the same [`L1`] trait, which an RPC
//! client can implement.

use crate::pool::{
    op_return, op_return_data, verify_key_spend, Pool, ANCHOR_PREFIX, DEPOSIT_PREFIX,
};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use std::collections::BTreeMap;

/// A deposit to the pool, as the chain shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainDeposit {
    pub outpoint: OutPoint,
    pub sats: u64,
    pub commitment: [u8; 32],
    pub confirmations: u32,
}

/// What a ramp needs of a chain, as Briolette's `L1Client` has it.
pub trait L1 {
    fn height(&self) -> u64;
    /// Deposits to `pool` carrying a pave commitment.
    fn deposits(&self, pool: &ScriptBuf) -> Vec<ChainDeposit>;
    /// Unspent outputs to `spk`, with their values.
    fn unspent(&self, spk: &ScriptBuf) -> Vec<(OutPoint, TxOut)>;
    fn balance(&self, spk: &ScriptBuf) -> u64 {
        self.unspent(spk)
            .iter()
            .map(|(_, o)| o.value.to_sat())
            .sum()
    }
    fn broadcast(&mut self, tx: Transaction) -> Result<Txid, String>;
    /// Every epoch anchor on the chain: (epoch, hash).
    fn anchors(&self) -> Vec<(u64, [u8; 32])>;
}

#[derive(Default)]
pub struct SimChain {
    height: u64,
    /// Each output, the height its transaction confirmed at (None in the mempool), and whether it's spent.
    outputs: BTreeMap<OutPoint, (TxOut, Option<u64>, bool)>,
    txs: Vec<(Transaction, Option<u64>)>,
    pools: Vec<Pool>,
    nonce: u32,
}

impl SimChain {
    pub fn new() -> SimChain {
        SimChain::default()
    }

    /// Spends of this pool are checked against it.
    pub fn watch(&mut self, pool: &Pool) {
        self.pools.push(pool.clone());
    }

    fn add(&mut self, tx: Transaction, height: Option<u64>) -> Txid {
        let id = tx.compute_txid();
        for (i, o) in tx.output.iter().enumerate() {
            self.outputs.insert(
                OutPoint {
                    txid: id,
                    vout: i as u32,
                },
                (o.clone(), height, false),
            );
        }
        self.txs.push((tx, height));
        id
    }

    /// An outside wallet pays `sats` to `to`, with `data` in an `OP_RETURN`
    /// if given. Its inputs are the outside wallet's, not modelled here.
    pub fn pay(&mut self, to: ScriptBuf, sats: u64, data: Option<&[u8]>) -> Txid {
        self.nonce += 1;
        let mut output = vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: to,
        }];
        if let Some(d) = data {
            output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return(d),
            });
        }
        // A unique lock time keeps otherwise-identical payments apart.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(self.nonce),
            input: vec![],
            output,
        };
        self.add(tx, None)
    }

    /// Mine `n` blocks, confirming the mempool in the first.
    pub fn mine(&mut self, n: u64) {
        for _ in 0..n {
            self.height += 1;
            let h = self.height;
            for (_, at) in self.txs.iter_mut().filter(|(_, at)| at.is_none()) {
                *at = Some(h);
            }
            for (_, at, _) in self.outputs.values_mut().filter(|(_, at, _)| at.is_none()) {
                *at = Some(h);
            }
        }
    }

    fn confirmations(&self, at: Option<u64>) -> u32 {
        at.map(|h| (self.height - h + 1) as u32).unwrap_or(0)
    }

    /// What an address has received, confirmed.
    pub fn received(&self, spk: &ScriptBuf) -> u64 {
        self.outputs
            .values()
            .filter(|(o, at, _)| &o.script_pubkey == spk && at.is_some())
            .map(|(o, _, _)| o.value.to_sat())
            .sum()
    }
}

impl L1 for SimChain {
    fn height(&self) -> u64 {
        self.height
    }

    fn deposits(&self, pool: &ScriptBuf) -> Vec<ChainDeposit> {
        let mut out = vec![];
        for (tx, at) in &self.txs {
            let id = tx.compute_txid();
            let commitment = tx
                .output
                .iter()
                .filter_map(|o| op_return_data(&o.script_pubkey))
                .find_map(|d| {
                    (d.len() == 36 && d.starts_with(DEPOSIT_PREFIX))
                        .then(|| <[u8; 32]>::try_from(&d[4..]).unwrap())
                });
            let Some(commitment) = commitment else {
                continue;
            };
            for (i, o) in tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| &o.script_pubkey == pool)
            {
                out.push(ChainDeposit {
                    outpoint: OutPoint {
                        txid: id,
                        vout: i as u32,
                    },
                    sats: o.value.to_sat(),
                    commitment,
                    confirmations: self.confirmations(*at),
                });
            }
        }
        out
    }

    fn unspent(&self, spk: &ScriptBuf) -> Vec<(OutPoint, TxOut)> {
        self.outputs
            .iter()
            .filter(|(_, (o, at, spent))| &o.script_pubkey == spk && at.is_some() && !spent)
            .map(|(p, (o, _, _))| (*p, o.clone()))
            .collect()
    }

    fn broadcast(&mut self, tx: Transaction) -> Result<Txid, String> {
        let prevouts: Vec<TxOut> = tx
            .input
            .iter()
            .map(|i| match self.outputs.get(&i.previous_output) {
                Some((o, Some(_), false)) => Ok(o.clone()),
                Some((_, _, true)) => Err("an input is already spent".to_string()),
                _ => Err("an input isn't a confirmed output".to_string()),
            })
            .collect::<Result<_, _>>()?;
        for (i, p) in prevouts.iter().enumerate() {
            match self
                .pools
                .iter()
                .find(|pool| pool.script_pubkey() == p.script_pubkey)
            {
                Some(pool) => pool.verify_spend(&tx, &prevouts, i)?,
                None => verify_key_spend(&tx, &prevouts, i)?,
            }
        }
        let (inn, out): (u64, u64) = (
            prevouts.iter().map(|o| o.value.to_sat()).sum(),
            tx.output.iter().map(|o| o.value.to_sat()).sum(),
        );
        if out > inn {
            return Err("outputs exceed inputs".into());
        }
        for i in &tx.input {
            self.outputs.get_mut(&i.previous_output).unwrap().2 = true;
        }
        Ok(self.add(tx, None))
    }

    fn anchors(&self) -> Vec<(u64, [u8; 32])> {
        self.txs
            .iter()
            .filter(|(_, at)| at.is_some())
            .flat_map(|(tx, _)| {
                tx.output
                    .iter()
                    .filter_map(|o| op_return_data(&o.script_pubkey))
            })
            .filter(|d| d.len() == 44 && d.starts_with(ANCHOR_PREFIX))
            .map(|d| {
                (
                    u64::from_be_bytes(d[4..12].try_into().unwrap()),
                    d[12..].try_into().unwrap(),
                )
            })
            .collect()
    }
}
