//! The pool: a Taproot output no single key can spend.
//!
//! The internal key is the BIP 341 "nothing up my sleeve" point, so there
//! is no key path. Two script leaves:
//!
//! - **Co-signed:** the ramp's key and `k` of the town's `n` co-signers
//!   (`<ramp> CHECKSIGVERIFY <c1> CHECKSIG <c2> CHECKSIGADD … <k> NUMEQUAL`).
//!   Every withdrawal goes this way, so the ramp can't pay out alone.
//! - **Recovery:** after `recovery` blocks unmoved, `k` of the co-signers
//!   alone, in case the ramp is gone.
//!
//! Deposits carry `PAV\x02` and a 32-byte commitment in an `OP_RETURN`;
//! epoch anchors carry `PAV\x01`, the epoch and a 32-byte hash, 44 bytes in
//! all, as Briolette's bridge does with its own prefix.

use bitcoin::hashes::Hash as _;
use bitcoin::key::{Keypair, Secp256k1, TapTweak, XOnlyPublicKey};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_NUMEQUAL, OP_RETURN,
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, KnownHrp, ScriptBuf, TapLeafHash, Transaction, TxOut, Witness};
use std::str::FromStr;

/// BIP 341's unspendable internal key.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub const DEPOSIT_PREFIX: &[u8; 4] = b"PAV\x02";
pub const ANCHOR_PREFIX: &[u8; 4] = b"PAV\x01";

/// Who can spend the pool.
#[derive(Clone, Debug)]
pub struct Pool {
    pub ramp: XOnlyPublicKey,
    pub cosigners: Vec<XOnlyPublicKey>,
    pub threshold: usize,
    /// Blocks after which the co-signers alone can move a pool output.
    pub recovery: u16,
    info: TaprootSpendInfo,
    cosigned: ScriptBuf,
    recover: ScriptBuf,
}

fn multisig(b: Builder, keys: &[XOnlyPublicKey], k: usize) -> Builder {
    let mut b = b;
    for (i, key) in keys.iter().enumerate() {
        b = b
            .push_x_only_key(key)
            .push_opcode(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
    }
    b.push_int(k as i64).push_opcode(OP_NUMEQUAL)
}

impl Pool {
    pub fn new(
        ramp: XOnlyPublicKey,
        cosigners: Vec<XOnlyPublicKey>,
        threshold: usize,
        recovery: u16,
    ) -> Result<Pool, String> {
        if threshold == 0 || threshold > cosigners.len() {
            return Err("the threshold must be between 1 and the number of co-signers".into());
        }
        let secp = Secp256k1::verification_only();
        let cosigned = multisig(
            Builder::new()
                .push_x_only_key(&ramp)
                .push_opcode(OP_CHECKSIGVERIFY),
            &cosigners,
            threshold,
        )
        .into_script();
        let recover = multisig(
            Builder::new()
                .push_int(recovery as i64)
                .push_opcode(OP_CSV)
                .push_opcode(OP_DROP),
            &cosigners,
            threshold,
        )
        .into_script();
        let internal = XOnlyPublicKey::from_str(NUMS).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(1, cosigned.clone())
            .and_then(|b| b.add_leaf(1, recover.clone()))
            .map_err(|e| e.to_string())?
            .finalize(&secp, internal)
            .map_err(|_| "taproot tree didn't finalize".to_string())?;
        Ok(Pool {
            ramp,
            cosigners,
            threshold,
            recovery,
            info,
            cosigned,
            recover,
        })
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.info.output_key())
    }

    pub fn address(&self, hrp: KnownHrp) -> Address {
        Address::p2tr_tweaked(self.info.output_key(), hrp)
    }

    pub fn cosigned_leaf(&self) -> &ScriptBuf {
        &self.cosigned
    }

    pub fn recovery_leaf(&self) -> &ScriptBuf {
        &self.recover
    }

    fn control(&self, leaf: &ScriptBuf) -> ControlBlock {
        self.info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("the leaf is in the tree")
    }

    /// What each signer signs for input `i` of `tx` spending the co-signed leaf.
    pub fn sighash(&self, tx: &Transaction, prevouts: &[TxOut], i: usize) -> Message {
        let leaf = TapLeafHash::from_script(&self.cosigned, LeafVersion::TapScript);
        let h = SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                i,
                &Prevouts::All(prevouts),
                leaf,
                TapSighashType::Default,
            )
            .expect("prevouts cover the inputs");
        Message::from_digest(h.to_byte_array())
    }

    /// Put the ramp's signature and the co-signers' (by co-signer index,
    /// missing ones left empty) on input `i`.
    pub fn witness(
        &self,
        ramp: &schnorr::Signature,
        cosigners: &[Option<schnorr::Signature>],
    ) -> Witness {
        // The script takes the ramp's signature first from the top of the
        // stack, then each co-signer's in order: so they go on in reverse.
        let mut w = Witness::new();
        for i in (0..self.cosigners.len()).rev() {
            match cosigners.get(i).copied().flatten() {
                Some(s) => w.push(s.as_ref()),
                None => w.push([]),
            }
        }
        w.push(ramp.as_ref());
        w.push(self.cosigned.as_bytes());
        w.push(self.control(&self.cosigned).serialize());
        w
    }

    /// Check a co-signed spend of input `i`: the leaf is the pool's, the
    /// control block commits to the output key, the ramp signed, and at
    /// least `threshold` co-signers did. Our own check of what Bitcoin's
    /// script interpreter would run for this leaf.
    pub fn verify_spend(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
        i: usize,
    ) -> Result<(), String> {
        let secp = Secp256k1::verification_only();
        let w: Vec<&[u8]> = tx.input[i].witness.iter().collect();
        if w.len() != self.cosigners.len() + 3 {
            return Err("not a co-signed spend of the pool".into());
        }
        let (control, script) = (w[w.len() - 1], w[w.len() - 2]);
        if script != self.cosigned.as_bytes() {
            return Err("not the pool's co-signed leaf".into());
        }
        let cb = ControlBlock::decode(control).map_err(|e| e.to_string())?;
        if !cb.verify_taproot_commitment(
            &secp,
            self.info.output_key().to_x_only_public_key(),
            &self.cosigned,
        ) {
            return Err("the control block doesn't commit to the pool".into());
        }
        let msg = self.sighash(tx, prevouts, i);
        let sig = |b: &[u8]| schnorr::Signature::from_slice(b).ok();
        let ramp = sig(w[w.len() - 3]).ok_or("the ramp didn't sign")?;
        secp.verify_schnorr(&ramp, &msg, &self.ramp)
            .map_err(|_| "the ramp's signature doesn't verify")?;
        let mut count = 0;
        for (j, key) in self.cosigners.iter().enumerate() {
            let el = w[w.len() - 4 - j];
            if el.is_empty() {
                continue;
            }
            let s = sig(el).ok_or("a co-signer's signature is malformed")?;
            secp.verify_schnorr(&s, &msg, key)
                .map_err(|_| "a co-signer's signature doesn't verify")?;
            count += 1;
        }
        if count < self.threshold {
            return Err(format!(
                "{count} co-signers signed; {} needed",
                self.threshold
            ));
        }
        Ok(())
    }
}

/// Sign `msg` with `key`.
pub fn sign(key: &Keypair, msg: &Message) -> schnorr::Signature {
    Secp256k1::new().sign_schnorr(msg, key)
}

/// An `OP_RETURN` carrying `data`.
pub fn op_return(data: &[u8]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(PushBytesBuf::try_from(data.to_vec()).expect("under 520 bytes"))
        .into_script()
}

/// The data an `OP_RETURN` script carries, if it is one with one push.
pub fn op_return_data(s: &ScriptBuf) -> Option<Vec<u8>> {
    let mut it = s.instructions();
    match (it.next()?.ok()?, it.next()) {
        (
            bitcoin::script::Instruction::Op(OP_RETURN),
            Some(Ok(bitcoin::script::Instruction::PushBytes(b))),
        ) => Some(b.as_bytes().to_vec()),
        _ => None,
    }
}

pub fn deposit_data(commitment: &[u8; 32]) -> Vec<u8> {
    [DEPOSIT_PREFIX.as_slice(), commitment].concat()
}

pub fn anchor_data(epoch: u64, hash: &[u8; 32]) -> Vec<u8> {
    [ANCHOR_PREFIX.as_slice(), &epoch.to_be_bytes(), hash].concat()
}

/// A single-key Taproot output, for the ramp's own fees (anchors).
pub fn key_spk(key: &Keypair) -> ScriptBuf {
    let secp = Secp256k1::new();
    ScriptBuf::new_p2tr(&secp, key.x_only_public_key().0, None)
}

/// Key-path signature for input `i`.
pub fn key_spend(key: &Keypair, tx: &Transaction, prevouts: &[TxOut], i: usize) -> Witness {
    let secp = Secp256k1::new();
    let tweaked = key.tap_tweak(&secp, None).to_keypair();
    let h = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), TapSighashType::Default)
        .expect("prevouts cover the inputs");
    let s = secp.sign_schnorr(&Message::from_digest(h.to_byte_array()), &tweaked);
    Witness::from_slice(&[s.as_ref()])
}

/// Check a key-path spend of input `i` against the output key in its prevout.
pub fn verify_key_spend(tx: &Transaction, prevouts: &[TxOut], i: usize) -> Result<(), String> {
    let secp = Secp256k1::verification_only();
    let spk = &prevouts[i].script_pubkey;
    if !spk.is_p2tr() {
        return Err("not a Taproot output".into());
    }
    let key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).map_err(|e| e.to_string())?;
    let w: Vec<&[u8]> = tx.input[i].witness.iter().collect();
    let s = w
        .first()
        .and_then(|b| schnorr::Signature::from_slice(b).ok())
        .ok_or("no key-path signature")?;
    let h = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(|e| e.to_string())?;
    secp.verify_schnorr(&s, &Message::from_digest(h.to_byte_array()), &key)
        .map_err(|_| "the key-path signature doesn't verify".to_string())
}
