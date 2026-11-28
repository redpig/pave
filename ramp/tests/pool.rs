//! The pool's spending rules and the chain's: what a co-signed spend needs,
//! and what the chain refuses.

use bitcoin::absolute::LockTime;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::transaction::Version;
use bitcoin::{Amount, KnownHrp, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use pave_ramp::chain::{SimChain, L1};
use pave_ramp::pool::{
    anchor_data, deposit_data, key_spend, key_spk, op_return, op_return_data, sign, Pool,
};

fn keys(n: usize) -> Vec<Keypair> {
    let secp = Secp256k1::new();
    (0..n)
        .map(|_| Keypair::new(&secp, &mut thread_rng()))
        .collect()
}

struct Setup {
    ramp: Keypair,
    cos: Vec<Keypair>,
    pool: Pool,
    chain: SimChain,
    tx: Transaction,
    prevouts: Vec<TxOut>,
}

/// A pool (ramp and 2 of 3) holding two confirmed outputs, and an unsigned
/// spend of both.
fn setup() -> Setup {
    let (ramp, cos) = (keys(1).remove(0), keys(3));
    let pool = Pool::new(
        ramp.x_only_public_key().0,
        cos.iter().map(|k| k.x_only_public_key().0).collect(),
        2,
        144,
    )
    .unwrap();
    let mut chain = SimChain::new();
    chain.watch(&pool);
    chain.pay(pool.script_pubkey(), 40_000, None);
    chain.pay(pool.script_pubkey(), 60_000, None);
    chain.mine(1);
    let utxos = chain.unspent(&pool.script_pubkey());
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: utxos
            .iter()
            .map(|(op, _)| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: key_spk(&keys(1)[0]),
        }],
    };
    let prevouts = utxos.into_iter().map(|(_, o)| o).collect();
    Setup {
        ramp,
        cos,
        pool,
        chain,
        tx,
        prevouts,
    }
}

/// Sign every input: the ramp with `ramp`, and co-signer `i` with `by[i]` if given.
fn signed(s: &Setup, ramp: &Keypair, by: &[Option<&Keypair>]) -> Transaction {
    let mut tx = s.tx.clone();
    for i in 0..tx.input.len() {
        let m = s.pool.sighash(&s.tx, &s.prevouts, i);
        let theirs: Vec<_> = by.iter().map(|k| k.map(|k| sign(k, &m))).collect();
        tx.input[i].witness = s.pool.witness(&sign(ramp, &m), &theirs);
    }
    tx
}

#[test]
fn thresholds_in_range() {
    let x: Vec<_> = keys(3).iter().map(|k| k.x_only_public_key().0).collect();
    assert!(Pool::new(x[0], x.clone(), 0, 10).is_err());
    assert!(Pool::new(x[0], x.clone(), 4, 10).is_err());
    assert!(Pool::new(x[0], x.clone(), 3, 10).is_ok());
    let p = Pool::new(x[0], x.clone(), 1, 10).unwrap();
    assert!(p
        .address(KnownHrp::Regtest)
        .to_string()
        .starts_with("bcrt1p"));
    assert!(p.address(KnownHrp::Mainnet).to_string().starts_with("bc1p"));
    assert_ne!(p.cosigned_leaf(), p.recovery_leaf());
    assert_ne!(
        p.script_pubkey(),
        Pool::new(x[0], x.clone(), 2, 10).unwrap().script_pubkey(),
        "the threshold is in the output"
    );
    assert_ne!(
        p.script_pubkey(),
        Pool::new(x[1], x, 1, 10).unwrap().script_pubkey(),
        "the ramp's key is in the output"
    );
}

#[test]
fn ramp_and_two_of_three() {
    let mut s = setup();
    let (c0, c1, c2) = (&s.cos[0], &s.cos[1], &s.cos[2]);
    for by in [
        [Some(c0), Some(c1), None],
        [Some(c0), None, Some(c2)],
        [None, Some(c1), Some(c2)],
        [Some(c0), Some(c1), Some(c2)],
    ] {
        let tx = signed(&s, &s.ramp, &by);
        for i in 0..tx.input.len() {
            s.pool.verify_spend(&tx, &s.prevouts, i).unwrap();
        }
    }
    let tx = signed(&s, &s.ramp, &[Some(c0), Some(c1)]);
    s.chain.broadcast(tx.clone()).unwrap();
    assert_eq!(
        s.chain.broadcast(tx).unwrap_err(),
        "an input is already spent"
    );
}

#[test]
fn what_a_spend_needs() {
    let s = setup();
    let (c0, c1, c2) = (&s.cos[0], &s.cos[1], &s.cos[2]);
    let err = |tx: &Transaction| s.pool.verify_spend(tx, &s.prevouts, 0).unwrap_err();

    assert_eq!(
        err(&signed(&s, &s.ramp, &[Some(c0), None, None])),
        "1 co-signers signed; 2 needed"
    );
    assert_eq!(
        err(&signed(&s, &s.ramp, &[None, None, None])),
        "0 co-signers signed; 2 needed"
    );
    // The co-signers without the ramp: a stranger's key in its place.
    let stranger = keys(1).remove(0);
    assert_eq!(
        err(&signed(&s, &stranger, &[Some(c0), Some(c1), Some(c2)])),
        "the ramp's signature doesn't verify"
    );
    // A co-signer's signature in another's place.
    assert_eq!(
        err(&signed(&s, &s.ramp, &[Some(c1), Some(c0), None])),
        "a co-signer's signature doesn't verify"
    );
    assert_eq!(
        err(&signed(&s, &s.ramp, &[Some(c0), Some(&stranger), None])),
        "a co-signer's signature doesn't verify"
    );

    // Signatures for another input, or another transaction.
    let mut tx = signed(&s, &s.ramp, &[Some(c0), Some(c1), None]);
    tx.input.swap(0, 1);
    assert_eq!(err(&tx), "the ramp's signature doesn't verify");
    let mut tx = signed(&s, &s.ramp, &[Some(c0), Some(c1), None]);
    tx.output[0].value = Amount::from_sat(98_000);
    assert_eq!(err(&tx), "the ramp's signature doesn't verify");

    // The wrong shape: a missing element, another leaf, another pool's control block, a malformed signature.
    let good = signed(&s, &s.ramp, &[Some(c0), Some(c1), None]);
    let w: Vec<Vec<u8>> = good.input[0].witness.iter().map(|e| e.to_vec()).collect();
    let with = |w: Vec<Vec<u8>>| {
        let mut tx = good.clone();
        tx.input[0].witness = Witness::from_slice(&w);
        tx
    };
    assert_eq!(
        err(&with(w[1..].to_vec())),
        "not a co-signed spend of the pool"
    );
    assert_eq!(
        err(&with([vec![vec![1; 64]], w.clone()].concat())),
        "not a co-signed spend of the pool",
        "an extra element: the stack wouldn't end clean"
    );
    let mut v = w.clone();
    v[4] = s.pool.recovery_leaf().to_bytes();
    assert_eq!(err(&with(v)), "not the pool's co-signed leaf");
    let other = setup();
    let mut v = w.clone();
    v[5] = signed(
        &other,
        &other.ramp,
        &[Some(&other.cos[0]), Some(&other.cos[1]), None],
    )
    .input[0]
        .witness
        .last()
        .unwrap()
        .to_vec();
    assert_eq!(
        err(&with(v)),
        "the control block doesn't commit to the pool"
    );
    let mut v = w.clone();
    v[3] = vec![1; 63];
    assert_eq!(err(&with(v)), "the ramp didn't sign");
    let mut v = w.clone();
    v[2] = vec![1; 10];
    assert_eq!(err(&with(v)), "a co-signer's signature is malformed");
}

#[test]
fn the_chain_refuses() {
    let mut s = setup();
    let (c0, c1) = (&s.cos[0], &s.cos[1]);
    // Too few co-signers, as the chain sees it.
    assert!(s
        .chain
        .broadcast(signed(&s, &s.ramp, &[Some(c0), None, None]))
        .unwrap_err()
        .contains("2 needed"));
    // More out than in.
    let mut big = s.tx.clone();
    big.output[0].value = Amount::from_sat(100_001);
    let tx = {
        let mut tx = big.clone();
        for i in 0..tx.input.len() {
            let m = s.pool.sighash(&big, &s.prevouts, i);
            tx.input[i].witness = s.pool.witness(
                &sign(&s.ramp, &m),
                &[Some(sign(c0, &m)), Some(sign(c1, &m))],
            );
        }
        tx
    };
    assert_eq!(s.chain.broadcast(tx).unwrap_err(), "outputs exceed inputs");

    // An unconfirmed output can't be spent yet; a key-path one needs its key.
    let k = keys(1).remove(0);
    s.chain.pay(key_spk(&k), 5_000, None);
    assert!(
        s.chain.unspent(&key_spk(&k)).is_empty(),
        "in the mempool: not unspent yet"
    );
    s.chain.mine(1);
    let (op, prev) = s.chain.unspent(&key_spk(&k)).remove(0);
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(4_000),
            script_pubkey: key_spk(&k),
        }],
    };
    let mut bad = spend.clone();
    bad.input[0].witness = key_spend(&keys(1)[0], &spend, std::slice::from_ref(&prev), 0);
    assert_eq!(
        s.chain.broadcast(bad).unwrap_err(),
        "the key-path signature doesn't verify"
    );
    let mut none = spend.clone();
    none.input[0].witness = Witness::new();
    assert_eq!(
        s.chain.broadcast(none).unwrap_err(),
        "no key-path signature"
    );
    let mut good = spend.clone();
    good.input[0].witness = key_spend(&k, &spend, &[prev], 0);
    let id = s.chain.broadcast(good).unwrap();
    // Its output is in the mempool: spending it now is refused.
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: id, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    assert_eq!(
        s.chain.broadcast(child).unwrap_err(),
        "an input isn't a confirmed output"
    );

    // A non-Taproot output nobody watches.
    let wsh = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_raw_hash(
        bitcoin::hashes::Hash::all_zeros(),
    ));
    s.chain.pay(wsh.clone(), 1_000, None);
    s.chain.mine(1);
    let (op, _) = s.chain.unspent(&wsh).remove(0);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    assert_eq!(s.chain.broadcast(tx).unwrap_err(), "not a Taproot output");
}

#[test]
fn deposits_and_anchors() {
    let mut s = setup();
    let spk = s.pool.script_pubkey();
    let c = [7u8; 32];
    s.chain.pay(spk.clone(), 1_000, Some(&deposit_data(&c)));
    // Not a deposit: no data, the anchor prefix, short data, another address.
    s.chain
        .pay(spk.clone(), 2_000, Some(&anchor_data(1, &c)[..36]));
    s.chain
        .pay(spk.clone(), 3_000, Some(&deposit_data(&c)[..35]));
    s.chain
        .pay(key_spk(&s.ramp), 4_000, Some(&deposit_data(&c)));
    let d = s.chain.deposits(&spk);
    assert_eq!(d.len(), 1);
    assert_eq!(
        (d[0].sats, d[0].commitment, d[0].confirmations),
        (1_000, c, 0)
    );
    s.chain.mine(3);
    assert_eq!(s.chain.deposits(&spk)[0].confirmations, 3);
    assert_eq!(s.chain.height(), 4);
    assert_eq!(s.chain.balance(&spk), 100_000 + 1_000 + 2_000 + 3_000);

    // Anchors count once confirmed, and only with the anchor prefix and length.
    s.chain.pay(key_spk(&s.ramp), 1, Some(&anchor_data(9, &c)));
    s.chain.pay(key_spk(&s.ramp), 1, Some(&deposit_data(&c)));
    s.chain.pay(
        key_spk(&s.ramp),
        1,
        Some(&[anchor_data(9, &c), vec![0]].concat()),
    );
    assert!(s.chain.anchors().is_empty());
    s.chain.mine(1);
    assert_eq!(s.chain.anchors(), vec![(9, c)]);

    assert_eq!(
        op_return_data(&op_return(b"hello")),
        Some(b"hello".to_vec())
    );
    assert_eq!(op_return_data(&key_spk(&s.ramp)), None);
    assert_eq!(op_return_data(&ScriptBuf::from_bytes(vec![0x6a])), None);
    assert_eq!(&deposit_data(&c)[..4], b"PAV\x02");
    assert_eq!(&anchor_data(1, &c)[..12], b"PAV\x01\0\0\0\0\0\0\0\x01");
}
