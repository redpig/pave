//! A ramp end to end: sats deposited into a Taproot pool become a town's
//! backed credit, move like any credit, and come back out as a payout the
//! town's auditors co-sign after the challenge period. The ledger and the
//! pool balance agree; a deposit credited twice, a withdrawal paid in the
//! wrong credit, a double-spent withdrawal, a payout altered after co-signing
//! and one with too few co-signers are all caught.

use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Address, KnownHrp};
use pave_board::node::{Node, PendingJoin};
use pave_board::pay::{Invoice, PayVerdict, Prefix};
use pave_kernel::hash::Hash;
use pave_kernel::Op;
use pave_ramp::chain::{SimChain, L1};
use pave_ramp::pool::deposit_data;
use pave_ramp::{anchor_hash, Cosigner, Ramp};

fn join(town: &mut Node, name: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", credits).unwrap();
    let mut n = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    for _ in 0..2 {
        let t = town
            .answer_refill(&n.refill_request(&town.refill_terms().unwrap(), 16).unwrap())
            .unwrap();
        n.take_tickets(t);
    }
    n
}

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle_for(&b.have()), b.bundle_for(&a.have()));
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
    a.outbox.clear();
    b.outbox.clear();
    let (sa, sb) = (a.standings(), b.standings());
    b.absorb_standings(sa);
    a.absorb_standings(sb);
}

/// The payer's side of a payment, up to the signed record.
fn pay_record(payer: &mut Node, payee: &mut Node, inv: &Invoice) -> pave_kernel::Record {
    payer.check_invoice(inv).unwrap();
    let offer = payer.offer(inv).unwrap();
    let lacks: Vec<Prefix> = payee.lacks(&offer);
    let mut p = payer
        .propose(&offer, &lacks, &pave_protocol::cheat_list(&payer.view))
        .unwrap();
    let mut v = payee.judge(&p);
    if let PayVerdict::NeedStanding(list) = v {
        p = payer.propose(&offer, &[], &list).unwrap();
        v = payee.judge(&p);
    }
    assert_eq!(v, PayVerdict::Accept);
    payer.pay_invoice(inv, offer.state).unwrap()
}

fn pay(payer: &mut Node, payee: &mut Node, inv: &Invoice) {
    let rec = pay_record(payer, payee, inv);
    let ack = payee.take_payment(&rec).unwrap();
    payer.confirm(&rec, &ack).unwrap();
}

fn held(n: &Node, schema: &Hash) -> u64 {
    n.my_coins_in(schema).iter().map(|c| c.amount).sum()
}

fn address() -> (Address, bitcoin::ScriptBuf) {
    let secp = Secp256k1::new();
    let k = Keypair::new(&secp, &mut bitcoin::secp256k1::rand::thread_rng());
    let a = Address::p2tr(&secp, k.x_only_public_key().0, None, KnownHrp::Regtest);
    let spk = a.script_pubkey();
    (a, spk)
}

#[test]
fn sats_in_credit_around_sats_out() {
    let dir = std::env::temp_dir().join(format!("pave-ramp-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut rampn = join(&mut town, "ramp", &dir, &[]);
    let mut ana = join(&mut town, "ana", &dir, &[]);
    let mut bea = join(&mut town, "bea", &dir, &[]);
    let mut cy = join(&mut town, "cy", &dir, &[50_000]);
    let mut auditors: Vec<Node> = (0..3)
        .map(|i| join(&mut town, &format!("aud{i}"), &dir, &[]))
        .collect();
    let cosigners: Vec<Cosigner> = (0..3).map(|_| Cosigner::new()).collect();
    let mut treasurer = join(&mut town, "treasurer", &dir, &[]);
    let treasury = treasurer.receive().unwrap();

    // The town opens a ramp: its own credit, a pool the ramp and two of the
    // three auditors spend, a 1% fee to the treasury, three confirmations,
    // and six blocks to challenge a withdrawal.
    let mut ramp = Ramp::open(
        &mut town,
        &mut rampn,
        "Pine sats, backed by ramp R",
        10_000_000,
        cosigners.iter().map(|c| c.public()).collect(),
        2,
        100,
        treasury.clone(),
        3,
        6,
    )
    .unwrap();
    meet(&mut rampn, &mut town);
    let schema = ramp.info.schema;
    let mut chain = SimChain::new();
    chain.watch(&ramp.pool);
    assert!(
        ramp.info.pool.starts_with("bcrt1p"),
        "a regtest Taproot address: {}",
        ramp.info.pool
    );

    // Ana deposits 100,000 sats. Her wallet makes the commitment; her
    // Bitcoin wallet puts it in an OP_RETURN beside the payment.
    let (claim, c) = ana.deposit_claim(&schema).unwrap();
    chain.pay(
        ramp.pool.script_pubkey(),
        100_000,
        Some(&deposit_data(&c.0)),
    );
    // A deposit nobody claims, and one to another address, credit nothing.
    chain.pay(
        ramp.pool.script_pubkey(),
        5_000,
        Some(&deposit_data(&[9; 32])),
    );
    chain.pay(address().1, 7_000, Some(&deposit_data(&c.0)));
    ramp.claim(c, claim);
    chain.mine(1);
    assert!(
        ramp.scan(&mut rampn, &chain).unwrap().is_empty(),
        "one confirmation of three"
    );
    chain.mine(2);
    assert_eq!(ramp.scan(&mut rampn, &chain).unwrap().len(), 1);
    assert!(
        ramp.scan(&mut rampn, &chain).unwrap().is_empty(),
        "credited once"
    );
    meet(&mut ana, &mut rampn);
    meet(&mut treasurer, &mut rampn);
    assert_eq!(held(&ana, &schema), 99_000, "less the 1% fee");
    assert_eq!(held(&treasurer, &schema), 1_000);

    // It's credit like any other: Ana pays Bea 40,000.
    meet(&mut ana, &mut bea);
    let inv = bea.invoice_in(schema, 40_000, Hash([1; 32])).unwrap();
    pay(&mut ana, &mut bea, &inv);
    meet(&mut ana, &mut bea);
    assert_eq!((held(&ana, &schema), held(&bea, &schema)), (59_000, 40_000));

    // Bea withdraws 30,000 to her Bitcoin address: a payment to the ramp
    // against an invoice that commits to the address and amount.
    let (bea_addr, bea_spk) = address();
    meet(&mut bea, &mut rampn);
    let inv = ramp
        .request_withdrawal(&mut rampn, &bea_addr.to_string(), 30_000)
        .unwrap();
    let rec = pay_record(&mut bea, &mut rampn, &inv);
    let ack = ramp.take_payment(&mut rampn, &rec, chain.height()).unwrap();
    bea.confirm(&rec, &ack).unwrap();
    let review = ramp.payout(&chain, 0).unwrap();
    for a in auditors.iter_mut() {
        meet(a, &mut rampn);
    }
    // Too early: the challenge period is six blocks.
    let early = cosigners[0]
        .review(
            &auditors[0],
            &ramp.info,
            &ramp.pool,
            &ramp,
            &review,
            chain.height(),
        )
        .unwrap_err();
    assert!(early.contains("challenge period"), "{early}");
    chain.mine(6);
    let h = chain.height();
    let sig0 = cosigners[0]
        .review(&auditors[0], &ramp.info, &ramp.pool, &ramp, &review, h)
        .unwrap();
    let sig1 = cosigners[1]
        .review(&auditors[1], &ramp.info, &ramp.pool, &ramp, &review, h)
        .unwrap();
    // The right memo on a payment of less: the treasurer pays 500 of its fee under Bea's memo.
    let tcoin = treasurer.my_coins_in(&schema)[0].clone();
    let Op::Split { receipt, .. } = review.payment.op.clone() else {
        panic!()
    };
    let parts = vec![
        (500, rampn.receive().unwrap()),
        (500, treasurer.receive().unwrap()),
    ];
    let short = pave_kernel::sign(
        treasurer.view.scheme(),
        &treasurer.key,
        &tcoin.holder,
        Op::Split {
            state: tcoin.state,
            parts,
            receipt,
        },
    );
    auditors[2].view.apply(&short).unwrap();
    // A review the ramp tampered with, each way, is refused.
    let refuse = |r: &pave_ramp::Review| {
        cosigners[2]
            .review(&auditors[2], &ramp.info, &ramp.pool, &ramp, r, h)
            .unwrap_err()
    };
    let (evil, evil_spk) = address();
    let mut r = review.clone();
    r.address = evil.to_string();
    r.tx.output[0].script_pubkey = evil_spk.clone();
    assert!(
        refuse(&r).contains("doesn't commit"),
        "another address than the payment commits to"
    );
    let mut r = review.clone();
    r.amount = 40_000;
    r.tx.output[0].value = bitcoin::Amount::from_sat(40_000 - 400 - 500);
    assert!(refuse(&r).contains("doesn't commit"), "another amount");
    let mut r = review.clone();
    r.tx.output[0].script_pubkey = evil_spk.clone();
    assert!(refuse(&r).contains("recipient its share"));
    let mut r = review.clone();
    r.tx.output[0].value = bitcoin::Amount::from_sat(29_201);
    assert!(refuse(&r).contains("recipient its share"));
    let mut r = review.clone();
    r.tx.output[1].script_pubkey = evil_spk.clone();
    assert!(
        refuse(&r).contains("outside the pool"),
        "change to someone else"
    );
    let mut r = review.clone();
    r.prevouts[0].script_pubkey = evil_spk.clone();
    assert!(refuse(&r).contains("outside the pool"));
    let mut r = review.clone();
    r.paid_at = h;
    assert!(
        refuse(&r).contains("challenge period"),
        "the window runs from the payment"
    );
    let mut r = review.clone();
    r.payment = short;
    assert!(refuse(&r).contains("isn't this amount"), "{}", refuse(&r));
    let mut r = review.clone();
    r.payment.op = Op::Retire {
        state: Hash([0; 32]),
    };
    assert!(refuse(&r).contains("not a payment"));
    // One co-signer isn't enough; nor are two on a payout altered after.
    let e = ramp
        .complete(
            &mut rampn,
            &mut chain,
            0,
            review.clone(),
            &[sig0.iter().copied().map(Some).collect()],
        )
        .unwrap_err();
    assert!(e.contains("1 co-signers signed; 2 needed"), "{e}");
    let mut altered = review.clone();
    altered.tx.output[0].script_pubkey = address().1;
    let both = vec![
        sig0.iter().copied().map(Some).collect::<Vec<_>>(),
        sig1.iter().copied().map(Some).collect(),
    ];
    assert!(ramp
        .complete(&mut rampn, &mut chain, 0, altered, &both)
        .unwrap_err()
        .contains("doesn't verify"));
    let last_review = review.clone();
    let txid = ramp
        .complete(&mut rampn, &mut chain, 0, review, &both)
        .unwrap();
    chain.mine(1);
    assert_eq!(
        chain.received(&bea_spk),
        30_000 - 300 - 500,
        "less the 1% fee and the miners' 500"
    );
    assert_eq!(ramp.withdrawals[0].done, Some(txid));

    // The audit: what's outstanding is what the pool holds.
    for a in auditors.iter_mut() {
        meet(a, &mut rampn);
    }
    let ledger = auditors[2].ramp_ledger(&schema);
    assert_eq!((ledger.minted, ledger.retired), (100_000, 29_700));
    let pool_sats = chain.balance(&ramp.pool.script_pubkey()) - 5_000; // less the unclaimed deposit
    assert_eq!(ledger.outstanding(), pool_sats);

    // Paid in the town's own credit, not the ramp's: no payout.
    let (cy_addr, _) = address();
    meet(&mut cy, &mut rampn);
    let inv = ramp
        .request_withdrawal(&mut rampn, &cy_addr.to_string(), 20_000)
        .unwrap();
    assert_eq!(inv.credit, Some(schema));
    assert!(
        cy.offer(&inv).is_err(),
        "Cy holds none of the ramp's credit"
    );
    let cash = cy.my_coins()[0].state;
    let rec = cy.pay_invoice(&inv, cash).unwrap();
    let e = ramp
        .take_payment(&mut rampn, &rec, chain.height())
        .unwrap_err();
    assert!(e.contains("another credit"), "{e}");
    // A ramp that pays out anyway: the auditors see it was cash.
    meet(&mut auditors[0], &mut rampn);
    meet(&mut auditors[0], &mut cy);
    let w = ramp.withdrawals[1].clone();
    let cash_review = pave_ramp::Review {
        address: w.address.clone(),
        amount: w.amount,
        nonce: w.nonce,
        payment: rec.clone(),
        paid_at: 0,
        tx: last_review.tx.clone(),
        prevouts: last_review.prevouts.clone(),
    };
    let e = cosigners[0]
        .review(
            &auditors[0],
            &ramp.info,
            &ramp.pool,
            &ramp,
            &cash_review,
            chain.height(),
        )
        .unwrap_err();
    assert!(e.contains("ramp's credit"), "{e}");
    // Small withdrawals, and a pool that can't cover one.
    // 836 less the 1% fee (8) and the miners' 500 leaves 328, under dust; 838 leaves 330.
    assert!(ramp
        .request_withdrawal(&mut rampn, &cy_addr.to_string(), 836)
        .unwrap_err()
        .contains("too small"));
    let n = ramp.withdrawals.len();
    ramp.request_withdrawal(&mut rampn, &cy_addr.to_string(), 838)
        .unwrap();
    assert_eq!(ramp.withdrawals.len(), n + 1);
    assert!(ramp.payout(&chain, n).unwrap_err().contains("not paid"));
    assert!(ramp
        .request_withdrawal(&mut rampn, "not an address", 6_000)
        .is_err());
    assert!(
        ramp.request_withdrawal(
            &mut rampn,
            &bitcoin::Address::p2tr(
                &Secp256k1::new(),
                Keypair::new(
                    &Secp256k1::new(),
                    &mut bitcoin::secp256k1::rand::thread_rng()
                )
                .x_only_public_key()
                .0,
                None,
                KnownHrp::Mainnet
            )
            .to_string(),
            6_000
        )
        .is_err(),
        "a mainnet address on a regtest ramp"
    );

    // Ana withdraws 20,000 but spends the same coin to Bea too. The
    // auditors who hear of it refuse, so the payout can't be co-signed.
    let (ana_addr, _) = address();
    meet(&mut ana, &mut rampn);
    let ana_w = ramp.withdrawals.len();
    let inv = ramp
        .request_withdrawal(&mut rampn, &ana_addr.to_string(), 20_000)
        .unwrap();
    let coin = ana.my_coins_in(&schema)[0].clone();
    let rec = pay_record(&mut ana, &mut rampn, &inv);
    let ack = ramp.take_payment(&mut rampn, &rec, chain.height()).unwrap();
    ana.confirm(&rec, &ack).unwrap();
    let state = coin.state;
    let to_bea = bea.receive().unwrap();
    let twice = pave_kernel::sign(
        ana.view.scheme(),
        &ana.key,
        &coin.holder,
        Op::Transfer {
            state,
            to: to_bea,
            receipt: Hash([2; 32]),
        },
    );
    let _ = bea.view.apply(&twice);
    meet(&mut ana, &mut bea);
    chain.mine(6);
    let review = ramp.payout(&chain, ana_w).unwrap();
    // Two auditors meet Bea; the third only hears the evidence by gossip.
    for a in auditors.iter_mut() {
        meet(a, &mut rampn);
    }
    for a in auditors.iter_mut().skip(1) {
        meet(a, &mut bea);
    }
    let ev: Vec<_> = bea.view.evidence().cloned().collect();
    assert!(!ev.is_empty());
    for e in &ev {
        assert!(auditors[0].view.import_evidence(e));
    }
    assert!(auditors[0].view.conflicts().is_empty());
    for (c, a) in cosigners.iter().zip(&auditors) {
        let e = c
            .review(a, &ramp.info, &ramp.pool, &ramp, &review, chain.height())
            .unwrap_err();
        assert!(e.contains("spent twice"), "{e}");
    }

    // An epoch anchor: the town's tick head and the ramp's ledger, which an
    // auditor recomputes from its own view.
    chain.pay(ramp.fee_spk(), 10_000, None);
    chain.mine(1);
    let head = pave_protocol::head(&rampn.view, &rampn.town.sequence)
        .map(|h| h.state)
        .unwrap_or(Hash([0; 32]));
    ramp.anchor(&rampn, &mut chain, 1, &head).unwrap();
    chain.mine(1);
    meet(&mut auditors[0], &mut rampn);
    assert_eq!(
        chain.anchors(),
        vec![(1, anchor_hash(&head, &auditors[0].ramp_ledger(&schema)))]
    );

    // A ramp that credits one deposit twice: anyone's audit shows it, and
    // what's outstanding then exceeds the pool.
    let (claim, c) = bea.deposit_claim(&schema).unwrap();
    chain.pay(ramp.pool.script_pubkey(), 10_000, Some(&deposit_data(&c.0)));
    chain.mine(3);
    let d = chain
        .deposits(&ramp.pool.script_pubkey())
        .into_iter()
        .find(|d| d.commitment == c.0)
        .unwrap();
    let dep = pave_board::ramp::Deposit {
        id: format!("{}:{}", d.outpoint.txid, d.outpoint.vout),
        amount: d.sats,
        commitment: c,
        confirmations: d.confirmations,
    };
    rampn.credit_deposit(&ramp.info, &dep, &claim).unwrap();
    rampn.credit_deposit(&ramp.info, &dep, &claim).unwrap();
    meet(&mut auditors[1], &mut rampn);
    let ledger = auditors[1].ramp_ledger(&schema);
    assert_eq!(ledger.double_credits.len(), 1);
    assert_eq!(
        ledger.outstanding(),
        chain.balance(&ramp.pool.script_pubkey()) - 5_000 + 10_000,
        "outstanding exceeds the pool by the second credit"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
