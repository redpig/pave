# Ramps: moving value in and out (design)

Pave's credit stays credit. A **ramp** is an accountable clerk at the edge of a town that exchanges it for something outside: bitcoin, ether, a stablecoin, or a bank transfer. The kernel doesn't change and doesn't learn what is on the other side. The design follows Briolette's bridge (`src/bridge` and `docs/design/bitcoin_l2.md` in [redpig/briolette](https://github.com/redpig/briolette)), whose `L1Client` already hides which chain is behind it.

## What a ramp needs from the outside system

Four things, as in Briolette:

1. **A pool** holding what backs the credit the ramp issued. On Bitcoin it's a Taproot address; on Ethereum, the bridge contract; on a bank, an account.
2. **Deposits** that name who should be credited.
3. **Withdrawals** paid out of the pool, after a challenge period.
4. **Anchors**: a 32-byte commitment per epoch, and the ramp's keys.

## In pave

**The ramp is a clerk with a budget.** The town issues the ramp an `IssueBudget` for a schema of its own, "Pine credit, backed by ramp R", so a ramp that fails hurts only its own credit, not the credit members earn by working. What the ramp issues is meant never to exceed its pool, and that is checked by audit, not enforced: detection, not prevention, as everywhere offline.

**Deposit:**

1. The depositor's wallet makes a fresh credential and computes its commitment: a hash of the ramp's schema, the credential and a nonce.
2. It sends the outside asset to the pool with the commitment attached: an `OP_RETURN` on Bitcoin, or a contract call's argument. It gives the ramp the credential and nonce, on the board or directly.
3. After the outside system's confirmations, the ramp mints the deposit to a key of its own and splits it. The depositor's credential gets its share, and the treasury gets the fee. The split's receipt is a hash of the deposit's id (txid and output) and the commitment.

Each deposit is credited once. A second credit naming the same deposit is visible to anyone reading the ramp's records, and is a ruling against the ramp.

**Withdrawal:**

1. The ramp invoices the holder in its own credit. The invoice's memo commits to the payout address, the amount and a nonce. The holder pays it like any invoice, so the coin can't also be paid away, and a double spend offline is caught when the records meet.
2. The ramp takes the payment with pave's acceptance check, against its standing list and the town's ticks. Its wallet refuses a payment in any other credit.
3. After the challenge period, counted in blocks from when the ramp took the payment, the co-signers each check the withdrawal against their own view and sign the payout.

   The period should cover the town's detection window: how long until a double spend has met the ramp. That is the same window that sets ticket and epoch lifetimes.
4. Evidence of a double spend arriving in that window is the challenge:
   - **Bitcoin:** the co-signers refuse.
   - **Ethereum:** the fraud proof.
5. Once the payout is broadcast, the ramp settles the credit: the town's fee goes to the treasury, and the rest is retired.

**The co-signers are the town's.** On Bitcoin a withdrawal needs the ramp and a threshold of co-signers. If the ramp disappears, the co-signers alone can move the pool after a long timelock. Briolette's design asks for independent, accountable co-signers. In a co-op that is the auditors or dispute panel the members elect ([elections.md](elections.md)). They each check the withdrawal's payment against their own records before signing, so a ramp can't pay out alone.

The Ethereum route differs. The contract verifies Briolette's fraud proofs on BN254. Pave's credentials are on BLS12-381, so an on-chain proof would go through a SNARK, as Briolette's decentralization notes describe. Until then the Bitcoin-style co-signing is the honest model on either chain.

**Anchors.** Each epoch the ramp posts a commitment to:
- the town's tick head;
- the boards' roots;
- its own ledger: issued, retired, outstanding.

That's 44 bytes in an `OP_RETURN` on Bitcoin, or a storage write on Ethereum. The pool's balance is public on the chain, so anyone can compare what's outstanding against it. The ramp's clerk key, the co-signers' keys and the pool's address are posted on the town board, and their hash is anchored.

## Paying for the town

A ramp charges a **fee at the edges**: a part of each deposit or withdrawal, minted or paid to the town's operations key. That pays for boards, clerks and dispute panels, and transfers inside the town stay free, which matters for small local payments. The rate is public on the board and set by vote. Several ramps can serve one town; each is its own clerk with its own pool and schema, so none of them becomes the platform.

The pool's yield is another possible source. It brings custody and regulatory questions, so it's out of scope here.

## The unit

- **A bitcoin ramp** backs credit in sats. Its value moves with bitcoin.
- **A town that prices in dollars** wants a dollar ramp: a stablecoin, or a bank account. The `L1Client` shape fits a bank as well as a chain: deposits are incoming transfers with a reference, withdrawals are payouts, and anchors go on the board alone.

Exchanging between a ramp's credit and the town's own is a swap at a posted rate, by whoever offers it.

## What's built and what isn't

- **In Briolette:**
  - the `L1Client` trait;
  - an Ethereum contract, with a client that runs;
  - a Bitcoin client that so far simulates deposits, with the Taproot scripts and the `OP_RETURN` formats.
- **In pave**, a Bitcoin ramp:
  - **The credit** ([`board/src/ramp.rs`](../board/src/ramp.rs)): the ramp's schema and budget; deposit claims and their commitments; crediting a deposit as a mint and a split (the depositor's share and the fee); withdrawal invoices whose memo commits to the payout; settling a payout; and `ramp_ledger`, the audit anyone can run from their records, which finds double credits.
  - **Invoices name their credit.** A town with a ramp has two credits, and a wallet refuses a payment in the wrong one.
  - **The pool** ([`ramp/src/pool.rs`](../ramp/src/pool.rs)): a Taproot output with an unspendable key path and two leaves. One needs the ramp and `k` of `n` co-signers; the other needs the co-signers alone after 4,320 blocks. It also has the sighashes and witnesses for spending it, and the `OP_RETURN` formats: `PAV\x02` plus a 32-byte commitment for deposits, and `PAV\x01`, epoch and hash for anchors.
  - **The chain** ([`ramp/src/chain.rs`](../ramp/src/chain.rs)): an `L1` trait in the shape of Briolette's `L1Client`, and a chain with regtest's rules in memory behind it. It tracks confirmations and unspent outputs, and refuses an unconfirmed or spent input, more out than in, a pool spend that doesn't verify, or a key spend without its key.
  - **The roles** ([`ramp/src/lib.rs`](../ramp/src/lib.rs)):
    - `Ramp` scans for and credits deposits, invoices and takes withdrawals, builds and broadcasts payouts, and anchors epochs, paying for them from its own fee output.
    - `Cosigner` reviews a payout against its own view before signing it. It checks:
      - the challenge period;
      - the memo's address and amount;
      - that the payment was in the ramp's credit;
      - for a double spend;
      - that the outputs pay the recipient its share, with change back to the pool.
  - **Tests**: [`ramp/tests/ramp.rs`](../ramp/tests/ramp.rs) runs sats in, credit around, and sats out end to end, then the audit, the anchor and each refusal; [`ramp/tests/pool.rs`](../ramp/tests/pool.rs) covers the spending rules. Each check has a mutation that the tests catch.

Not yet built:
- **bitcoind on regtest.** The pool's spends are checked by our own reading of the leaf, not by Bitcoin's interpreter. An RPC client behind `L1` would check them against the interpreter and a real mempool.
- **Reorgs.**
- **The recovery leaf's spend.**
- **Fee estimation.** The miners' share is a fixed 500 sats.
- **The co-signers' keys from the town's election.** Today they are given to `Ramp::open`.
- **Posting the keys and the pool's address on the board.** The anchor commits to the tick head and the ledger, but not yet to the boards' roots.
- **An Ethereum or bank `L1`.**

Open questions, as in Briolette's note:
- how the co-signers' keys are made and rotated;
- managing the pool's UTXOs and fees;
- handling reorgs;
- when BitVM could replace the co-signers;
- whether Lightning could carry small deposits and withdrawals.
