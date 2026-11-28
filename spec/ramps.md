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

1. The depositor's wallet makes a fresh credential and computes its commitment: a hash of the ramp, the credential and a nonce.
2. It sends the outside asset to the pool with the commitment attached: an `OP_RETURN` on Bitcoin, or a contract call's argument. It gives the ramp the credential and nonce, on the board or directly.
3. After the outside system's confirmations, the ramp mints to the credential. The receipt is a hash of the deposit's id (txid and output) and the commitment.

Each deposit is credited once. A second mint naming the same deposit is visible to anyone reading the ramp's records, and is a ruling against the ramp.

**Withdrawal:**

1. The holder retires credit with a receipt naming the ramp, the payout address, the amount and a nonce. A retire is a spend, so the same coin can't also be paid away. A double spend offline is caught when the records meet.
2. The ramp checks the retire with pave's acceptance check, against its standing list and the town's ticks.
3. The ramp pays out after the challenge period:
   - **Bitcoin:** an output timelocked with `OP_CHECKSEQUENCEVERIFY`.
   - **Ethereum:** the contract's withdrawal delay.

   The period should cover the town's detection window: how long until a double spend has met the ramp. That is the same window that sets ticket and epoch lifetimes.
4. Evidence of a double spend arriving in that window is the challenge:
   - **Bitcoin:** the co-signers refuse.
   - **Ethereum:** the fraud proof.

**The co-signers are the town's.** On Bitcoin a withdrawal needs the ramp and a threshold of co-signers. Briolette's design asks for independent, accountable co-signers. In a co-op that is the auditors or dispute panel the members elect ([elections.md](elections.md)). They each run the acceptance check on the retire before signing, so a ramp can't pay out alone.

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
- **In pave:** nothing yet. The pieces it would use are all there:
  - a clerk with a budget;
  - mints and retires with receipts;
  - the acceptance check;
  - boards for keys and rates;
  - elections for the co-signers and the fee.

Next: a pave ramp against Bitcoin regtest, using Briolette's script and `OP_RETURN` formats, with the town's auditors as co-signers.

Open questions, as in Briolette's note:
- how the co-signers' keys are made and rotated;
- managing the pool's UTXOs and fees;
- handling reorgs;
- when BitVM could replace the co-signers;
- whether Lightning could carry small deposits and withdrawals.
