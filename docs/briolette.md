# Pave and Briolette

Pave's credential scheme is Briolette's v1: ECDAA over BLS12-381, from [redpig/briolette](https://github.com/redpig/briolette)'s `briolette-crypto`, pinned in `Cargo.lock` at `82a067c`. That is also the fork's current head, so the cryptography isn't behind. What differs is how much of the fork pave uses. This is that comparison, as of that commit.

## What pave uses

From `briolette-crypto` v1, through [`schemes/briolette`](../schemes/briolette):

| Function | For |
|---|---|
| `generate_wallet_keypair`, `generate_issuer_keypair`, `issue_credential` | Joining a group |
| `randomize_credential` | A fresh unlinkable credential per holding and role |
| `sign`, `verify` | Every signature, with or without a basename |
| `credential_in_group` | Non-revocation proofs (`nonrevoked.rs`) |
| `deflate_signature`, `inflate_signature` | Storing signatures without the credential every record already carries: 98 bytes, not 291 |

The patterns pave builds on are Briolette's design rather than its code: tickets and transfer as spend, basenames that link only misbehavior, epochs with revoked groups, gossip, extra requests in an epoch linking rather than being refused, and soft expiry pushing swaps.

## What the fork has that pave doesn't

**Worth taking soon:**

1. **Hardware attestation at enrollment.** Built in pave as [`board/src/attest.rs`](../board/src/attest.rs), after the fork's `src/registrar/src/attestation.rs`. Pave's version is stricter:
   - It checks every signature in the chain, RSA and P-384 included; the fork trusts an RSA or unknown signature by its place in the chain.
   - It refuses everything when no roots are configured; the fork skips the root check then.
   - It requires every issuer to be a CA and every certificate to be in date.
   - On Android it checks the boot is verified and locked, and that the attestation is for a trusted app.
   - On Apple it checks the key id and credential, the counter and the environment.

   A class the town's policy names is granted only on an attestation that earns it.
2. **The mobile app.** `mobile/` is a Kotlin Multiplatform app:
   - shared Compose screens;
   - UniFFI bindings to the Rust wallet;
   - a QR scanner;
   - Android key attestation and persistence;
   - `build-rust.sh` for Android and iOS.

   Pave's [`mobile/`](../mobile) has a C interface and hand-written wrappers not yet built on a device. Moving pave onto that shell, with one UniFFI function over `pave_call`, is the short path to a phone.
3. **The bridge.** `src/bridge` defines a chain-agnostic `L1Client` and implements it twice:
   - **Ethereum:** a contract with an on-chain ECDAA fraud-proof verifier, and a real client.
   - **Bitcoin:** a Taproot pool with a federation co-signing withdrawals; its client is so far a simulation.

   It is pave's on- and off-ramp; see [spec/ramps.md](../spec/ramps.md).
4. **Recovery.** `docs/design/recovery.md` and `src/recovery`:
   - an opt-in binding registered before loss;
   - recovery only after the lost wallet's holdings expire;
   - the old wallet's group revoked;
   - value paid from a pool of already-issued tokens, so nothing new is minted.

   Pave's lost-wallet row (W9 in [threats.md](threats.md)) is a gap. This design fits pave's kernel as it stands: a recovery clerk with a budget, receipts naming the binding, and revocation on the dispatch-style ticks.

**Worth taking when pave needs it:**

5. **Split signing with a card.** `v1::split` (Brickell–Li style) divides the signing key between the host and a smart card. The card's share needs only G1 scalar arithmetic, no pairings. This is the top tier of [phone-keys.md](phone-keys.md): a phone alone can't sign. It needs a card or credstick, since phone secure hardware does P-256 only. In pave it would be a second `HolderKey` kind in the scheme.
6. **Regional swap services with bonded pools.** In `docs/design/decentralization.md`, a relay holding a pool swaps long-history or expiring tokens for fresh ones during long partitions, staking against the risk. Pave's coins must be swapped after a few offline transfers, so this is what a town needs for weeks offline.
7. **x402 and agent-to-agent payments.** `src/x402` and `src/a2a` implement pay-per-request HTTP (402 Payment Required) and agent task payments. Pave's delegated agents, which hold capabilities derived from their principal's ([design-log.md](design-log.md)), would pay this way.

**Where pave chooses differently:**

- **Decloaking.** The fork's registrar maps a double-spender's pseudonym back to the attested device, auditable because every wallet in a group faces the same basenames. Pave keeps no such map: there is no master unmasking key ([principles.md](principles.md), 13). A double spend links the cheat's own signatures and is revoked by group; a ban sticks through the nullifier recorded at enrollment ([protocol.md](../spec/protocol.md)), not a device identity. Attestation still helps pave, by setting a class's terms and stopping cheap re-enrollment.
- **Formal models.** The fork has TLA+ for token lifecycle, gossip convergence, fork detection, revocation and recovery. Pave's models live in the project (`CivicKernel`, `CivicGossip` and others) and cover its own invariants. They overlap in gossip and revocation and would be worth cross-checking.

## Suggested order

1. Attestation at enrollment, so classes are earned, not declared.
2. Pave on the fork's mobile app, through UniFFI.
3. Ramps on the bridge, against regtest or testnet only.
4. Recovery.
