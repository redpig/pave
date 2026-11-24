# CivicSequences TLA+ results (2026-11-23, TLC 1.8.0)

This models the six-invariant kernel, which keeps no time. It replaces CivicHolders.tla as the current model gate.

## What is modeled

- **Epochs as a sequence.** Epochs are a protocol schema. The issuer mints epoch n+1 by spending epoch n.
- **No global clock.** Each site knows only the latest epoch it has seen.
- **Issuer equivocation.** A dishonest issuer can mint two different epoch n+1s while the network is split, one at each site.
- **Coin settings.** Unit coins carry schema settings: a soft expiry, a hard expiry (soft plus Grace) and an offline-transfer limit.
- **Recipients enforce expiry, not the kernel.** Honest recipients refuse a coin that is past its soft expiry, judged by the epoch they know, or past its transfer limit. Dishonest recipients may take anything.
- **Swaps.** A swap is online only. It retires a coin and issues a fresh one. The swapper takes coins up to their hard expiry, which is the redemption window.
- **Partitions and merges.** Two sites can split and later merge. At merge:
  - The later epoch wins.
  - If both sites have an epoch with the same number but different content, both records are kept and the issuer is flagged.
  - If a coin was used twice, site A's chain stands and the double-signer is flagged.

## Properties checked

| Property | What it says |
|---|---|
| Consent | Invariant 2. |
| OneView | Invariant 1, Conservation: after merge, all sites agree on who holds each coin. |
| OneEpoch | After merge, every site has the same latest epoch. |
| Detected | Invariant 6, for coins: every double use flags its signer. |
| EpochDetected | Invariant 6, for epochs: equivocation flags the issuer. |
| NoFalseFlag | No honest holder or issuer is ever flagged. |
| HonestLossAccounted | C4: an honest party loses only what it signed away, or what it received on a fork whose dishonest double-signer was flagged. |
| HonestAcceptsInDate | The expiry and limit schema, held by honest recipients' acceptance policy. |
| NoOneAcceptsExpired | Expected to fail. It shows the kernel itself doesn't stop an expired coin from moving. |

## Runs

| Config | Result |
|---|---|
| Safe: People {a, b, m}, Bad {m}, honest issuer a, 1 coin, MaxHops 2, Life 1, Grace 1, MaxEpoch 2 | No error, 733,596 distinct states |
| SafeBadIssuer: same, but the issuer is m (dishonest) | No error, 1,682,454 distinct states |
| Witness: NoOneAcceptsExpired | Violated, as expected: m (dishonest) takes a coin at epoch 1 with soft expiry 1. No kernel invariant breaks. |
| Bug steal (transfer by a non-holder) | Consent violated |
| Bug nolimit (honest recipients ignore the transfer limit) | HonestAcceptsInDate violated |
| Bug ignoreexpiry (honest recipients ignore soft expiry) | HonestAcceptsInDate violated |
| Bug noevidence (merge records no coin evidence) | Detected violated |
| Bug flagrecipient (evidence also names the recipient) | NoFalseFlag violated |
| Bug positiononly (conflict = same coin position, any signer) | NoFalseFlag violated |
| Bug noepochevidence (merge ignores epoch equivocation) | EpochDetected violated |
| Bug honestrepeat (an honest issuer spends the same epoch twice) | NoFalseFlag violated: the issuer is flagged |

Seven injected faults, each caught by the property meant to catch it. The two-coin config was not run for this model. CivicHolders already showed that two coins add nothing new for holding.

## Findings

1. **Epoch equivocation needs no new kernel machinery.** It is caught by the same rule as a coin double-spend: the same signer using the same state twice.
2. **An issuer's wallet is held to the same rule as any holder's.** The honestrepeat fault shows that an issuer who rolls the same epoch twice, even by accident (a restore from backup, two replicas), is indistinguishable from an equivocator. Issuer implementations need the same never-sign-twice guard as wallets.
3. **Expiry is only as fresh as the recipient's latest epoch.** During a split, site B can lag behind A. A recipient at B can then accept a coin that is already expired at A, and that is correct by its own knowledge. A recipient that needs freshness must fetch the issuer's latest epoch before accepting. This is the protocol rule that a recipient needs each sequence's latest epoch, now confirmed in the model.
4. **The kernel invariants hold even when dishonest recipients ignore expiry.** Honoring expiry really is a recipient choice, not something the kernel relies on.

## Not modeled

- Split and merge of value.
- Receipts and partial reveal.
- More than two sites.
- Tickets as their own sequences, with per-credential expiry across a coin's history.
- Liveness, such as an issuer withholding epochs.
- Roles misbehaving beyond the issuer (see CivicRecursion.tla).
