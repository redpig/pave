# CivicGossip TLA+ results and gossip simulation (2026-11-23, updated 2026-11-24; TLC 1.8.0)

This model treats tickets as their own sequences and treats gossip as an optimization layered on the protocol. Briolette's `formal/GossipConvergence.tla` already covers gossip of one clerk's signed epochs: monotonic epochs, convergence within the network diameter, and a double-spender that refuses to gossip blocking a line but not a ring. This model checks what is new in the fabric instead.

## What is modeled

- **No hub and no clock.** Three sites, declared symmetric. People transact at a site using what that site knows, and a holder can carry a coin to another site.
- **Two clerks with their own sequences.** Each issuer mints epoch n+1 by spending epoch n. A dishonest issuer can sign two versions of one epoch at different sites.
- **Tickets.** Every transfer holds the coin under a fresh ticket from the recipient's clerk, stamped with that clerk's epoch as the site knows it.
- **History.** A coin's history is every ticket it has been held under.
- **Recipient checks.** Honest recipients check:
  - the sender's ticket against its clerk's sequence (soft expiry: TLife epochs after it was issued);
  - the coin's mint-time ticket against its own clerk's sequence (hard expiry: THard epochs);
  - the transfer limit;
  - that they hold no evidence against the sender.
- **Provenance and forks.**
  - A coin's provenance travels only with the coin.
  - When a coin meets its own fork at a site, that site holds evidence: the same signer using the same coin state twice.
  - Locally, the copy seen first wins.
- **Gossip.** Any site may pass another site the signed epochs and the evidence it holds, and nothing else. Receivers verify signatures.

## Properties

| Property | What it says |
|---|---|
| Consent | Invariant 2. |
| NoForgedEpoch | No site holds an epoch its issuer didn't sign. |
| NoFalseFlag | No site holds evidence against an honest party, including an honest issuer. |
| GossipDiscloses | Invariant 3, minimal disclosure: a site knows only transfers it took part in or was shown as a coin's provenance. |
| HonestAcceptsInDate | The sender's ticket was in date and the coin within its lifetime from mint, each in its own sequence, and the transfer limit held. |
| NoStaleHistory (witness) | Expected to fail: an honest recipient can take a coin with a soft-expired ticket earlier in its history, carried on by someone with a fresh one, until its hard expiry. |
| HonestNoKnownCheat | Honest recipients never take a coin from someone they hold evidence against. |
| FirstSeenWins | An action property: a site never drops a record from its chain. |
| EvidenceSpreads | Once gossip has spread, every site flags every double-signer that any site has evidence on, and every equivocating issuer. |

## Runs

Rerun 2026-11-24 with the rule from decision D1 (soft expiry on the last hop, hard expiry from the mint-time ticket), TLife 1, THard 1, MaxEpoch 1.

| Config | Result |
|---|---|
| SmallBadIssuer: People {a, m}, Bad {m}, issuer of clerk x = m (dishonest), clerk y = a; m starts with the coin; MaxHops 2 | No error, 405,783 distinct states (exhaustive) |
| NoGossip (the same without gossip) | No error, 243,254 distinct states |
| SafeBadIssuer: People {a, b, m} | 2026-11-23, with the earlier rule: stopped after 27 min at 9,402,342 distinct states, depth 14, no violation (not exhaustive). Not rerun |
| StaleWitness: SmallBadIssuer with MaxHops 3, checking NoStaleHistory | Violated, as expected (802 states): m pays a on clerk y; y rolls, so a's ticket expires; a pays m, who accepts anything; m pays a again on a fresh x ticket, and a accepts a coin whose history holds a's expired ticket |
| Bug steal | Consent violated |
| Bug nolimit | HonestAcceptsInDate violated |
| Bug ignoreexpiry | HonestAcceptsInDate violated |
| Bug latestonly (check only the sender's ticket: no lifetime from mint) | HonestAcceptsInDate violated |
| Bug ignoreevidence | HonestNoKnownCheat violated |
| Bug forge (receiver keeps an unsigned epoch) | NoForgedEpoch violated |
| Bug fakeevidence (receiver keeps evidence that isn't two signed uses) | NoFalseFlag violated |
| Bug gossiprecords (gossip also carries transfer records) | GossipDiscloses violated |
| Bug overwrite (gossip or carry replaces a site's own chain) | FirstSeenWins violated |
| Bug positiononly | NoFalseFlag violated |

Ten injected faults, each caught.

The three-person run outgrew this two-core workspace. It is worth finishing on a bigger machine, or with TLC `-simulate` for deeper random traces.

## Findings

1. **Gossip can't make things worse.** It carries only signed epochs and self-certifying evidence. Withholding or delaying leaves a recipient at what it already knew. Forging fails a signature check.
2. **Gossip must not carry transfer records.** Doing so would leak the transaction graph (the gossiprecords fault). Evidence can still form offline, because a coin's provenance travels with it and a site sees a fork when the coin meets its own fork.
3. **Count each ticket by its own sequence.** With per-clerk sequences, a coin's lifetime must be counted from its mint-time ticket on that ticket's own clerk, not from whatever ticket is newest. Under the earlier rule (soft expiry on every ticket) the latestonly fault showed an older ticket from a faster clerk expiring first; under decision D1 it shows a coin outliving its hard expiry.
3a. **What decision D1 gives up (the witness).** With soft expiry only on the last hop, a coin held on a stale ticket can be carried on by someone with a fresh one and accepted honestly, until its hard expiry. Briolette accepts the same exposure; the hard expiry and the hop limit bound it.
4. **Evidence about an issuer works like evidence about a coin.** Two signed versions of one epoch, gossiped to the same place, flag the issuer.
5. **Evidence size (corrected 2026-11-23 against Briolette v1 crypto).**
   - Evidence is the shared basename (the coin state, 32 bytes) plus two signatures-with-nym over different messages. Each signature is 336 bytes on BLS12-381 (`SIGNATURE_WITH_NYM_LENGTH`), and each signed message adds a 32-byte digest. The nym K is the same in both, which proves one signer used one coin state twice.
   - That comes to about 770 bytes. It does not fit one short APDU (255 bytes of data) or one Meshtastic packet (about 231 bytes). It needs APDU chaining or an extended APDU (the credstick's 2,048-byte buffers fit it), or about four mesh packets.
   - An earlier estimate of about 160 bytes assumed 64-byte ECDSA signatures and was wrong.
6. **What evidence identifies.** The pseudonym K is per basename, so evidence names the coin and the ticket credential it was held under (with that ticket's group number). It does not name the cheater's other coins or tickets.
   - Offline, a peer can refuse that coin (both forks and everything descended from them) and that ticket.
   - A peer can also choose to treat that ticket's group as suspect until the next epoch. That slows down innocent members of the group.
   - Reaching the cheater's other tickets took the clerk and the challenge test in Briolette. In pave, standing does it: see [CivicStanding](CivicStanding-RESULTS.md).
   - The simulation's cheater has only one coin, so "refuse that coin" equals "refuse the cheater" there. A cheater with many coins limits the benefit to the forked coins, plus the group if peers quarantine it.

## Benefit (gossip_sim.py, 200 seeds)

The town is 96 wallets in 8 neighborhoods with sparse links between them, run for 6,000 steps with an epoch every 400 steps. One dishonest wallet m holds one coin, tries to spend it to everyone it meets, and never gossips. Evidence reaches the issuer only when a holder swaps online, and the issuer's next epoch then names m.

**m stays in its neighborhood**

| Regime | Victims (median / 90th) | Late victims | Steps until 90% would refuse m |
|---|---|---|---|
| No gossip | 7 / 10 | 4 / 7 | 1572 / 1977 |
| Epoch gossip (Briolette) | 7 / 10 | 4 / 7 | 661 / 1061 |
| Epoch and evidence gossip | 5 / 8 | 2 / 5 | 652 / 1053 |

**m moves around town**

| Regime | Victims (median / 90th) | Late victims | Steps until 90% would refuse m |
|---|---|---|---|
| No gossip | 16 / 21 | 12 / 16 | 1452 / 1759 |
| Epoch gossip (Briolette) | 12 / 17 | 8 / 12 | 635 / 1013 |
| Epoch and evidence gossip | 10 / 14 | 6 / 9 | 625 / 935 |

"Late victims" are people fooled after evidence already existed somewhere.

- **Epoch gossip** more than halves the time until the town would refuse the cheater. That matches Briolette.
- **Evidence gossip** removes another quarter to half of the late victims, because evidence found offline spreads before the issuer's next epoch.
- **A mobile cheater** is where gossip matters most.

These are toy parameters, so read the numbers as relative.

## Not modeled

- Liveness and convergence time. Briolette's GossipConvergence covers diameter bounds, and the simulation measures convergence time.
- Swaps.
- Split and merge of value.
- More than one coin in the TLA+ model.
- Gossip of revocation lists inside epochs. They are signed with the epoch, so the same reasoning applies.
