# CivicTiered TLA+ results and two-tier gossip simulation (2026-11-23, TLC 1.8.0)

Gossip in two tiers: a compressed tier of hints that switches to an extended tier of proofs when a hint calls for it. This builds on CivicGossip.tla: three sites, no hub, tickets checked across a coin's history, provenance carried with the coin, and first seen wins locally.

## The two tiers

- **Compressed tier: hints only.** A head hint names a sequence, an epoch number and a tag (hash prefix). A fork hint names a coin state (coin, position). Hints are unsigned, and a dishonest party can inject false ones.
- **Extended tier: proofs, have/want.** A site asks a peer for the proof behind one hint it holds, and only when the peer can prove that hint and the site can't. The peer sends just that proof: the signed epoch, or the evidence items at that coin state.
- **What a hint may do.** It never flags anyone and never moves an epoch. Optionally (HintWait), an honest recipient may hold off accepting a coin offline while an unproven fork hint names it.
- **Fresh tickets.** Each ticket is stamped with where it was fetched, so two spends to the same person are different records, as with real randomized tickets.

## Properties

| Property | What it says |
|---|---|
| Consent, NoForgedEpoch, NoFalseFlag, GossipDiscloses, HonestAcceptsInDate, HonestNoKnownCheat, FirstSeenWins | As in CivicGossip. |
| KnownIsSigned | Every epoch a site uses to judge expiry was signed by its issuer, even with false head hints around. |
| HintsSuffice | Once every site holds every hint and no extended exchange is still triggered, every site holds every signed epoch and every piece of evidence any site holds. Hints are a complete trigger: no proof gets stuck. |
| NoFalseHintDelay | Expected to fail with HintWait. It shows a false fork hint can hold off an honest recipient. |

## Runs

| Config | Result |
|---|---|
| SmallHonestIss: People {a, m}, Bad {m}, one clerk (issuer a), m starts with the coin, false fork hint at position 0 and a false head, MaxHops 2, TLife 1, MaxEpoch 1, HintWait off | No error, 9,053,902 distinct states (exhaustive, 32 min) |
| Witness (HintWait on): NoFalseHintDelay | Violated, as expected: a false fork hint holds off honest a, and nothing else changes |
| Bug trusthint (a fork hint taken as evidence against whoever signed that position; false hint at position 1) | NoFalseFlag violated: honest a is flagged by a false hint |
| Bug hintepoch (unsigned head hints count toward the known epoch) | KnownIsSigned violated: a false head makes coins look expired |
| Bug forge (the extended tier keeps an unsigned epoch) | NoForgedEpoch violated |
| Bug ignoreevidence | HonestNoKnownCheat violated |
| Bug gossiprecords | GossipDiscloses violated |
| Bug overwrite | FirstSeenWins violated |
| Bug notrigger (fork hints never start an extended exchange) | HintsSuffice violated: evidence stalls at the site that found it, even after every hint has spread |
| SmallBadIssuer (issuer m), random traces: 175,089 traces, 7.1M states, depth up to 40 | No violation (not exhaustive) |

**Scope notes.**
- One clerk and an honest issuer keep the exhaustive run tractable on a two-core machine.
- Multiple sequences and a cheating issuer were already checked exhaustively in CivicSequences and CivicGossip.
- The first version of this model let notrigger, ignoreevidence, overwrite and the witness pass, for two reasons. A double-spend to the same person at the same epoch produced identical records, so no fork ever formed. And the extended exchange copied every proof whenever any hint triggered it. Stamping tickets with where they were fetched and switching to per-hint have/want fixed both. Those passes were gaps in the model, not in the design.

## Simulation (gossip_tiers_sim.py, 100 seeds)

The town is 96 wallets in 8 neighborhoods, with 6 epoch sequences. Everyone relies on sequence 0, the cash issuer whose epochs carry the revocation, plus one or two others. One cheater roams the town spending one coin to everyone it meets.

Sizes (Briolette v1 where it has them):
- signed epoch: about 170 bytes
- evidence: about 770 bytes
- head hint: 20 bytes
- fork hint: 10 bytes
- frame overhead: 10 bytes
- one Meshtastic packet: about 231 bytes (one short APDU: 255 bytes)

| Regime | Victims (median) | Bytes per frame (mean) | p99 | Frames in one packet | Frames that went extended | Epoch lag (relied-on sequences) |
|---|---|---|---|---|---|---|
| Briolette one-tier, extended to 6 sequences | 13 | 1030 | 1030 | 0% | 0% | 0.22 |
| Full: every epoch and every piece of evidence | 10 | 1635 | 1800 | 0% | 0% | 0.21 |
| Tiered | 12 | 163 | 480 | 87% | 12.9% | 0.33 |
| Tiered with HintWait | 10 | 163 | 480 | 87% | 13.0% | 0.33 |
| Tiered with HintWait, carrying all sequences | 10 | 223 | 820 | 68% | 32.1% | 0.21 |

## Findings

1. **Hints never decide.** No flag and no epoch comes from a hint, even with false hints injected (trusthint and hintepoch show what breaks if they did). The worst a false hint does is hold off one coin, and only for a recipient that chose HintWait.
2. **Hints are a complete trigger.** HintsSuffice holds: once hints have spread and every triggered exchange has run, proofs are everywhere. Have/want is enough; nobody needs to push proofs blindly.
3. **One-tier gossip doesn't scale to many sequences.** Briolette's design (one clerk, one signed epoch per encounter) fits an APDU. With six sequences it is about 1 KB per frame and never fits one packet.
4. **Two tiers fit.** Tiered gossip averages 163 bytes per frame, 87% of frames fit one packet, and about one encounter in eight goes extended.
5. **HintWait buys back what full evidence gossip gets.** With HintWait, tiered gossip fools as few people as full evidence gossip (10, against 12 without it), at a tenth of the bytes. A hint spreads faster than a proof and is enough to make a careful recipient wait.
6. **Freshness has a dial.** If wallets fetch only the sequences they rely on, epoch lag rises slightly (0.33 against 0.21), because fewer neighbors carry each sequence. Letting wallets also carry signed epochs for sequences they don't rely on restores freshness, at 223 bytes per frame and 68% single-packet frames. It is a per-wallet choice, so it fits the open model: hubs and well-connected wallets can carry, and phones on a mesh needn't.

## Not modeled

- A cheater with many coins, and group quarantine.
- Hint budgets per peer.
- Bloom or cuckoo filters to compress many fork hints.
- Liveness (Briolette's GossipConvergence covers diameter bounds).
