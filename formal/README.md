# Formal models (TLA+)

Each model has a `*-RESULTS.md` with what it checks, every run and the findings. Configs are in `configs/`, prefixed by model.

| Model | What it covers | Prefix |
|---|---|---|
| `CivicSequences.tla` | The six-invariant kernel with no clock. Epochs as an issuer sequence (each spends the one before). Expiry and transfer limits honored by honest recipients only. Online swaps. Partitions and merges, including issuer equivocation. | `Seq_` |
| `CivicGossip.tla` | Tickets as sequences from two clerks, checked across a coin's history. Three sites with no hub. Provenance carried with the coin. One-tier gossip of signed epochs and evidence. | `Gos_` |
| `CivicTiered.tla` | Two-tier gossip: unsigned, injectable hints in the compressed tier, and per-hint have/want proofs in the extended tier. Checks that hints never decide and that hints are a complete trigger. | `Tier_` |
| `CivicRecursion.tla` | Civic recursion: role and service gigs held by possibly adversarial members. | `Rec` |

## Running

Download `tla2tools.jar` from the [TLA+ releases](https://github.com/tlaplus/tlaplus/releases), then from this directory:

```bash
java -cp tla2tools.jar tlc2.TLC -deadlock -workers auto \
  -config configs/Seq_Safe.cfg CivicSequences.tla
```

- **`-deadlock`.** The models are bounded, so running out of moves is expected.
- **Safe configs** (`*Safe*`, `Tier_SmallHonestIss`) should report no error. The larger ones take from minutes to about half an hour on a laptop.
- **Fault configs** set `Bug` to inject one fault and should fail with the invariant named in the results file.
- **Witness configs** check a property that is expected to fail, to show something the kernel deliberately does not prevent.

The three-person `Gos_SafeBadIssuer` and the cheating-issuer `Tier_Small` were not run exhaustively; they need a bigger machine. For deeper random traces, use TLC's `-simulate`.

## Relation to Briolette's models

Briolette's [`formal/`](https://github.com/redpig/briolette/tree/main/formal) covers its own protocol: one clerk's epochs, fork detection, revocation, recovery and gossip convergence within the network diameter. These models cover what pave changes: several independent sequences, an issuer that may equivocate, recipient-chosen expiry, offline evidence, and two-tier gossip.
