# Traceability

Each kernel invariant from [spec/kernel.md](../spec/kernel.md), the TLA+ properties that model it (with the injected faults that break them), the Rust code that enforces or checks it in [`pave-kernel`](../kernel), and the tests. Property names match across layers.

| # | Kernel invariant | TLA+ properties (faults) | Rust | Tests | Verus |
|---|---|---|---|---|---|
| 1 | Conservation | `OneView` in CivicSequences; conservation in CivicHolders | `View::apply` balances every mint, split and merge; `invariants::conservation` | `mint_and_transfer_conserve`, `minting_never_exceeds_budget`, `split_and_merge_conserve_and_respect_divisibility`, `double_mint_offline_is_detected`, `partitions` | — |
| 2 | Consent | `Consent` in CivicSequences, CivicGossip and CivicTiered (`steal`) | `Reject::NotHolder`, `Reject::BadSignature`, `Reject::NotAllowedToSend`; `invariants::consent` (replay) | `steal_is_rejected`, `send_needs_consent`, `partitions` | `lemma_consent` (draft) |
| 3 | Minimal disclosure | `GossipDiscloses` in CivicGossip and CivicTiered (`gossiprecords`) | Structural: evidence carries only the two conflicting records; receipts reveal branch by branch; the scheme randomizes each holding | `receipts_reveal_branch_by_branch`, `holdings_are_unlinkable_but_reuse_links` (Briolette v1) | — |
| 4 | Transparency | not modeled | Records and receipt roots are what views exchange | — | — |
| 5 | Fixed at creation | Structural in all models | `Schema::id` is the hash of its settings; `ScopeRules::within`; `Op::Derive` only narrows; `invariants::fixed_at_creation` | `per_holder_limit`, `child_scope_is_never_looser`, `derive_only_narrows` | — |
| 6 | Detectable conflict | `Detected`, `EpochDetected`, `NoFalseFlag` and `HonestLossAccounted` in CivicSequences; `Detected` and `NoFalseFlag` in CivicGossip and CivicTiered (`noevidence`, `flagrecipient`, `positiononly`, `fakeevidence`, `honestrepeat`, `noepochevidence`) | `View::apply` (first seen wins, second use becomes `Evidence`); `verify_evidence`; `invariants::detected`, `invariants::no_false_flag` | `offline_double_spend_is_detected_and_names_only_the_signer`, `forged_evidence_is_refused`, `double_mint_offline_is_detected`, `partitions`, `offline_double_spend_with_ecdaa` (Briolette v1) | `lemma_step_preserves_inv`, `lemma_detected`, `lemma_names_signer` (draft) |

## Protocol-level properties

These are not in the kernel crate yet; they belong in a protocol crate.

| TLA+ property | Model | Where it will live |
|---|---|---|
| `FirstSeenWins` | CivicGossip, CivicTiered | Kernel already: `View::apply` keeps the first spend; asserted in `offline_double_spend_is_detected_and_names_only_the_signer` |
| `HonestAcceptsInDate` | CivicSequences, CivicGossip, CivicTiered | Wallet acceptance policy over `Coin::history` and `Coin::hops` |
| `OneEpoch`, `EpochDetected` | CivicSequences | Epoch sequences as exclusive capabilities; equivocation is already a kernel conflict |
| `NoForgedEpoch`, `KnownIsSigned`, `HintsSuffice`, `EvidenceSpreads` | CivicGossip, CivicTiered | Gossip: compressed hints, extended proofs |

## Mutation checks

The kernel tests were checked against injected faults in `View::apply`, matching the TLA+ fault names. Each fault fails tests; the unmodified kernel passes all of them.

| Fault | What was changed | Failing tests |
|---|---|---|
| `noevidence` | A second use is refused but no evidence is kept | 4 |
| `flagrecipient` | Evidence names the first spend's recipient | 3 |
| `steal` | The holder check on inputs is removed | 2 |
