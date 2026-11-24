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

## Protocol properties

Checked in [`pave-protocol`](../protocol) (`protocol/tests/protocol.rs`).

| TLA+ property (faults) | Model | Rust | Tests |
|---|---|---|---|
| `FirstSeenWins` (`overwrite`) | CivicGossip, CivicTiered | `View::apply` keeps the first spend | `offline_double_spend_is_detected_and_names_only_the_signer`, `epoch_equivocation_is_a_kernel_conflict` |
| `EpochDetected` (`noepochevidence`, `honestrepeat`) | CivicSequences | `epochs::roll` spends the current epoch state, so two versions are a kernel conflict | `epoch_equivocation_is_a_kernel_conflict` |
| `HonestAcceptsInDate` (`ignoreexpiry`, `nolimit`, `latestonly`) | CivicSequences, CivicGossip, CivicTiered | `accept::check`: soft expiry on the last hop, hard expiry from the first ticket, each against its own sequence; transfer limit. CivicGossip checks the same rule; CivicTiered keeps the earlier, stricter rule (soft expiry on every ticket), which doesn't interact with what it checks about hints | `recipients_honor_soft_expiry_and_the_kernel_doesnt`, `expiry_follows_the_last_hop_and_the_mint`, `a_stale_sender_is_refused`, `transfer_limit_is_honored`, `revoked_groups_are_refused_per_issuer` |
| `Contained`, `NoStranding` (`nowindow`, `nolasthop`) | CivicStanding | `accept::check`: a revoked group stops the last hop always, earlier hops within `Policy::revocation_window` of the revocation | `revocation_taints_history_only_within_its_window` |
| `HonestNoKnownCheat` (`ignoreevidence`) | CivicGossip, CivicTiered | `accept::check` refuses flagged senders | `known_cheats_are_refused` |
| `NoForgedEpoch` (`forge`) | CivicGossip, CivicTiered | Epochs come only from signed rolls; `Knowledge::add_epoch_data` keeps data only if a roll commits to it; `Knowledge::add_ticket` verifies the clerk | `epochs_roll_and_commit_their_data`, `tickets_must_come_from_a_trusted_clerk` |
| `KnownIsSigned` (`hintepoch`) | CivicTiered | `epochs::head` reads only the view's signed records | `false_head_hints_never_advance_an_epoch` |
| `NoFalseFlag` with hints (`trusthint`); witness `NoFalseHintDelay` | CivicTiered | Hints never reach `View::flagged`; `Policy::wait_on_hints` can only hold off a coin | `false_fork_hints_only_delay` |
| `HintsSuffice` (`notrigger`) | CivicTiered | `gossip::wants` asks per hint; `gossip::serve` answers only with proofs | `hints_suffice_across_a_relay` |
| `CheatStopped` (`nostanding`), `NoFalseFlag` (`fakeevidence`) | CivicStanding | `accept::check` requires the sender's `Standing` once any cheat is known; `nonrevoked::prove` refuses for the cheat's key | `senders_show_standing_once_cheats_are_known`, `anyone_can_prove_they_are_not_the_cheat_except_the_cheat`, `the_whole_story_on_ecdaa` |
| `ClassContained` (`noclassrevoke`) | CivicStanding | `Node::roll_epoch` revokes every group a closed class was given | `the_whole_story_on_ecdaa` |
| `GossipDiscloses` (`gossiprecords`) | CivicGossip, CivicTiered | `gossip::serve` sends only epoch rolls and evidence | `hints_suffice_across_a_relay` |

## Mutation checks

The tests were checked against injected faults matching the TLA+ fault names. Each fault fails tests; the unmodified code passes all of them.

| Fault | What was changed | Failing tests |
|---|---|---|
| `noevidence` | A second use is refused but no evidence is kept | 4 |
| `flagrecipient` | Evidence names the first spend's recipient | 3 |
| `steal` | The holder check on inputs is removed | 2 |
| `latestonly` | Only the newest ticket in the history is checked | 2 |
| `ignoreexpiry` | Soft expiry is never checked | 3 |
| `nolimit` | The transfer limit is never reached | 2 |
| `ignoreevidence` | Flagged senders are accepted | 2 |
| `notrigger` | Fork hints never start a request | 2 |
| `hintepoch` | Unsigned head hints count toward the known epoch | 2 |
| `nostanding` | Standing is never required | 2 |
| `identityproof` | The prover skips its own cheat check and the verifier accepts T = identity | 2 |
| `nocap` | Ticket `max_spend` is never checked | 2 |
| `norate` | Ticket requests aren't counted per epoch | 1 |
| `noclassrevoke` | Closing a class doesn't revoke its groups | 1 |
| `nowindow` | A revoked group anywhere in the history stops the coin | 1 |
| `softall` | Soft expiry checks every ticket, not just the last hop | 2 |
| `nohard` | Hard expiry is never checked | 1 |
| `nodedupe` (reports) | Every report counts, not each person once per issue | 1 |
| `ignoreruling` (reports) | A report ruled malicious still counts | 1 |
| `nostanding` (reports) | A report counts without standing against earlier rulings | 1 |
| `anypermit` (reports) | Any mirrored permit in a reply covers the issue | 1 |
| `anymirror` (reports) | Permits and rulings from anyone count | 1 |
| `anythread` (reports) | A report counts under its issue whatever thread it names | 1 |
| `carryposts` (boards) | Wallets take board posts from each other's bundles | 1 |
| `nocontenthash` (boards) | A post's content isn't checked against its binding | 1 |
| `noendorsecheck` (boards) | The host takes posts with forged endorsements | 1 |
| `noreceiptsig` (boards) | An author accepts a receipt without the host's signature | 1 |
| `receiptanypost` (boards) | A receipt for one post stands for another with the same content | 1 |
| `anyaccept` (jobs) | Anyone, not only the poster, can accept a worker | 1 |
| `vouchanyone` (vouches) | A vouch counts from anyone, not only the job's poster | 1 |
| `vouchanytype` (vouches) | A vouch's job type needn't match its payment's receipt | 1 |
| `notradesig` (vouches) | A reply can name a contractor without its trade key's signature | 1 |
| `vouchperjob` (vouches) | Vouches count per job, not per person | 1 |
| `vouchunnamed` (vouches) | A vouch counts for a contractor the worker didn't name | 1 |
| `stableunchecked` (vouches) | A vouch shows a stable credential without its signature | 1 |
| `stablenotbound` (vouches) | A stable credential's signature isn't bound to its vouch | 1 |
| `takeanymanifest` (parcels) | A courier takes a parcel whatever manifest it was shown | 1 |
| `takeunchecked` (parcels) | A courier takes a parcel without its usual coin checks | 1 |
| `anyconfirm` (parcels) | Anyone holding a parcel can confirm delivery | 1 |
| `anyretire` (parcels) | Any retirement counts as delivery | 1 |
| `paycheat` (parcels) | A courier caught in a double handoff is paid | 1 |
| `paytwice` (parcels) | A courier is paid again for the same hop | 1 |
| `byunchecked` (boards) | A post's identity counts without its signature | 2 |
| `bynotbound` (boards) | An identity's signature isn't bound to its post | 2 |
