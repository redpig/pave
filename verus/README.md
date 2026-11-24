# Verus

TLA+ covers distribution: partitions, merges and gossip. Verus is for showing the Rust does what the model says. The first target is the step everything else rests on: spending one exclusive state in `pave-kernel`'s `View::apply`.

`spend.rs` states that step as a spec-level transition and proves it preserves the invariants traced in [../formal/TRACEABILITY.md](../formal/TRACEABILITY.md):

- **`lemma_consent`:** a spend is accepted only from the holder.
- **`lemma_detected`:** a second, different spend by the same holder always leaves evidence.
- **`lemma_names_signer`:** evidence names only whoever spent that state, never a recipient.
- **`lemma_step_preserves_inv`:** the step keeps those facts true.

**Status: draft, not yet checked.** The toolchain Verus pins wasn't reachable where this was written. Run it with:

```bash
verus verus/spend.rs
```

Next steps:
1. Check this file.
2. Add conservation for split, merge and mint over a summed map.
3. Connect the spec to the executable code, either by moving `apply`'s spend path into `verus!` or by proving a refinement against the spec.
