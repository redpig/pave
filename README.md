# pave

Experiments in multifaceted credential protocols.

pave is a small, recursive, local-first fabric of credentials and capabilities for civic use: local work, local credit and local services that keep working offline and don't depend on any one operator behaving well. It generalizes [Briolette](https://github.com/redpig/briolette), an offline digital currency design, so that money, time, votes, certifications and access are all the same kind of object: a capability under a schema.

A pavé setting is many small stones set close together to make one surface. Here, the stones are small kernels that anyone can run, joined only by the trust choices of the people using them.

## Layers

| Layer | What it is | Where |
|---|---|---|
| Kernel | Axioms only: three objects (scope, capability, message), holding, schemas, receipts, five operations and six invariants. No time, no roles, no code. | [spec/kernel.md](spec/kernel.md) |
| Protocol | Corollaries, standard schemas (epochs, expiry, tickets, value, time, votes, certification, recovery), core mechanisms (evidence, revocation, receipts, proof of means, two-tier gossip), role guarantees and profiles. | [spec/protocol.md](spec/protocol.md) |
| Profiles | Cash (Briolette), civic work board, offline mesh. | end of the protocol |

The values behind it are in [docs/principles.md](docs/principles.md), and the reasoning behind each decision is in [docs/design-log.md](docs/design-log.md).

## Code

- [kernel/](kernel/): `pave-kernel`, the kernel in Rust. Scopes, shared and exclusive capabilities, signed records, local views that merge after being apart (first seen wins, a second use becomes evidence), receipts with partial reveal, and runtime checks named after the TLA+ properties. Credentials and signatures are opaque behind a `Scheme` trait.
- [protocol/](protocol/): `pave-protocol`. Epoch sequences, where rolling is spending, so two versions of an epoch are an ordinary conflict. Tickets checked across a coin's whole history, each against its own clerk's sequence. Recipient policy for expiry, transfer limits, revocation and evidence. Two-tier gossip: compressed hints that fit one packet, and per-hint proofs.
- [board/](board/): a neighborhood work board on pave, and `pave-node`, a wallet process driven by JSON lines on stdin, by a person, a script or an agent alike. [demo/board_demo.py](demo/board_demo.py) runs the whole story across separate processes: a job posted, done and paid offline, a double-spend caught when two neighbors meet, and a revocation spread by two-tier gossip.
- [schemes/briolette/](schemes/briolette/): Briolette v1 (ECDAA over BLS12-381) as a scheme. Holdings are unlinkable, and a second use links only through its 48-byte pseudonym.

```bash
cargo test
```

## Checking it

- [formal/](formal/): TLA+ models with fault injection. Each injected fault is caught by the property meant to catch it, and the safe configurations pass. [TRACEABILITY.md](formal/TRACEABILITY.md) maps every kernel invariant to its TLA+ properties, Rust checks and tests.
- [kernel/tests/](kernel/tests/) and [protocol/tests/](protocol/tests/): tests named after the TLA+ faults, plus a property test over random offline histories with a dishonest holder. Each test suite was checked against the faults it names.
- [verus/](verus/): a Verus spec of the spend step (a draft, not yet checked).
- [sim/](sim/): simulations of gossip benefit and bytes on the wire.

## Status

A draft design with a first kernel implementation. Nothing here handles real money; demos use test credit only.

Next:
- swaps, and recovery as a self-minted capability
- the work board on two phones, and with Briolette v1 credentials (prefetched tickets)
- checking the Verus spec, then extending it to conservation
- the mechanisms and use-case write-ups

## License

Apache-2.0. See [LICENSE](LICENSE).
