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

## Checking it

- [formal/](formal/): TLA+ models with fault injection. Each injected fault is caught by the property meant to catch it, and the safe configurations pass.
- [sim/](sim/): simulations of gossip benefit and bytes on the wire.

## Status

This is a draft design, not an implementation. Nothing here handles real money; demos use test credit only.

Not yet in this repo:
- the mechanisms and use-case write-ups
- an updated encoding sketch (FIDL and CBOR/CDDL)
- a reference implementation

## License

Apache-2.0. See [LICENSE](LICENSE).
