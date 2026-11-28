# pave

Experiments in multifaceted credential protocols.

pave is a small, recursive, local-first fabric of credentials and capabilities for civic use: local work, local credit and local services that keep working offline and don't depend on any one operator behaving well. It generalizes [Briolette](https://github.com/redpig/briolette), an offline digital currency design, so that money, time, votes, certifications and access are all the same kind of object: a capability under a schema.

A pavé setting is many small stones set close together to make one surface. Here, the stones are small kernels that anyone can run, joined only by the trust choices of the people using them.

## Layers

| Layer | What it is | Where |
|---|---|---|
| Kernel | Axioms only: three objects (scope, capability, message), holding, schemas, receipts, five operations and six invariants. No time, no roles, no code. | [spec/kernel.md](spec/kernel.md) |
| Protocol | Corollaries, standard schemas (epochs, expiry, tickets, value, time, votes, certification, recovery), core mechanisms (evidence, revocation, receipts, proof of means, two-tier gossip), role guarantees and profiles. | [spec/protocol.md](spec/protocol.md) |
| Profiles | Cash (Briolette), offline mesh, boards (the job board and civic reports), parcels, disputes, and an example election. | end of the protocol; [spec/boards.md](spec/boards.md), [spec/parcels.md](spec/parcels.md), [spec/disputes.md](spec/disputes.md), [spec/elections.md](spec/elections.md) |

Profiles can be published as data that one app loads and acts on: see [spec/profiles.md](spec/profiles.md) and [profiles/parcels.json](profiles/parcels.json). [spec/orders.md](spec/orders.md) runs a restaurant order end to end on it: the restaurant's own system, a co-op, and a courier the co-op badged so the courier carrying food to a door is known ([spec/food.md](spec/food.md)). [spec/web.md](spec/web.md) sketches pave as a web platform feature: the wallet in the user agent, providers' own pages using it, and a host app until browsers ship it.

To design a system on pave, start with [docs/building.md](docs/building.md): the decisions in order, with how to choose basenames and clocks, where checks go, and worked examples. The patterns it uses are defined in [spec/toolkit.md](spec/toolkit.md).

The values behind it are in [docs/principles.md](docs/principles.md), and the reasoning behind each decision is in [docs/design-log.md](docs/design-log.md). Every component's attack surface, the attacks on it and how each is prevented or answered are in [docs/threats.md](docs/threats.md). How pave uses Briolette, and what Briolette has that pave doesn't yet, is in [docs/briolette.md](docs/briolette.md); moving value in and out through ramps, designed on Briolette's bridge, is in [spec/ramps.md](spec/ramps.md). What a wallet sends and computes, and what phones can do with it today, is in [docs/devices.md](docs/devices.md); the wallet for phone apps is [mobile/](mobile/), one library behind UniFFI and a C interface, with a Kotlin Multiplatform app in [mobile/app](mobile/app), and [demo/phone_demo.py](demo/phone_demo.py) drives it through a counter pickup over a radio and a door handoff by QR codes.

## Code

- [kernel/](kernel/): `pave-kernel`, the kernel in Rust. Scopes, shared and exclusive capabilities, signed records, local views that merge after being apart (first seen wins, a second use becomes evidence), receipts with partial reveal, and runtime checks named after the TLA+ properties. Credentials and signatures are opaque behind a `Scheme` trait.
- [protocol/](protocol/): `pave-protocol`. Epoch sequences, where rolling is spending, so two versions of an epoch are an ordinary conflict. Recipient policy: soft expiry on the last hop and a lifetime from the mint-time ticket, each against its own clerk's sequence; transfer limits and ticket caps; revocation within a window; evidence, and standing proofs that stop a caught cheat under every credential. Two-tier gossip: compressed hints that fit one packet, and per-hint proofs.
- [board/](board/): a neighborhood work board on pave, and `pave-node`, a wallet process on Briolette v1 credentials, driven by JSON lines on stdin by a person, a script or an agent alike. Wallets join with keys they generate, belong to a class of device, fetch tickets anonymously, use a fresh credential for every holding and role, seal their state and never sign one coin twice. They pay each other with a handshake that sends only the coin's history, meet incrementally, and swap old coins with the town. Posts to the job board and the reports board go straight to the town, which hosts them, and come back with a receipt. A poster can pay with a vouch: a zero-value coin that goes to the contractor with the pay, counted on the board once per person per job type. [demo/board_demo.py](demo/board_demo.py) runs the whole story across separate processes: a job posted, done, paid and vouched for, a direct payment, a double spend caught when two neighbors meet, a cheat stopped by standing, a revocation spread by two-tier gossip, a class closed after a flaw, and an expired coin swapped. [demo/reports_demo.py](demo/reports_demo.py) runs civic reports: a blocked sidewalk reported, counted once per person, checked against mirrored permits, forwarded to 311 and cleared, and a false report ruled out without unmasking anyone. [demo/parcel_demo.py](demo/parcel_demo.py) runs packages through two couriers with custody as a coin (signed, by code, and left at the door) and a delivery dispute over a parcel left at the wrong door: the addressee's photos and public records beside the courier's committed photo, a panel drawn by hash whose wallets check the evidence, an appeal paid upfront into escrow, and reputation following the final ruling. [demo/food_demo.py](demo/food_demo.py) runs food delivery by badged couriers: an order bound and paid, the delivery offered as a job and given on a badge, an unbadged pickup refused, the address checked against the order, the seal and the deadline checked at the door, pay and both kinds of vouch, a no-show released and re-offered, a courier who took the bag disputed rather than released, a refund, and a revoked badge.
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
- incremental sync between wallets
- the work board on two phones
- checking the Verus spec, then extending it to conservation
- the mechanisms and use-case write-ups

## License

Apache-2.0. See [LICENSE](LICENSE).
