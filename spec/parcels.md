# Parcels profile

Packages for a delivery co-op, with custody as a coin. A parcel moves from shipper to courier to courier to addressee, hand to hand and offline if need be, because each next holder wants it: holding it is what gets a courier paid. Nothing here needs the kernel to change.

The prototype is [`board/src/parcel.rs`](../board/src/parcel.rs), with a test in [`board/tests/parcel.rs`](../board/tests/parcel.rs).

## Objects

- **The parcel schema.** One unit, not divisible, never expiring, at most 32 transfers.
- **A parcel budget.** The town issues one to a shipper, as a budget of so many parcels. Shipping mints one parcel to the shipper; the parcel's id is its origin state.
- **The manifest.** What it is, the cell it's from and the cell it's going to, the addressee's credential and the pay per hop. It travels with the parcel. Every handoff's receipt commits to its hash and the hop number, so a courier can check the manifest it was shown against the parcel it was given.

## Custody

| Step | Kernel operation | Signed by |
|---|---|---|
| Ship | Mint from the parcel budget | The shipper |
| Hand off | Transfer to the next courier's credential, receipt committing to (manifest, hop) | The holder |
| Take | Transfer to a fresh credential of the taker's own, receipt committing to (manifest, hop) | The courier who received it |
| Deliver | Retire | The addressee |

- **Taking is the acknowledgment.** A handoff is the giver's word; the take is a record only the taker can sign, so the giver can show the handoff happened. A courier takes a parcel only after checking the manifest and running its usual coin checks.
- **Delivery can't be claimed.** A parcel is delivered only when the manifest's addressee retires it. A courier who retires it himself has lost it, visibly.
- **A double handoff is a double spend.** Handing one parcel to two people uses one state twice: kernel evidence that leads to the courier's ticket group. Once a courier knows of it, the cheat can't hand them anything else, under any credential, because the cheat can't prove standing.
- **Pay.** Once the addressee has retired the parcel, the shipper pays the signer of every handoff after its own, `pay_per_hop` each, with a receipt naming the parcel and courier. Each courier is paid once, and never a courier caught handing the parcel to two people.

## Not built yet

- Couriers accountable to the co-op by name: a courier's take signed with one of its identities, so dispatch knows which member holds a parcel.
- A dispute when the addressee won't retire a parcel that was handed to it.
- Dispatch: offering parcels as jobs on the job board, and routing.
- Proof of where a handoff happened.
- A demo across processes.
