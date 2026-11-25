# Parcels profile

Packages for a delivery co-op, with custody as a coin. A parcel moves from shipper to courier to courier to addressee, hand to hand and offline if need be, because each next holder wants it: holding it is what gets a courier paid. Nothing here needs the kernel to change.

The prototype is [`board/src/parcel.rs`](../board/src/parcel.rs), with a test in [`board/tests/parcel.rs`](../board/tests/parcel.rs).

## Objects

- **The parcel schema.** One unit, not divisible, never expiring, at most 32 transfers.
- **A parcel budget.** The town issues one to a shipper, as a budget of so many parcels. Shipping mints one parcel to the shipper; the parcel's id is its origin state.
- **The manifest.** What it is, the cell it's from and the cell it's going to, the addressee's credential and the pay per hop. It travels with the parcel. Every handoff's receipt commits to its hash and the hop number, so a courier can check the manifest it was shown against the parcel it was given.

## Delivery modes

The shipper picks one in the manifest:

| Mode | When | How delivery is shown |
|---|---|---|
| Signed | The addressee has a wallet and is there | The addressee retires the parcel |
| Code | The recipient has no wallet, like the PIN some apps use for alcohol | The shipper gives the recipient a code; the recipient tells the courier at the door; the courier's closing record (a transfer to itself) commits to it. Only the shipper, who knows the code, can check it |
| Drop | Nobody's there | The courier's closing record commits to the cell and a salted photo hash, and the courier posts a matching note on the job board. It counts as delivered once a window of epochs passes without a party's dispute |

A courier can't downgrade a delivery: only the mode the shipper chose counts. A wrong code is checked and fails; only the closing that delivered is paid.

## Disputes

A party (the addressee, the shipper, a courier in its custody) can dispute delivery on the job board ([disputes.md](disputes.md)). An open dispute holds the parcel; the final ruling decides it, yes or no; a referral to an outside authority holds it. A signed delivery stands whatever is ruled. Anyone else's dispute holds nothing, and so does one nobody staffs.

## Custody

| Step | Kernel operation | Signed by |
|---|---|---|
| Ship | Mint from the parcel budget | The shipper |
| Hand off | Transfer to the next courier's credential, receipt committing to (manifest, hop) | The holder |
| Take | Transfer to a fresh credential of the taker's own, receipt committing to (manifest, hop) | The courier who received it |
| Deliver (signed) | Retire | The addressee |
| Deliver (code or drop) | Transfer to a fresh credential of the courier's own, receipt committing to the code, or to the cell and photo | The courier |

- **Taking is the acknowledgment.** A handoff is the giver's word; the take is a record only the taker can sign, so the giver can show the handoff happened. A courier takes a parcel only after checking the manifest and running its usual coin checks.
- **Delivery can't be claimed.** A parcel is delivered only when the manifest's addressee retires it. A courier who retires it himself has lost it, visibly.
- **A double handoff is a double spend.** Handing one parcel to two people uses one state twice: kernel evidence that leads to the courier's ticket group. Once a courier knows of it, the cheat can't hand them anything else, under any credential, because the cheat can't prove standing.
- **Pay.** Once the addressee has retired the parcel, the shipper pays the signer of every handoff after its own, `pay_per_hop` each, with a receipt naming the parcel and courier. Each courier is paid once, and never a courier caught handing the parcel to two people.

## Not built yet

- Couriers accountable to the co-op by name: a courier's take signed with one of its identities, so dispatch knows which member holds a parcel.
- Dispatch: offering parcels as jobs on the job board, and routing.
- Proof of where a handoff happened.
- A demo across processes.
