# Parcels profile

Packages for a delivery co-op, with custody as a coin. A parcel moves from shipper to courier to courier to addressee, hand to hand and offline if need be, because each next holder wants it: holding it is what gets a courier paid. Nothing here needs the kernel to change.

The prototype is [`board/src/parcel.rs`](../board/src/parcel.rs), with a test in [`board/tests/parcel.rs`](../board/tests/parcel.rs). [`demo/parcel_demo.py`](../demo/parcel_demo.py) runs signed, code and drop deliveries, a dispute and an escrowed appeal across separate processes.

## Objects

- **The parcel schema.** One unit, not divisible, never expiring, at most 32 transfers.
- **A parcel budget.** The town issues one to a shipper, as a budget of so many parcels. Shipping mints two parcel coins: the token that travels, whose origin state is the parcel's id, and a lineage coin the shipper keeps (see Lost phones).
- **The label.** A code printed on the package. The manifest commits to its hash; the shipper keeps the code.
- **The manifest.** What it is, the cell it's from and the cell it's going to, the addressee's credential and the pay per hop. It travels with the parcel. Every handoff's receipt commits to its hash and the hop number, so a courier can check the manifest it was shown against the parcel it was given.

## Provider, and who holds it

- **Provider.** A shipper may name a shipping provider, such as a co-op, in the manifest before the first handoff. Then the shipper pays the provider once the parcel is delivered (once, with a receipt naming the parcel), and only the provider pays the couriers. The first handoff is the shipper's own and is never paid.
- **Who holds it.** A courier may take a parcel under one of its identities: it posts a note on the job board, signed by the credential that signed the take and by the identity. Whoever was given that identity, such as the co-op's dispatch, sees which member holds the parcel; anyone else sees an identity it can't name. A note from anyone who didn't take the parcel is ignored.

## Dispatch

A co-op that carries parcels can run a dispatch ([`board/src/dispatch.rs`](../board/src/dispatch.rs)), named in the manifest before the first handoff. It is the town's own layering one level down: a roll like a class, a daily credential like an access credential, and shift-key requests like refills.

- **Members are an issuer group.** Joining is a join on a key the member's device made.
- **Checking in is the count.** Each day dispatch runs a fresh issuer group. A member checks in by joining it, the join signed by its member credential with (dispatch, day) as basename. That pseudonym is the same for a member all day and unrelated across days, so dispatch counts distinct couriers without learning who anyone is, and a second check-in the same day (a new phone) is linked and counted once. The day credential is the courier's daily credential.
- **Shift keys are slotted refills.** A courier asks for tickets for the keys it will take parcels under, signed twice: by its member credential with (dispatch, day, slot) as basename, and by its day credential with no basename. A courier's first 4 requests a day can't be linked to each other; each later one is served and linked to an earlier one. The day signature shows the courier checked in today and links nothing. Shift tickets carry the request's pseudonym and the day as a tag.
- **Its own ticks.** Dispatch signs shift tickets on its own tick sequence, and revokes on it.

Shift keys are anonymous: dispatch knows a member carried it, not which. That fits relays between fixed points, never a home address; food goes by badged couriers whom the co-op and the restaurant can name ([food.md](food.md)).

Membership is enforced where custody moves:

| Where | Check |
|---|---|
| Hand off | The next key (other than the addressee's) holds this dispatch's shift ticket. The courier shows it with the key: meets carry tickets only for keys their records name |
| Take | The usual coin checks with the dispatch's clerk also trusted, which refuses a revoked key; the take goes to one of the courier's shift keys |
| Pay | Only couriers at shift keys are paid |

**Bans outlast the day.** A ruling puts the (basename, pseudonym) of the request the courier's key came from on dispatch's ruled list. Both check-ins and shift requests are signed by the member credential, so every later one needs its standing against the list, on any day and under any slot, which the ruled courier can't produce. The ruling also revokes that request's group on dispatch's ticks, so nobody takes a parcel from those keys and they take nothing. Keys from the courier's other requests that day are unlinkable to the ruled one and keep working until they're used.

## Lost phones

The token was on the phone; the package wasn't. Whoever has the package and its label code can ask the shipper to remint it to a new key.

- **A remint is layered on the lineage coin.** The shipper moves the lineage coin to a fresh key of its own, with a receipt committing to (old parcel, new parcel), mints a token for the next generation, and hands it to the new key. The new manifest names the old parcel and the next generation.
- **Once per generation.** Reminting one generation twice is one lineage state used twice: kernel evidence against the shipper. A taker who knows of it refuses the parcel.
- **The old token is void** for anyone whose view has the lineage past its generation, as a stale epoch is. A taker refuses it. The shipper posts the lineage record on the job board so takers hear of it soon.
- **Pay** follows the package: the old token's couriers up to the remint, then the new token's. Nobody is paid for the old token's later hops.
- **A double token shows up.** A courier who remints and keeps moving the old token is seen by anyone holding both records: the old token moves after its lineage did.

## Delivery modes

The shipper picks one in the manifest:

| Mode | When | How delivery is shown |
|---|---|---|
| Signed | The addressee has a wallet and is there | The addressee retires the parcel |
| Code | The recipient has no wallet, like the PIN some apps use for alcohol | The shipper gives the recipient a code; the recipient tells the courier at the door; the courier's closing record (a transfer to itself) commits to it. Only the shipper, who knows the code, can check it |
| Drop | Nobody's there | The courier's closing record commits to the cell and a salted photo hash, and the courier posts a matching note on the job board. It counts as delivered once a window of epochs passes without a party's dispute. The drop note commits to the original photo, metadata included; the courier's wallet keeps it and its salt, shows a panel a stripped copy, and can reveal the original ([disputes.md](disputes.md#evidence)) |

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

- Routing, and offering parcels as jobs on the job board.
- Dispatch as a separate service from the town operator, with network messages.
- Proof of where a handoff happened.
