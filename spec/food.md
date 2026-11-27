# Food profile (example): delivery by accountable couriers

Food goes to someone's door, so its courier must be known. Not to the customer, who needn't learn who it was, but to the restaurant and the co-op, so a courier answers for how they deliver, well or badly. The anonymous shift keys of [parcels](parcels.md#dispatch) don't do that: they fit a relay between fixed points (a locker, a depot, a shop counter), never a home address.

The description is [`profiles/food.json`](../profiles/food.json), with the order binding from [`profiles/orders.json`](../profiles/orders.json) ([orders.md](orders.md)). [`board/tests/food.rs`](../board/tests/food.rs) runs it end to end.

## Badges

A badge is a **ticket**, not an access credential. The co-op vets a courier outside pave (who they are, insurance, a trial run) and its dispatch clerk issues a ticket on one stable key of the courier's, tagged with the courier's id and the dispatch's badge purpose, in a group of its own.

- **A ticket, because it names a key.** Custody moves between keys, and the acceptance check already asks whether a key holds a good ticket. An access credential is for proving membership without naming a key, which is exactly what food delivery shouldn't do.
- **A certification on the courier's pseudonym.** The key is the courier's own stable key for the work, best its trade key, so deliveries and other jobs build one reputation ([boards.md](boards.md#job-board)). The badge is what an issuer adds: someone answers for who is behind it.
- **One stable key.** The same key takes every bag, so every custody chain the courier was in names that key, and the co-op maps it to the courier. The restaurant sees the courier id on the badge when it's shown.
- **Revocable on its own.** Each badge has its own group, so revoking one courier is one entry on dispatch's ticks; nobody hands that key a bag, and it takes none, once they've heard.
- **A key holds one ticket.** A badge key carries custody only. The wallet refuses to post under it, since a post would put a post ticket on the key in the badge's place.

## The flow

1. **Order.** The customer orders on the restaurant's own system. The binding carries the order's hash, the total and fee, a coarse cell, a **commitment to the address** (a hash of a salt and the address), the customer's key, the co-op, and a **deadline** (`due`).
2. **Pay.** The restaurant invoices the binding's `paid` receipt; the customer pays it.
3. **Ship.** The restaurant bags the order with a seal sticker that carries the label code, and ships a parcel about the binding with the co-op and its dispatch named.
4. **Offer.** The co-op offers the delivery as a job about the parcel, posted under the provider key the manifest names, whose worker must show the dispatch's badge ([boards.md](boards.md#job-board)). Couriers reply anonymously; the co-op accepts one on their badge. The restaurant reads which key that is: only the one job about the parcel under the provider key assigns anybody, and two such offers assign nobody until settled.
5. **Pick up.** The courier shows their badge. `hand_off` goes only to the addressee or to a key with this dispatch's badge; a member with only shift keys is refused.
6. **Address.** The restaurant gives the courier the address and salt, off the record. The courier checks them against the binding's commitment, so the address they were given is the one the customer paid for.
7. **Carry.** `take` stays on the badge key, with the dispatch's clerk trusted, so a revoked badge takes nothing.
8. **Deliver.** The courier hands the bag to the customer's key. The customer confirms, and posts a `delivered` note on the jobs board giving the seal code they read off the sticker.
9. **Pay out.** The restaurant pays the co-op its fee. The courier marks the job done, and the co-op pays the job with a vouch once custody shows the courier's key handed the bag to the customer and the customer confirmed: the pay goes to the key the courier replied under, and the vouch coin with it, so the courier holds its record. A parcel with a delivery job isn't paid per hop as well.

## Outcomes

`food_outcome` reads the customer's note against the manifest and the deadline:

| Outcome | When |
|---|---|
| Pending | No note yet from the key the bag was delivered to; a note from anyone else, the courier included, doesn't count |
| On time | The note's seal code matches the label, and the board's clock on it is at or before `due` |
| Late | As on time, but after `due`, by how much |
| Seal broken | The seal code doesn't match the label |

The board's clock is the time witness: the server binds its epoch and clock into each post, so a note can't be backdated (H8). A dispute reads the same outcomes, with the custody chain naming the badge.

## Vouching for the courier

A courier gets two kinds of vouch on the one key. The co-op's rides on its payment for the delivery job, as any job's does: a zero-value coin the courier holds, offline too. The customer, who doesn't pay the courier, vouches with a post instead:

The customer can vouch for the courier who handed the bag over, in the thread of that courier's key: with the badge on its trade key, deliveries and other jobs add up on one record. A customer's vouch is a counted post carrying the manifest and the parcel's custody records, from its mint to the customer's confirmation. A reader learns those records, as from any meet, and counts the vouch only if:

- it is signed by the manifest's addressee;
- the custody shows that courier's key handing the bag to the addressee;
- the addressee confirmed it.

Each parcel counts once, and each person once however many bags they vouch for. The courier can't vouch for itself, nobody can credit a bag the cafe handed over itself to a courier, and a bag not yet confirmed earns nothing. Whether to vouch for a late or opened bag is the customer's call; the outcome is on the board beside it.

A reader also needs the shipper's budget history to check a bag's mint. It travels like any record; a reader without it doesn't count the vouch yet.

## Still to build

- **Badge renewal.** A badge lasts until revoked. A co-op would re-issue after re-vetting, on a period of its choosing.
- **Re-offering after a no-show**: today a second offer leaves the bag unassigned; closing the first job is not built. **Refunds**; **a real adapter**; **the host app**: as in [orders.md](orders.md).
