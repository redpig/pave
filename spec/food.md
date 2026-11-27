# Food profile (example): delivery by accountable couriers

Food goes to someone's door, so its courier must be known. Not to the customer, who needn't learn who it was, but to the restaurant and the co-op, so a courier answers for how they deliver, well or badly. The anonymous shift keys of [parcels](parcels.md#dispatch) don't do that: they fit a relay between fixed points (a locker, a depot, a shop counter), never a home address.

The description is [`profiles/food.json`](../profiles/food.json), with the order binding from [`profiles/orders.json`](../profiles/orders.json) ([orders.md](orders.md)). [`board/tests/food.rs`](../board/tests/food.rs) runs it end to end.

## Badges

A badge is a **ticket**, not an access credential. The co-op vets a courier outside pave (who they are, insurance, a trial run) and its dispatch clerk issues a ticket on one stable key of the courier's, tagged with the courier's id and the dispatch's badge purpose, in a group of its own.

- **A ticket, because it names a key.** Custody moves between keys, and the acceptance check already asks whether a key holds a good ticket. An access credential is for proving membership without naming a key, which is exactly what food delivery shouldn't do.
- **One stable key.** The same key takes every bag, so every custody chain the courier was in names that key, and the co-op maps it to the courier. The restaurant sees the courier id on the badge when it's shown.
- **Revocable on its own.** Each badge has its own group, so revoking one courier is one entry on dispatch's ticks; nobody hands that key a bag, and it takes none, once they've heard.
- **A key holds one ticket.** A badge key carries custody only. The wallet refuses to post under it, since a post would put a post ticket on the key in the badge's place.

## The flow

1. **Order.** The customer orders on the restaurant's own system. The binding carries the order's hash, the total and fee, a coarse cell, a **commitment to the address** (a hash of a salt and the address), the customer's key, the co-op, and a **deadline** (`due`).
2. **Pay.** The restaurant invoices the binding's `paid` receipt; the customer pays it.
3. **Ship.** The restaurant bags the order with a seal sticker that carries the label code, and ships a parcel about the binding with the co-op and its dispatch named.
4. **Pick up.** The courier shows their badge. `hand_off` goes only to the addressee or to a key with this dispatch's badge; a member with only shift keys is refused.
5. **Address.** The restaurant gives the courier the address and salt, off the record. The courier checks them against the binding's commitment, so the address they were given is the one the customer paid for.
6. **Carry.** `take` stays on the badge key, with the dispatch's clerk trusted, so a revoked badge takes nothing.
7. **Deliver.** The courier hands the bag to the customer's key. The customer confirms, and posts a `delivered` note on the jobs board giving the seal code they read off the sticker.
8. **Pay out.** The restaurant pays the co-op; the co-op pays the courier at the badge key.

## Outcomes

`food_outcome` reads the customer's note against the manifest and the deadline:

| Outcome | When |
|---|---|
| Pending | No note yet from the key the bag was delivered to; a note from anyone else, the courier included, doesn't count |
| On time | The note's seal code matches the label, and the board's clock on it is at or before `due` |
| Late | As on time, but after `due`, by how much |
| Seal broken | The seal code doesn't match the label |

The board's clock is the time witness: the server binds its epoch and clock into each post, so a note can't be backdated (H8). A dispute reads the same outcomes, with the custody chain naming the badge.

## Still to build

- **Badge renewal.** A badge lasts until revoked. A co-op would re-issue after re-vetting, on a period of its choosing.
- **Delivery vouches.** A delivered, on-time, sealed bag is a good mark for the badge: the voucher is the customer who confirmed, and the courier's identity is the badge's. Not built.
- **Offering deliveries** to checked-in, badged couriers; **refunds and no-shows**; **a real adapter**; **the host app**: as in [orders.md](orders.md).
