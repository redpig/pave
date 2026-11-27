# Order profile (example): restaurant delivery

A restaurant that keeps its own ordering system (Toast, say) delivers through a local co-op, with pave carrying only what a platform would otherwise hold. The description is [`profiles/orders.json`](../profiles/orders.json); The parcel it ships is carried under the food profile, by a badged courier: see [food.md](food.md), and [`board/tests/food.rs`](../board/tests/food.rs) for the whole flow.

## What stays where

| With the restaurant's system | In pave |
|---|---|
| The menu, the order's contents, the address, kitchen tickets | The order's **binding**: the hash of the order as the restaurant's system has it, the total, the delivery fee, a coarse cell, a commitment to the address, the customer's key, the co-op, and a deadline |
| Its customer relationship and marketing | The payment, committing to the binding |
| Order status for its staff and the customer | The parcel, its custody, and the pay; the restaurant's adapter reads custody back into its own statuses |

## The flow

1. **Order.** The customer orders on the restaurant's own site. Its system keeps the order; the customer's wallet builds the binding from the order profile.
2. **Invoice.** The restaurant's adapter checks the binding against the order in its system and invoices the total, with the invoice's memo the order's `paid` receipt: a hash of the binding.
3. **Pay.** The customer pays the invoice. The payment record commits to the binding.
4. **Ship.** The restaurant ships a parcel to the customer's key ([parcels](parcels.md)), saying what it's for (`about`: the binding's hash), with the co-op as provider and its dispatch named.
5. **Carry.** A courier the co-op badged takes it under the badge key, is given the address, and hands it to the customer's key. The customer confirms by retiring it and posts the seal code ([food.md](food.md)).
6. **Pay out.** The restaurant pays the co-op its delivery fee, once, against the parcel's shipping receipt. The co-op pays its couriers.

In the test, in cents of test credit: the customer pays $24.00 ($19 of food and a $5 delivery fee); the cafe keeps $19; the co-op keeps $1 of its $5; the courier earns $4. Nobody else takes a cut. The split is illustrative, not a proposal.

## What fitting it needed

Nothing new in the kernel, and the order profile itself is one layout and two receipts: the rest is parcels, dispatch, invoices and payments as they were. Two small additions came out of it:

- **A manifest says what a parcel is for:** `about`, an optional hash, named before the first handoff.
- **An invoice can commit to a hash:** `invoice_for`, so a payment commits to a binding rather than a text memo.

## What a product still needs

- **Offering the delivery.** Built as a job for badged couriers: see [food.md](food.md#the-flow).
- **The address, only to the courier carrying it.** Built as a commitment: the binding carries a salted hash, and the restaurant gives the badged courier the address and salt at pickup. Sending it sealed to the badge key instead, as evidence is sealed to a panel, is not built.
- **Refunds and no-shows.** Payment goes to the restaurant up front. If the order is never delivered, the refund is the restaurant's payment back, or a dispute. A courier who takes a parcel and doesn't deliver is a dispute with the custody chain as evidence.
- **A real adapter.** The test's adapter maps custody to "READY", "PICKED_UP" and "DELIVERED". A real one polls the restaurant's system and writes those statuses back.
- **The customer's side.** A host app that confirms delivery by NFC or QR at the door ([web.md](web.md)).
