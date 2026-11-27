# Order profile (example): restaurant delivery

A restaurant that keeps its own ordering system (Toast, say) delivers through a local co-op, with pave carrying only what a platform would otherwise hold. The description is [`profiles/orders.json`](../profiles/orders.json); [`board/tests/order.rs`](../board/tests/order.rs) runs the whole flow.

## What stays where

| With the restaurant's system | In pave |
|---|---|
| The menu, the order's contents, the address, kitchen tickets | The order's **binding**: the hash of the order as the restaurant's system has it, the total, the delivery fee, a coarse cell, the customer's key, and the co-op |
| Its customer relationship and marketing | The payment, committing to the binding |
| Order status for its staff and the customer | The parcel, its custody, and the pay; the restaurant's adapter reads custody back into its own statuses |

## The flow

1. **Order.** The customer orders on the restaurant's own site. Its system keeps the order; the customer's wallet builds the binding from the order profile.
2. **Invoice.** The restaurant's adapter checks the binding against the order in its system and invoices the total, with the invoice's memo the order's `paid` receipt: a hash of the binding.
3. **Pay.** The customer pays the invoice. The payment record commits to the binding.
4. **Ship.** The restaurant ships a parcel to the customer's key ([parcels](parcels.md)), saying what it's for (`about`: the binding's hash), with the co-op as provider and its dispatch named.
5. **Carry.** A courier who checked in with the co-op today takes it under a shift key, and hands it to the customer's key. The customer confirms by retiring it.
6. **Pay out.** The restaurant pays the co-op its delivery fee, once, against the parcel's shipping receipt. The co-op pays its couriers.

In the test the customer pays 2400; the cafe keeps 1900; the co-op keeps 100 of its 500 fee; the courier earns 400. Nobody else takes a cut.

## What fitting it needed

Nothing new in the kernel, and the order profile itself is one layout and one receipt: the rest is parcels, dispatch, invoices and payments as they were. Two small additions came out of it:

- **A manifest says what a parcel is for:** `about`, an optional hash, named before the first handoff.
- **An invoice can commit to a hash:** `invoice_for`, so a payment commits to a binding rather than a text memo.

## What a product still needs

- **Offering the delivery.** In the test the restaurant hands the parcel to a courier it chose. A co-op would post it on its dispatch board for checked-in couriers, and the one who accepts gets the assignment, as a job's acceptance is. Not built.
- **The address, only to the courier carrying it.** The binding carries a cell; the street address must go sealed to the courier's shift key once they're assigned, as evidence is sealed to a panel. Not built.
- **Refunds and no-shows.** Payment goes to the restaurant up front. If the order is never delivered, the refund is the restaurant's payment back, or a dispute. A courier who takes a parcel and doesn't deliver is a dispute with the custody chain as evidence.
- **A real adapter.** The test's adapter maps custody to "READY", "PICKED_UP" and "DELIVERED". A real one polls the restaurant's system and writes those statuses back.
- **The customer's side.** A host app that confirms delivery by NFC or QR at the door ([web.md](web.md)).
