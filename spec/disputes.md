# Disputes profile

Disputes are jobs on the job board. Anyone can open one, arbiters offer to take it, a panel nobody picks decides, anyone can appeal by paying for a bigger and better panel, and arbiters build a reputation from rulings that hold up. Some disputes leave pave: a panel can refer one to an outside authority.

The prototype is [`board/src/dispute.rs`](../board/src/dispute.rs), with a test in [`board/tests/dispute.rs`](../board/tests/dispute.rs). The parcels profile uses it for delivery disputes.

## Posts

| Kind | Content | Signed by |
|---|---|---|
| `dispute` | Subject (a parcel, a job), a yes-or-no question, tier, panel size, pay per arbiter, and the dispute it appeals, if any | The opener: a party's credential, or a fresh one |
| `reply` | An offer to arbitrate, under the arbiter's trade key | The arbiter's fresh credential, which the trade key signs over |
| `ruling` | Yes, no, or refer to a named outside authority | The panelist's offering credential |

## Panels

- **Offers.** Arbiters offer during the window: the dispute's epoch and the next. Any wallet can arbitrate, including one an AI agent drives; a panel of agents is just a panel. Pay can be zero, for volunteers, as forum moderators volunteer.
- **The draw.** Once the window closes, the panel is the eligible offers with the lowest hash of (dispute, contractor). Neither party picks it.
- **Eligible.** Not having ruled earlier on the same subject, and, from tier 1 up, a score of at least the tier minus one.
- **Deciding.** A majority of the panel decides. Referrals agree with each other whatever authority they name.
- **Lapsing.** A dispute nobody staffs by the end of its window, or one undecided three epochs after it, lapses and holds nothing.

## Appeals

Anyone may dispute a decided dispute, and pays for it. An appeal counts only if it is on the same subject, one tier up, with at least two more panelists and at least double the pay per arbiter. The decided dispute of the highest tier is final. A referral is final inside pave: the subject is held, and the outside result is the outside's.

## Reputation

An arbiter scores +1 for every ruling that agrees with its subject's final outcome and -1 for every one overturned. Higher tiers need higher scores and pay more, so reputation is what gets an arbiter onto better panels. A dispute's eligibility counts only disputes opened before it, so nothing about a dispute shapes its own panel.

## Who a dispute binds

A profile decides whose disputes count. For a parcel, only disputes opened by its parties hold its delivery (the addressee, the shipper, the couriers in its custody), with any appeals of those. Anyone else's dispute is just a post.

## Not built yet

- Escrow: the opener pays the panel after it rules, and nothing yet forces it to.
- Loser pays, or the appellant refunded on winning.
- Evidence: photos revealed to the panel, codes shown by the shipper.
- Arbiters declaring themselves agents or people, and parties requiring one or the other.
- Scores by kind of dispute, and decay over time.
