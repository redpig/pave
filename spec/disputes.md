# Disputes profile

Disputes are jobs on the job board. Anyone can open one, arbiters offer to take it, a panel nobody picks decides, anyone can appeal by paying for a bigger and better panel, and arbiters build a reputation from rulings that hold up. Some disputes leave pave: a panel can refer one to an outside authority.

The prototype is [`board/src/dispute.rs`](../board/src/dispute.rs), with a test in [`board/tests/dispute.rs`](../board/tests/dispute.rs). The parcels profile uses it for delivery disputes.

## Posts

| Kind | Content | Signed by |
|---|---|---|
| `dispute` | Subject (a parcel, a job), a yes-or-no question, the answer the filer argues for, the counterparty if any, tier, panel size, pay per arbiter, the dispute it appeals if any, and for a paid appeal its escrow deposit | The opener: a party's credential, or a fresh one; endorsed when it names a counterparty |
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

## Escrow

An appeal with pay is paid upfront. Its deposit is a split of one of the appellant's coins with at least `panel * pay_each` to the town's escrow credential, whose receipt commits to the appeal's terms (subject, tier, panel, pay, the dispute appealed). The appeal post carries the deposit record, and readers ignore an appeal whose deposit is missing, made for other terms, too small, or already used by another appeal. Once the appeal is decided or lapses, the town retires the deposit and mints each panelist who ruled its pay and the appellant the rest, as the swapper does.

A first round is funded by the side the filer disputes, such as the provider. It may fund it upfront: a `fund` post carrying a deposit whose receipt commits to the first round's terms, into the same escrow; the town pays the panel from it and refunds the rest to the funder. Or it may pay the panel after it rules.

## Appeal window and settlement

An appeal must be filed within two epochs of the ruling that decided the dispute it appeals. A chain is *settled* once nothing in it is still being decided and its top dispute is past its appeal window, or is a referral. Money that depends on who won waits for settlement.

## Terms for filers

A counterparty may publish terms under its trade key: from filers who have lost to it at least so many times, a deposit of so much, paid to a credential it names. A first-round filing against it from a filer whose record (by its pseudonym with that counterparty) meets the terms must carry the deposit, into escrow, or readers ignore it. Once the chain is settled, the town returns the deposit to the filer if it won or nothing was decided, and pays it to the counterparty if it lost. A filer's wallet pays the deposit itself when the terms apply. Terms signed by anyone but the counterparty's trade key are ignored.

## Sides and records

A dispute states the answer its filer argues for. It may name its counterparty, a contractor (a courier, a provider). Then the filer endorses it with the counterparty as basename, so the filer has one pseudonym per counterparty:

- **A filer's record with a counterparty**: filed, won, lost, referred, judged by each dispute's own appeal chain. A provider sees that one pseudonym has filed five times against it and lost five, without learning who it is; against anyone else the same person is unrelated.
- **The counterparty's record**: distinct people who disputed it, how many it lost to and won against. Ten disputes from one angry customer count once.

## Who owes whom

Once an appeal chain is final, `liability` computes loser-pays: the losing side owes what the winning side paid for panels, except that a loser who never escalated owes at most the first round's cost. Whoever escalates carries the escalation's risk. A referral settles no costs. This is computed, not enforced; see the example below.

## Reputation

An arbiter scores +1 for every ruling that agrees with its subject's final outcome and -1 for every one overturned. Higher tiers need higher scores and pay more, so reputation is what gets an arbiter onto better panels. A dispute's eligibility counts only disputes opened before it, so nothing about a dispute shapes its own panel.

## Who a dispute binds

A profile decides whose disputes count. For a parcel, only disputes opened by its parties hold its delivery (the addressee, the shipper, the couriers in its custody), with any appeals of those. Anyone else's dispute is just a post.

## Example: paying for disputes (non-normative)

One way a delivery co-op could use all this. Nothing here is required by the profile.

- **The shipper pays the provider** (the co-op) for shipping, and the co-op pays its couriers.
- **The first round is the provider's cost**, like customer service: the customer files for free. The provider pays the panel.
- **Appeals are paid upfront** by whoever appeals, into escrow.
- **Loser pays, capped.** At the final ruling the losing side owes what the winning side paid, but a side that never escalated owes at most the first round. A provider with deep pockets can't appeal twice and leave a customer owing for rounds the customer never chose.
- **Reputation before debt.** A filer who keeps losing against a provider is visible to that provider by pseudonym, so the provider can ask that filer for a deposit before the next first round: its terms for filers. That deters spurious disputes without anyone collecting debts. A provider or courier who keeps losing to different people is visible too.
- **Debts, if a co-op uses them at all, block little.** An unpaid amount could put the debtor's pseudonym on a list that standing proofs must cover for opening disputes, the way a ruling stops a reporter, and nothing else. It would expire after some number of epochs. Blocking payments would punish too much for a small debt.
- **Linkage is a choice.** Per counterparty is the default here. A co-op could choose per dispute (no records at all) or per board (one record across every counterparty), the way identities come in tiers.
- **Open questions.** Partial outcomes (a refund of part of the price) rather than yes or no; who pays when a dispute lapses; whether arbiters' pay should vary with the amount at stake; how records of new filers and providers should be read.

## Not built yet

- Enforcing liabilities, and the debtors list sketched above.
- Evidence: photos revealed to the panel, codes shown by the shipper.
- Arbiters declaring themselves agents or people, and parties requiring one or the other.
- Scores by kind of dispute, and decay over time.
