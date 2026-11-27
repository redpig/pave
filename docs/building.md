# Building on pave

This is a manual for designing a system on pave's kernel: a delivery co-op, a tool library, a town's reports board, an election. It goes through the decisions in the order you'll meet them, says which kernel and protocol parts answer each, and spends the most time on the decision that's easiest to get wrong: **what each basename links**.

It assumes you've skimmed [the toolkit](../spec/toolkit.md), which defines every pattern named here. The worked examples come from code in [`board/src`](../board/src), and each section points to one.

## The shape of a pave system

Pave gives you very few primitives, listed in the toolkit's kernel table. A system is a choice of:

1. **Who takes part**: rolls and classes, as issuer groups.
2. **What is held**: exclusive states, minted from budgets, moved by transfers.
3. **What is said**: posts on boards, which spend tokens.
4. **What is counted or limited**: pseudonyms from basename signatures.
5. **Whose clock counts**: tick sequences, and which a recipient trusts.
6. **Where checks run**: at whoever receives, serves, pays or tallies.
7. **How things are fixed after a loss or a lie**: revocation, standing, remints, evidence.

If something you want doesn't fit one of these, look harder before adding to the kernel. Every application so far has fit, and the toolkit's rule is that a pattern adds no object types of its own.

## 1. Sort your nouns: held, said or shown

For each thing in your system, ask three questions:

| Question | If yes | Built from | Examples |
|---|---|---|---|
| Would giving it to two people be cheating? | It's **held**: an exclusive state | A schema and a budget; `Transfer`, `Split`, `Retire` | Money, a parcel, a vote coin, a job's assignment, a borrowed tool |
| Does it have an audience rather than a recipient? | It's **said**: a post | A board, post tokens, a content hash | A job listing, a report, a ruling, a drop note |
| Is it a fact about a person that they show, not give? | It's **shown**: a credential | A roll or class (an issuer group) | Co-op membership, being on a district's voter roll, a trade license |

Two tests help when something seems to be more than one:

- **Who wants it next?** Coins move offline because the next holder wants them: a courier wants the parcel because holding it gets them paid. If nobody wants to receive the thing, it isn't a held state. It's a post or a credential.
- **What does a double use look like?** If two uses would be a real conflict (two workers for one job, two votes from one coin), make it a state, and the conflict becomes kernel evidence for free. A job's assignment is a transfer of the zero-value state its proof of means created ([`board.rs`](../board/src/board.rs)), so a poster can't give one job twice.

## 2. Decide who takes part

Participation is an issuer group. Joining is a **join**: the member's device makes the key, and the issuer signs a credential for its public key. The issuer never holds the secret.

- **Town classes** (`hardware`, and so on) are the town's own groups, used for access credentials. Every member has one, and they gate every network service and refill.
- **A roll of your own** is for when your system has its own membership: a co-op's members ([`dispatch.rs`](../board/src/dispatch.rs)), a district's voters ([`election.rs`](../board/src/election.rs)). Who may join is decided outside pave, by whoever runs the roll, as today.

One roll per **thing you need to tell apart** at the mint: an election has one roll per district, so the district comes from which group key verifies, and nobody states it.

## 3. Name your mints

A mint is whoever can create states of a schema. It holds a capability with the `issue` right, derived from the town's root, and spends a budget.

- **One budget per request** keeps a token's history short: a reader verifying it needs only that budget and its mints, not every token ever made. The board mint and the election mint both do this.
- **Ordinary wallets ignore schemas they don't use.** That's what lets one board mint serve many board servers: post tokens are a schema servers accept and wallets don't. Scaling is adding servers that take the schema.
- **A mint that's also a clerk** tickets the credentials it mints to. The ticket is where policy lives: its group (for revocation), its epoch (for expiry), an optional spend cap and an optional tag.

## 4. Choose basenames

This is the decision everything else rests on.

### What a basename does

A basename signature by a credential yields a **pseudonym**. The same holder and the same basename always give the same pseudonym. Different basenames give unrelated ones, and nobody can tell they're the same holder. Two signatures under one basename by one holder are linkable to each other, and to nothing else.

So **the basename sets what can be linked: over what span, and for whom.** Whatever you need to count, cap or recognize, you can only do it within one basename. Whatever must stay unlinkable has to fall under different basenames.

### Two uses, kept apart

| Use | Basename | Links | Purpose |
|---|---|---|---|
| **Spending a state** | The state's id (the kernel does this) | Only a second use of that state | Double-spend evidence, and nothing else |
| **A request by a roll or access credential** | The linkage scope you choose | Every request in that scope | Rate limits, counting people, one live token, recognizing a returning holder |

Never mix them. A coin's signer is a transfer credential; a request's signer is a randomization of a roll or access credential. They are different keys in different groups, and they answer different questions.

### Choosing the scope

Ask three questions, in order:

1. **What do I need to enforce?** A limit per period, one count per person per topic, one live token per person, recognizing someone who comes back.
2. **Over what span must it hold?** An epoch, a day, a thread, an election, forever.
3. **What must never be linkable?** Usually: across topics, across periods, across deployments, and to the person.

The basename is the smallest scope that covers question 2, named so it can't overlap anything in question 3.

| Basename | Linkable within | Enforces | Used in |
|---|---|---|---|
| (service, epoch) | One service, one epoch | Connections per client, barring for the epoch | Network access ([`nac.rs`](../board/src/nac.rs)) |
| (sequence, epoch, slot) | One slot, one epoch | A budget of unlinkable requests per period; past it, requests are linked, not refused | Ticket refills, post-token requests ([`slots.rs`](../board/src/slots.rs)) |
| (board, kind, thread) | One topic | One count per person per topic | Reports and clearings ([`report.rs`](../board/src/report.rs)) |
| (board, "vouch", contractor) | One counterparty | One vouch count per person per contractor | Vouches |
| (board, "dispute", counterparty) | One counterparty | A filer's record with that party | Disputes |
| election | One election | One live vote coin per voter; recognizing a voter who comes back | [Elections](../spec/elections.md) |
| (dispatch, day) | One co-op, one day | A daily check-in: counting distinct couriers; a second check-in is linked | [Dispatch](../spec/parcels.md) |
| (dispatch, day, slot) | One slot, one day | Shift-key requests: a budget unlinkable to each other | Dispatch |

### One request type

Every request to a mint in pave is the same type ([`request.rs`](../board/src/request.rs)): a **spec** (a domain string, the mint's scope, a linkage, and how fresh it must be) plus your profile's **body**. The linkage is the decision this section is about:

| Linkage | Basename | For |
|---|---|---|
| `Slots(n)` | (domain, scope, period, slot), slot below n | A budget of unlinkable requests per period |
| `Period` | (domain, scope, period) | One pseudonym per holder per period: counting |
| `Scope` | (domain, scope) | One pseudonym per holder for the whole scope: one live coin |

A request is signed by a group credential with standing against the mint's ruled list. It can also be signed under another basename (a pseudonym for a purpose, as counted posts are) or by another group's credential with no basename (showing membership, as a courier's day credential is). The mint checks all of it with one call. Because the spec is data, an app can build any mint's requests from a profile's description.

### Budgets, not caps: slots

When you want to limit how often someone asks, don't refuse past a count. Give them a **budget of unlinkable requests** instead: sign with (domain, scope, period, slot) and accept only slots 0 to N−1. This is Briolette's ticket-request pattern.

- Each slot's first use in a period gives a fresh pseudonym, so a holder's first N requests can't be linked to each other.
- Request N+1 has to reuse a slot, so it carries that slot's pseudonym: the mint serves it, and knows it's the same holder as an earlier request, without knowing who.
- The mint applies its policy to linked requests (serve, throttle, charge, review). Nothing fails because a phone was lost or a day ran long.

The wallet picks slots in order and wraps around, so linking happens only past the budget.

### Counting people is its own goal

A slotted basename can't count people: one person shows up under several pseudonyms. If you need a count (how many couriers worked today, how many people reported an issue), design a request for it whose basename has no slot, and have the other requests intersect with it without linking:

- **Check in.** A member joins the period's own issuer group with a join signed under (mint, period). Distinct pseudonyms are the count, and a second check-in is linked, so it counts once.
- **Show the period credential.** Later requests are also signed by the credential the check-in gave, with no basename. That proves "counted this period" and links nothing.
- **Keep bans on the long-lived credential.** Sign check-ins and requests with the roll credential too, under their own basenames, so standing against a ruled list works across periods. A period credential is a fresh key each period, so a ban on it would end with the period.

This is the town's own layering (class, access credential, refills) applied one level down. Dispatch's daily courier credential is the example.

### Rules of thumb

- **Prefer a budget to a cap.** Slots give unlinkable requests up to the budget and linked ones after; a hard refusal past a count turns every edge case (a lost phone, a long day) into a failure.
- **The span you enforce is the span that's linkable.** Longer spans enforce more and reveal more. An election-long pseudonym can recognize a voter who lost a phone, but it also links that voter's requests all election. Choose deliberately.
- **Bans must outlive the basename.** A day pseudonym can't stop a banned courier tomorrow. Put the ruled (basename, pseudonym) on a list, and require **standing** against the list with every request. The ruled holder can't produce it, nobody else is affected, and nobody learns who was ruled. Boards and dispatch both do this.
- **The authority fixes the basename, not the requester.** If a requester can pick the basename, they pick a fresh one to dodge a limit. So the day must be today; the thread must be the issue's id, derived from the issue's content; the election is the one being run. Check that at the mint.
- **Name the deployment in it.** Put the mint's or election's id in the basename (`("pave/election/v1", election_id)`), so two elections, two co-ops or two towns never share a pseudonym.
- **Give it a domain string and a version.** `"pave/dispatch/v1"`, so a basename can't be confused with one from another protocol, and you can change it later.
- **Put a period in it only if the period is the enforcement window.** An epoch in a refill basename makes the budget per epoch. Legal windows (polling hours, a filing deadline) are wall-clock checks at the mint and the recipient, not basenames.
- **Two basenames, one holder.** A request signed twice by the same credential randomization, once per basename, shows that both pseudonyms belong to one holder. That's how a token request is both rate-limited per epoch and counted per purpose.
- **Assume a tagged pseudonym is public.** When a mint puts a pseudonym in a ticket's tag, readers see it next to what the token was spent on. Choose a scope where that's fine: a per-issue pseudonym on a report is; an election pseudonym on a ballot is too, since it's unlinkable to the voter.
- **Never put anything identifying in a basename.** No names, no addresses, no stable device ids.

### Anti-patterns

| Pattern | Why it's wrong |
|---|---|
| A constant basename | One pseudonym per holder forever, across everything: a tracking id |
| A basename the requester chooses freely | Limits can be dodged by picking a new one |
| One basename for two purposes | Counting in one purpose links the holder in the other |
| A hard cap on requests per period | Turns a lost phone or a busy day into a refusal; use slots, and link past the budget |
| Counting people with a slotted basename | One person appears under several pseudonyms; count with a check-in of its own |
| A basename for the person's lifetime, "to be safe" | Links everything they ever do with that mint; use the shortest span that enforces what you need, and standing for bans |
| Deriving the basename from the content of a free-text field | Two people describing one thing differently become two topics; derive it from structured fields (a category and a cell, as reports do) |

## 5. Choose your clocks

The kernel has no time. Time in pave is a **tick sequence**: an indivisible coin its clerk holds, each roll a transfer committing to that tick's data, so two versions of one tick are a conflict.

- **Use the town's epochs** when your freshness and revocation can follow the town's rhythm: refills, post tokens.
- **Run your own ticks** when revocation is driven by events, not time. An election ticks when a coin is reissued; dispatch ticks on a ruling. Nothing waits for the town's next epoch.
- **Leave legal time to the law.** If a deadline is set in wall-clock terms by someone outside the system (polling hours, a court's extension), give the schema no expiry and check the window where the mint and the recipient act. Let the authority move it.
- **Freshness is the recipient's choice.** A recipient's policy names which clerks it trusts, each with its sequence; whether it honors expiry; its revocation window; whether it requires standing. A board server, a booth and a courier's wallet each set their own.
- **Get a clock before signing.** If a recipient checks a clock or a window, ask it for its clock first and sign with that. Otherwise a holder can spend a state on something the recipient will refuse. Board posts and ballots both work this way.

## 6. Put checks where things move

Every refusal belongs at a point where something changes hands. List them:

| Where | Runs | Examples |
|---|---|---|
| **A receiver taking a state** | The ordinary acceptance check (tickets from trusted clerks, expiry, revocation, standing), plus the profile's checks | A courier taking a parcel; a board server taking a post token; a booth taking a vote |
| **A giver choosing whom to give to** | That the recipient's key qualifies | A dispatched parcel handed only to shift keys; the courier shows its ticket with the key, because meets carry tickets only for keys that records already name |
| **A payer** | That each payee qualifies and hasn't cheated | A shipper pays only shift keys, and never a courier with evidence against it |
| **A reader or tallier** | Every record, from the mint to the final retire, and the tags | A board copy; an election tally |
| **A mint** | Roll membership, the basename's scope, caps, standing, request times | Every request handler |

Two habits:

- **A check that the honest client already does must also be done by the server.** A ruled wallet won't build a request it can't prove standing for, so the server's check never runs in an honest test. Test it with a request built on the terms from before the ruling. Several of pave's mutation checks found exactly this gap.
- **Make the server's "took it" a kernel record.** A board server retires the post token, a booth retires the vote coin. The retire is the proof the author holds, and a copy can't fake it.

## 7. Plan for loss and lies

| Problem | Tool | Example |
|---|---|---|
| Someone uses a state twice | Nothing to build: kernel evidence names the signer's group | A double handoff, a double vote, a double assignment |
| A credential or batch must stop working | Revoke its ticket group on your ticks | A ruled courier's day keys; a reissued vote coin |
| A person must stop taking part, unnamed | Standing against a ruled list | A ruled reporter; a banned courier |
| A device is lost with a state on it | Remint, layered on a state that never leaves the issuer | A parcel's lineage coin ([`parcel.rs`](../board/src/parcel.rs)) |
| A device is lost and the holder can prove who they are to the mint | Reissue under the same pseudonym, revoking the old group | A voter coming back to the vote mint |

**Layering makes a remint double-spend safe.** When the issuer mints a token that travels, it also mints a lineage coin it keeps, and the token's manifest names the lineage and a generation. A remint moves the lineage (its receipt committing to the old and new token) and mints the next generation. Reminting one generation twice is then a second use of one lineage state: kernel evidence, not a convention. A token behind its lineage is void to anyone who has seen the lineage move, exactly as a stale epoch is.

**Decide what proves a claim to a remint.** For a parcel it's the package and its label code: possession of the physical thing. For a vote it's the voter's roll credential: a voter who restored it from a backup is recognized by their pseudonym.

**Accept the offline gap, and make it visible.** A holder who hasn't heard of a revocation or remint can accept a stale token. You can't prevent that offline. Design so it surfaces: the old token moving after its lineage did, two ballots with one pseudonym, a tally that keeps each pseudonym's newest ticket.

## 8. Saying things

When something is said rather than held:

- **Use a board.** A post spends a token from a board mint, at a board server, committing to the content hash, a prior post and the server's clock. Content stays with the server; copies can serve it, and readers check every record. See [boards.md](../spec/boards.md).
- **Count with tags, not with content.** A post that should count one person once is a counted post, its token's ticket tagged for the purpose.
- **Let people choose how identifiable to be.** Identity tiers: a stable credential shared with chosen people signs the binding, or nothing does.
- **Keep posts off the wallet-to-wallet path.** Meets carry value, epochs and evidence. Post tokens go from mint to holder to server, and records that make or move them stay out of bundles.

## 9. Settling and proving later

Use the toolkit's patterns rather than inventing: **commit and reveal** for anything you'll show later (a code, a photo, an original before redaction); **sealed material** for what only a panel should see; **disputes** as jobs, with panels drawn by hash, rulings as posts, appeals paid into escrow, and records counted per counterparty. Escrow's holder is trusted until code-bound identity is built; say so.

## 10. Check your design

Before writing code:

- [ ] Every noun is held, said or shown, and every held thing has a meaningful double use.
- [ ] Every mint names its capability, schema and budget per request.
- [ ] Every request basename has a stated span, a deployment id, a domain string and a version, and the mint fixes it.
- [ ] Every limit is a slot budget with linking past it, not a refusal; every count is a check-in of its own.
- [ ] Every ban outlives its basename through standing.
- [ ] Every tick sequence names who rolls it and when; every legal window is a wall-clock check.
- [ ] Every point where something moves has its checks listed, at the server as well as the client.
- [ ] Every loss has a recovery, and every recovery that mints again is layered so a second one is a double spend.
- [ ] Every offline gap is written down, along with how it surfaces.

While writing code, do what pave's profiles do:

- **A test for every refusal.** Include one where a cheating client skips its own check.
- **A mutation check for every refusal.** Break the check, confirm a test fails, restore it. A mutation no test catches is a missing test, or a check that something earlier already covers. Know which.
- **A threat-model row for every attack**, with its status: built (and the mutations that cover it), partial, or a gap.

## Worked examples

Two systems that aren't in the code, sketched with the decisions above. Neither needs anything new.

### A tool library

Members borrow tools; a tool goes back to the library or straight to the next borrower.

| Decision | Choice |
|---|---|
| Held | A **tool token** per tool: indivisible, no expiry, a transfer limit. Lending is a handoff with a receipt committing to the loan terms; the borrower's take acknowledges. Returning is a handoff back. Lending one tool to two people is a double spend |
| Shown | **Library membership**: a roll |
| Mint | The library holds a budget of tool tokens, one per tool it owns |
| Basename | **(library, week, slot)** for borrow requests: a member's first few borrows a week can't be linked to each other; more are served and linked, so the library sees heavy borrowing without knowing who. If the library wants to count distinct borrowers, a weekly check-in under (library, week) does it |
| Bans | A member who keeps tools goes on the ruled list; standing of the member credential keeps them out in any week, under any slot |
| Clock | The library's own ticks for revocation; due dates are wall-clock terms in the loan's receipt |
| Checks | The library hands a tool only to a key with a membership ticket for this week; a borrower takes after the usual coin checks |
| Loss | A lost phone with a tool token on it: the member brings the tool back and the library remints, layered on a lineage coin per tool. A lost tool is a dispute, with the custody chain as evidence |
| Said | A board for the catalog and for reporting broken tools; reports counted per (board, "broken", tool) |

### Shift swaps

Workers at a co-op kitchen trade shifts.

| Decision | Choice |
|---|---|
| Held | A **shift token** per scheduled shift: indivisible, good until the shift starts (a wall-clock check by whoever takes or pays it, not a schema expiry). Swapping is a transfer to the other worker with a receipt naming the shift. Giving one shift to two people is a double spend |
| Shown | **Staff membership**: a roll |
| Mint | The scheduler mints the week's shift tokens to workers' keys |
| Basename | **(kitchen, week, slot)** for taking swapped shifts: a worker's first few swaps a week are unlinkable; more are linked, so a labor rule (no one takes on too many) is a review of linked requests, not a refusal. A weekly check-in under (kitchen, week) counts who worked |
| Clock | The kitchen's own ticks; a shift's start is a wall-clock check |
| Checks | A worker takes a swapped shift only from a key with a staff ticket; payroll pays the key that holds the shift token at its start, and never a key with evidence against it |
| Loss | A lost phone: the scheduler remints the shift, layered on a lineage coin per shift; proof is the staff roll credential, under the (kitchen, week) pseudonym |
| Said | A board for offering and asking for shifts; an accept is a transfer of the shift token, as a job's accept is |

Both are assembled from parts that already exist: rolls, budgets, custody tokens, layered remints, a period basename with standing for bans, own ticks, wall-clock windows, and a board. If your system needs something that isn't on this list, write down why before reaching for the kernel.
