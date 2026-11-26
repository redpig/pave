# Design log

Decisions behind the current [kernel](../spec/kernel.md) and [protocol](../spec/protocol.md), and why. Newest first within each section.

## Layers

1. **Kernel**: axioms only. Three objects (scope, capability, message), holding, schemas, receipts, five operations, one initial state, six invariants. No corollaries, no roles, no time, no domain words.
2. **Protocol**: corollaries, standard schemas (epochs, expiry, tickets, access credentials, value, time, votes, certification, recovery), core mechanisms, what each role must guarantee, and profiles. Briolette's design generalized: every piece is a capability under a schema.
3. **Profiles**: which schemas a context uses and how they're set (cash, offline mesh, boards).

## Kernel

- **Six invariants:** conservation, consent, minimal disclosure, transparency, fixed at creation, detectable conflict. An earlier seventh, "bounded", was removed once honoring expiry became the recipient's choice. It added nothing beyond schemas being data that is fixed and public.
- **No time in the kernel.** Expiry, epochs and the sequences that count them are protocol schemas. Wall time stays outside entirely ("like Linux going tickless"). A rough-time service, for example for recovery, would be independent of the core.
- **No programmability.** Schemas and scope rules come from a closed menu: data, not code. Otherwise "it's just a crappy blockchain."
- **No conditionals or hashed timelocks.** They need agreed time and countersigning, and they can be attacked when the internet is down but the local network is up. The protocol uses proof of means (a zero-value split) and nested, salted receipt hashes instead. Escrow is just a holder both parties choose.
- **A schema never says who accepts it.** It holds operation rules only, and each recipient chooses which schemas and roots it accepts. This keeps the system open.
- **Holding is one level.** Every capability is held under a credential, itself a capability: a fresh randomized one (unlinkable) or a stable one the holder chooses to keep. Nothing nests deeper.
- **No roles in the axioms.** Registrars, ticket and epoch issuers, mints, swappers, validators and revokers are holders of particular capabilities. Whatever must hold goes into the presentation, so nothing depends on a role behaving well. Swappers are optional, a convenience so mints don't have to swap.
- **Nothing acts as you.** Recovery is a capability each holder mints for itself. The kernel never becomes an identity provider.

## Epochs, tickets and expiry

- **An epoch is a sequence.** Each epoch is minted by spending the one before, so two versions of one epoch are an ordinary detectable conflict. No special kernel machinery is needed.
- **Epoch policy.** When to roll is the issuer's published policy. The default is activity-driven: an epoch ends once enough distinct holders have drawn tickets.
- **Tickets.** A ticket is a randomized credential acting as a short-lived holding slot, and transfer is spend. Extra tickets from one holder in an epoch link and count once, so active users pay in linkability, never in access.
- **Expiry on the last hop, with a lifetime from mint.** Soft expiry applies to the sender's and holder's tickets, so active coins keep circulating; hard expiry runs from the coin's first ticket, so every coin's life is capped. Each ticket counts by its own issuer's sequence. This is Briolette's rule. Checking soft expiry on every ticket in the history, as pave first did, bounded undetected copies more tightly but forced swaps on active coins and acted as a hidden lifetime cap.
- **Revocation within a window.** A revoked group always stops the last hop, and earlier hops only if their ticket was issued within a few epochs before the revocation, so honest coins that passed through a group long ago aren't stranded. Tainting the whole history would have stranded every coin that ever touched a closed class. The window needs no tuning for volume: it counts the issuer's epochs, and activity-driven epochs already roll faster when traffic is heavy.
- **Composable epochs.** Different capabilities can count different issuers' epochs. There is no shared clock.

## Wallets

- **Prefetched tickets.** A wallet enrolls once and gets a batch of tickets, each certifying a fresh randomized credential in its revocation group. Every holding and every role uses a fresh one, so actions are unlinkable unless a state is used twice.
- **Tickets travel with provenance.** A wallet shares tickets only for credentials that appear in records it shares, never its unused pool.
- **Refills are authenticated** by one of the wallet's own credentials, so the clerk issues in the right group without learning anything new.
- **Revocation by group.** Evidence names one credential; its ticket's group leads to the wallet. Revoking the group in an epoch catches the cheater's other, unlinkable coins once the epoch reaches a recipient.

## Gossip

- **Gossip is an optimization; nothing depends on it.** It never carries transfer records, so it carries no transaction graph.
- **Two tiers.**
  - *Compressed:* hints only (sequence heads and fork hints), sized to fit one APDU or mesh packet.
  - *Extended:* proofs (signed epochs and evidence), fetched per hint, have/want style.
  - A hint never flags anyone or moves an epoch. A recipient may choose to hold off one coin offline while an unproven fork hint names it.
- **Evidence.** The shared basename plus two signatures with the same nym. With Briolette v1 crypto it is about 770 bytes, so it travels only in the extended tier. It names the forked coin and its ticket. The cheat's other coins are under unlinkable credentials, so evidence alone can't name them. Standing closes that: once a recipient knows of a cheat, a sender proves its key isn't the cheat's (EPID's non-revoked proof), which the cheat can't do for any coin.
- **Tokenmap stays, as an optional role.** Syncing to it records what you held, which helps recovery, and gives online double-spend detection. What it publishes is evidence, never a verdict.
- **Issuer revocation bitfields still work per issuer,** for that issuer's own tickets, carried in its signed epochs. They are no longer the only revocation channel.

## Boards, and what moves like a coin

- **Content goes to its audience.** A board is an online service. Posts go straight to the host with a pave record binding their content by hash; the host answers with a receipt, and anyone with a copy can serve readers, who check everything. Reports first went wallet to wallet like coins, which raised what peers learn on the way and led toward relaying and cover traffic, an anonymity network pave shouldn't build. A post's audience is the board, so it goes to the board.
- **What moves like a coin.** Peer-to-peer movement is for things the *recipient* wants and must check without reaching anyone: value, and what checking value needs (epochs, standing, evidence). A capability moves like a coin when it is exclusive (one holder at a time, and using it twice is the fraud), the recipient wants it, and the handoff happens where the network may not be: a transit pass or voucher, custody of a package passed courier to courier, a shift swapped between workers, the key to a shared tool or locker. These are coins with their own schemas, and need nothing new in the kernel. Parcels are built this way ([spec/parcels.md](../spec/parcels.md)): mint, transfer, a self-transfer as the taker's acknowledgment, and retirement by the addressee as delivery. Where the addressee can't sign, a code or a drop closes it, and disputes settle it.
- **Disputes are jobs, and judgment is a market.** Arbiters offer as contractors; a panel is drawn so neither party picks; rulings that hold up on appeal build reputation, and reputation is what gets an arbiter onto higher tiers, which pay more. Disputing a dispute is allowed and costs more: a bigger panel at double the pay. There is a range: volunteers at zero pay, as forum moderators volunteer; AI agents, or panels of them, since any wallet can arbitrate; and referral to the legal system, where pave holds the subject and stops. Appeals are paid upfront into escrow. Records by pseudonym, one per counterparty, show spurious filers and failing providers without naming anyone; debts are the risky lever, so loser-pays is computed and capped for whoever didn't escalate, and the debtors list stays an example. See [spec/disputes.md](../spec/disputes.md).
- **Recommendations are coins, held by the contractor.** "Who did your fence?" gets a contact passed hand to hand, but the contact isn't the recommendation. The recommendation is a reputational commitment for a job type, and it belongs with the contractor, who keeps and shows it; the friend asking wouldn't do anything with it. So a vouch is a zero-value output of the payment itself, to the worker, with a receipt committing to the job, the contractor and the type: it goes to the contractor with the pay and checks like money. The poster also posts it, endorsed, in the contractor's thread on the board, so readers count distinct people per type. In a town, vouches from people you know matter most, so a voucher may also sign with a stable credential it has shared only with its contacts: they recognize it, and everyone else sees one unnamed person. That is an ordinary pave credential, not new cryptography, and it works for any post, not just vouches: a wallet starts with one identity per privacy tier (close, contacts, public), and each time someone posts they choose how identifiable to be. See [spec/boards.md](../spec/boards.md).
- **What doesn't.** Content (posts, reports, listings) has an audience, not a recipient. Presented credentials (a license, a certification) are shown, not handed over. Counted acts (votes, reports) are one per person per purpose, which basenames do.
- **Budgets, not caps.** Refills, post tokens and dispatch first refused a holder past a count per period, with one pseudonym per period linking every request in it. Briolette did better: a basename per slot, so a holder's first few requests a period are unlinkable, and any past the budget reuses a slot and is linked, not refused. Pave now does the same everywhere it rate-limits requests. Counting people became a goal of its own: a check-in, a join to the period's own issuer group under an unslotted basename, whose credential later requests show with no basename. Bans stay on the long-lived roll credential so they outlast the period.
- **A board is a clerk.** The first board had its own parts: a host receipt, endorsements signed at post time, ruled lists. Each duplicated something the town already had. Now the right to post is a token: a board mint answers anonymous requests the way the clerk answers refills, a post is the token's transfer to a board server committing to the content, and the server takes it by retiring the token. The token is exclusive, so using it twice is a double spend, but it isn't carried between peers: it goes from the mint to its holder to a server. Counting is the clerk checking a purpose basename and putting the pseudonym in the ticket's tag; rulings are standing against the mint's list and group revocation. Because ordinary wallets don't accept the token's schema and servers do, one mint can serve many boards, and a board scales by adding servers that never coordinate. Two basename uses stay distinct: a coin's basename is its state, so it links only on a second use; an access credential's basename is the linkage scope chosen (an epoch for rate limits, a purpose for counting).

## Design notes not yet in the spec

- **Roots of trust.** Enrollment can come from a government mobile ID (zero-knowledge proofs over ISO mdocs, for example Longfellow), a community (threshold issuance by mesh nodes, presence attestations, staked vouching), attested hardware, or a bonded provider account (low assurance). A one-time enrollment records a document-derived nullifier and binds a member secret, from which pseudonyms are derived per scope. Low-entropy document numbers are never hashed directly.
- **Agents.** A delegated agent holds capabilities derived from its principal's and is bounded by them. A sovereign agent needs an attested hardware-backed key and earns its limits through a bond or task reputation. Attestation sources are accountable groups. Physical jobs need a human, and votes are one per person.
- **Credential-addressed messages.** A message's address is a credential predicate ("licensed electricians within five miles"), delivered encrypted so only matching holders can open it.
- **Custody and hosting.** Shared resources are held under bonds and checked by randomly sampled possession audits. Cloud is just another host, under the same rules and with caps per provider and region.
- **Jobs and time.** A job is a scope that holds nothing, and steps are child scopes. Workers mint their own time, and double-booking is a detectable conflict. Each job scope lists which receipts it accepts as proof; not every job has a proof moment.
- **Encoding (leaning).** FIDL for protocols and CBOR (CDDL schemas, COSE signatures) for everything signed. A schema would be a CDDL definition plus its rules, identified by hash.

## Model findings

Each is checked in [formal/](../formal/).

- **Evidence must be the same signer using the same coin state twice.** Matching on coin position alone blames honest holders downstream of a fork.
- **An issuer needs the same never-sign-twice guard as a wallet.** A restore from backup, or two replicas, looks exactly like equivocation.
- **Check every ticket in the history.** With several clerks, checking only the newest ticket fails once clerks roll at different rates.
- **Expiry is only as fresh as the recipient's latest epoch.** A recipient that needs freshness fetches it first.
- **One-tier gossip doesn't scale to many sequences.** With six sequences it is about 1 KB per frame. Two tiers average 163 bytes, and 87% of frames fit one packet.
