# Civic Fabric Protocol v0

Draft, November 2026

The standard capabilities and mechanisms built on the [kernel](kernel.md)'s axioms. It is Briolette's design generalized: every piece is a capability under a schema, and none is special to the kernel. Profiles, at the end, pick which pieces a context uses and how to set them. How each piece is implemented, and the patterns built from them, are on the mechanisms page.

## Corollaries of the kernel

These follow from the axioms and are stated so no one adds a feature that duplicates or contradicts them. Numbers in brackets are the kernel invariants each follows from.

- **C1 Derivation bounds every action:** no capability exceeds the one it derives from.
- **C2 Everything chains to the root:** only nesting and derivation create scopes and capabilities, so every chain of authority ends at a root, and every check ends in something anyone can verify, such as a signed receipt or a public commitment.
- **C3 No double-booking:** time is an exclusive capability, so one block in two places is a detectable conflict (1, 6).
- **C4 You can only lose what you signed away:** the only custody is a holder's, so escrow is a holder both parties chose (2).
- **C5 Proof, not locks:** a zero-value split proves possession and a receipt commits to terms, without moving anything. Nothing waits on a condition (1, 3, 4).
- **C6 An untrusted kernel can't affect you:** its capabilities matter only to those who trust its root (C2).
- **C7 Delegation never adds budget** (C1).
- **C8 The root roots but doesn't rule** (5).
- **C9 Nothing acts as you:** no role or kernel can sign, recover or re-issue on a holder's behalf. Recovery is a capability each holder mints for itself under a recovery schema (2, C1).
- **C10 The minter can't tell you how to act:** an issuer chooses only what it mints and its operation rules. Who holds, accepts, swaps or serves is each party's own choice (2, C2).
- **C11 Linkage is the holder's choice:** holders are unlinkable by default and may present a stable credential to build a relationship or certify a business. A recipient may decline to serve without one, but nothing else can make a holder linkable (3).
- **C12 Every answer is evidence:** every role's response is signed, so refusals and misbehavior always leave proof (4, C2).
- **C13 Certifying is holding:** a certifier either grants a right to self-mint a certification onto any fresh randomized credential, or binds it to a stable credential the holder chose to keep. No credential needs partial attribute disclosure (3, 5, C11).
- **Two separate orders:** integrity follows the scope tree, so nothing changes what is above it (Biba, from 5); confidentiality follows credential predicates, so a message reaches only holders who match it (Bell–LaPadula, from 2 and 3).

## Standard schemas

- **Epochs.** A sequence: its issuer mints each epoch by spending the one before, an exclusive capability it holds, so two different epochs at the same position are the same capability used twice, a detectable conflict. The kernel needs nothing special for this. When to mint the next one is the issuer's published, checkable policy. The default: an epoch ends once enough distinct holders, a set fraction of those active in the last epoch, have drawn the issuer's tickets, so dormant members can't stall it and a few heavy users can't rush it. Different capabilities can count different issuers' epochs; there is no shared clock.
- **Expiry.** A schema may carry a soft and a hard expiry and an offline-transfer limit, each counted in epochs of a sequence the schema or the holding credential names. Soft expiry applies to the last hop: the sender's and holder's tickets, so a coin stays good as long as its holders keep fresh tickets. Hard expiry runs from the first (mint-time) ticket, so every capability's life is capped from its creation. Each ticket counts by its own sequence. An accomplice with a fresh ticket can carry a coin held on a stale one onward, but only until its hard expiry. A recipient checks with the latest epoch of each of those sequences, which travel like any other capability. Honoring expiry is each recipient's choice; wallets honor it by default, and wall-clock time stays out of the protocol too.
- **Tickets.** A randomized credential, certified by a ticket issuer and issued blind in randomized groups, whose schema makes it a short-lived holding slot. It names the epoch sequence it counts by and carries policy such as a maximum spend. Value is held under the ticket it was transferred to, and transfer is spend. A wallet that needs more tickets in one epoch reuses a basename, so those requests link: active users pay in linkability within the epoch, never in access. A long-lived ticket is a stable identity, which merchants and banks want.
- **Access credentials.** Issued at enrollment from a root of trust (a government mobile ID, a community, attested hardware or a bonded account), recording a nullifier so no one enrolls twice. Where a legal ID isn't digital, a proxy issuer digitizes it outside the system.
- **Value.** Credit, local currency or dollar-backed tokens: divisible, with a soft and a hard expiry in epochs and an offline-transfer limit, held under tickets. Honoring expiry is each recipient's choice.
- **Time.** Minted by the worker, k units per time block. Using one unit in two accepts is a detectable conflict, which is double-booking.
- **Votes.** Open: member ballots fetched blind from the scope's mint when a proposal opens (an eligibility and weight snapshot), a stable pseudonym for the length of a dispute panel, or a self-mint under membership for low-stakes polls.
- **Certification rights and bindings.** A self-mint right is bound to the key the certifier certified, a stable identity of its own; each self-minted binding proves it comes from that key, so it can't be lent. A binding is bound to the message it's used in, such as one job reply, so it needs no expiry of its own, and it carries the right's expiry and revocation group for offline checks. Issuers can also bind directly to a stable credential, as a licensing board and an insurer do for a general contractor.
- **Recovery.** A capability each holder mints for itself and keeps where it chooses: another device, friends it picks, or a recovery service. A swapper honors it only under a recovery schema and roots it accepts. A holder may bind it to an issued legal ID, so a reissued ID can recover only the capabilities that binding names.

## Core mechanisms

- **Conflict evidence.** A basename is the signer's key plus the thing used up, so using the same capability twice links both uses to that signer and never to anyone who only received it.
- **Standing.** Evidence names one credential, but a cheat has many unlinkable ones. A recipient that knows of any cheat asks the sender for its standing: a proof that the sending credential's key is none of the cheats' keys, built from the evidence's (basename, pseudonym) pairs. It is EPID's non-revoked proof: an honest holder proves it without revealing anything else (144 bytes and about 3 ms per listed cheat with Briolette v1), and a cheat can't, under any credential. This stops a cheat wherever the evidence has reached, with no issuer, no list to trust and nothing done to anyone else. A clerk can ask the same before issuing tickets. A cheat's entry can be dropped once every ticket it could hold has expired.
- **Revocation.** A fast, coarse list of revoked groups, each with the epoch it was revoked in, gossiped peer to peer, plus short lifetimes that force a swap. A revoked group always stops the last hop. Earlier in a coin's history it stops the coin only if that ticket was issued within the recipient's window before the revocation (two epochs by default), so coins that passed through a group long before the trouble aren't stranded. The window counts the issuer's own epochs, so an issuer that rolls faster under heavy traffic narrows it in time without a separate setting. An issuer can revoke a whole class of wallets after a class break. Standing replaces the challenge test for keeping known cheats out, and a dispute ruling counts as detected misbehavior.
- **Receipts.** Every transaction commits to one root of salted, nested hashes, with branches for public, parties-only and private details. A leaf can be another receipt's root, so evidence chains without anything going on the ledger.
- **Proof of means.** A zero-value split of the estimated pay proves the poster held the means and commits to the terms receipt. The worker's zero-value split of its time units does the same in reverse.
- **Swapping and escrow.** Both are holders, not kernel operations. A swapper is a convenience so mints don't have to swap: it takes old capabilities by transfer and pays out fresh ones of the same value from its pool, which may come from the mint or from its own turnover, as a grocery store cashes checks. On a double spend, first seen wins, and the loser holds cryptographic proof for a claim.
- **Gossip, an optimization in two tiers.** Nothing depends on it, and gossip never carries transfer records, so it carries no transaction graph. A coin's provenance travels only with the coin, so a holder sees a fork only when a coin meets its own fork.
  - *Compressed (fits one APDU or mesh packet):* hints only. Sequence heads (a short issuer id, the epoch number and a hash prefix, about 20 bytes each) and fork hints (a prefix of a forked coin state's hash). A hint can't be checked, so it never flags anyone, never advances an epoch and never blocks a coin by itself.
  - *Extended (chained APDUs or several packets):* proofs. Signed epochs, including any issuer revocation bitfield for its own tickets, and evidence: the shared basename plus two signatures with the same nym (about 770 bytes with Briolette v1 crypto). Receivers check every signature before keeping anything.
  - *What starts an extended exchange:* a peer advertises a newer or different head for a sequence I rely on, a fork hint matches a coin I'm about to accept or already hold, or we're on a richer link. Otherwise hints just wait.
  - *What a hint may do:* start a request for the proof. As its own policy, a recipient may also hold off accepting that one coin offline until the proof arrives. False hints are bounded: a hint names a coin state, so only someone who has seen the coin can name it; the most it can do is delay that coin; and peers can set a hint budget per peer.
  - Once a proof spreads, the evidence travels without waiting for the issuer's next epoch, and two versions of one epoch expose an equivocating issuer the same way. Whatever someone withholds or delays, a recipient stays at what it already knew.
  - Modeled in [CivicGossip](../formal/CivicGossip.tla) and [CivicTiered](../formal/CivicTiered.tla); bytes and benefit in [gossip\_sim.py](../sim/gossip_sim.py) and [gossip\_tiers\_sim.py](../sim/gossip_tiers_sim.py).
- **Tokenmap, optional.** A holder that keeps what you sync to it: online double-spend detection, and a record of what you held, which makes recovering a lost wallet easier (C9). Syncing is the user's choice. What it publishes is evidence anyone can check, never a verdict.
- **Disclose step by step.** A reply shows only unlinked proofs, one per required certification. Accepting a regulated job anchors a stable identity with its certifications, to the poster only, before any work.

## Roles in detail

What each role must guarantee lives in the presentation, so it never depends on the role behaving. Each role keeps some latitude, on public terms with signed answers.

- **Registrar.** Must hold: every enrollment proof is checkable against the root's public keys, and enrollments are public commitments anyone can recount. Latitude: which roots it accepts.
- **Ticket and epoch issuer.** Must hold: tickets are issued to anonymous requests (signed under a per-class access credential with the epoch as basename, so the issuer learns only the class and a per-epoch count), in a random group per batch that it maps to a class and never to a person, and only for credentials with standing against every cheat it knows of; issuance counts and epochs are public and checkable, and equivocation is a detectable conflict. Latitude: its epoch policy, published.
- **Mint.** Must hold: what is outstanding is publicly checkable against the mint limit. Latitude: what and how much to mint within its right.
- **Swapper.** Never mints and never pays out without taking something in. It may choose whom it serves, as a bank serves its own customers, but the minter can't choose for it, and a refusal that breaks its own terms is evidence.
- **Validator.** Its approval is a signed statement, so approving a double spend leaves its own signature as evidence against its bond.
- **Revoker.** Every revocation cites a public ruling or conflict evidence; one without evidence is itself evidence.

## Profiles

A profile picks standard schemas, sets their parameters and sets wallet defaults for one context.

- **Cash (Briolette).** Value held under tickets from an operator's ticket and epoch issuers. Wallets honor expiry and refuse tickets from revoked groups by default, online validation is a secondary check, maximum-spend tags give velocity limits, and swappers are run by the operator and by large merchants.
- **Boards.** Posting to an online service with pave credentials: a post is a small record binding a content hash, the content lives with the host, endorsements count people once per thread, and the host's receipts make dropping a post visible. Boards are not carried between wallets. The job board and civic reports are boards. See [boards.md](boards.md).
- **Civic work board.** Access credentials from the roots each scope accepts, time minted by workers, certification rights, jobs as scopes, receipts and proof of means, and the root scope's rules that the requester pays at cost and workers never pay to work. Regulated categories require step-by-step disclosure. Test credit only until there is an operator.
- **Parcels.** Packages for a delivery co-op, with custody as a coin: minted from a shipper's parcel budget, handed courier to courier and taken with an acknowledgment only the taker can sign, delivered when the addressee retires it, and paid per hop. A double handoff is a double spend. See [parcels.md](parcels.md).
- **Civic reports.** A board for public reports of problems in the street, useful before any city adopts it. One count per person per issue through endorsements, permits mirrored from the city's published data, rulings enforced by standing. See [boards.md](boards.md).
- **Offline mesh.** One unit per time block, coarse blocks, small offline-transfer limits, posts and proofs that fit a single packet, and epochs and revocation lists gossiped over the mesh. Test credit only.
