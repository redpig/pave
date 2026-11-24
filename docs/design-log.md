# Design log

Decisions behind the current [kernel](../spec/kernel.md) and [protocol](../spec/protocol.md), and why. Newest first within each section.

## Layers

1. **Kernel**: axioms only. Three objects (scope, capability, message), holding, schemas, receipts, five operations, one initial state, six invariants. No corollaries, no roles, no time, no domain words.
2. **Protocol**: corollaries, standard schemas (epochs, expiry, tickets, access credentials, value, time, votes, certification, recovery), core mechanisms, what each role must guarantee, and profiles. Briolette's design generalized: every piece is a capability under a schema.
3. **Profiles**: which schemas a context uses and how they're set (cash, civic work board, offline mesh).

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
- **Expiry across the whole history.** Expiry runs from every ticket in a coin's history, each checked against its own issuer's sequence. A recipient needs each sequence's latest epoch to check it.
- **Composable epochs.** Different capabilities can count different issuers' epochs. There is no shared clock.

## Gossip

- **Gossip is an optimization; nothing depends on it.** It never carries transfer records, so it carries no transaction graph.
- **Two tiers.**
  - *Compressed:* hints only (sequence heads and fork hints), sized to fit one APDU or mesh packet.
  - *Extended:* proofs (signed epochs and evidence), fetched per hint, have/want style.
  - A hint never flags anyone or moves an epoch. A recipient may choose to hold off one coin offline while an unproven fork hint names it.
- **Evidence.** The shared basename plus two signatures with the same nym. With Briolette v1 crypto it is about 770 bytes, so it travels only in the extended tier. It names the forked coin and its ticket, not the cheater's other coins.
- **Tokenmap stays, as an optional role.** Syncing to it records what you held, which helps recovery, and gives online double-spend detection. What it publishes is evidence, never a verdict.
- **Issuer revocation bitfields still work per issuer,** for that issuer's own tickets, carried in its signed epochs. They are no longer the only revocation channel.

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
