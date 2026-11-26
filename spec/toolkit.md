# Toolkit

Pave's applications (the job board, civic reports, parcels, disputes) are built from a few patterns. This document defines each pattern as a composition of what the kernel offers, so that bringing up a new application is assembling known parts, and so that the kernel doesn't grow every time an application wants something.

**The rule.** A pattern adds no object types of its own. If a pattern seems to need one, either it can be expressed in kernel terms after all, or the kernel is missing something, and that is a kernel decision made on its own merits, not inside an application.

There are three layers:

1. **Kernel offerings**: the only primitives.
2. **Protocol services**: what every town runs, built from kernel offerings.
3. **Toolkit patterns**: building blocks for applications, each defined from the two layers above.

The last section lists where the code doesn't yet match these definitions.

## 1. Kernel offerings

From [`kernel/`](../kernel) and [kernel.md](kernel.md).

| Offering | What it is |
|---|---|
| **Credentials** | A scheme's randomizable group credentials. A signature shows membership in the group, nothing more. A credential kept and reused is stable; a fresh one is unlinkable to the last. |
| **Basename signatures** | A signature with a basename yields a pseudonym: the same for one holder and one basename, unrelated across basenames. Two uses of one basename by one holder are linkable. |
| **Scopes** | Places records are sent to, created under a shared capability with `create-scope`, with rules: who may send (`senders`: a capability to present), which schemas count, and a lifetime reference. A child is never looser than its parent. |
| **Shared capabilities** | Rights held by a credential, narrowed with `Derive` and presented when sending. |
| **Schemas and budgets** | A schema says how a kind of value behaves (divisible, expiry references, transfer limits). `IssueBudget` creates a mint right for one; `Mint` spends it. |
| **Exclusive states** | Coins: `Transfer`, `Split` (zero-value parts prove possession), `Merge`, `Retire`. Each use of a state is a basename signature on that state, so using it twice is a conflict. |
| **Conflicts and evidence** | Two records using one state are evidence against the signer, linkable to the signer's group, from the records alone. |
| **Receipts** | The hash every `Transfer`, `Split`, `Merge` and `Send` commits to. Whatever the receipt commits to (terms, a statement, a content hash) is fixed by the signature. |
| **Sends** | A record sent to a scope, with a body, a receipt, and a capability presented if the scope requires one. |
| **Views** | A node's set of records, applied and checked. There is no time in the kernel. |

## 2. Protocol services

From [`protocol/`](../protocol) and [protocol.md](protocol.md). Every town runs these.

| Service | Built from |
|---|---|
| **Epochs (the clock)** | An indivisible coin its issuer holds. Each roll is a `Transfer` whose receipt commits to the epoch's data, so two epochs at one number are a conflict. Time in pave is epoch numbers. |
| **Classes and anonymous refills** | Access credentials from a per-class issuer; refills are basename signatures with (sequence, epoch) as basename, so each person asks a bounded number of times per epoch. |
| **Tickets** | A clerk's signature binding a holding credential to an epoch and a revocation group. (A signed protocol object, not a kernel record.) |
| **Standing** | A proof that a credential's holder is none of a list of pseudonyms, without saying who it is. Lists come from conflicts (double spenders) or from any ruling a profile makes. |
| **Network access** | Every service a node exposes opens with a challenge. The client signs it with a fresh randomization of its access credential, with (service, epoch) as basename, so the service learns only the class and a pseudonym that changes per service and per epoch. It counts and can bar that pseudonym for the epoch. The same access credential and signing as refills, with another basename. |
| **Gossip** | Carrying records, epochs and evidence between nodes that meet, offline if need be. |

## 3. Toolkit patterns

Each pattern: what it is for, what it is built from, and who uses it today.

### Value and custody

| Pattern | For | Built from | Used by |
|---|---|---|---|
| **Payment** | Paying for something specific | `Transfer` or `Split` whose receipt commits to what it pays for (a job, a parcel hop, a panelist) | Job board, parcels, disputes |
| **Proof of means** | Showing you hold enough, without paying | A zero-value `Split` part to yourself, its receipt committing to the terms | Job board |
| **Custody token** | Something one party holds at a time and hands on, offline | A schema (indivisible, a transfer limit) minted from a budget; handing on is `Transfer`, acknowledging is a `Transfer` to yourself, finishing is `Retire`. Handing it to two people is a conflict | Parcels |
| **Vouch** | A reputational commitment that rides on real payment | A zero-value `Split` part to the paid party, the payment's receipt committing to the statement | Job board |
| **Escrow** | Holding value until something is decided | A coin transferred to a holder's credential, the receipt committing to the terms; the holder retires it and pays out. The holder is trusted; see code-bound identity for the stronger form | Disputes |
| **Code-bound identity** *(not built)* | Escrow, a swapper or any program whose behavior is fixed in advance | A shared capability, derived by an attestor to a credential, whose right names a code version. Paying a coin to that credential with the capability presented binds the payment to the code. Trust moves to the attestor, explicitly | Escrow, the swapper |

### Speaking and counting

| Pattern | For | Built from | Used by |
|---|---|---|---|
| **Board** | Content with an audience: posts, listings, reports | A clerk. A board mint (a capability to issue a post-token schema, derived from the root) tickets and mints tokens on anonymous requests, like refills. A post is the token's `Transfer` to a board server, its receipt the hash of the binding (board, kind, thread, content hash, prior post, the server's epoch and clock); the server takes it by `Retire`. Ordinary wallets don't accept the schema and servers do, so one mint serves many boards and servers. The content stays with the server; copies serve posts with their records and readers check them | Job board, reports, disputes |
| **Counting people** | One count per person, without names | A token request also signed by the access credential with the purpose as basename; the mint puts the pseudonym in the tickets' tag. The purpose sets the scope of linkage: per thread (one count per issue), per counterparty (a record with one party) | Reports, vouches, dispute records |
| **Ruling someone out** | Stopping a pseudonym from counting again without unmasking it | Its tag on the mint's list, against which every token request needs access-credential standing; its ticket group revoked at the next roll | Reports |
| **Identity tiers** | Choosing how identifiable to be | A stable credential shared with chosen people; signing a binding with it. A wallet keeps one per tier (close, contacts, public); none is anonymous | Any post |
| **Records** | Reputation from what happened | Counting pseudonyms over posts and outcomes | Vouches, dispute records, arbiter scores |

### Proving later

| Pattern | For | Built from | Used by |
|---|---|---|---|
| **Commit and reveal** | Fixing something now, showing it later | A salted hash in a receipt or a binding; opening it is showing the salt and the thing | Parcel codes and drop photos, evidence originals |
| **Sealed material** | Something only some may see | A board post of its hash; the material itself with a host that hands it only to requests signed by a credential the profile names (a panelist's, a party's) | Evidence |
| **Disputes** | Settling a disagreement | Posts on a board; arbiters offering under stable credentials; a panel drawn by hash; rulings as posts; appeals paid into escrow; records counted per counterparty | Parcels, any subject |

## Bringing up an application

To bring up an application, pick a board for what people say, a schema for anything held one at a time, and the patterns above for paying, counting, proving and settling.

## Where the code doesn't match yet

- **One mint, one server.** The design has a board mint and any number of servers; the prototype's town runs both, and its mint's list takes rulings only from the reports board.
- **Tags are a ticket field.** `Ticket::tag` is a protocol addition: the clerk's word for a per-purpose pseudonym, trusted as tickets are.
- **Generic patterns live inside profiles.** Escrow and counterparty terms are in `board/src/dispute.rs`; commit and reveal is split across `parcel.rs` and `evidence.rs`; sealed material and parcel-specific evidence kinds share `evidence.rs`.
- **Escrow's holder is the town.** That is a trusted holder, stated as such; code-bound identity is not built.
- **Tickets are signed protocol objects**, not kernel records.
