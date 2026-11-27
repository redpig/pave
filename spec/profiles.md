# Profiles as data

A profile can be published as a description that an app loads and acts on, with no code for that profile in the app. One wallet can then carry parcels, post to boards or collect a vote coin for any town or co-op that publishes the profiles it runs.

This works because of one property of pave: **every binding and receipt is CBOR.** A manifest, a post binding, a handoff receipt are `hash_of(domain, value)` over a CBOR encoding. A description that gives the exact layout lets an app build the same CBOR, and so compute the same hashes as the profile's own code.

The interpreter is [`board/src/profile.rs`](../board/src/profile.rs). The parcel core is described in [`profiles/parcels.json`](../profiles/parcels.json). [`board/tests/profile.rs`](../board/tests/profile.rs) runs it: wallets acting from the description and wallets running the Rust profile carry one parcel between them, read the same custody, and the Rust shipper pays the couriers.

## What a profile describes

| Part | Says | Example (parcels) |
|---|---|---|
| `schemas` | Each kernel schema the profile uses, and what a state of it means | `parcel`: a package in someone's custody |
| `layouts` | Each structure it hashes: a hash domain and typed fields, a CBOR map in field order | `manifest`, in `pave/parcel/manifest` |
| `receipts` | Each receipt: a domain and parts. One part hashes the value itself; more hash the array | `handoff` = hash_of(`pave/parcel/handoff`, [manifest hash, hop]) |
| `actions` | Each kernel operation a participant can take: the state it consumes, the operation, its target, its receipt, and what must hold first | `mint`, `hand_off`, `take`, `confirm` |
| `walks` | How to read a state's history back as named steps, by matching each transfer's receipt | `custody`: handoff, take, …, retired |
| requests | How to ask a mint for something. Already data: a [`RequestSpec`](../board/src/request.rs) and a body | refills, post tokens, check-ins |

### Types

Fields and parameters are typed: `hash` (32 bytes), `credential`, `text`, `u32`, `u64`, `{"opt": T}` (null when not given), and `any` (a value the caller builds, such as an enum). A field may have a JSON `default`. The interpreter refuses a value of the wrong type.

### Expressions

Receipts, action states and predicates compute values from:

| Expression | Value |
|---|---|
| `{"param": "manifest"}` | A parameter the caller gives |
| `{"field": {"of": E, "name": "parcel"}}` | A field of a map |
| `{"hash": {"layout": "manifest", "of": E}}` | The hash of a value under a layout's domain |
| `"hop"` | The hop in context: the state's hops plus the action's `hop` offset, or the hop a walk is at |
| `"holder"` | The key holding the state an action is about to use |

### Actions

| Key | Values |
|---|---|
| `state` | `{"held": {"origin": E}}`: an unspent state this wallet holds with that origin. `{"budget": {"schema": S}}`: a mint budget of schema S this wallet holds |
| `op` | `{"transfer": {"to": T, "receipt": R}}`, `"retire"`, or `{"mint": {"to": T}}` (one unit; the change stays with the budget's key) |
| target `T` | `{"param": name}`, or `"fresh"` for a fresh ticketed key of this wallet's |
| `hop` | Offset added to the state's hops for `"hop"` in the receipt |
| `requires` | Predicates checked first (below) |
| `check` | Run the ordinary acceptance check on the state first, as a recipient does |
| `trust` | Clerks the check also trusts, each `{"clerk": E, "sequence": E}`; skipped if either is null |

A target may also be `{"key_from": {"clerk": E, "sequence": E}}`: a key of this wallet's with a ticket from that clerk, such as a dispatch's shift key, or a fresh key if either is null. A target of `"holder"` keeps the state on the key already holding it, as the food profile's take does so custody stays on the courier's badge.

### Predicates

They are general, not per profile:

| Predicate | Holds when |
|---|---|
| `{"created_with": {"receipt": R}}` | The state was made by a transfer with that receipt, evaluated at the state's hops |
| `{"holder_is": E}` | The state's holder is that credential |
| `{"equal": [E, E]}` | The two values are equal |
| `{"any_of": [P, …]}` | Any of them holds |
| `{"if_present": {"value": E, "then": P}}` | The value is null, or P holds: for optional parts such as a dispatch |
| `{"ticket_from": {"key": E, "clerk": E, "sequence": E, "purpose": E?}}` | The key holds a ticket this wallet knows from that clerk on that sequence, tagged for the purpose if one is given, that checks out and whose group the sequence hasn't revoked |
| `{"lineage_current": {"lineage": E, "generation": E}}` | The lineage coin hasn't moved past that generation, and none of its states was used twice: the token isn't void |

A field of a null value reads as null, so a description can reach into optional structures (the manifest's `dispatch.clerk`) and guard them with `if_present`.

Every action is one kernel operation, signed by the state's holder and guarded by the wallet's signing log. So an action from a description can't do anything the kernel wouldn't allow.

## How an app uses one

1. Load the description and check its name and version.
2. Show the actions, with their docs and parameters.
3. Build layouts from what the user enters. The interpreter type-checks each field.
4. Run actions. Each produces one record, which the app sends the same way as any other.
5. Read walks to show where things stand: a parcel's custody, a job's status.
6. Compute receipts, to show what a payment or handoff commits to.

## Publishing and finding profiles (not built)

A town or co-op publishes each description as a post on a registry board, with the content hash as its id. The posts are signed under a capability the town derives from its root for that purpose. An app reads the registry, checks the posts' records as any board reader does, and loads the descriptions. A profile's name and version, and the version in each domain string, let two versions run side by side.

## What can't be described yet

With the general predicates, the parcel description covers dispatch gating and void tokens after a remint: the test hands a dispatched parcel only to shift keys, takes it under one, and refuses a reminted token, all from the description. What's left is logic over many records, or several operations at once:

- reminting itself (a lineage move, a mint and a handoff together, and a board note);
- which couriers get paid;
- board message validity (only the poster accepts);
- counting tags, tallies, and dispute windows and rulings.

These stay in profile code for now. The plan for them:

- **Grow the predicates first.** Most rules turn out to be general (a ticket from a clerk, a lineage that hasn't moved), and a general predicate serves every profile.
- **Keep the rest where the profile runs.** Rules over many records stay in the profile's own code at its servers, and in untrusted page code where they only advise.
- **A WASM sandbox in the wallet is the fallback, not the plan.** [web.md](web.md) puts the wallet in the user agent with the web's sandbox around provider pages; a pinned module would only be needed for a rule every party must evaluate that no predicate can express.

Until then, a description covers the part of a profile that moves things, checks who may receive them, and reads their history. [web.md](web.md) considers where such rules would run if the kernel were a web platform API, instead of a sandbox of pave's own.
