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

### Actions

| Key | Values |
|---|---|
| `state` | `{"held": {"origin": E}}`: an unspent state this wallet holds with that origin. `{"budget": {"schema": S}}`: a mint budget of schema S this wallet holds |
| `op` | `{"transfer": {"to": T, "receipt": R}}`, `"retire"`, or `{"mint": {"to": T}}` (one unit; the change stays with the budget's key) |
| target `T` | `{"param": name}`, or `"fresh"` for a fresh ticketed key of this wallet's |
| `hop` | Offset added to the state's hops for `"hop"` in the receipt |
| `requires` | Predicates checked first: `{"created_with": {"receipt": R}}` (the state was made by a transfer with that receipt, evaluated at the state's hops); `{"holder_is": E}` |
| `check` | Run the ordinary acceptance check on the state first, as a recipient does |

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

Some rules aren't one operation with a receipt check. They're logic over many records:

- dispatch gating (a key must hold a dispatch's shift ticket);
- remint rules (a token behind its lineage is void; two remints of one generation are evidence);
- which couriers get paid;
- board message validity (only the poster accepts);
- counting tags, tallies, and dispute windows and rulings.

These stay in profile code for now. The plan for them:

- **Rules as pure functions.** Each is a function from records, tickets and parameters to a verdict, with no I/O. That's true of every rule above: they're already written that way in the Rust profiles.
- **Compiled to WASM, pinned by hash.** A description names a rule as `{"rule": {"module": <code hash>, "fn": "dispatched"}}`. An app runs it in a sandbox with no host functions beyond reading the records it's given. The hash pins the exact code: this is the toolkit's code-bound identity, so a profile's rules can be audited and versioned like its layouts.
- **Predicates and walks can call rules.** A rule is just one more kind of predicate, so actions and walks stay declarative around it.

Until then, a description covers the part of a profile that moves things and reads their history. That's enough for an app to carry a parcel, but not to decide whether a dispatched one may be handed to someone.
