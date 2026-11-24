# Civic Fabric Kernel v0

Draft, November 2026

The axioms every implementation must hold. How it's met is on the mechanisms page; what gets built when is in the plan.

## Objects

| Object | Does one thing | Recurses by |
| --- | --- | --- |
| **Scope** | Sets rules: who may send to it, which schemas from which roots count in it, and how long it lasts | Nesting; a child is never looser than its parent |
| **Capability** | Grants a right under a schema: a shared one to act, an exclusive one to a resource | Deriving narrows a shared one; splitting and merging divide an exclusive one |
| **Message** | Carries a signed statement, and any capabilities it transfers, to a scope or a credential predicate | Committing to receipts, which can be other messages |

Every capability is held under a credential, itself a capability: a fresh randomized one, which is unlinkable, or a stable one the holder chooses to keep. Nothing nests deeper, a capability is usable only while the credential it's held under is valid, and scopes hold nothing.

A schema is a capability's operation rules, chosen from a closed menu: divisible or not, a soft and a hard expiry, how many offline transfers it may make before it must be swapped, and how much one holder may have. A schema is data, not code. Anyone may publish one, and it never says who may accept it: each recipient chooses which schemas and roots it accepts. Scope rules come from a closed menu too, so the kernel checks signatures and settings and never runs code. It keeps no time: expiry, epochs and the sequences that count them are schemas on the protocol page, and honoring them is each recipient's choice.

Every message commits to its receipts through one root of salted, nested hashes. The receipts stay with the parties, and any branch can be revealed later without revealing the rest.

## Operations

- **Scope:** create a child.
- **Capability:** derive a shared one, leaving the original with its holder; mint an exclusive one under a mint right; transfer, which moves it to be held under another credential; split and merge, including a zero-value split; retire.
- **Message:** send.

A kernel starts with one root scope and one **rooting capability**: the right to create the first scopes and capabilities, not to change them afterward. Anyone can run a kernel, and each participant chooses which kernels' roots to trust, and for what. Every input is signed. There is no global order: records made apart, even offline, merge later.

## Invariants

1. **Conservation:** exclusive capabilities are never duplicated. They're minted only under a mint right, within its limit on what is outstanding; splitting or merging keeps the total, and retiring removes it from what is outstanding.
2. **Consent:** an exclusive capability moves only by its holder's signature, and a message reaches a holder only under a capability that holder granted or by spending an exclusive capability.
3. **Minimal disclosure:** a presentation, including one to a role, reveals only the rights it carries and, where a scope requires one, a stable pseudonym for that scope. Uses are unlinkable unless something is used more often than allowed, no one is identified except by an outside legal process, and there is no master unmasking key. Receipts are revealed only branch by branch, by their parties.
4. **Transparency:** every scope's rules, every mint and every transfer are public, as a receipt root and its public branch. Personal data stays off the ledger.
5. **Fixed at creation:** a scope's rules and a capability's schema, rights and settings are set when it's created. Afterward an ancestor keeps only what it reserved then, such as expiry or revocation, and nothing can change what is above it.
6. **Detectable conflict:** a holder using the same exclusive capability twice always produces evidence linking both uses to that holder, whenever the records merge, and never implicates anyone who only received it.

Everything else is built from these, including the roles the fabric runs on (registrars, ticket and epoch issuers, mints, swappers, validators and revokers, each just a holder of particular capabilities). The corollaries that follow from these axioms, the standard schemas and the profiles are on the [protocol](protocol.md) page; implementation detail and patterns such as jobs, escrow, votes and hosting are on the mechanisms page. The fabric's own policies, such as "the requester pays, at cost," "workers never pay to work" and "no fee on a fee," are rules of its root scope. When the plan's lock gates pass, the kernel is real.
