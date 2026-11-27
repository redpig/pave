# Threat model

This document lists the attack surface of every component in pave, the attacks on each, and how each is prevented or reacted to. It also compares each one with Briolette, whose design documents, security model and audit were the baseline. Every Briolette attack has a row here.

## How to read it

Each component has its attack surface, then a table of attacks.

- **Prevent** is what stops the attack before it succeeds. **React** is what limits the damage, detects it and responds once prevention fails or isn't possible (offline, a double spend can only be detected).
- **Briolette** is the baseline mitigation.
- **Status** is where pave stands today:
  - **Built**: in the code and covered by tests.
  - **Modeled**: in the spec, a TLA+ model or a simulation, but not yet in code.
  - **Fixed**: a bug this audit found and fixed.
  - **Gap**: missing.
  - **Bug**: wrong in the code today.
- **+** marks where pave does better than Briolette. **−** marks where it does worse.

The ranked list of gaps and the decisions taken on expiry and revocation are at the end.

## Adversaries

| Adversary | Wants | Can |
|---|---|---|
| Dishonest holder | Spend the same value twice, or take value without consent | Run modified software, roll back its own state, go offline, collude |
| Sybil | Many identities, for limits, reputation or votes | Enroll many devices or keys |
| Class breaker | Clone value at scale | Extract keys from every device of one model (a secure element bug plus a phone exploit) and enroll fresh identities from it |
| Thief, finder of a lost device | Spend the victim's value | Physical access, with time |
| Malicious relay, point of sale or phone | Redirect, misreport or withhold | Sit between two holders, show its own screen |
| Network attacker | Link people, censor | Eavesdrop, drop, delay, partition, eclipse a holder |
| Dishonest role | Inflate, censor, deanonymize, frame | Run the registrar, clerk, mint, swapper, validator or recovery service, or several at once |
| Coop insider | Pay itself, change rules quietly | Hold operator keys |
| Cryptanalyst | Forge or link | Break the curve or the scheme, now or later (quantum) |
| Spammer, denial of service | Exhaust people or services | Send junk, flood requests |

What we assume:
- The signature scheme is sound and anonymous.
- At least one honest path eventually connects any two holders.
- Each recipient picks its own roots and policy.

We do not assume that any role behaves well (principle 10), that devices are tamper-proof, or that anyone is online.

## Components

1. Kernel: records, views and evidence
2. Credential scheme
3. Holder wallet and keys
4. Registrar and enrollment
5. Clerk: tickets and epochs
6. Mint and budgets
7. Acceptance: the recipient's policy
8. Gossip and relays
9. Peer link
10. Validator, swapper and holder sync
11. Recovery
12. Boards and the job board
13. Operator state and role keys
14. Payment bridge and redemption
15. Cross-cutting: the class break
16. Civic reports
17. Parcels
18. Disputes

---

## 1. Kernel: records, views and evidence

`kernel/src/view.rs`, `objects.rs`, `invariants.rs`

**Attack surface:** every record and evidence object received from anyone (`apply`, `merge_from`, `import_evidence`); schema and scope definitions; the CBOR decoder.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| K1 | Spend another holder's coin | A transfer needs a signature by the coin's holder credential (invariant 2) | n/a | Same, through the ECDAA chain | Built |
| K2 | Create value by split, merge or mint | Every record conserves amount and kind (invariant 1); a split is one record, so its sum is checked offline by every recipient | n/a | Each half shows only `split <= original`; only the tokenmap sees the sum (audit H-5) | Built **+** |
| K3 | Double spend offline | Not preventable offline | First seen wins. When two records consume one state under one signer and pseudonym, any view that holds both makes evidence (invariant 6). The evidence verifies on its own and travels anywhere (about 770 B) | Only the tokenmap sees the fork, once both copies are uploaded | Built **+** (proptest over partitions; CivicSequences) |
| K3a | After being caught, keep spending other coins held under unlinkable credentials | Standing: once a recipient knows of a cheat, the sender proves its key isn't the cheat's (EPID's non-revoked proof, 144 B and about 3 ms per listed cheat). The cheat can't, under any credential | n/a | Revoke the cheat's ticket groups in a later epoch, which also hits everyone else in those groups until they pass the challenge test | Built **+** (mutations `nostanding`, `identityproof`) |
| K4 | Frame an honest holder with fake evidence | Evidence needs two valid signatures with the same basename and pseudonym, which needs the holder's secret key | `no_false_flag` invariant | Non-frameability, provided the issuer never learns the secret key | Built; see S2 |
| K5 | Blame the recipient instead of the cheat | Evidence names the signer's pseudonym, never the recipient | n/a | Same | Built (mutation `flagrecipient`) |
| K6 | Change a schema's rules after minting | A schema's id is the hash of its settings (invariant 5) | n/a | Token descriptor fixed by the mint signature | Built |
| K7 | Replay a record elsewhere | Records bind the exact states they consume; a replay is the same record and is a no-op | n/a | `previous_signature` chaining | Built |
| K8 | Hide an earlier spend by not sharing it | n/a | Detected when any holder of the other copy meets any holder of this one | Detected at the tokenmap | Built (`cheat` in the demo) |
| K9 | Issuer equivocation: two different successors to one epoch | An epoch is a sequence capability, so two rolls from one epoch are a double use | Evidence, exactly as for a double spend | Signed epochs compared out of band; an optional secondary signature | Built **+** (CivicSequences) |
| K10 | Malformed or huge input that panics or exhausts a node | Typed CBOR decoding; a 64 MiB frame cap | n/a | Audit M-7 (panic on currency mismatch) | Gap: no-panic audit and fuzzing of `apply`, `absorb` and the scheme adapter, plus per-object size caps |
| K12 | Every minted coin's provenance includes its mint budget's chain, one record per earlier mint, so a first payment between strangers grows with the town's issuance | n/a | Payees usually hold most of the chain already, and only missing records travel | The mint key's signature anchors each token | Gap: budget checkpoints (an anchor the root signs, or a recipient trusting mints it has seen) |
| K11 | History growth until coins are too big to move | `offline_transfers` caps hops per schema | Swap for a fresh coin | Maximum provenance length plus swap; ZK compression proposed | Built (cap and swap); Gap: compression |

---

## 2. Credential scheme

`schemes/briolette`, using Briolette v1 ECDAA over BLS12-381

**Attack surface:** credential issuance (join); randomization; signing with and without a basename; verification of untrusted signatures and credentials; the pseudonym.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| S1 | Link a holder's uses | A fresh randomized credential per holding and per role; the pseudonym exists only for one basename | n/a | Same; randomized tickets | Built (`holdings_are_unlinkable_but_reuse_links`); ticket groups leak, see C3 |
| S2 | The issuer frames a member or signs as one | The member generates its key and sends only a public key with a proof of its secret; the issuer issues on that, and the member checks the credential is bound to its key | n/a | Wallets generate their keys; the split-key join still rebuilt the combined key on the host | **Fixed** in this audit. Previously `Issuer::enroll` generated every member key, so the registrar could forge evidence and spends |
| S3 | Forge a credential without the issuer | Unforgeability (q-SDH / LRSW) | n/a | Same; the implementation is custom (audit I-6) | Inherited; Gap: external review of the implementation and a proof for the exact composition |
| S4 | An issuer mints rogue credentials for Sybils | Not cryptographically preventable | Rogue credentials sit under that issuer's group key. Recipients drop the key, and evidence clustered in one group points to it | Attestation provider registry with stake and slashing; tiered NAC keys | Gap: per-registrar and per-class group keys; enrollment receipts |
| S5 | Cryptanalysis or a quantum computer: forgery, or linking past histories | `Scheme` is a trait and schemas name their scheme, so a scheme can be swapped without changing the kernel | Roll to a new scheme by epoch; expiry retires old coins | Post-quantum fallback registration recommended | Modeled (trait); Gap: a post-quantum or hybrid scheme. Histories recorded today can be linked once discrete log falls |
| S6 | Timing side channels | v1 hashes to the curve in constant time (RFC 9380) | n/a | Audit M-5 (v0 was not constant time) | Inherited |
| S7 | Reuse a signature in another context | basename = the consumed state; message = the record; v1 domain separation | n/a | Same (I-9) | Built |

---

## 3. Holder wallet and keys

`board/src/node.rs`, the `.pave` state file, and later a secure element

**Attack surface:** the state file at rest; the process memory; the control channel (stdin JSON); the display a person trusts; backups and restores; the agent or script driving the node.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| W1 | Steal keys from the device (malware, theft, backups) | Keys in a secure element or keystore; split key between phone and card; PIN | Recovery; group revocation | Same; audit M-3 found plaintext JSON | Partial: the state file is sealed (XChaCha20-Poly1305) under a keystore key; the repo's keystore is a 0600 file beside it. Gap: platform keystores ([phone-keys.md](phone-keys.md)) |
| W2 | Roll back or restore state, then sign a basename again | The device signs each basename once, with anti-rollback storage (monotonic counter or Merkle root) | Evidence, then revocation | Credstick bloom filter, and swap authorization for false positives | Built: the signing log, saved before a signature leaves, and the state sealed under a key that rotates every save, so a rollback-resistant keystore makes an old copy unopenable. Software keystores still allow a restore of both files; evidence is the backstop there. Gap: platform keystores and a split key with a card |
| W3 | Clone the wallet and spend in parallel | As W2 | Evidence on first meeting; revocation | Tokenmap | Built (detection); prevention as W2 |
| W4 | A relay, point of sale or app shows one amount and asks the key to sign another | The signing device shows the amount it is about to sign (a trusted display) | n/a | Credstick e-ink shows the amount from the APDU | Gap: there is no hardware signer yet. The node signs exactly what its command says |
| W5 | Pocket attack: a reader signs without the person knowing | PIN or button between taps above a threshold | n/a | PIN between taps; amount threshold; attempt limits on a hardware counter | Gap |
| W6 | An agent driving a node exceeds its authority | A spending cap the node enforces, below the agent | Spend history in receipts | n/a (no agents) | Gap: per-session caps, or a sub-wallet funded with only what the agent may spend |
| W7 | Running out of tickets offline, so the holder can't receive | Prefetched pool | Refill when online | Same | Built |
| W8 | Reusing a credential, which links holdings | A fresh credential per holding, change and role | n/a | Same | Built |
| W9 | A lost or destroyed wallet | n/a | Recovery (section 11) | Opt-in recovery binding | Gap |
| W10 | An interrupted payment: signed but never delivered | The payer keeps the signed record pending until the payee's signed acknowledgment; `resume` resends the same record and the payee acknowledges it again; the signing log refuses any other use of the coin | Evidence if the holder later re-signs | Deferred payments mark tokens `PENDING_SEND` | Built |

---

## 4. Registrar and enrollment

`Issuer`, `pave-node join`, `enroll` and `finish`

**Attack surface:** the join request; attestation, which doesn't exist yet; the registrar's group secret key; the link between a person and their enrollment.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| R1 | Sybil enrollment | Hardware attestation; rate limits per attestation key; lower assurance gets tighter limits (principle 18) | Revoke a class or group | Tiered NAC (low, medium, high); `Algorithm::NONE` online-only; `--require-attestation` | Partial: classes with their own access issuers and ticket terms are built; Gap: attestation decides the class. Today the operator enrolls whoever it is told to. Test credit only (principle 24) |
| R2 | Class break: a whole device model's keys extracted | See section 15 | See section 15 | NAC tier ↔ randomized ticket groups; class revocation; challenge test | Built (containment); see section 15 |
| R3 | Impersonate a service (registrar, clerk) | Services authenticate to wallets; genesis pins the root | n/a | Service identities from deterministic nonces (audit H-3, fixed) | Partial: genesis and the clerk credential are pinned in `Town`; Gap: authenticated service endpoints |
| R4 | The registrar or clerk links a person to all their tickets | Anonymous ticket requests, signed with a fresh randomization of a per-class access credential and basename = epoch, so linkable only within one epoch; a random group per batch, mapped to a class and not to a person; enrollment tickets cover only the minted credit | n/a | NAC signatures with epoch basenames; randomized groups mapped to a NAC group | **Fixed** in this audit. Previously each wallet had one sequential group, and refills were signed by its own ticketed credentials, so the clerk could link all of a wallet's tickets to its enrollment |
| R5 | The registrar's key is compromised | Offline or HSM key | Rotate the group key by epoch data; drop the old key | Repeated key fields in epoch data (audit L-2) | Gap |
| R6 | A registrar refuses someone (exclusion) | Many registrars; each recipient chooses roots (principles 9 and 12) | n/a | One operator trust list | Modeled **+** |
| R7 | The holder side accepts a bogus credential | `finish` checks the credential is in the group and bound to the holder's key, and that every pooled credential signs | n/a | n/a | Built (Fixed with S2) |

---

## 5. Clerk: tickets and epochs

`protocol/src/epochs.rs`, `tickets.rs`

**Attack surface:** ticket requests; the clerk key; epoch rolls and their data (revoked groups); ticket policy fields (epoch, group, `max_spend`).

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| C1 | Show different revocation lists to different people | A roll is a transfer of the sequence capability, so two rolls from one epoch are a double use | Evidence | Gossip comparison | Built **+** |
| C2 | Suppress a known revocation | Evidence is public and verifies on its own; each recipient refuses known cheats and asks for standing, whatever the clerk publishes | A signed epoch plus older evidence it ignores is proof of suppression | Optimistic challenge with stake; relays sign what they serve | Built (recipients refuse independently) **+**; Gap: a suppression-proof format |
| C3 | Ticket groups link holders | Random group per ticket batch out of 4096 (Briolette allows up to 32768), mapped privately to a class | n/a | Randomized groups | **Fixed** (see R4) |
| C4 | Ticket flooding: endless receiving addresses | Requests carry at most 16 credentials; a wallet's first 4 an epoch are unlinkable, and every later one is linked to an earlier one (slotted basenames, as Briolette's) | The clerk sees one holder making many requests and can act on it | NAC basename = epoch; per-NAC ticket budget | Built (mutations `refill_slot_bound`, `wallet_wrap`); Gap: a policy for heavily linked holders, and per-class budgets |
| C4a | A caught cheat gets fresh tickets | Every requested credential needs standing against every cheat the clerk knows of | n/a | Challenge test: sign the cheat's earlier request basename and show a different pseudonym | Built **+**: standing reveals nothing, while a challenge answer can link an honest wallet's requests across epochs |
| C5 | Replay an old epoch as current | The head is the longest valid chain of rolls, so an older epoch can't replace a newer one | n/a | Epoch monotonicity | Built |
| C6 | A holder stays offline to dodge revocation | A sender's ticket past `soft_expiry` is refused, and every coin dies at `hard_expiry` from its mint-time ticket | n/a | Elastic ticket lifetimes (short, medium, long); `T_evict = T_detect + 1 + D + T_life`; refresh | Built (per schema); Gap: per-ticket elastic lifetimes and refresh |
| C6a | An accomplice with a fresh ticket carries a coin held on a stale one onward | Bounded by hard expiry and the hop cap | Revocation within the window | Same exposure | Accepted, as in Briolette (decision D1) |
| C7 | The clerk key is compromised | Offline signing of rolls; separate keys for tickets and epochs | Rotate keys through epoch data; trust in the old key ends with the roll | Repeated key fields; the state key can be air-gapped | Gap: rotation |
| C8 | The clerk refuses tickets to someone | Several clerks and sequences; recipients choose (principle 9) | n/a | One clerk | Modeled |
| C9 | Spend more than the ticket allows | `max_spend` on tickets, set from the class's terms; recipients check the sender's and holder's tickets | Server-side velocity sums | `max_spend`; velocity | **Fixed** (mutation `nocap`); Gap: velocity |
| C10 | Revocation strands honest holders downstream | A revoked group always stops the last hop, but earlier hops only if their ticket was issued within the recipient's window (2 of the issuer's epochs by default) before the revocation | Swap for a fresh coin | Within a revocation epoch window only | **Fixed** (decision D2; mutation `nowindow`) |
| C11 | Expiry applied to the whole history caps a coin's life | Soft expiry on the last hop only; hard expiry from the mint-time ticket | n/a | Current ticket only, plus token `valid_until` | **Fixed** (decision D1; mutations `softall`, `nohard`). `hard_expiry` was previously never enforced |

---

## 6. Mint and budgets

**Attack surface:** mint keys; budget capabilities; who trusts which mint.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| M1 | Over-mint beyond the authorized supply | Minting consumes a `MintBudget` capability, and conservation covers budgets | n/a | The mint key is unlimited; the supply cap is central policy | Built **+** |
| M2 | A mint key is compromised | Loss is bounded by the budget the key holds | Coins carry their origin; recipients drop that budget's coins | Rotate the mint key | Built (bounded); Gap: rotation |
| M3 | Double mint from one budget offline | n/a | Evidence, as for any spend | n/a | Built **+** |
| M4 | Unknown or private mints (points, IOUs) | Each recipient chooses which roots it accepts | n/a | Wallets may trust non-operator mints | Built |
| M5 | The mint learns the first recipient | Mint to a fresh credential | Self-transfer or swap before spending | Same | Built (fresh credential) |

---

## 7. Acceptance: the recipient's policy

`protocol/src/accept.rs`

**Attack surface:** every coin and history offered as payment; the recipient's knowledge (tickets, epoch data, hints); the payment handshake.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| A1 | Pay with a coin held under an unticketed or foreign credential | Every credential in the history needs a valid ticket from a trusted clerk | n/a | Credential ↔ ticket binding | Built |
| A2 | Pay with an expired coin | Soft expiry on the last hop, hard expiry from mint, each per sequence | n/a | See C11 | Built (mutations `ignoreexpiry`, `softall`, `nohard`) |
| A3 | Exceed the offline hop limit | `offline_transfers` | n/a | Maximum provenance | Built (mutation `nolimit`) |
| A4 | Pay with a coin from a known cheat | `refuse_known_cheats` for the named credential; standing for every other credential (K3a) | n/a | Revoked groups only, after the next epoch | Built (mutations `ignoreevidence`, `nostanding`) **+** |
| A5 | Pay before the recipient knows a revocation | The handshake exchanges hints first; `wait_on_hints` holds a coin when a fork hint is pending | n/a | Required state exchange before every transaction | Built (mutations `notrigger`, `hintepoch`) |
| A6 | Pay to a ticket that is invalid or revoked (the payer gets stuck) | The payer checks the invoice's ticket: signed by a trusted clerk, in date, not in a revoked group, allowed to receive the amount | n/a | Payer validates payee | Built (`board/tests/pay.rs`) |
| A7 | Redirect a payment at a point of sale | Merchant identity tickets; receive-only tickets for points of sale | n/a | Same | Gap |
| A8 | Large offline exposure | `max_per_holder`, `max_spend`, validation thresholds published in epoch data | Validate online above a threshold | Validation thresholds; incentives for high value | Partial: `max_per_holder` in schemas; Gap: thresholds |
| A9 | A payment reveals the payer's other coins, or coins before the payer has seen the invoice | The invoice comes first; the offer names one coin, and only that coin's provenance travels, as id prefixes the payee can decline | n/a | 3-tap private mode | Built **+** (payee learns no other coins; the change output of a split is visible to it, as in Briolette) |

---

## 8. Gossip and relays

`protocol/src/gossip.rs`; CivicGossip and CivicTiered models

**Attack surface:** compressed hint packets; want and have exchanges; proofs served on demand; any node acting as a relay.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| G1 | Fake hints to make peers fetch or stall | Hints never decide anything; only proofs do. A false fork hint costs one want | Proofs that don't verify are dropped | n/a (bitfield gossip) | Built; Gap: per-peer want budgets |
| G2 | A relay withholds or selectively forwards revocations | Any single honest path suffices | Freshness receipts: a relay signs what it served, so serving a stale epoch is evidence | Same; receipts proposed | Built (models); Gap: receipts |
| G3 | Eclipse or partition a holder | Not preventable | Expiry bounds how long stale knowledge matters | Same | Built |
| G4 | Fake evidence | Evidence is verified before it is absorbed | n/a | n/a | Built |
| G5 | Replay an old epoch through gossip | Chain head | n/a | Monotone epoch | Built |
| G6 | Gossip as tracking: hints reveal what a holder cares about | Hints carry only sequence heads and conflicted basenames, not holdings | n/a | Bitfield only | Built; worth measuring |
| G7 | Oversized proofs | Size caps per proof | n/a | APDU-sized frames | Gap |

---

## 9. Peer link

`board/src/net.rs`: length-prefixed CBOR over TCP

**Attack surface:** the socket; frames; the IP address or radio identifier.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| P1 | An eavesdropper links IP addresses to people's activity | An encrypted channel with no long-term identity (Noise NN), so unlinkability holds | n/a | Server-authenticated TLS, not mutual TLS (audit C-1) | Gap: plaintext TCP |
| P2 | Someone in the middle alters messages | Everything that matters is signed | They can still drop or delay | Same | Built; Gap: channel integrity |
| P3 | Malformed frames | 64 MiB cap; typed decode | n/a | Rate limits | Partial; Gap: smaller caps and a per-message-type limit |
| P4 | Resource exhaustion of a node | Every exposed service asks for a network access credential first: a basename signature with (service, epoch), counted per pseudonym per epoch | Bar a pseudonym from a service for the epoch; revoke a class | IP token bucket (audit M-6) | Built (`board/src/nac.rs`: every connection, 4096 per pseudonym per service per epoch). Gap: work before the gate (the TCP accept and one frame) is unbounded, enrolled Sybils each get their own limit (R1), and a server can hold a client that's behind at an invented future epoch until the challenge carries the signed epoch head |
| P5 | A peer learns a wallet's whole history | Payments send only the paid coin's provenance; enrollment sends a new member only its own coins' provenance, the epoch sequence and the board | n/a | Tokens carry only their own history | Built for payments and enrollment. A `meet` is still a full sync, for peers a holder chooses (its own devices, the town); incremental, but not private |

---

## 10. Validator, swapper and holder sync

Specified roles, not yet built

**Attack surface:** what a holder uploads; what the service answers; the pool a swapper pays out of.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| V1 | Accept high-value coins with no online check | Any peer view can act as a validator; validate above a threshold | n/a | Validator plus tokenmap | Gap: the service |
| V2 | A validator lies ("it's fine") | Every answer is a signed head or evidence (principle 10), so a false "fine" is provable once the fork surfaces | The validator's answer is evidence against it | Validator is trusted | Modeled **+** |
| V3 | Launder a double spend through a swap | The swapper judges the coin before taking it: standing against every cheat it knows, the usual acceptance except expiry, and the transfer must be the only use it has seen. Coins tainted by a revoked group are held for two epochs and paid only if no evidence surfaces | Retire and mint are public, paired records | Swapper uses the tokenmap | Built **+** (`board/tests/swap.rs`) |
| V3a | A swapper takes a coin and then refuses to pay | The holder transfers only after a signed quote; the transfer commits to the holder's fresh credential | The quote plus the transfer is evidence against the swapper | n/a | Built (quote); Gap: a claim format |
| V4 | A central log of every history (privacy) | No mandatory tokenmap; holders sync if they want recovery | n/a | Tokenmap sees every uploaded history | Modeled **+** (the tradeoff: recovery needs the holder to sync) |
| V5 | Bloom filter false positive blocks an honest spend | A swap authorized by the swapper bypasses the filter | n/a | `INS_SIGN_COMMIT_SWAP` | Gap (no guard to bypass yet) |

---

## 11. Recovery

Specified as a holder-created capability (spec C9), not yet built

**Attack surface:** recovery bindings; claims; the recovery pool; the old wallet if it comes back.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| RC1 | False loss claim against a live wallet | Recovery only after the coin and its ticket have expired, plus a cooling-off period | The live wallet revokes its binding during the cooling-off period | Same | Gap |
| RC2 | Recover coins already spent | Expiry plus cooling-off gives honest holders time to swap | A spend after recovery conflicts with the recovery record, which is evidence | Fork detection; `RevokedCannotRecover` | Gap |
| RC3 | Recover twice | A binding is consumed; a small list of recovered states | n/a | `NoDoubleRecovery` | Gap |
| RC4 | The lost wallet comes back and spends | Its tickets are revoked after recovery | Evidence | Old wallet's group revoked | Gap |
| RC5 | Binding spam | One binding per pseudonym per epoch | n/a | NAC epoch basename | Gap |
| RC6 | The recovery service steals or mints | It holds no mint keys; it pays from a pool; it needs the delegate's proof | Its payouts are transfers, so they're public | Same | Gap |
| RC7 | Recovery acts as the holder | Nothing signs as a holder (principle 11); the binding is set up by the holder in advance | n/a | Opt-in binding | Modeled |
| RC8 | Escrowed or disputed coins recovered out from under a counterparty | Coins under a pending claim are ineligible | n/a | Escrow tag | Gap |

---

## 12. Boards and the job board

`board/src/bulletin.rs`, `board/src/board.rs`; [spec/boards.md](../spec/boards.md)

**Attack surface:** the board mint and the token requests it answers; the server that takes posts and serves them; copies that serve readers; post records and their content; tags, identities and retires; on the job board, posts, replies, accept, done and paid messages, proof of means and payment receipts.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| H1 | The host alters a post's content | The record binds the content by hash; readers check it | n/a | n/a | Built (mutation `nocontenthash`) |
| H2 | The server or a copy invents posts | A post is a token from the board mint, transferred to the server and retired by it; readers check all three records | n/a | n/a | Built (mutations `copy_receipt`, `retire_state`, `copy_mint`) |
| H3 | The server drops posts it took, or censors selectively | The server takes a post by retiring its token, a kernel record naming exactly that token | The author shows the retire; several servers for one board | n/a | Built (mutation `retire_state`); Gap: several servers |
| H4 | The host refuses posts up front | n/a | Post to another host of the board; the refusal is visible to the author | n/a | Gap: several hosts |
| H5 | The server links a post to the connection it arrived on | The post carries a fresh key and, if counted, a per-purpose pseudonym and a class, nothing else | Send through an anonymity network the author already uses (Tor, Oblivious HTTP) | n/a | Accepted: like any website |
| H6 | Posts or post tokens ride along in wallet meets, so peers learn which keys posted | Bundles leave out every record that makes or moves a post token, and wallets drop them from bundles they get; posts go to the server | n/a | n/a | Built (mutation `bundle_filter`) |
| H7 | A forged tag inflates a count | The mint tags a ticket only after checking the access credential's signature with the purpose as basename; a post counts only for the purpose its ticket is tagged with | n/a | n/a | Built (mutations `tag_sig`, `report_purpose`, `vouch_purpose`) |
| H8 | A post backdated or a token used twice | The binding commits to the server's proposed epoch and clock, checked on arrival; a token's second use is a conflict at any server | Evidence names the poster | n/a | Built (mutations `clock`, `epoch`) |
| H9 | Tokens from another issuer, or tokens a ruled or revoked author still holds | Servers and readers take tokens only from the board mint's budgets; servers run the ordinary acceptance check, which refuses revoked groups | Rulings revoke the ruled post's group at the next roll | n/a | Built (mutations `host_mint`, `copy_mint`, `accept_check`, `ruled_groups`) |
| H8 | A post is backdated to open or close a window early | The host takes a post only in its current epoch or the one before, and receipts carry that to every copy | n/a | n/a | Built (mutation `backdate`) |
| H9 | Someone signs a post as another person's identity | An identity's signature covers the post's binding; holding someone's identity doesn't let you sign with it | n/a | n/a | Built (mutations `byunchecked`, `bynotbound`) |
| B1 | Post a job without the pay to back it | Proof of means: a zero-value split of the poster's coin that commits to the terms | The proof is evidence if the coin is spent elsewhere first | n/a | Built |
| B2 | Accept or mark paid on someone else's job | Only the poster's key can accept or mark paid; only the accepted worker's key can mark done | Ignored | n/a | Built (mutation `anyaccept`) |
| B3 | A false "done", or a poster who doesn't pay | n/a | A dispute about the job, posted as a job (section 18) | n/a | Partial: disputes take any subject; nothing yet ties a job's payment to a ruling |
| B4 | Spam posts | Every post spends a token from the mint; a wallet's first 8 token requests an epoch are unlinkable, and every later one is linked to an earlier one | Rule the author out; revoke its group; the mint sees one holder asking a lot | n/a | Partial (mutation `token_slot_bound`); Gap: a policy for heavily linked holders, per-class budgets, and Sybils get their own slots (R1) |
| B5 | A poster gives one job to two workers | Accepting transfers the job's state to the worker; a second transfer is a second use of it | Readers mark the job contested | Built (mutations `assigns`, `contested`) |
| B5 | Sybil reputation | A vouch rides on a real payment from the job's poster, and counts each enrolled person once per job type; only the poster can vouch, and only for a worker who named the contractor with its trade key | Rulings against false vouches | n/a | Built (mutations `vouchanyone`, `vouchanytype`, `notradesig`, `vouchperjob`, `vouchunnamed`); Gap: rulings. Self-dealing still costs a second enrollment, not money: the pay goes back to oneself |
| B6 | Link a worker across jobs | A fresh credential per role | n/a | n/a | Built |
| B7 | A poster can't tell who it is hiring, or hires someone uncertified | A job can require a stable pseudonym or a roster's badge on it, shown before the accept; readers ignore an accept for such a job that doesn't show it | The roster revokes the badge; posters who've heard refuse it | n/a | Built (mutations `needs_known`, `badge_key`, `trade_sig`, `badge_needed`, `accept_plain`, `accept_revoked`); Gap: a reader who hasn't heard of a revocation still counts an accept that showed the badge |
| B8 | A worker sheds a bad record by making a new pseudonym | A stable pseudonym alone can't stop it: a new key has no record, which posters can weigh. A badge can: the roster answers for who is behind the key, and won't badge a second key for them | The roster revokes | n/a | By design: a poster who needs it asks for a badge |
| B9 | Showing a stable key links the worker's replies | Replies stay under fresh keys; only the accepted worker shows its key, and only to the poster before the accept | n/a | n/a | Built (test) |
| B7 | Claim a payment that doesn't match the job | The payment receipt commits to the job | n/a | n/a | Built |

---

## 13. Operator state and role keys

`town.pave`

**Attack surface:** the town file holding the registrar, root, clerk and minter secrets; the one operator who runs every role today.

| # | Attack | Prevent | React | Briolette | Status |
|---|---|---|---|---|---|
| O1 | Steal the town file | Encrypt at rest, file mode 0600, HSM or offline keys for the root and the clerk's epoch key | Rotate keys | Audit M-4 (0600 permissions); an air-gapped state key | Partial: sealed like any wallet, key file 0600; the role keys sign through the signing log, so the clerk can't roll one epoch twice by accident. Gap: HSM or offline keys |
| O2 | One operator holds every role | Each role has its own key, so roles can be handed over (principle 22) | n/a | Separate services | Built (separate keys); Gap: handover |
| O3 | An insider pays itself | Every mint and budget is public; budgets cap issuance | n/a | n/a | Built **+** |
| O4 | No key rotation | Overlap, migrate, retire, through epoch data | n/a | Repeated key fields | Gap |

---

## 14. Payment bridge and redemption

Not built, by design. Test credit only until there is an accountable operator (principle 24). Briolette's bridge (Ethereum and Bitcoin deposits) was flagged for separate review (audit I-4); pave will need the same.

---

## 15. Cross-cutting: the class break

The attack: someone finds a weakness in one device model's secure element or firmware. Combined with a phone exploit, they extract keys at scale. They can then double-spend every coin those devices hold, enroll fresh identities with the extracted attestation keys, and evade the per-device limits.

Evidence and standing don't handle this alone. Evidence catches every double spend, and standing stops each caught identity everywhere the evidence has reached. But a class breaker has thousands of identities, and each one can cheat once before it is caught. Briolette's answer is containment by class, and pave needs the same layers:

| Layer | What it does | Briolette | pave |
|---|---|---|---|
| Prevent | The secure element signs each basename once, with anti-rollback storage; attestation at enrollment | Credstick bloom filter; Key Attestation and App Attest; split key | Gap (W2, R1) |
| Bound | Lower-assurance classes get shorter ticket lifetimes, smaller `max_spend` and fewer tickets per epoch, so each extracted identity is worth little | GroupPolicy per NAC group; elastic lifetimes; per-NAC ticket budgets | Partial: per-class `max_spend`, ticket requests limited per epoch, schema-level expiry and hop limits; Gap: per-class lifetimes and budgets |
| Detect | The first double spend that surfaces names the credential | Tokenmap, once tokens are uploaded | Built **+**: any two holders who meet detect it, with no service |
| Contain one cheat | Standing: wherever its evidence has reached, a caught identity can't spend any coin under any credential, and no one else is affected | Group revocation, with collateral on the group | Built **+** |
| Contain | The clerk maps each randomized ticket group to the class (attestation tier and model) that requested it. When evidence piles up in one class, the clerk revokes every group of that class in the next epoch and closes the class to new tickets, and recipients refuse those tickets | Groups ↔ NAC group; class revocation | Built (`roll` with `revoke_class`); taints coins only within the revocation window (D2) |
| Recover | Honest members of the broken class update and enroll again under a new class, then swap stranded coins. Standing replaces the challenge test | Challenge test; re-registration after update; recovery | Partial: re-enrollment works; Gap: attestation of the update, and the swapper |

Where pave can do better once this is built:
- Detection needs no tokenmap, so a class break shows up wherever the cloned coins meet, including entirely offline.
- Evidence is a portable proof, so the clerk's decision to revoke a class can be checked by anyone, and so can a decision not to.
- Containment does not need anyone to be named: the group-to-class map holds no identities.

---

## 16. Civic reports

`board/src/report.rs`; [spec/boards.md](../spec/boards.md)

**Attack surface:** reports, clearings, replies and forwards on a public board; tags and their pseudonyms; the mirror's permits; the moderator's rulings; the reporter's device. The board host is covered in section 12. Briolette has no counterpart, so its column is omitted.

| # | Attack | Prevent | React | Status |
|---|---|---|---|---|
| RP1 | Retaliation: the subject of a report finds out who filed it | Reports are signed by a fresh credential whose ticket's tag is a per-issue pseudonym of the access credential, unrelated across issues; only a 150 m cell and a day are public | n/a | Built |
| RP2 | Timing gives the reporter away ("posted at 8:02 from that corner") | A post shows the server's epoch and clock when it arrived, which is when the wallet synced, not when the reporter saw anything; a report made offline goes out at the next sync | n/a | Partial: the clock is the arrival time the server already knew (H5); Gap: a coarser clock for reports |
| RP3 | The host learns which connection a report came from | As H5: the post carries nothing that names the reporter | Send through an anonymity network the reporter already uses | Accepted: like any website |
| RP4 | A photo identifies the reporter, bystanders or number plates | Photos are committed by a salted hash and revealed only to a verifier; strip metadata, blur faces and plates on the device | n/a | Partial: commitment built; Gap: reveal, stripping, blurring |
| RP5 | Brigading: one person files many reports, or many reports from many credentials | One pseudonym per person per issue, whatever credential they use; reporters must be enrolled members, so Sybils cost an enrollment each | Counts by wallet class show a skew toward low-assurance wallets | Built (mutation `nodedupe`) |
| RP6 | A false or malicious report about a business or a rival crew | The report states only what was seen; the permit check comes from the city's data, and a valid permit settles it; the subject can reply in the thread | A ruling discounts the report and puts its tag on the board mint's list; the reporter's later token requests need standing against it, which only they can't produce | Built (mutations `ruled_standing`, `report_purpose`) |
| RP7 | A ruled reporter starts a fresh issue to get around the ruling | The mint's list stops token requests for any purpose, on any board | n/a | Built |
| RP8 | A ruled reporter keeps posting with tokens it already holds | The ruled post's ticket group is revoked at the next roll, and servers refuse revoked tokens | n/a | Built (mutation `ruled_groups`); tokens from the same request work until the roll |
| RP9 | The moderator silences critics by ruling honest reports malicious | Rulings are public and name the report; a panel rather than one moderator; appeals | Rulings are evidence against the moderator; a recipient can choose not to honor a moderator | Partial: rulings public; Gap: panels and appeals |
| RP10 | A forged permit or ruling, posted by someone other than the role | Only the mirror's permits and the moderator's rulings count | n/a | Built (test: forged permit and ruling ignored) |
| RP11 | The mirror invents permits, or leaves real ones out so honest work looks unpermitted | Anyone can check a mirrored permit against the city's data; several independent mirrors | A false or missing permit is evidence against the mirror | Partial: one mirror; Gap: comparing mirrors |
| RP12 | The subject points to a permit that doesn't cover the site | A permit in a reply counts only if it covers the issue's area on the day it opened | n/a | Built (mutation `anypermit`) |
| RP13 | The subject's allies mark an issue cleared while it isn't | Clearings count each person once, like reports; the thread shows both counts | n/a | Built |
| RP14 | A reporter claims a place or day they weren't at | Not preventable; independent corroboration by distinct people is what carries weight | A verifier's visit, as a paid job | Accepted |
| RP15 | Paying for reports creates false ones | Pay for checking and forwarding, never for reporting | n/a | Design rule |
| RP16 | Spam on the board | Every post spends a token from the mint, rate-limited per access pseudonym; per-issue counting caps what one person adds | n/a | Partial (B4) |
| RP17 | One person counts twice by filing a report under another thread | A report counts only under its own issue's thread | n/a | Built (mutation `anythread`) |

---

## 17. Parcels

`board/src/parcel.rs`; [spec/parcels.md](../spec/parcels.md)

**Attack surface:** the shipper's parcel budget; manifests; handoffs, takes and the addressee's retirement; per-hop pay. Briolette has no counterpart, so its column is omitted.

| # | Attack | Prevent | React | Status |
|---|---|---|---|---|
| PC1 | A courier hands one parcel to two people | It is one state used twice | Kernel evidence; the cheat can't prove standing to anyone who knows of it, so can't hand off anything else; the shipper doesn't pay it | Built (mutations `takeunchecked`, `paycheat`) |
| PC2 | A courier claims delivery | Only the addressee's retirement counts; a courier can't sign as the addressee | A courier who retires a parcel has visibly lost it | Built (mutations `anyconfirm`, `anyretire`) |
| PC3 | The giver claims a handoff that didn't happen | The take is a record only the taker can sign | n/a | Built |
| PC4 | A courier is shown a false manifest (higher pay, another address) | Every handoff's receipt commits to the manifest's hash and hop | n/a | Built (mutation `takeanymanifest`) |
| PC5 | A courier is paid twice for one hop | Each payment's receipt names the parcel and courier | n/a | Built (mutation `paytwice`) |
| PC6 | A courier keeps the parcel | The custody chain shows who holds it; a courier taking under its co-op identity is named to dispatch | The co-op acts on its member | Built (mutation `anytook`): opt-in per courier; a co-op can require it |
| PC11 | A shipper or provider pays a courier twice, or both pay | With a provider, only the provider pays couriers; payments name the parcel and courier; the shipper's own handoff is never paid | n/a | Built (mutations `shipperpayscouriers`, `payshipper`, `providertwice`) |
| PC7 | The addressee takes the parcel but won't retire it, or isn't there | Code and drop delivery modes; a party's dispute | A panel rules on it | Built (mutations `anycode`, `nowindow`) |
| PC9 | A courier backdates a drop note to settle its window at once | As H8: the binding commits to the server's epoch and clock, and readers take a post from any copy only with the server's retire | n/a | Built (mutations `epoch`, `retire_state`) |
| PC10 | A stranger disputes deliveries to hold them | Only a party's disputes, and their appeals, count for a parcel | n/a | Built (mutation `anyonedisputes`) |
| PC8 | A shipper ships more than it was allowed | Parcels are minted from a budget the town issued | Budgets are capabilities (M1, M3) | Built |
| PC12 | A non-member carries a co-op's parcels | A dispatched parcel goes only to keys with the dispatch's shift ticket, and is paid only there | n/a | Built (mutations `handoff_gate`, `pay_gate`, `take_shiftkey`) |
| PC13 | A banned courier comes back the next day | Dispatch's ruled list: check-ins and shift requests need member-credential standing against it; the ruling revokes the ruled request's keys | n/a | Built (mutations `ruled`, `checkin_ruled`, `rule_list`, `rule_revoke`); keys from the courier's other requests that day keep working until used |
| PC14 | A courier works uncounted, or is counted twice | Checking in is a join to the day's group signed under a (dispatch, day) basename: one pseudonym per member per day; shift requests must show a day credential | n/a | Built (mutations `count_by_nym`, `day_cred`, `checkin_member`); Gap: a member with two cards counts twice (R1), and a day credential lent to another member |
| PC17 | A courier's shift requests are linked into a day's work profile | Slotted basenames: a courier's first 4 shift requests a day are unlinkable | n/a | Built (mutation `shift_slot_bound`) |
| PC15 | A found phone passes on a parcel's token | Whoever has the package and label code gets the token reminted; the old token is void once a taker's view has the lineage past it | The shipper pays the old token's hops only up to the remint | Built (mutations `void_take`, `label`, `pay_before`); Gap: a taker who hasn't heard of the remint accepts the old token, and it shows up when the records meet |
| PC18 | An unknown courier is given a home address | The food profile hands off only to a key with the dispatch's badge, a ticket on the courier's stable key naming them to the co-op; shift keys are refused | The co-op revokes the badge on its ticks | Built (mutations `purpose`, `holder_target`, `revoked`) |
| PC19 | A courier is given the wrong address, or the restaurant later claims it gave another | The binding the customer paid commits to a salted hash of the address; the courier checks what it was given | n/a | Built (test) |
| PC20 | A courier claims an on-time delivery, or a customer backdates one | Only the addressee's note counts; its time is the board's clock on the post (H8) | n/a | Built (mutations `note_signer`, `late`) |
| PC21 | A bag is opened on the way | The customer posts the seal code off the sticker; a mismatch is a broken seal | A dispute, with the custody chain naming the badge | Built (mutation `seal`); a resealed sticker with the code copied off isn't caught |
| PC22 | Posting under a badge key replaces the badge with a post ticket | A key holds one ticket; the wallet won't post under a key holding another clerk's ticket | n/a | Built (mutation `post_guard`) |
| PC16 | A shipper remints one parcel twice | Each remint moves the lineage coin, so a second is a double spend | Kernel evidence; takers refuse the parcel | Built (mutations `remint_once`, `twice_take`) |

---

## 18. Disputes

`board/src/dispute.rs`; [spec/disputes.md](../spec/disputes.md)

**Attack surface:** dispute, offer and ruling posts on the job board; the panel draw; appeals; arbiter scores. Briolette has no counterpart, so its column is omitted.

| # | Attack | Prevent | React | Status |
|---|---|---|---|---|
| DS1 | A party picks a friendly arbiter | The panel is drawn by hash from eligible offers | n/a | Built |
| DS2 | Someone off the panel rules | Only the drawn panelists' rulings count | n/a | Built (mutation `offpanelruling`) |
| DS3 | A party appeals for free until it wins | An appeal needs a tier up, two more panelists and double the pay, paid by the appellant | n/a | Built (mutation `appealnoescalate`) |
| DS4 | An overturned arbiter keeps taking high tiers | Scores fall for overturned rulings; tiers need scores | n/a | Built (mutations `noscorepenalty`, `noreputationgate`) |
| DS5 | An arbiter rules again on appeal of its own ruling | Arbiters who ruled earlier on a subject can't be drawn | n/a | Built (mutation `reseat`) |
| DS6 | A dispute is left open forever to hold its subject | Unstaffed or undecided disputes lapse | n/a | Built (mutation `nolapse`) |
| DS7 | A plurality decides | A majority of the panel decides | n/a | Built (mutation `nomajority`) |
| DS8 | A referral is appealed inside pave | A referral is final inside pave | n/a | Built (mutation `appealreferral`) |
| DS18 | A party swaps its evidence after seeing the other side's | Every submission's hash is noted in public when it is submitted | n/a | Built |
| DS19 | A courier shows a photo of the right door taken after the dispute | Only a photo matching the drop note's commitment counts as taken at the drop; others are labeled as not | n/a | Built (mutation `anyphoto`) |
| DS20 | A courier's committed photo shows the wrong door | The addressee's pictures and public records go to the panel beside it | The panel rules | Built |
| DS23 | Evidence leaks where and when a party was (Exif location, device, time) | Pictures are shown stripped of metadata; originals stay with the party behind a salted commitment | The party reveals the original if it helps | Built for JPEG and PNG structure (mutations `keepc2pa`, `showoriginal`); Gap: blurring faces and plates is the app's |
| DS24 | A party "reveals" an original it didn't commit to | An original counts only if it opens a commitment shown; others are labeled as matching nothing | n/a | Built (mutations `anyoriginal`, `unmatchedoriginal`) |
| DS21 | Someone other than the panel or the parties reads the evidence (a porch, a face) | The host answers only current requests signed by a panelist's or an opener's credential | n/a | Built (mutations `evidenceforall`, `askunsigned`, `staleask`); the host sees it, like any website |
| DS22 | Evidence submitted in someone else's name | Submissions are signed by the submitter's credential; the panel sees each party's role from custody | n/a | Built (mutation `evidenceunsigned`) |
| DS9 | An arbiter games the draw by offering from many trade keys | Each trade key is a contractor; scores start at zero and tiers need them | Rulings are public | Partial: sybil arbiters can fill tier 0 |
| DS10 | An appellant doesn't pay the panel | Appeals with pay carry an escrow deposit committing to their terms; the town pays the panel from it | n/a | Built (mutations `nodeposit`, `depositanyterms`) |
| DS11 | One deposit funds two appeals | Readers count each deposit once | n/a | Built (mutation `depositreuse`) |
| DS12 | A provider escalates to leave a customer owing for rounds it never chose | A loser who never escalated owes at most the first round | n/a | Built, computed not enforced (mutation `nocap`) |
| DS13 | A spurious filer keeps disputing a provider | The filer's record with that provider, by pseudonym; the provider's terms ask such filers for a deposit, which it keeps if they lose | n/a | Built (mutations `subjectnotchain`, `nofilerdeposit`, `termsforall`, `refundflipped`) |
| DS14 | One person disputes a provider many times to ruin its record | The provider's record counts distinct people | n/a | Built (mutation `countnotpeople`) |
| DS15 | The first round's funder doesn't pay its panel | It may fund upfront into escrow | Visible: payments name the dispute and arbiter | Built: funding is optional |
| DS16 | Someone publishes terms in a provider's name | Terms count only under the provider's trade key | n/a | Built (mutation `termsunsigned`) |
| DS17 | A deposit is paid out before an appeal can change the result | A filer's deposit waits for the chain to settle; appeals have a window | n/a | Built (mutations `unsettledrelease`, `noappealwindow`) |

---

## 19. Elections (example)

`board/src/election.rs`; [spec/elections.md](../spec/elections.md)

**Attack surface:** the voter rolls; vote requests and the mint; the election's ticks; booths; published ballots and the tally. Briolette has no counterpart, so its column is omitted.

| # | Attack | Prevent | React | Status |
|---|---|---|---|---|
| EL1 | A voter collects two live coins | The request's basename is the election, so the mint sees the same pseudonym; a new coin revokes the old one's group on the election's ticks | Booths refuse the revoked coin | Built (mutations `no_revoke`, `booth_check`) |
| EL2 | A voter votes twice | A coin is spent once; with voting again off, a voter who voted gets no new coin; the tally counts each pseudonym once, from its newest ticket | Double spend evidence | Built (mutations `revote_rule`, `tally_revoked`, `tally_newest`) |
| EL3 | Someone off the rolls votes | A request must verify under a district's roll | n/a | Built (mutation `roll_check`) |
| EL4 | A vote counted in the wrong district | Tickets are tagged with the district the roll showed; a booth takes only its district's | n/a | Built (mutation `booth_district`) |
| EL5 | Votes outside the legal window | The mint and the booth check the window when they act; the authority moves it only as the law does | n/a | Built (mutations `mint_window`, `booth_window`) |
| EL6 | A captured request replayed to revoke a voter's coin | Requests carry a time; the mint takes only newer ones, within ten minutes | n/a | Built (mutation `replay`) |
| EL7 | A voter is pressed to vote a certain way and show it | With voting again on, a later private vote replaces it | n/a | Partial: the booth's retire is a receipt; an election's choice |
| EL8 | The authority links a ballot to a voter | The roll credential's pseudonym is unlinkable to the voter; the mint and booths see only the pseudonym and district | n/a | Built; Gap: the connection a request arrives on (as H5) |
| EL9 | A rogue registrar stuffs a roll | Not preventable in pave | Roll sizes are public per group and can be audited against registrations | Gap |

---

## Where pave is ahead of Briolette

- **Offline detection.** Two holders who meet find a double spend on their own, with a portable 770-byte proof (K3).
- **Anonymous refills without the challenge test.** Standing keeps cheats out of the clerk's tickets and reveals nothing, where a challenge answer reveals a pseudonym the clerk can compare across epochs (C4a).
- **Individual revocation without groups.** Once the evidence reaches a recipient, a caught cheat can't spend under any of its unlinkable credentials, while honest senders prove they aren't the cheat in 144 bytes per listed cheat that link them to nothing (K3a). Briolette revokes a whole ticket group in the next epoch.
- **Offline split conservation** (K2).
- **Issuer equivocation is a kernel conflict** (K9, C1).
- **Bounded minting.** Budgets are capabilities (M1, M3).
- **Revocation needs no trust in the clerk.** Recipients refuse known cheats from evidence alone (C2, A4).
- **Hints switch gossip tiers.** A 21-byte hint pulls a proof only when it's needed (A5, G1).
- **Civic reports that count people without naming them** (section 16): one pseudonym per person per issue, and rulings that stop a malicious reporter through the standing proof without unmasking anyone.
- **No central log is required** (V4). A validator's answers are evidence against it (V2).

## Where pave is behind

These are ranked by how much they matter before anyone other than us uses this.

1. **Platform keystores and a split key with a card** (W1, W2, O1). The signing log and sealed state are built; on a phone alone the transfer key is still in app memory while it signs ([phone-keys.md](phone-keys.md)).
2. **Attestation and per-class policy** (R1, R2): assurance tiers set at enrollment, lifetimes per tier, ticket budgets.
3. **Encrypted peer channel** (P1) and **no-panic fuzzing** (K10).
4. **Merchant identity** (A7) and a validator service (V1).
5. **Recovery** (section 11).
6. **Key rotation** for every role (R5, C7, M2, O4).
7. **Trusted display and PIN** once there is hardware (W4, W5), and caps for agents (W6).
8. **Post-quantum scheme** (S5) and an external review of the ECDAA implementation (S3).

## Decisions taken

### D1. Which tickets does expiry look at?

Soft expiry applies to the sender's and holder's tickets; hard expiry runs from the coin's first (mint-time) ticket, which serves as Briolette's `valid_until` with no new field. This is Briolette's rule.

With the test town's numbers (an epoch is a day, `soft_expiry` 4, `hard_expiry` 8): on day 0 the mint pays Alice, on day 3 Alice pays Bob (ticket from day 2), and on day 4 Bob pays Carol. Carol accepts, because Bob's ticket is fresh, until it ages out on day 6. The coin itself dies on day 8. The rule before refused on day 4, because Alice's ticket was 4 days old.

The cost: an undetected double-spent copy can circulate for up to `hard_expiry` epochs (and `offline_transfers` hops) instead of `soft_expiry`, and an accomplice with a fresh ticket can carry on a coin held on a stale one (C6a).

### D2. How far back does a revoked group taint a coin?

A revoked group always stops the last hop. Earlier in the history it stops a coin only if that ticket was issued within `w` epochs before the revocation. This is Briolette's windowed rule.

On day 1 Carol (group 1188) honestly pays Dave, on day 2 Dave pays Erin, and on day 3 the town revokes 1188. With `w` = 2, Carol's ticket from day 0 is older than day 3 − 2, so Frank accepts Erin's coin. The rule before stranded Erin, and closing a class stranded every coin that had ever touched it.

`w` is each recipient's setting (`Policy::revocation_window`, default 2), counted in the issuer's own epochs. There is no separate window setting for volume: an issuer that rolls epochs faster under heavy traffic narrows the window in time, and lengthens it when traffic is light. The same cadence also shortens ticket lifetimes, since `soft_expiry` counts the same epochs.

Standing stops an individual cheat wherever its evidence reaches, so the window matters mainly for class breaks.
