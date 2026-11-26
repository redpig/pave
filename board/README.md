# pave-board

A neighborhood work board on pave, and `pave-node`, which runs one wallet as a process. Credentials are Briolette v1 (ECDAA over BLS12-381).

## Civic reports

The same node runs the [civic reports profile](../spec/reports.md): public reports of problems in the street, counted once per person per issue through per-issue pseudonyms, checked against permits the town mirrors from the city's published data, and ruled on without unmasking anyone. A wallet holds its own reports until the next epoch. `python3 demo/reports_demo.py` runs it across separate processes.

## Wallets and tickets

- **Enrollment, once, online, into a class.** A class is a kind of device or level of assurance (this test town has `hardware` and `software`). The wallet generates two keys of its own, one for transfers and one for network access, and sends only public keys with proofs (`pave-node join`). No role ever holds a member's key, so none can sign or forge evidence as one. The town issues a transfer credential, shared by everyone so coins don't show the class, and an access credential from the class's own issuer, and mints the test credit (`pave-node enroll`). The wallet checks both credentials are bound to its keys (`pave-node finish`).
- **Anonymous refills.** All other tickets come from refills. A refill is signed with a fresh randomization of the access credential, with the epoch as basename. The clerk learns the wallet's class and can count its requests this epoch (at most 2), and nothing links the request to the wallet's name, its tickets or its other requests. Each requested credential carries standing against every cheat the clerk knows of, so a caught cheat gets no tickets.
- **Network access on every connection.** Every service a node exposes opens with a challenge, and the client answers with its access credential the same way, with (service, epoch) as basename. A service learns the class and a pseudonym it can count (4096 connections per epoch) and bar until the epoch rolls, and nothing that links the client across services or epochs.
- **Random groups, on class terms.** Each batch gets a fresh random group out of 4096. The clerk privately maps groups to classes, never to people. Tickets carry the class's terms (software wallets: at most 50 per coin), never the class itself.
- **One fresh credential per use.** Every holding, and every role in a job (posting, replying, change from a payment), uses a fresh credential, so a wallet's actions are unlinkable unless it uses one state twice.
- **Ticket privacy.** Tickets travel only for credentials that appear in shared records, never for the unused pool.
- **Paying directly.** `send` runs a handshake with the payee: an invoice naming a fresh credential and its ticket, which the payer checks first (trusted clerk, in date, not revoked, allowed to receive the amount); an offer of one coin with its provenance as 8-byte id prefixes; the records the payee lacks, the tickets they name and the payer's standing; the payee's verdict; and only then the signed payment and the payee's signed acknowledgment. Only that coin's provenance travels, so the payee learns nothing about the payer's other coins. A payment whose acknowledgment is lost stays pending, and `resume` resends the very same record.
- **Meeting incrementally.** A meet first swaps summaries (8-byte prefixes of record, evidence and epoch ids), then only what each side lacks. Enrollment sends a new member only its own coins' provenance, the epoch sequence and the board, never the rest of the town's view.
- **Swaps.** The town takes an old coin and pays a fresh one of the same value: a signed quote first, so the holder never signs its coin away before it knows the answer, then the transfer, a public retirement and a mint. Expired coins swap at once. Coins tainted by a revoked group are held for two epochs and paid only if no evidence against their sender surfaces. Known cheats are refused.
- **Sealed state and the signing log.** A wallet's state file is encrypted and authenticated, and every save seals it under a fresh key and retires the old one. Every signature first goes into the wallet's signing log, saved before the signature leaves, so the wallet never signs one coin state twice, even after a crash. On a rollback-resistant keystore an old copy of the state won't open at all. The keystore here is a file beside the state, which only detects a restore through evidence; see [docs/phone-keys.md](../docs/phone-keys.md).
- **Revocation.** Evidence names one credential, and standing stops the cheat under all the others. A town can also revoke ticket groups, or close a whole class after a class break: every group it ever gave that class is revoked, and its wallets get no tickets until they update and enroll again. Revocation is cumulative.

- **Posting spends a post token.** A board is a clerk: the town's board mint answers anonymous token requests the way the clerk answers refills, tickets each key the wallet wants to post as and mints it a token. A post is that token's transfer to the board server, committing to the content hash, a prior post and the epoch and clock the server proposed; the server takes it by retiring the token. Ordinary wallets don't accept post tokens and board servers do, so one mint can serve many boards and servers. See [spec/boards.md](../spec/boards.md).
- **A job** is a post on the job board. It carries a proof of means: a zero-value split of the poster's coin that commits to the terms.
- **Replies, accepting and marking done** are posts too. Only the poster can accept or mark a job paid, and only the accepted worker can mark it done; anything else is ignored.
- **Payment** is an ordinary transfer whose receipt commits to the job.

Test credit only; it has no cash value.

## Run the demo

```bash
cargo build --release -p pave-board
python3 demo/board_demo.py
```

It enrolls four neighbors at the town office, each wallet fetches its tickets anonymously, then runs each person as a separate process, meeting only over local TCP:
1. Alice posts a job, Bob replies, she accepts, he finishes and she pays. Then Bob pays Alice directly with `send`: about 5.7 KB, roughly 24 BLE packets, and about 4 KB for a second payment whose history she already has.
2. Carol spends the same coin to Bob and to Alice. Neither can tell, until Bob and Alice meet: the evidence, linked by a 48-byte pseudonym, leads only to Carol's ticket group, and that coin is refused.
3. Carol's other coin is under an unlinkable credential, but Alice now knows of a cheat, so she asks the sender to prove it isn't one. Carol can't, under any credential, and is refused with no help from the town. Bob pays Alice and proves it with 144 bytes that link him to nothing.
4. The town also revokes Carol's ticket group. The new epoch spreads by two-tier gossip (53 bytes of hints in one packet, then a 1.7 KB proof fetched because the hint asked for it).
5. Carol can't refill her tickets; Bob can.
6. A flaw is found in the software wallet. The town closes the class: Dave, honest but on the same model, can't refill until he re-enrolls, and Alice's hardware wallet carries on.
7. Weeks pass and Alice's coin reaches its hard expiry. Refused offline, she swaps it with the town for a fresh one.

The whole run takes about 3 seconds. Measured on one core: randomizing a credential takes 1.8 ms, signing with a basename 1.9 ms, verifying 7.4 ms, and proving or checking standing about 3 ms per known cheat (`cargo run --release -p pave-scheme-briolette --example timing`).

## Driving a node

`pave-node run --state alice.pave --listen 127.0.0.1:7001` reads one JSON command per line on stdin and answers with one JSON object per line on stdout. A person, a script or an agent drives it the same way. Every reply has `"ok": true` or `"ok": false` with an `"error"`.

| Command | Fields | Returns |
|---|---|---|
| `whoami` | | `class`, `group`, `balance`, `coins`, `epoch`, `tickets_left`, `flagged_groups` |
| `board` | | `jobs` with status, poster, worker and replies |
| `post` | `title`, `pay` | `job` |
| `reply` | `job`, `note` | `message` |
| `accept` | `job`, `worker` | `message` |
| `done` | `job` | `message` |
| `pay` | `job` | `payment` (the new coin's state) |
| `receive` | | a fresh `credential` to be paid at |
| `check` | `state` | `accept`, or a `refusal` (expired, revoked, known cheat, …) |
| `spend` | `state`, `to` | `state` |
| `meet` | `peer` (`host:port`) | `new_evidence`, `bytes` |
| `gossip` | `peer` | `compressed_bytes`, `wants`, `extended_bytes` |
| `refill` | `peer`, `count` | `tickets` received from the town |
| `issues` | | each issue: category, cell, day opened, distinct `reporters` by class, `permit` (found, nearby or none), replies, forwards, `cleared`, `discounted` |
| `report` | `category`, `lat`, `lon`, `observed`, `note`, `photo`; or `issue`, `observed`, `note` | `issue`; held until the next epoch |
| `respond` | `issue`, `text`, `permit` | the reply's id |
| `forward` | `issue`, `channel`, `receipt` | the record's id |
| `clear` | `issue` | held until the next epoch |
| `mirror` | `file` | permits signed in (town only) |
| `rule` | `report`, `malicious` | the ruling's id (town only) |
| `send` | `peer`, `amount`, `memo` | `paid` (the payee's new coin), or `refused`, with the `bytes` of each step |
| `resume` | `peer` | `acknowledged`: payments resent after a dropped connection |
| `swap` | `peer`, `state` | `paid` (the fresh coin's state), or `held_until` an epoch |
| `collect` | `peer` | `paid` and `held_until` for swaps whose hold was pending |
| `evidence` | | `evidence` (state, signer, ticket group, pseudonym size) |
| `roll` | `revoke` (groups), `revoke_class` (classes) | `epoch`, `revoked_groups` (town operator only) |
| `cheat` | `state`, `to` | signs a second spend and hides the first, to demonstrate detection |

Hashes and credentials are hex. For example:

```
{"cmd":"post","title":"Fix the back fence","pay":30}
{"job":"d4feb1fb…","ok":true}
```

## Not yet

- **No incremental sync.** A meet swaps whole record logs (27–80 KB in the demo, with 336-byte signatures and 192-byte credentials). Incremental sync is the next size win.
- **Swaps and recovery.**
- **Wallet keys live in the state file.** A real wallet keeps them in a secure element.
