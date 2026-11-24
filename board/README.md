# pave-board

A neighborhood work board on pave, and `pave-node`, which runs one wallet as a process. Credentials are Briolette v1 (ECDAA over BLS12-381).

## Wallets and tickets

- **Enrollment, once, online.** The registrar issues the wallet's group credential and the clerk issues a batch of prefetched tickets. Each ticket certifies a fresh randomized credential, in the wallet's revocation group, at the current epoch.
- **One fresh credential per use.** Every holding, and every role in a job (posting, replying, change from a payment), uses a fresh credential, so a wallet's actions are unlinkable unless it uses one state twice.
- **Ticket privacy.** Tickets travel only for credentials that appear in shared records, never for the unused pool.
- **Refills.** A wallet asks the town for more tickets, signing the request with one of its own credentials so the clerk knows its group.
- **Revocation.** Evidence names one credential. Its ticket's group leads to the wallet, and revoking the group in a new epoch catches the cheater's other, unlinkable coins once the epoch reaches a recipient.

- **A job** is a message to the board scope. Its post carries a proof of means: a zero-value split of the poster's coin that commits to the terms.
- **Replies, accepting and marking done** are messages too. Only the poster can accept or mark a job paid, and only the accepted worker can mark it done; anything else is ignored.
- **Payment** is an ordinary transfer whose receipt commits to the job.

Test credit only; it has no cash value.

## Run the demo

```bash
cargo build --release -p pave-board
python3 demo/board_demo.py
```

It enrolls three neighbors at the town office, then runs each person as a separate process, meeting only over local TCP:
1. Alice posts a job, Bob replies, she accepts, he finishes and she pays.
2. Carol spends the same coin to Bob and to Alice. Neither can tell, until Bob and Alice meet: the evidence, linked by a 48-byte pseudonym, leads only to Carol's ticket group, and that coin is refused.
3. Carol's other coin is under an unlinkable credential, so it still passes.
4. The town revokes Carol's group. The new epoch spreads by two-tier gossip (53 bytes of hints in one packet, then a 1.7 KB proof fetched because the hint asked for it), and her other coin is refused.
5. Bob refills his tickets from the town.

The whole run takes about 3 seconds. Measured on one core: randomizing a credential takes 1.8 ms, signing with a basename 1.9 ms, and verifying 7.4 ms (`cargo run --release -p pave-scheme-briolette --example timing`).

## Driving a node

`pave-node run --state alice.pave --listen 127.0.0.1:7001` reads one JSON command per line on stdin and answers with one JSON object per line on stdout. A person, a script or an agent drives it the same way. Every reply has `"ok": true` or `"ok": false` with an `"error"`.

| Command | Fields | Returns |
|---|---|---|
| `whoami` | | `group`, `balance`, `coins`, `epoch`, `tickets_left`, `flagged_groups` |
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
| `evidence` | | `evidence` (state, signer, ticket group, pseudonym size) |
| `roll` | `revoke` (groups) | `epoch` (town operator only) |
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
