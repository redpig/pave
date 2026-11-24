# pave-board

A neighborhood work board on pave, and `pave-node`, which runs one wallet as a process.

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
2. Carol spends the same coin to Bob and to Alice. Neither can tell, until Bob and Alice meet: the evidence names only Carol, and their wallets refuse her coins.
3. The town revokes Carol's ticket group, and the new epoch spreads by two-tier gossip. The hints fit one packet, and the proofs are fetched only because the hints asked for them.

## Driving a node

`pave-node run --state alice.pave --listen 127.0.0.1:7001` reads one JSON command per line on stdin and answers with one JSON object per line on stdout. A person, a script or an agent drives it the same way. Every reply has `"ok": true` or `"ok": false` with an `"error"`.

| Command | Fields | Returns |
|---|---|---|
| `whoami` | | `me`, `group`, `balance`, `coins`, `epoch`, `flagged` |
| `board` | | `jobs` with status, poster, worker and replies |
| `post` | `title`, `pay` | `job` |
| `reply` | `job`, `note` | `message` |
| `accept` | `job`, `worker` | `message` |
| `done` | `job` | `message` |
| `pay` | `job` | `payment` (the new coin's state) |
| `check` | `state` | `accept`, or a `refusal` (expired, revoked, known cheat, …) |
| `spend` | `state`, `to` | `state` |
| `meet` | `peer` (`host:port`) | `new_evidence`, `bytes` |
| `gossip` | `peer` | `compressed_bytes`, `wants`, `extended_bytes` |
| `evidence` | | `evidence` (state, signer) |
| `roll` | `revoke` (groups) | `epoch` (town operator only) |
| `cheat` | `state`, `to` | signs a second spend and hides the first, to demonstrate detection |

Hashes and credentials are hex. For example:

```
{"cmd":"post","title":"Fix the back fence","pay":30}
{"job":"d4feb1fb…","ok":true}
```

## Not yet

- **Not anonymous.** It uses the test scheme, so credentials are plain keys. Wiring in Briolette v1 needs a supply of prefetched tickets, one per fresh holding credential.
- **No incremental sync.** A meet swaps whole record logs, a few to about 18 KB in the demo; incremental sync would cut that.
- **No swaps or recovery yet.**
