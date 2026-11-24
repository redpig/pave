# Board profile

A board is an online service someone hosts: a town's job board, its civic reports board, a co-op's dispatch board. Content goes straight to the host and lives there, as posts to any website would. Pave adds two things: who may post, and a binding anyone can check.

Boards are not carried between wallets. Wallets meeting offline carry value, epochs, standing and evidence, because a recipient wants those and has to check them without reaching anyone. A post's audience is the board, so it goes to the board.

The prototype is [`board/src/bulletin.rs`](../board/src/bulletin.rs). The job board ([`board.rs`](../board/src/board.rs)) and civic reports ([`report.rs`](../board/src/report.rs)) are built on it, with tests in [`board/tests/board.rs`](../board/tests/board.rs) and [`board/tests/reports.rs`](../board/tests/reports.rs).

## Posts

A post is a kernel record in the board's scope. Its body is a small, fixed binding, never the content:

| Field | Says |
|---|---|
| `kind` | What the post is, in the profile's terms: `job`, `reply`, `report`, `ruling` |
| `thread` | The thread it belongs to. None opens a thread named by the post's own record id |
| `content` | The hash of the content, which the host holds |
| `epoch` | The poster's epoch, from the town's sequence |
| `endorsement` | Optional: an anonymous count of one person (below) |

The record's `receipt` field is the content hash too, and the kernel checks the signature as for any record.

**The signer is the author's key for that post.** It is a fresh credential, unlinkable to the author's others. The author signs later posts with the same key to act as the author: a poster accepting a worker, a worker marking a job done. Hosts index posts by the hash of that key and by content hash, so either finds the post.

**Content is the profile's.** The host stores it beside the record, up to 64 KB per post. A reader who gets a post from anyone checks the record's signature and that the content hashes to the binding, so a copy needn't be trusted.

## Endorsements

An endorsement lets a thread count distinct people without learning who they are:

- It is a signature by a fresh randomization of the author's access credential, with (board, kind, thread) as basename, over the binding.
- Its pseudonym is the same for one person on one thread, and unrelated across threads. Ten neighbors count as ten and one person counts once, whatever credential signs the post.
- The access credential's issuer shows which class of wallet endorsed, nothing more.
- It carries standing against the endorsements the profile has ruled out. A ruled author can't produce it; nobody else is affected or identified.

This is the mechanism anonymous ticket requests use, and the standing proof that stops a double spender.

## Hosts, receipts and copies

- **Submitting.** A wallet signs a post and queues it. At its next sync it sends the record and content directly to the host. The host checks the binding and any endorsement, keeps the post and answers with a **receipt**: its signature over (board, post id, content hash).
- **Receipts make dropping visible.** If the host later omits a post, its author shows the receipt. A receipt stands for one post only, even when two posts have the same content.
- **Fetching.** A reader sends the ids it has and gets the rest. Any node with a copy can serve a fetch: a mirror, a library kiosk, a neighbor. Copies are a choice, and checking makes them safe.
- **What the host sees.** The host sees the connection a post arrives on, as any website does. The post shows only its content, a fresh key and, if endorsed, a per-thread pseudonym and a class. A reporter who needs to hide the connection too can send through an anonymity network they already use, such as Tor or an Oblivious HTTP relay; pave doesn't build one.
- **Roles.** A board names the credentials of roles whose posts the profile gives weight, such as a mirror and a moderator. Anyone can post anything; posts claiming a role from any other key are kept and ignored.

## Job board

Kinds: `job`, `reply`, `accept`, `done`, `paid`, with the job as thread.

- A job post carries a **proof of means**: a zero-value split of the poster's coin that commits to the terms. The split is a value record and travels like one.
- Only the poster's key can accept a worker or mark the job paid, and only the accepted worker's key can mark it done.
- **Payment is not a post.** It is an ordinary transfer whose receipt commits to the job, and it moves wallet to wallet like any coin, offline if need be. The board shows the poster's claim that it paid; the coin is the proof.

## Civic reports

Public reports of problems in the street, such as a sidewalk blocked without a permit. The board is useful before any city adopts it: the city's own published permit data is mirrored in, so "no permit" is something anyone can check rather than an accusation.

| Kind | Signed by | Endorsed | Content |
|---|---|---|---|
| `report` | A fresh credential | Yes | An issue (category, cell, day opened), the day seen, a short note, and optionally a salted hash committing to a photo |
| `cleared` | A fresh credential | Yes | The issue is gone |
| `reply` | Anyone | No | Text, and optionally the id of a mirrored permit |
| `forwarded` | Anyone | No | The issue was sent on through another channel, with that channel's receipt (a 311 ticket number) |
| `permit` | The mirror role | No | One permit from a city's published data: source, id, kind, cell, start and end day |
| `ruling` | The moderator role | No | A report is malicious (or not) |

**Issues.** An issue is a category in a cell, opened on a day, and is the thread: everyone who reports the same thing reports the same issue, and the issue's id is the hash of those three. A report whose thread isn't its issue's id doesn't count, since it would carry a second pseudonym for the same person.

**Cells.** A cell is a geohash of 7 characters, about 150 m on a side. That is the only location made public.

**Rulings.** A report the moderator rules malicious stops counting, and its (basename, pseudonym) goes on the ruled list. A report counts only if its standing covers every ruling made before the report's epoch, so a ruled reporter can't count again even from a copy that hasn't heard of the ruling.

**Permits.** An issue is *covered* when a mirrored permit's cell matches and its dates include the day it was seen, and *nearby* when a permit covers a neighboring area that day. A reply that points to a permit changes the issue's status only if that permit covers the issue's area on the day it opened.

**Facts, not verdicts.** A thread shows what was seen, how many distinct people saw it (by class), whether a permit covers it, replies, where it was forwarded and how many people confirmed it cleared. It never says "illegal".

**Roles.**
- **Mirror.** Imports a city's published permits. Anyone can check a mirrored permit against the city's data, so a false one is evidence against the mirror. The sample in `demo/permits_sample.json` is invented, in a normalized shape.
- **Moderator.** Rules on reports. The prototype has one moderator credential. The design calls for rulings to be jobs taken by a panel, with the ruling and its reasons public and open to appeal.
- **Forwarder.** Anyone. Filing an issue with the city's existing channels can be a paid job on the job board. Pay for checking and forwarding, never for reporting, since paying reporters invites false reports.

## Not built yet

- Several hosts for one board, and comparing them.
- Kernel scope rules restricting who may post (`senders`), for boards limited to holders of a capability.
- Pruning old posts, and limits per author.
- Moderation by a panel, and appeals.
- Revealing a committed photo to a verifier, and stripping metadata and blurring faces and number plates on the device.
- Mirror adapters for real city datasets.
- Neighboring-cell matching for issues on a cell boundary.
