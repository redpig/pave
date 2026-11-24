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

**Identities are the author's choice.** A post may also carry a signature over its binding by one of the author's stable credentials. A wallet starts with one per privacy tier, so the choice is ready at the first post:

| Tier | Who can tell it's you |
|---|---|
| none (the default) | Nobody: a fresh key per post, and a per-thread pseudonym if endorsed |
| `close` | The few people you gave it to |
| `contacts` | Your network: the neighbors and friends you gave it to |
| `public` | Anyone: you post it openly as yours |

Whoever was given an identity knows who posted; anyone else sees one unnamed author behind every post it signed. Holding someone's identity doesn't let you sign with it, and its signature covers the binding, so it can't be moved to another post. A profile decides what an identity changes; counts don't depend on it.

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

### Vouches

A vouch is a reputational commitment for a job type, and it is a coin. It rides on a real payment, so a reputation can't be had without paid work.

- **Opting in.** A worker who wants vouches replies under a stable **trade key**, which signs over the job and the fresh credential the worker will be paid at. The contractor's id is the hash of that key, and its thread on the board is where its vouches go. A trade key links every job replied to under it, which is what a contractor wants; a worker who replies without one stays unlinkable.
- **The vouch coin.** The poster pays with a split whose second output is zero-value, to the worker, and whose receipt commits to (job, contractor, job type). That output goes to the contractor with the pay, is held like money and checks like money, offline too. It isn't money: it carries no value.
- **The vouch post.** The poster also posts the vouch in the contractor's thread, signed by the job's poster key, carrying the payment record and endorsed with the contractor as basename.
- **Counting.** A vouch counts only if it comes from the job's poster, the job is paid with that payment, the worker named this contractor with its trade key, the payment is signed and pays the worker with a vouch output whose receipt names this job, contractor and type, and the endorsement checks out. Each job counts once, and each person once per job type however many jobs they vouch for. A worker can't vouch for itself, a poster can't relabel a payment's job type, and nobody can credit a job to a contractor who didn't do it.
- **Known to your contacts.** A voucher may sign the vouch with one of its identities. A reader who was given it sees which contact vouched; anyone else sees one unnamed person behind those vouches. Without one a vouch is anonymous, and the counts are the same for every reader.
- **Who it goes to.** The coin goes to the contractor and the post to the board. A friend asking who did your fence gets the contractor's id and checks the board, or asks the contractor to show their vouch coins.

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

**Identified reporters.** A reporter may sign with an identity, on any of their reports. The thread shows how many counted reporters are identified, and each reader sees which of them are its contacts. A reporter is still counted once.

**Facts, not verdicts.** A thread shows what was seen, how many distinct people saw it (by class), whether a permit covers it, replies, where it was forwarded and how many people confirmed it cleared. It never says "illegal".

**Roles.**
- **Mirror.** Imports a city's published permits. Anyone can check a mirrored permit against the city's data, so a false one is evidence against the mirror. The sample in `demo/permits_sample.json` is invented, in a normalized shape.
- **Moderator.** Rules on reports. The prototype has one moderator credential. The design calls for rulings to be jobs taken by a panel, with the ruling and its reasons public and open to appeal.
- **Forwarder.** Anyone. Filing an issue with the city's existing channels can be a paid job on the job board. Pay for checking and forwarding, never for reporting, since paying reporters invites false reports.

## Not built yet

- Several hosts for one board, and comparing them.
- A vouch schema of its own: today a vouch coin is a zero-value coin of the payment's schema, so it expires and can be transferred like one. It should never expire and never move.
- Showing vouch coins to a client directly, with a holding proof, and rulings against false vouches.
- Kernel scope rules restricting who may post (`senders`), for boards limited to holders of a capability.
- Pruning old posts, and limits per author.
- Moderation by a panel, and appeals.
- Revealing a committed photo to a verifier, and stripping metadata and blurring faces and number plates on the device.
- Mirror adapters for real city datasets.
- Neighboring-cell matching for issues on a cell boundary.
