# Civic reports profile

Public reports of problems in the street, such as a sidewalk blocked without a permit. The profile is useful before any city adopts it: reports are public posts, and the city's own published permit data is mirrored in, so "no permit" is something anyone can check rather than an accusation.

The prototype is [`board/src/report.rs`](../board/src/report.rs), with tests in [`board/tests/reports.rs`](../board/tests/reports.rs) and a demo in [`demo/reports_demo.py`](../demo/reports_demo.py).

## Objects

Everything is a message in a town's **reports scope**. Nothing here needs the kernel to change.

| Message | Signed by | Says |
|---|---|---|
| `Report` | A fresh credential, plus an endorsement | An issue (category, cell, day opened), the day seen, a short note, and optionally a salted hash committing to a photo |
| `Cleared` | A fresh credential, plus an endorsement | The issue is gone |
| `Reply` | Anyone | Text, and optionally the id of a mirrored permit |
| `Forwarded` | Anyone | The issue was sent on through another channel, with that channel's receipt (a 311 ticket number) |
| `Permit` | The mirror role | One permit from a city's published data: source, id, kind, cell, start and end day |
| `Ruling` | The moderator role | A report is malicious (or not), as of an epoch |

**Issue.** An issue is a category in a cell, opened on a day. Everyone who reports the same thing reports the same issue, and the issue's id is the hash of those three.

**Cell.** A cell is a geohash of 7 characters, about 150 m on a side. That is the only location made public.

## Rules

**One person, one count per issue, unlinkably.**
- A report's endorsement is a signature by a fresh randomization of the reporter's access credential, with the issue as basename.
- Its pseudonym is the same for one person on one issue, and unrelated across issues.
- An issue's count is the number of distinct pseudonyms among reports that count. Ten neighbors count as ten, one person counts once, and nobody learns who anyone is.
- The access credential's issuer shows which class of wallet reported, so a thread can show, say, "2 hardware, 1 software".
- Clearing works the same way, with its own basename.

This is the mechanism anonymous ticket requests use.

**Rulings without unmasking.**
- A report the moderator rules malicious stops counting.
- Its (basename, pseudonym) pair goes on a public list.
- Every endorsement carries standing against the rulings its reporter knows of. A report counts only if its standing covers every ruling made before the report's epoch.
- The ruled reporter can't produce that standing for any later report. Everyone else can, and nobody is identified.

This is the same proof that stops a double spender.

**Permits from the city's own data.**
- The mirror role signs permits from a city's published dataset into the scope, once each.
- An issue is *covered* when a mirrored permit's cell matches and its dates include the day the issue was seen. It is *nearby* when a permit covers a neighboring area that day.
- A reply that points to a permit changes the issue's status only if that permit covers the issue's area on the day it opened.
- Only the mirror's permits and the moderator's rulings count. The same messages from anyone else are ignored.

**Facts, not verdicts.** A thread shows:
- what was seen;
- how many distinct people saw it, by class;
- whether a permit covers it;
- replies;
- where it was forwarded;
- how many people confirmed it cleared.

It never says "illegal".

**Delayed publication.** A wallet holds its own reports and clearings until the next epoch, so a post doesn't say "sent at 8:02 from that corner".

## Roles

- **Mirror.** Imports a city's published permits. Anyone can check a mirrored permit against the city's data, so a false one is evidence against the mirror. Cities publish this in different shapes and on different schedules; the sample in `demo/permits_sample.json` is invented, in a normalized shape.
- **Moderator.** Rules on reports. The prototype has one moderator credential. The design calls for rulings to be jobs taken by a panel, with the ruling and its reasons public and open to appeal.
- **Forwarder.** Anyone. Filing an issue with the city's existing channels can be a paid job on the work board. Pay for checking and forwarding, never for reporting, since paying reporters invites false reports.

## Not built yet

- Moderation by a panel, and appeals.
- Revealing a committed photo to a verifier, and stripping metadata and blurring faces and number plates on the device.
- Mirror adapters for real city datasets.
- Routing reports through other peers before they reach anyone who could link a delivery to a device.
- Neighboring-cell matching for issues on a cell boundary.
