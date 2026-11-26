# Election profile (example)

A municipal election, built only from what the town already has. It is an example of two choices the kernel leaves to each mint and each recipient: **what a basename links**, and **whose clock counts**. A board's mint links requests per epoch, for rate limits. An election's mint links them per election, so it can see a voter come back. Its clock is its own, and the time limits that matter are legal ones.

The prototype is [`board/src/election.rs`](../board/src/election.rs), with the test in [`board/tests/election.rs`](../board/tests/election.rs).

## Parts

| Part | Built from |
|---|---|
| **Voter rolls** | One issuer group per district, as classes are. Registering is a join: the voter's device makes the key, the registrar issues a credential on its public key, and never holds the secret. Who may register is checked outside pave, as today |
| **The mint** | A capability to issue the vote schema, derived from the town's root. The election's id is that capability's id |
| **The election's clock** | Its own tick sequence: a coin its clerk holds, rolled only when a vote coin is reissued, each roll carrying the revoked groups. Nothing depends on the town's epochs |
| **The window** | Wall-clock dates set by law. The mint and the booths check them; the authority moves them when a court or an ordinance does. The vote schema has no expiry |
| **A vote coin** | Indivisible, one per holder, spent once. Ticketed in a fresh random group with a tag: (election, pseudonym, district) |
| **A booth** | A board server for its district's ballot box |
| **A ballot** | The coin's `Transfer` to the booth, its receipt the hash of the ballot's binding (as a board post: the ballot box, the choice's hash, a nonce, the election's tick and the booth's clock). The booth takes it by retiring the coin |

## The basename is the election

A vote request is signed by a fresh randomization of the voter's roll credential, with the **election** as basename, over the credential the coin should be held under and the request time.

- The pseudonym is the same for one voter for the whole election, however long the window, and unrelated across elections, even with the same key.
- The mint learns the district and the pseudonym, never who.
- **One live coin per pseudonym.** A voter who comes back during the window (a lost phone, a wrong booth) is recognized and gets a new coin. The old coin's group is revoked on a new tick, so a booth refuses it.
- **Requests only move forward.** The mint keeps each pseudonym's latest request time and refuses older or stale ones, so a captured request can't be replayed to revoke a voter's coin.

## Voting

1. The voter asks the booth for its clock. Outside the window the booth refuses, so the voter never spends a coin on a ballot the booth would refuse.
2. The voter signs the coin's transfer to its district's booth.
3. The booth checks: inside the window; its own ballot box; a choice on the ballot; a coin from this election's mint; a ticket tagged for this election and this district; and the ordinary acceptance check with the election's clerk and ticks trusted, which refuses a revoked group. It retires the coin and keeps the ballot.

Using a coin twice is a double spend. A ballot re-sent is refused, since its coin is spent.

## Voting again is the law's choice

| `revote` | A voter whose coin was cast comes back | Effect |
|---|---|---|
| off | Refused: "already voted" | One vote, final |
| on | A new coin; the cast coin's group is revoked | The later vote counts instead. A voter pressed to vote one way can vote again in private |

## Tallying

Anyone can tally from the published ballots and the election's revoked groups:

- Each ballot is checked as a board post is: the mint's capability, the coin's budget and mint, the transfer to the booth with the ballot's binding, and the booth's retire.
- A ballot counts only if its ticket is tagged for this election and district and its group wasn't revoked.
- Each pseudonym counts once, from its **newest ticket**. So a booth that took a ballot before hearing of a revocation, or a reader without the revocations, still counts each voter once.

## What it doesn't do

- **Who may register.** Eligibility, residency and district assignment are checked outside pave, by the registrar, as today. A rogue registrar can add voters to a roll; its group key is public, so its roll can be audited against the published count.
- **Connections.** The mint and the booth see the connections requests arrive on. A booth in a polling place, or an anonymity network the voter already uses, hides them.
- **Receipts.** The voter holds the booth's retire, which shows how they voted. With `revote` on, a later vote overrides one shown to anyone else.
- **The mint knows each pseudonym's ballot**, as anyone does from the tag: pseudonyms are public. It can't tie one to a voter.
- **Not built:** booths as separate servers with their own copy of the election's ticks (here the authority runs them), network messages and a CLI, ranked choices, and publishing ballots through a board's copies.
