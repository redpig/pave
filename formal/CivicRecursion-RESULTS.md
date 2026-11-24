# CivicRecursion TLA+ results (2026-11-22, TLC 1.8.0)

Recursion gate: sequencer, issuer and auditor gigs held by possibly adversarial members (People = {h, x1, x2}, Honest = {h}, every role assignment explored).

## RecSafe.cfg
```
CONSTANTS
    People = {h, x1, x2}
    Honest = {h}
    Budget = 1
    MaxIssue = 2
    Bond = 1
    MaxT = 3
    Deadline = 1
    ReceiptsCount = TRUE
    PublicCommitments = TRUE
SPECIFICATION FairSpec
INVARIANTS HonestWorkerPaid BondConservation RecursionTerminates
PROPERTIES OverIssueCaught
```
## RecNoReceipts.cfg
```
CONSTANTS
    People = {h, x1, x2}
    Honest = {h}
    Budget = 1
    MaxIssue = 2
    Bond = 1
    MaxT = 3
    Deadline = 1
    ReceiptsCount = FALSE
    PublicCommitments = TRUE
SPECIFICATION FairSpec
INVARIANTS HonestWorkerPaid BondConservation RecursionTerminates
PROPERTIES OverIssueCaught
```
## RecNoCommitments.cfg
```
CONSTANTS
    People = {h, x1, x2}
    Honest = {h}
    Budget = 1
    MaxIssue = 2
    Bond = 1
    MaxT = 3
    Deadline = 1
    ReceiptsCount = TRUE
    PublicCommitments = FALSE
SPECIFICATION FairSpec
INVARIANTS HonestWorkerPaid BondConservation RecursionTerminates
PROPERTIES OverIssueCaught
```
## Results
```
== RecSafe
Progress(11) at 2026-11-22 23:42:35: 10,113 states generated, 4,329 distinct states found, 0 states left on queue.
Model checking completed. No error has been found.
10113 states generated, 4329 distinct states found, 0 states left on queue.
== RecNoReceipts
Error: Invariant HonestWorkerPaid is violated.
899 states generated, 657 distinct states found, 354 states left on queue.
Finished in 00s at (2026-11-22 23:42:36)
== RecNoCommitments
Progress(11) at 2026-11-22 23:42:38: 6,969 states generated, 3,219 distinct states found, 0 states left on queue.
Error: Temporal property OverIssueCaught was violated.
6969 states generated, 3219 distinct states found, 0 states left on queue.
```

Notes: BackupRoute forfeits the sequencer's bond whenever a receipt is posted by witness, a simplification (a real rule would forfeit only for a missed promise deadline). One epoch of issuance is modeled.
