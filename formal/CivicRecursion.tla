--------------------------- MODULE CivicRecursion ---------------------------
(***************************************************************************)
(* Recursion gate: the fabric runs itself. Its services are gigs (scopes)  *)
(* held by bonded members, any of whom may be adversarial:                 *)
(*   - Sequencer: orders messages; may censor.                             *)
(*   - Issuer: issues role credentials within a per-epoch budget; may      *)
(*     over-issue. Issuance must be committed publicly to be valid         *)
(*     (transparency), so over-issuance is visible.                        *)
(*   - Auditor: checks the issuer; may collude and stay silent.            *)
(* Oversight chains must end in a proof (anyone can recompute from public  *)
(* commitments or a signed receipt), a vote, or the root.                  *)
(*                                                                         *)
(* Checked: an honest worker who proves on time is paid despite a          *)
(* censoring sequencer; over-issuance is always caught and the issuer's    *)
(* bond forfeited even if the auditor colludes; bonds are conserved;       *)
(* every oversight chain terminates.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    People,        \* members who can hold service gigs
    Honest,        \* the honest subset (others may do anything allowed)
    Budget,        \* credentials the issuer may issue this epoch
    MaxIssue,      \* most credentials anyone tries to issue
    Bond,          \* bond each service holder posts
    MaxT,
    Deadline,
    ReceiptsCount, \* TRUE = a signed sequencer receipt counts as proof of timely submission
    PublicCommitments \* TRUE = issuance is committed publicly, so anyone can recompute

ASSUME Honest \subseteq People
ASSUME ReceiptsCount \in BOOLEAN /\ PublicCommitments \in BOOLEAN

Services == {"sequencer", "issuer", "auditor"}
(* Who oversees whom. Terminals: "proof" (anyone recomputes), "vote", "root". *)
Overseer == [sequencer |-> "proof",      \* signed receipts expose censorship
             issuer    |-> "auditor",
             auditor   |-> "proof"]      \* commitments are public; anyone recomputes
Terminals == {"proof", "vote", "root"}

VARIABLES
    holder,     \* holder[svc]: member filling the gig
    bonds,      \* bonds[svc]: bond currently posted
    forfeited,  \* bond units forfeited to the job pool / reserve
    clock,
    proofSent,  \* the worker submitted proof and holds a signed receipt
    sentAt,
    included,   \* the proof is in the log
    closed, paidWorker,
    issued,     \* credentials issued (all committed publicly)
    flagged,    \* over-issuance flagged
    replaced    \* the issuer was replaced after a flag

vars == <<holder, bonds, forfeited, clock, proofSent, sentAt, included,
          closed, paidWorker, issued, flagged, replaced>>

Init ==
    /\ holder \in [Services -> People]
    /\ bonds = [s \in Services |-> Bond]
    /\ forfeited = 0
    /\ clock = 0
    /\ proofSent = FALSE /\ sentAt = 0
    /\ included = FALSE
    /\ closed = FALSE /\ paidWorker = FALSE
    /\ issued = 0
    /\ flagged = FALSE /\ replaced = FALSE

IsHonest(svc) == holder[svc] \in Honest

(* The worker submits proof and gets a signed receipt (an inclusion promise). *)
SendProof ==
    /\ ~proofSent /\ clock <= Deadline /\ ~closed
    /\ proofSent' = TRUE /\ sentAt' = clock
    /\ UNCHANGED <<holder, bonds, forfeited, clock, included, closed,
                   paidWorker, issued, flagged, replaced>>

(* The sequencer includes it: an honest sequencer always may; an adversarial *)
(* one may choose to (or censor by never doing so).                           *)
SeqInclude ==
    /\ proofSent /\ ~included /\ ~closed
    /\ included' = TRUE
    /\ UNCHANGED <<holder, bonds, forfeited, clock, proofSent, sentAt, closed,
                   paidWorker, issued, flagged, replaced>>

(* Backup route: the receipt itself is the proof. Anyone can post it via a  *)
(* witness, and the sequencer's bond is forfeited for the broken promise.    *)
BackupRoute ==
    /\ ReceiptsCount
    /\ proofSent /\ ~included /\ ~closed
    /\ clock > sentAt
    /\ included' = TRUE
    /\ bonds' = [bonds EXCEPT !["sequencer"] = 0]
    /\ forfeited' = forfeited + bonds["sequencer"]
    /\ UNCHANGED <<holder, clock, proofSent, sentAt, closed, paidWorker,
                   issued, flagged, replaced>>

(* The job closes: pays the worker if the proof is in the log, otherwise     *)
(* refunds at the deadline. Deadlines count from the receipt's timestamp.    *)
CloseJob ==
    /\ ~closed
    /\ \/ included /\ paidWorker' = TRUE
       \/ /\ ~included /\ clock > Deadline
          \* with receipts, a timely receipt blocks the refund until it's posted
          /\ ~(ReceiptsCount /\ proofSent /\ sentAt <= Deadline)
          /\ paidWorker' = FALSE
    /\ closed' = TRUE
    /\ UNCHANGED <<holder, bonds, forfeited, clock, proofSent, sentAt,
                   included, issued, flagged, replaced>>

(* Issue a credential. Honest issuers stay within budget; adversarial ones   *)
(* may not. Every issuance is committed publicly or it isn't valid.          *)
Issue ==
    /\ issued < MaxIssue
    /\ IsHonest("issuer") => issued < Budget
    /\ ~replaced
    /\ issued' = issued + 1
    /\ UNCHANGED <<holder, bonds, forfeited, clock, proofSent, sentAt,
                   included, closed, paidWorker, flagged, replaced>>

(* The auditor flags over-issuance: only if honest (a colluder stays silent). *)
AuditFlag ==
    /\ IsHonest("auditor")
    /\ issued > Budget /\ ~flagged
    /\ flagged' = TRUE
    /\ UNCHANGED <<holder, bonds, forfeited, clock, proofSent, sentAt,
                   included, closed, paidWorker, issued, replaced>>

(* Proof path: commitments are public, so ANY member can recompute and      *)
(* flag. This is where the oversight chain terminates, not in another gig.  *)
AnyoneFlags ==
    /\ PublicCommitments
    /\ \E p \in Honest : TRUE
    /\ issued > Budget /\ ~flagged
    /\ flagged' = TRUE
    /\ UNCHANGED <<holder, bonds, forfeited, clock, proofSent, sentAt,
                   included, closed, paidWorker, issued, replaced>>

(* A flag forfeits the issuer's bond and replaces the issuer. *)
ReplaceIssuer ==
    /\ flagged /\ ~replaced
    /\ \E p \in People \ {holder["issuer"]} :
          holder' = [holder EXCEPT !["issuer"] = p]
    /\ forfeited' = forfeited + bonds["issuer"]
    /\ bonds' = [bonds EXCEPT !["issuer"] = 0]
    /\ replaced' = TRUE
    /\ UNCHANGED <<clock, proofSent, sentAt, included, closed, paidWorker,
                   issued, flagged>>

Tick ==
    /\ clock < MaxT
    /\ clock' = clock + 1
    /\ UNCHANGED <<holder, bonds, forfeited, proofSent, sentAt, included,
                   closed, paidWorker, issued, flagged, replaced>>

Next == SendProof \/ SeqInclude \/ BackupRoute \/ CloseJob \/ Issue
        \/ AuditFlag \/ AnyoneFlags \/ ReplaceIssuer \/ Tick

(* Fairness only for things honest parties do: the worker proves, anyone   *)
(* honest may post a receipt or recompute, clocks run, and jobs close.     *)
(* Adversarial sequencers and auditors get no fairness: they may censor.   *)
Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Tick) /\ WF_vars(SendProof) /\ WF_vars(BackupRoute)
            /\ WF_vars(AnyoneFlags) /\ WF_vars(ReplaceIssuer) /\ WF_vars(CloseJob)

-----------------------------------------------------------------------------
(* An honest worker who proved on time is paid, censorship or not. *)
HonestWorkerPaid ==
    closed /\ proofSent /\ sentAt <= Deadline => paidWorker

(* Bonds are conserved: posted + forfeited is constant. *)
BondConservation ==
    bonds["sequencer"] + bonds["issuer"] + bonds["auditor"] + forfeited = 3 * Bond

(* Over-issuance is always caught and the issuer replaced (liveness). *)
OverIssueCaught == (issued > Budget) ~> (flagged /\ replaced)

(* Every oversight chain ends at a terminal within |Services| steps. *)
RECURSIVE Ends(_, _)
Ends(x, n) == IF x \in Terminals THEN TRUE
              ELSE IF n = 0 THEN FALSE ELSE Ends(Overseer[x], n - 1)
RecursionTerminates == \A s \in Services : Ends(s, Cardinality(Services))
=============================================================================
