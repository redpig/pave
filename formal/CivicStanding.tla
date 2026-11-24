---------------------------- MODULE CivicStanding ----------------------------
(***************************************************************************)
(* Standing, revocation windows and class revocation.                      *)
(*                                                                         *)
(* A cheat holds many coins, each under its own unlinkable credential.     *)
(* Evidence of a double spend names one credential. The questions:         *)
(*                                                                         *)
(*  - Standing: once a site holds evidence on a cheat, is the cheat stopped *)
(*    under every credential, and is nobody honest ever stopped?            *)
(*  - Revocation window: a revoked group always stops the last hop, and    *)
(*    earlier hops only if their ticket was issued within W epochs before  *)
(*    the revocation. Are honest coins that passed through a group long    *)
(*    ago never stranded, while recent hops through it are contained?      *)
(*  - Class revocation: closing a class revokes every group it was given.  *)
(*                                                                         *)
(* Two sites, each with its own view of every coin; a dishonest holder can *)
(* sign one coin position at both. Evidence forms where both uses meet     *)
(* (modeled as Detect) and spreads by gossip. One honest clerk rolls       *)
(* epochs and revokes groups or whole classes; sites learn its epochs by   *)
(* Sync. Every holding is under a fresh credential <<person, coin, hop>>,  *)
(* in a ticket group of the holder's class, stamped with the epoch the     *)
(* site knows. Expiry is checked in CivicGossip and left out here.         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS Sites, People, Bad, Coins, Holder0, Class, Groups, GroupClass,
          MaxHops, MaxEpoch, W, Bug

ASSUME Bad \subseteq People
ASSUME Bug \in {"none", "nostanding", "nowindow", "noclassrevoke", "fakeevidence",
                "nolasthop"}

Honest == People \ Bad
Classes == {Class[p] : p \in People}
Person(cr) == cr[1]
Last(h) == h[Len(h)]
Sender(h) == Last(h).cred

VARIABLES
    own,      \* own[s][c]: the coin's history as site s sees it, a sequence of hops [cred, g, ep]
    ep,       \* the clerk's epoch
    rev,      \* rev[g]: the epoch group g was revoked in, 0 if not revoked
    closed,   \* classes the clerk has closed
    kep,      \* kep[s]: the epoch site s knows
    krev,     \* krev[s]: the revocations site s knows
    kclosed,  \* kclosed[s]: the closed classes site s knows
    ev,       \* ev[s]: credentials site s holds evidence on
    signed,   \* every transfer ever signed: [c, pos, from, to]
    broken    \* ghost: which honest-recipient guarantees were ever skipped

vars == <<own, ep, rev, closed, kep, krev, kclosed, ev, signed, broken>>

FirstGroup(p) == CHOOSE g \in Groups : GroupClass[g] = Class[p]

Init ==
    /\ own = [s \in Sites |-> [c \in Coins |->
                 << [cred |-> <<Holder0[c], c, 1>>, g |-> FirstGroup(Holder0[c]), ep |-> 0] >>]]
    /\ ep = 0
    /\ rev = [g \in Groups |-> 0]
    /\ closed = {}
    /\ kep = [s \in Sites |-> 0]
    /\ krev = [s \in Sites |-> [g \in Groups |-> 0]]
    /\ kclosed = [s \in Sites |-> {}]
    /\ ev = [s \in Sites |-> {}]
    /\ signed = {}
    /\ broken = {}

(* Credentials that signed two different transfers from one position. *)
Cheated == {t.from : t \in {t1 \in signed : \E t2 \in signed :
                t1 # t2 /\ t1.c = t2.c /\ t1.pos = t2.pos /\ t1.from = t2.from}}
CheatPeople(s) == {Person(cr) : cr \in ev[s]}

(* Does hop i of history h stop a coin, given revocations r? *)
Taints(h, i, r) ==
    LET hop == h[i] IN
    /\ r[hop.g] > 0
    /\ \/ i = Len(h) /\ Bug # "nolasthop"
       \/ Bug = "nowindow"
       \/ hop.ep + W >= r[hop.g]

(* The recipient's policy at site s, for a coin with history h. *)
Accepts(q, s, h) ==
    \/ q \in Bad
    \/ /\ Sender(h) \notin ev[s]
       /\ Person(Sender(h)) \notin CheatPeople(s) \/ Bug = "nostanding"
       /\ \A i \in 1..Len(h) : ~Taints(h, i, krev[s])

(* The holder of c at site s pays q, in ticket group g of q's class. *)
Transfer(s, c, q, g) ==
    LET h == own[s][c]
        from == Sender(h)
        p == Person(from)
        to == <<q, c, Len(h) + 1>>
        t == [c |-> c, pos |-> Len(h), from |-> from, to |-> to]
        recent(i) == krev[s][h[i].g] > 0 /\ (i = Len(h) \/ h[i].ep + W >= krev[s][h[i].g])
    IN
    /\ Len(h) < MaxHops
    /\ p # q
    /\ GroupClass[g] = Class[q]
    /\ rev[g] = 0                      \* the clerk never issues into a revoked group
    /\ Class[q] \notin closed
    /\ p \in Bad \/ ~\E t2 \in signed : t2.c = c /\ t2.pos = Len(h) /\ t2.from = from
    /\ Accepts(q, s, h)
    /\ own' = [own EXCEPT ![s][c] = Append(h, [cred |-> to, g |-> g, ep |-> kep[s]])]
    /\ signed' = signed \cup {t}
    /\ broken' = broken
         \cup (IF q \in Honest /\ p \in CheatPeople(s) THEN {"cheat"} ELSE {})
         \cup (IF q \in Honest /\ \E i \in 1..Len(h) : recent(i) THEN {"taint"} ELSE {})
         \cup (IF q \in Honest /\ GroupClass[Last(h).g] \in kclosed[s] THEN {"class"} ELSE {})
    /\ UNCHANGED <<ep, rev, closed, kep, krev, kclosed, ev>>

(* The clerk rolls, revoking some groups, or closing a class. *)
Roll(gs, cl) ==
    LET classGroups == IF cl = "none" \/ Bug = "noclassrevoke" THEN {}
                       ELSE {g \in Groups : GroupClass[g] = cl}
        newly == gs \cup classGroups
    IN
    /\ ep < MaxEpoch
    /\ ep' = ep + 1
    /\ rev' = [g \in Groups |-> IF rev[g] = 0 /\ g \in newly THEN ep + 1 ELSE rev[g]]
    /\ closed' = IF cl = "none" THEN closed ELSE closed \cup {cl}
    /\ UNCHANGED <<own, kep, krev, kclosed, ev, signed, broken>>

Sync(s) ==
    /\ kep[s] # ep
    /\ kep' = [kep EXCEPT ![s] = ep]
    /\ krev' = [krev EXCEPT ![s] = rev]
    /\ kclosed' = [kclosed EXCEPT ![s] = closed]
    /\ UNCHANGED <<own, ep, rev, closed, ev, signed, broken>>

(* Both uses of a cheat's credential meet at s: evidence. *)
Detect(s, cr) ==
    /\ cr \in Cheated \/ (Bug = "fakeevidence" /\ cr[1] \in Honest)
    /\ cr \notin ev[s]
    /\ ev' = [ev EXCEPT ![s] = @ \cup {cr}]
    /\ UNCHANGED <<own, ep, rev, closed, kep, krev, kclosed, signed, broken>>

Gossip(s, t) ==
    /\ s # t
    /\ ~(ev[s] \subseteq ev[t])
    /\ ev' = [ev EXCEPT ![t] = @ \cup ev[s]]
    /\ UNCHANGED <<own, ep, rev, closed, kep, krev, kclosed, signed, broken>>

AllCreds == {<<p, c, n>> : p \in People, c \in Coins, n \in 1..MaxHops}

Next ==
    \/ \E s \in Sites, c \in Coins, q \in People, g \in Groups : Transfer(s, c, q, g)
    \/ \E gs \in SUBSET Groups, cl \in Classes \cup {"none"} : Roll(gs, cl)
    \/ \E s \in Sites : Sync(s)
    \/ \E s \in Sites, cr \in AllCreds : Detect(s, cr)
    \/ \E s, t \in Sites : Gossip(s, t)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Evidence only ever names a credential that signed one position twice. *)
NoFalseFlag == \A s \in Sites : ev[s] \subseteq Cheated

(* Standing: wherever a site holds evidence on any of a cheat's            *)
(* credentials, honest recipients there take nothing from any of them.     *)
CheatStopped == "cheat" \notin broken

(* Containment: honest recipients never take a coin whose sender's ticket  *)
(* is in a revoked group, or with an earlier hop through a revoked group   *)
(* issued within W epochs before the revocation.                           *)
Contained == "taint" \notin broken

(* Class revocation: once a site knows a class is closed, honest           *)
(* recipients there take nothing sent from that class's tickets.           *)
ClassContained == "class" \notin broken

(* No stranding: an honest holder whose coin is clean (its own ticket not  *)
(* revoked, no recent hop through a revoked group) can always pay another  *)
(* honest person at its site.                                              *)
Clean(s, h) ==
    \A i \in 1..Len(h) :
        LET at == krev[s][h[i].g] IN at = 0 \/ (i < Len(h) /\ h[i].ep + W < at)
NoStranding ==
    \A s \in Sites, c \in Coins :
        LET h == own[s][c] IN
        (Person(Sender(h)) \in Honest /\ Clean(s, h) /\ Len(h) < MaxHops)
          => \A q \in Honest \ {Person(Sender(h))} : Accepts(q, s, h)

=============================================================================
