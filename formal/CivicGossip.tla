----------------------------- MODULE CivicGossip -----------------------------
(***************************************************************************)
(* Tickets as sequences, and gossip as an optimization on the protocol.    *)
(*                                                                         *)
(* No hub and no clock. Three sites; people transact at a site using what  *)
(* that site knows, and holders can carry a coin from one site to another. *)
(*                                                                         *)
(*  - Two clerks, each with its own epoch sequence (per-clerk epochs). An  *)
(*    issuer mints epoch n+1 by spending epoch n; a dishonest issuer can   *)
(*    sign two versions of one epoch at different sites.                   *)
(*  - Every transfer holds the coin under a fresh ticket from a clerk the  *)
(*    recipient chooses, stamped with that clerk's epoch as the site knows *)
(*    it. A coin's history is every ticket it has been held under.         *)
(*  - Honest recipients check the sender's ticket against its clerk's     *)
(*    sequence (soft expiry: TLife epochs), the coin's mint-time ticket    *)
(*    against its own clerk's sequence (hard expiry: THard epochs), the    *)
(*    transfer limit, and refuse a sender they hold evidence against.      *)
(*  - A transfer's provenance travels with the coin. When a coin meets its *)
(*    own fork at a site, that site holds evidence: the same signer using  *)
(*    the same coin state twice. Locally, first seen wins.                 *)
(*  - Gossip, the optimization: any site may pass another site the signed  *)
(*    epochs and the evidence it holds. It never passes transfer records,  *)
(*    so gossip carries no transaction graph. Receivers check signatures:  *)
(*    an epoch must be issuer-signed, evidence must be two signed uses.    *)
(*                                                                         *)
(* Checked: gossip never makes anything worse. Consent, no forged epochs,  *)
(* no false flags, minimal disclosure on the gossip channel, honest        *)
(* recipients' expiry and evidence checks, first-seen-wins locally, and    *)
(* that once gossip has spread, every site holds every piece of evidence   *)
(* and every equivocation.                                                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Sites, People, Bad, Owner0, IssX, IssY, YUsers, Coins, MaxHops, TLife, THard, MaxEpoch,
          Gossiping, Bug

ASSUME Bad \subseteq People /\ Owner0 \in People
ASSUME {IssX, IssY} \subseteq People
ASSUME Gossiping \in BOOLEAN
ASSUME Bug \in {"none", "steal", "nolimit", "ignoreexpiry", "latestonly", "softall",
                "ignoreevidence", "forge", "fakeevidence", "gossiprecords",
                "overwrite", "positiononly"}

Clerks == {"x", "y"}
Tags == {1, 2}
Honest == People \ Bad
IssuerOf(k) == IF k = "x" THEN IssX ELSE IssY
\* Each person holds under one clerk's tickets (a modeling bound).
ClerkOf(q) == IF q \in YUsers THEN "y" ELSE "x"
Pos(r) == <<r.c, r.hop>>
Max(S) == CHOOSE n \in S : \A m \in S : n >= m

VARIABLES
    eps,       \* eps[s]: signed epoch records [k, n, tag] site s holds
    everEp,    \* every epoch record an issuer ever signed
    issSpent,  \* <<k, n>> epochs an issuer has already spent
    view,      \* view[s][c] = [owner, hop, hist, cur, mint, chain] as site s sees it
    recs,      \* recs[s]: transfer records site s has seen as provenance
    saw,       \* ghost: records site s legitimately saw (transfer or carry)
    ev,        \* ev[s]: signers site s holds gossiped evidence against
    everRecs,  \* every transfer record ever signed
    spent,     \* spent[p]: coin positions p's wallet has signed
    broken     \* ghost: which honest-recipient checks were ever skipped

vars == <<eps, everEp, issSpent, view, recs, saw, ev, everRecs, spent, broken>>

Known(s, k) == Max({e.n : e \in {f \in eps[s] : f.k = k}})

(* Evidence a site can show itself: two signed uses of one coin state by   *)
(* one signer, both in its provenance records.                             *)
Clash(r1, r2) ==
    /\ r1 # r2
    /\ Pos(r1) = Pos(r2)
    /\ (r1.from = r2.from \/ Bug = "positiononly")
OwnEvidence(s) == {r.from : r \in {r1 \in recs[s] : \E r2 \in recs[s] : Clash(r1, r2)}}
(* Epoch equivocation: two different epochs at the same number from one   *)
(* issuer's sequence, both signed.                                         *)
Equivocators(s) == {IssuerOf(e.k) : e \in {e1 \in eps[s] :
                        \E e2 \in eps[s] : e1 # e2 /\ e1.k = e2.k /\ e1.n = e2.n}}
Flagged(s) == OwnEvidence(s) \cup ev[s] \cup Equivocators(s)

Init ==
    /\ eps = [s \in Sites |-> {[k |-> k, n |-> 0, tag |-> 1] : k \in Clerks}]
    /\ everEp = {[k |-> k, n |-> 0, tag |-> 1] : k \in Clerks}
    /\ issSpent = {}
    /\ view = [s \in Sites |-> [c \in Coins |->
                 [owner |-> Owner0, hop |-> 0,
                  hist |-> {[k |-> "x", e |-> 0]},
                  cur |-> [k |-> "x", e |-> 0], mint |-> [k |-> "x", e |-> 0],
                  chain |-> {}]]]
    /\ recs = [s \in Sites |-> {}]
    /\ saw = [s \in Sites |-> {}]
    /\ ev = [s \in Sites |-> {}]
    /\ everRecs = {}
    /\ spent = [p \in People |-> {}]
    /\ broken = {}

(* An issuer rolls its sequence at the site where it is. *)
Roll(s, k, t) ==
    LET n == Known(s, k)
        e == [k |-> k, n |-> n + 1, tag |-> t]
    IN
    /\ n < MaxEpoch
    /\ e \notin everEp
    /\ IssuerOf(k) \in Bad \/ <<k, n>> \notin issSpent
    /\ eps' = [eps EXCEPT ![s] = @ \cup {e}]
    /\ everEp' = everEp \cup {e}
    /\ issSpent' = issSpent \cup {<<k, n>>}
    /\ UNCHANGED <<view, recs, saw, ev, everRecs, spent, broken>>

(* The recipient's policy (decision D1). Soft expiry on the sender's      *)
(* ticket; hard expiry from the mint-time ticket, each against its own    *)
(* clerk's sequence. Bug "latestonly" checks only the sender's ticket, so  *)
(* a coin has no lifetime from mint. Bug "softall" is the earlier, stricter *)
(* rule: soft expiry on every ticket in the history.                       *)
Expired(s, t) == Known(s, t.k) >= t.e + TLife
HardExpired(s, v) == Known(s, v.mint.k) >= v.mint.e + THard
Stale(s, v) == Expired(s, v.cur) \/ HardExpired(s, v)
InDate(s, v) ==
    CASE Bug = "latestonly" -> ~Expired(s, v.cur)
      [] Bug = "softall"    -> (\A t \in v.hist : ~Expired(s, t)) /\ ~HardExpired(s, v)
      [] OTHER              -> ~Stale(s, v)

Accepts(q, s, p, v) ==
    \/ q \in Bad
    \/ /\ InDate(s, v) \/ Bug = "ignoreexpiry"
       /\ v.hop < MaxHops \/ Bug = "nolimit"
       /\ p \notin Flagged(s) \/ Bug = "ignoreevidence"

Transfer(s, c, p, q) ==
    LET v == view[s][c]
        k == ClerkOf(q)
        tk == [k |-> k, e |-> Known(s, k)]
        r == [c |-> c, hop |-> v.hop, from |-> p, to |-> q, tk |-> tk]
        nv == [owner |-> q, hop |-> v.hop + 1, hist |-> v.hist \cup {tk},
               cur |-> tk, mint |-> v.mint, chain |-> v.chain \cup {r}]
    IN
    /\ p # q
    /\ v.owner = p \/ Bug = "steal"
    /\ v.hop < MaxHops \/ (Bug = "nolimit" /\ v.hop = MaxHops)  \* model bound
    /\ Accepts(q, s, p, v)
    /\ p \in Bad \/ Pos(r) \notin spent[p]
    /\ view' = [view EXCEPT ![s][c] = nv]
    /\ recs' = [recs EXCEPT ![s] = @ \cup {r}]
    /\ saw' = [saw EXCEPT ![s] = @ \cup {r}]
    /\ everRecs' = everRecs \cup {r}
    /\ spent' = [spent EXCEPT ![p] = @ \cup {Pos(r)}]
    /\ broken' = broken
         \cup (IF q \in Honest /\ Stale(s, v) THEN {"expiry"} ELSE {})
         \cup (IF q \in Honest /\ \E t \in v.hist : Expired(s, t) THEN {"stale"} ELSE {})
         \cup (IF q \in Honest /\ v.hop >= MaxHops THEN {"limit"} ELSE {})
         \cup (IF q \in Honest /\ p \in Flagged(s) THEN {"evidence"} ELSE {})
    /\ UNCHANGED <<eps, everEp, issSpent, ev>>

(* A holder carries a coin to another site and shows its provenance there. *)
(* If it extends what that site knows, the site adopts it; if it is a fork *)
(* of what the site already saw, the site keeps its own (first seen wins)  *)
(* and now holds both records, which is the evidence.                      *)
Carry(c, s, t) ==
    LET vs == view[s][c]
        vt == view[t][c]
    IN
    /\ s # t
    /\ vs.chain # {}
    /\ ~(vs.chain \subseteq recs[t])
    /\ recs' = [recs EXCEPT ![t] = @ \cup vs.chain]
    /\ saw' = [saw EXCEPT ![t] = @ \cup vs.chain]
    /\ view' = IF vt.chain \subseteq vs.chain \/ Bug = "overwrite"
               THEN [view EXCEPT ![t][c] = vs]
               ELSE view
    /\ UNCHANGED <<eps, everEp, issSpent, ev, everRecs, spent, broken>>

(* Gossip from x to y: signed epochs and evidence, nothing else. *)
Gossip(x, y) ==
    /\ Gossiping
    /\ x # y
    /\ \/ ~(eps[x] \subseteq eps[y])
       \/ ~(OwnEvidence(x) \cup ev[x] \subseteq ev[y])
       \/ Bug = "gossiprecords" /\ ~(recs[x] \subseteq recs[y])
    /\ eps' = [eps EXCEPT ![y] = @ \cup eps[x]]
    /\ ev' = [ev EXCEPT ![y] = @ \cup OwnEvidence(x) \cup ev[x]]
    /\ recs' = IF Bug = "gossiprecords"
               THEN [recs EXCEPT ![y] = @ \cup recs[x]] ELSE recs
    /\ UNCHANGED <<everEp, issSpent, view, saw, everRecs, spent, broken>>

(* Faults a gossiper could try if receivers skipped their checks. *)
ForgeEpoch(y, k) ==
    /\ Bug = "forge"
    /\ ~\E f \in eps[y] : f.tag = 9
    /\ eps' = [eps EXCEPT ![y] = @ \cup {[k |-> k, n |-> Known(y, k) + 1, tag |-> 9]}]
    /\ UNCHANGED <<everEp, issSpent, view, recs, saw, ev, everRecs, spent, broken>>
FakeEvidence(y, p) ==
    /\ Bug = "fakeevidence"
    /\ p \notin ev[y]
    /\ ev' = [ev EXCEPT ![y] = @ \cup {p}]
    /\ UNCHANGED <<eps, everEp, issSpent, view, recs, saw, everRecs, spent, broken>>

Next ==
    \/ \E s \in Sites, k \in Clerks, t \in Tags : Roll(s, k, t)
    \/ \E s \in Sites, c \in Coins, p, q \in People : Transfer(s, c, p, q)
    \/ \E c \in Coins, s, t \in Sites : Carry(c, s, t)
    \/ \E x, y \in Sites : Gossip(x, y)
    \/ \E y \in Sites, k \in Clerks : ForgeEpoch(y, k)
    \/ \E y \in Sites, p \in People : FakeEvidence(y, p)

Spec == Init /\ [][Next]_vars
Sym == Permutations(Sites)

-----------------------------------------------------------------------------
(* 2 Consent: every transfer was signed by whoever held that position. *)
Consent ==
    \A r \in everRecs :
        IF r.hop = 0 THEN r.from = Owner0
        ELSE \E r0 \in everRecs : r0.c = r.c /\ r0.hop = r.hop - 1 /\ r0.to = r.from

(* Receivers verify issuer signatures: no site holds an unsigned epoch. *)
NoForgedEpoch == \A s \in Sites : eps[s] \subseteq everEp

(* No false flags: no site holds evidence against an honest party. *)
NoFalseFlag == \A s \in Sites : Flagged(s) \subseteq Bad

(* 3 Minimal disclosure on the gossip channel: a site knows only the       *)
(* transfers it took part in or was shown as a coin's provenance.          *)
GossipDiscloses == \A s \in Sites : recs[s] \subseteq saw[s]

(* Expiry schema, by honest recipients: the sender's ticket was in date,   *)
(* the coin was within its lifetime from mint, each in its own sequence,   *)
(* and the transfer limit held.                                            *)
HonestAcceptsInDate == broken \cap {"expiry", "limit"} = {}

(* Witness, expected to fail: an honest recipient can take a coin with a   *)
(* soft-expired ticket earlier in its history, carried on by someone with  *)
(* a fresh one, until the coin's hard expiry (threat C6a).                 *)
NoStaleHistory == "stale" \notin broken

(* Honest recipients never take a coin from someone they hold evidence on. *)
HonestNoKnownCheat == "evidence" \notin broken

(* First seen wins locally: a site never drops a record from its chain. *)
FirstSeenWins ==
    [][\A s \in Sites, c \in Coins : view[s][c].chain \subseteq view'[s][c].chain]_vars

(* Once gossip has spread (every site holds the same epochs and evidence), *)
(* every site flags every double-signer any site has evidence on, and     *)
(* every equivocating issuer.                                              *)
Spread == \A s, t \in Sites : eps[s] = eps[t] /\ Flagged(s) = Flagged(t)
GossipComplete == \A s, t \in Sites :
    eps[s] = eps[t] /\ OwnEvidence(s) \cup ev[s] = OwnEvidence(t) \cup ev[t]
EvidenceSpreads == GossipComplete =>
    \A s \in Sites :
        /\ \A t \in Sites : OwnEvidence(t) \subseteq Flagged(s)
        /\ \A k \in Clerks :
             (\E e1, e2 \in everEp : e1 # e2 /\ e1.k = k /\ e2.k = k /\ e1.n = e2.n)
               => IssuerOf(k) \in Flagged(s)

=============================================================================
