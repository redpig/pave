----------------------------- MODULE CivicTiered -----------------------------
(***************************************************************************)
(* Two-tier gossip: a compressed tier of hints that switches to an        *)
(* extended tier of proofs when a hint calls for it.                       *)
(*                                                                         *)
(* Same world as CivicGossip.tla: three sites, no hub, two clerk sequences, *)
(* tickets checked across a coin's history, provenance carried with the    *)
(* coin, first seen wins locally. Gossip now has two tiers:                *)
(*                                                                         *)
(*  - Compressed: hints only. A head hint names a sequence, an epoch       *)
(*    number and a tag (the hash prefix); a fork hint names a coin state   *)
(*    (coin, position). Hints are unsigned and anyone, including a         *)
(*    dishonest party, can inject false ones.                              *)
(*  - Extended: proofs. Signed epochs and evidence items (the signer and   *)
(*    the coin state it used twice, standing for the two signatures).      *)
(*    It runs only when a hint the receiver holds names something the      *)
(*    sender can prove and the receiver can't.                             *)
(*  - A hint never flags anyone and never moves an epoch. As its own       *)
(*    policy (HintWait), an honest recipient may hold off accepting a coin *)
(*    offline while an unproven fork hint names it.                        *)
(*                                                                         *)
(* Checked: the CivicGossip safety properties, plus that hints never       *)
(* decide (no flag and no epoch from a hint, even with injected false      *)
(* hints) and that hints suffice: once hints have spread and no exchange   *)
(* is still triggered, every site holds every signed epoch and every       *)
(* piece of evidence.                                                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Sites, People, Bad, Owner0, IssX, IssY, YUsers, Clerks, Coins, MaxHops,
          TLife, MaxEpoch, HintWait, FakeHops, Bug

ASSUME Bad \subseteq People /\ Owner0 \in People
ASSUME {IssX, IssY} \subseteq People
ASSUME HintWait \in BOOLEAN
ASSUME Bug \in {"none", "trusthint", "hintepoch", "notrigger", "forge",
                "ignoreevidence", "gossiprecords", "overwrite"}

Tags == {1, 2}
Honest == People \ Bad
IssuerOf(k) == IF k = "x" THEN IssX ELSE IssY
ClerkOf(q) == IF q \in YUsers THEN "y" ELSE "x"
Pos(r) == <<r.c, r.hop>>
Max(S) == CHOOSE n \in S : \A m \in S : n >= m

(* False hints a dishonest party can inject: a fork hint at each position *)
(* in FakeHops, and a head for an epoch no issuer will ever sign.         *)
FakeHints ==
    {[t |-> "fork", c |-> c, hop |-> h] : c \in Coins, h \in FakeHops}
    \cup {[t |-> "head", k |-> k, n |-> MaxEpoch + 1, tag |-> 3] : k \in Clerks}

VARIABLES
    eps,       \* eps[s]: signed epoch records [k, n, tag] site s holds
    everEp,    \* every epoch record an issuer ever signed
    issSpent,  \* <<k, n>> epochs an issuer has already spent
    view,      \* view[s][c] = [owner, hop, hist, chain]
    recs,      \* recs[s]: transfer records site s has seen as provenance
    saw,       \* ghost: records site s legitimately saw
    ev,        \* ev[s]: evidence items [p, c, hop] received by extended gossip
    hints,     \* hints[s]: hints received by compressed gossip
    everRecs,
    spent,
    broken     \* ghost: honest-recipient checks ever skipped, or hint delays

vars == <<eps, everEp, issSpent, view, recs, saw, ev, hints, everRecs, spent,
          broken>>

(* What a site "knows" about a sequence: signed epochs only, unless the    *)
(* hintepoch fault also counts unsigned head hints.                        *)
HeadsUsed(s, k) ==
    {e.n : e \in {f \in eps[s] : f.k = k}}
    \cup (IF Bug = "hintepoch"
          THEN {h.n : h \in {g \in hints[s] : g.t = "head" /\ g.k = k}} ELSE {})
Known(s, k) == Max(HeadsUsed(s, k))

Clash(r1, r2) == r1 # r2 /\ Pos(r1) = Pos(r2) /\ r1.from = r2.from
OwnEv(s) == {[p |-> r.from, c |-> r.c, hop |-> r.hop] :
                r \in {r1 \in recs[s] : \E r2 \in recs[s] : Clash(r1, r2)}}
EvAll(s) == OwnEv(s) \cup ev[s]
Equivocators(s) == {IssuerOf(e.k) : e \in {e1 \in eps[s] :
                        \E e2 \in eps[s] : e1 # e2 /\ e1.k = e2.k /\ e1.n = e2.n}}
(* trusthint: a fork hint is taken as evidence against whoever signed that *)
(* position in the site's own records.                                     *)
HintBlamed(s) ==
    IF Bug = "trusthint"
    THEN {r.from : r \in {r1 \in recs[s] : \E h \in hints[s] :
                              h.t = "fork" /\ h.c = r1.c /\ h.hop = r1.hop}}
    ELSE {}
Flagged(s) == {e.p : e \in EvAll(s)} \cup Equivocators(s) \cup HintBlamed(s)

(* The hints a site makes from what it can prove. *)
HintsOf(s) ==
    {[t |-> "head", k |-> e.k, n |-> e.n, tag |-> e.tag] : e \in eps[s]}
    \cup {[t |-> "fork", c |-> e.c, hop |-> e.hop] : e \in EvAll(s)}

(* x can prove hint h and y can't: this is what triggers an extended run. *)
Proves(x, h) ==
    IF h.t = "head" THEN [k |-> h.k, n |-> h.n, tag |-> h.tag] \in eps[x]
    ELSE \E e \in EvAll(x) : e.c = h.c /\ e.hop = h.hop
Lacks(y, x, h) ==
    IF h.t = "head" THEN [k |-> h.k, n |-> h.n, tag |-> h.tag] \notin eps[y]
    ELSE \E e \in EvAll(x) : e.c = h.c /\ e.hop = h.hop /\ e \notin EvAll(y)
(* Whether the implementation would ask: notrigger never asks on fork hints. *)
Asks(y, h) == Bug # "notrigger" \/ h.t = "head"
Triggered(x, y) ==
    \E h \in hints[y] : Asks(y, h) /\ Proves(x, h) /\ Lacks(y, x, h)

Init ==
    /\ eps = [s \in Sites |-> {[k |-> k, n |-> 0, tag |-> 1] : k \in Clerks}]
    /\ everEp = {[k |-> k, n |-> 0, tag |-> 1] : k \in Clerks}
    /\ issSpent = {}
    /\ view = [s \in Sites |-> [c \in Coins |->
                 [owner |-> Owner0, hop |-> 0,
                  hist |-> {[k |-> "x", e |-> 0, at |-> "mint"]}, chain |-> {}]]]
    /\ recs = [s \in Sites |-> {}]
    /\ saw = [s \in Sites |-> {}]
    /\ ev = [s \in Sites |-> {}]
    /\ hints = [s \in Sites |-> {}]
    /\ everRecs = {}
    /\ spent = [p \in People |-> {}]
    /\ broken = {}

Roll(s, k, t) ==
    LET n == Max({e.n : e \in {f \in eps[s] : f.k = k}})
        e == [k |-> k, n |-> n + 1, tag |-> t]
    IN
    /\ n < MaxEpoch
    /\ e \notin everEp
    /\ IssuerOf(k) \in Bad \/ <<k, n>> \notin issSpent
    /\ eps' = [eps EXCEPT ![s] = @ \cup {e}]
    /\ everEp' = everEp \cup {e}
    /\ issSpent' = issSpent \cup {<<k, n>>}
    /\ UNCHANGED <<view, recs, saw, ev, hints, everRecs, spent, broken>>

Expired(s, t) == Known(s, t.k) >= t.e + TLife
InDate(s, h) == \A t \in h : ~Expired(s, t)
(* An unproven fork hint names this coin at or before its current position. *)
HintedUnproven(s, c, hop) ==
    \E h \in hints[s] : h.t = "fork" /\ h.c = c /\ h.hop <= hop
                        /\ ~\E e \in EvAll(s) : e.c = c /\ e.hop = h.hop

Accepts(q, s, p, v, c) ==
    \/ q \in Bad
    \/ /\ InDate(s, v.hist)
       /\ v.hop < MaxHops
       /\ p \notin Flagged(s) \/ Bug = "ignoreevidence"
       /\ ~(HintWait /\ HintedUnproven(s, c, v.hop))

Transfer(s, c, p, q) ==
    LET v == view[s][c]
        k == ClerkOf(q)
        tk == [k |-> k, e |-> Known(s, k), at |-> s]   \* a fresh ticket
        r == [c |-> c, hop |-> v.hop, from |-> p, to |-> q, tk |-> tk]
        nv == [owner |-> q, hop |-> v.hop + 1, hist |-> v.hist \cup {tk},
               chain |-> v.chain \cup {r}]
    IN
    /\ p # q
    /\ v.owner = p
    /\ v.hop < MaxHops
    /\ Accepts(q, s, p, v, c)
    /\ p \in Bad \/ Pos(r) \notin spent[p]
    /\ view' = [view EXCEPT ![s][c] = nv]
    /\ recs' = [recs EXCEPT ![s] = @ \cup {r}]
    /\ saw' = [saw EXCEPT ![s] = @ \cup {r}]
    /\ everRecs' = everRecs \cup {r}
    /\ spent' = [spent EXCEPT ![p] = @ \cup {Pos(r)}]
    /\ broken' = broken
         \cup (IF q \in Honest /\ ~(\A t \in v.hist :
                  Max({e.n : e \in {f \in eps[s] : f.k = t.k}}) < t.e + TLife)
               THEN {"expiry"} ELSE {})
         \cup (IF q \in Honest /\ p \in {e.p : e \in EvAll(s)} \cup Equivocators(s)
               THEN {"evidence"} ELSE {})
    /\ UNCHANGED <<eps, everEp, issSpent, ev, hints>>

(* Ghost only: an honest recipient was held off by a fork hint that no    *)
(* site anywhere can prove (a false hint). Records the delay; changes     *)
(* nothing else.                                                           *)
HintDelay(s, c, p, q) ==
    LET v == view[s][c] IN
    /\ HintWait
    /\ q \in Honest /\ p # q /\ v.owner = p /\ v.hop < MaxHops
    /\ "falsehintdelay" \notin broken
    /\ \E h \in hints[s] : h.t = "fork" /\ h.c = c /\ h.hop <= v.hop
         /\ ~\E t \in Sites : \E d \in EvAll(t) : d.c = c /\ d.hop = h.hop
    /\ broken' = broken \cup {"falsehintdelay"}
    /\ UNCHANGED <<eps, everEp, issSpent, view, recs, saw, ev, hints, everRecs,
                   spent>>

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
               THEN [view EXCEPT ![t][c] = vs] ELSE view
    /\ UNCHANGED <<eps, everEp, issSpent, ev, hints, everRecs, spent, broken>>

(* Compressed tier: hints only, relayed as well as made. *)
Compressed(x, y) ==
    /\ x # y
    /\ ~(HintsOf(x) \cup hints[x] \subseteq hints[y])
    /\ hints' = [hints EXCEPT ![y] = @ \cup HintsOf(x) \cup hints[x]]
    /\ UNCHANGED <<eps, everEp, issSpent, view, recs, saw, ev, everRecs, spent,
                   broken>>

(* Extended tier: y asks x for the proof behind one hint it holds, and x  *)
(* sends just that (have/want). notrigger: fork hints never ask.          *)
Extended(x, y, h) ==
    /\ x # y
    /\ h \in hints[y]
    /\ Asks(y, h)
    /\ Proves(x, h) /\ Lacks(y, x, h)
    /\ IF h.t = "head"
       THEN /\ eps' = [eps EXCEPT ![y] = @ \cup {[k |-> h.k, n |-> h.n, tag |-> h.tag]}]
            /\ ev' = ev
       ELSE /\ ev' = [ev EXCEPT ![y] = @ \cup
                        {e \in EvAll(x) : e.c = h.c /\ e.hop = h.hop}]
            /\ eps' = eps
    /\ recs' = IF Bug = "gossiprecords"
               THEN [recs EXCEPT ![y] = @ \cup recs[x]] ELSE recs
    /\ UNCHANGED <<everEp, issSpent, view, saw, hints, everRecs, spent, broken>>

InjectHint(y, h) ==
    /\ \A s \in Sites : h \notin hints[s]   \* inject once; relays spread it
    /\ hints' = [hints EXCEPT ![y] = @ \cup {h}]
    /\ UNCHANGED <<eps, everEp, issSpent, view, recs, saw, ev, everRecs, spent,
                   broken>>

(* forge: the extended tier keeps an unsigned epoch named by a false head. *)
ForgeEpoch(y) ==
    /\ Bug = "forge"
    /\ \E h \in hints[y] : h.t = "head" /\ h.tag = 3
         /\ [k |-> h.k, n |-> h.n, tag |-> 3] \notin eps[y]
         /\ eps' = [eps EXCEPT ![y] = @ \cup {[k |-> h.k, n |-> h.n, tag |-> 3]}]
    /\ UNCHANGED <<everEp, issSpent, view, recs, saw, ev, hints, everRecs, spent,
                   broken>>

Next ==
    \/ \E s \in Sites, k \in Clerks, t \in Tags : Roll(s, k, t)
    \/ \E s \in Sites, c \in Coins, p, q \in People : Transfer(s, c, p, q)
    \/ \E s \in Sites, c \in Coins, p, q \in People : HintDelay(s, c, p, q)
    \/ \E c \in Coins, s, t \in Sites : Carry(c, s, t)
    \/ \E x, y \in Sites : Compressed(x, y)
    \/ \E x, y \in Sites, h \in UNION {hints[z] : z \in Sites} : Extended(x, y, h)
    \/ \E y \in Sites, h \in FakeHints : InjectHint(y, h)
    \/ \E y \in Sites : ForgeEpoch(y)

Spec == Init /\ [][Next]_vars
Sym == Permutations(Sites)

-----------------------------------------------------------------------------
Consent ==
    \A r \in everRecs :
        IF r.hop = 0 THEN r.from = Owner0
        ELSE \E r0 \in everRecs : r0.c = r.c /\ r0.hop = r.hop - 1 /\ r0.to = r.from

NoForgedEpoch == \A s \in Sites : eps[s] \subseteq everEp

(* Hints never decide: every epoch a site judges expiry by was signed. *)
KnownIsSigned ==
    \A s \in Sites, k \in Clerks : \E e \in everEp : e.k = k /\ e.n = Known(s, k)

NoFalseFlag == \A s \in Sites : Flagged(s) \subseteq Bad

GossipDiscloses == \A s \in Sites : recs[s] \subseteq saw[s]

HonestAcceptsInDate == "expiry" \notin broken
HonestNoKnownCheat == "evidence" \notin broken

FirstSeenWins ==
    [][\A s \in Sites, c \in Coins : view[s][c].chain \subseteq view'[s][c].chain]_vars

(* Hints suffice: once every site holds every hint and no extended run is *)
(* still triggered, every site holds every signed epoch any site holds,   *)
(* every piece of evidence, and so flags every double-signer and every    *)
(* equivocating issuer.                                                    *)
Quiet ==
    /\ \A x, y \in Sites : HintsOf(x) \cup hints[x] \subseteq hints[y]
    /\ ~\E x, y \in Sites : x # y /\ Triggered(x, y)
HintsSuffice == Quiet =>
    \A x, y \in Sites :
        /\ eps[x] \subseteq eps[y]
        /\ EvAll(x) \subseteq EvAll(y)

(* Witness, expected to FAIL with HintWait: a false fork hint can hold off *)
(* an honest recipient. That delay is the whole cost of a false hint.      *)
NoFalseHintDelay == "falsehintdelay" \notin broken
=============================================================================
