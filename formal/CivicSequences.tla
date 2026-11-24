--------------------------- MODULE CivicSequences ---------------------------
(***************************************************************************)
(* The six-invariant kernel (2026-11-23, later): the kernel keeps no time.  *)
(*                                                                         *)
(*  - Epochs are a protocol schema: a sequence whose issuer mints epoch    *)
(*    n+1 by spending epoch n. A dishonest issuer can equivocate while the *)
(*    network is split (two different epoch n+1s, one per site). That is   *)
(*    the same signer using the same state twice, so it is caught as an    *)
(*    ordinary detectable conflict (invariant 6) after merge.              *)
(*  - Each site knows only the latest epoch it has seen. There is no       *)
(*    global clock.                                                        *)
(*  - Coins carry schema settings: a soft expiry and a hard expiry in the  *)
(*    issuer's epochs, and an offline-transfer limit. The kernel does not  *)
(*    enforce them. Each recipient decides: honest recipients refuse a     *)
(*    coin past its soft expiry (by the epoch they know) or past its       *)
(*    transfer limit; dishonest recipients may take anything.              *)
(*  - A swap (online only) retires a coin and issues a fresh one; the      *)
(*    swapper takes coins up to their hard expiry (the redemption window). *)
(*                                                                         *)
(* Checked: Consent (2), Conservation as one view after merge (1),         *)
(* Detectable conflict for coins and for epochs (6), no false flags,       *)
(* honest loss accounted (C4), one epoch after merge, and that honest      *)
(* recipients' acceptance policy holds the expiry and limit schema.        *)
(* A witness config shows dishonest recipients can accept expired coins    *)
(* without breaking any kernel invariant.                                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS People, Bad, Issuer, Coins, MaxHops, Life, Grace, MaxEpoch, Bug

ASSUME Bad \subseteq People /\ Issuer \in People
ASSUME Bug \in {"none", "steal", "nolimit", "ignoreexpiry", "noevidence",
                "flagrecipient", "positiononly", "noepochevidence",
                "honestrepeat"}

Sites == {"A", "B"}
Honest == People \ Bad
Tags == {1, 2}          \* two possible contents for an epoch (equivocation)
Pos(r) == <<r.c, r.gen, r.hop>>

VARIABLES
    known,     \* known[s]: latest epoch number site s has seen
    epochs,    \* epochs[s]: epoch records [n, tag] site s has seen
    everEp,    \* every epoch record the issuer ever signed
    issSpent,  \* epoch numbers the issuer has already spent (rolled from)
    connected,
    view,      \* view[s][c] = [owner, hop, gen, soft, hard]
    recs,      \* recs[s]: transfer records site s knows
    everRecs,  \* every transfer record ever signed
    base,      \* <<c, gen, owner>> at each mint or swap
    spent,     \* spent[p]: coin positions p's wallet has signed
    flagged    \* signers with evidence of double use against them

vars == <<known, epochs, everEp, issSpent, connected, view, recs, everRecs,
          base, spent, flagged>>

Init ==
    /\ known = [s \in Sites |-> 0]
    /\ epochs = [s \in Sites |-> {[n |-> 0, tag |-> 1]}]
    /\ everEp = {[n |-> 0, tag |-> 1]}
    /\ issSpent = {}
    /\ connected = TRUE
    /\ \E own \in [Coins -> People] :
         /\ view = [s \in Sites |-> [c \in Coins |->
                      [owner |-> own[c], hop |-> 0, gen |-> 0,
                       soft |-> Life, hard |-> Life + Grace]]]
         /\ base = {<<c, 0, own[c]>> : c \in Coins}
    /\ recs = [s \in Sites |-> {}]
    /\ everRecs = {}
    /\ spent = [p \in People |-> {}]
    /\ flagged = {}

(* The issuer mints the next epoch at site s by spending the current one.  *)
(* Online, both sites see it. Split, only s does; an honest issuer never   *)
(* spends the same epoch twice, a dishonest one may (with other content).  *)
Roll(s, t) ==
    LET n == known[s]
        e == [n |-> n + 1, tag |-> t]
    IN
    /\ n < MaxEpoch
    /\ e \notin everEp
    /\ Issuer \in Bad \/ n \notin issSpent \/ Bug = "honestrepeat"
    /\ IF connected
       THEN /\ known' = [x \in Sites |-> n + 1]
            /\ epochs' = [x \in Sites |-> epochs[x] \cup {e}]
       ELSE /\ known' = [known EXCEPT ![s] = n + 1]
            /\ epochs' = [epochs EXCEPT ![s] = @ \cup {e}]
    /\ everEp' = everEp \cup {e}
    /\ issSpent' = issSpent \cup {n}
    /\ UNCHANGED <<connected, view, recs, everRecs, base, spent, flagged>>

(* The recipient's policy, not the kernel's: honest recipients honor the   *)
(* coin's soft expiry against the epoch they know, and its transfer limit. *)
Accepts(q, s, v) ==
    \/ q \in Bad
    \/ /\ known[s] < v.soft \/ Bug = "ignoreexpiry"
       /\ v.hop < MaxHops \/ Bug = "nolimit"

Transfer(s, c, p, q) ==
    LET v == view[s][c]
        r == [c |-> c, gen |-> v.gen, hop |-> v.hop, from |-> p, to |-> q,
              ep |-> known[s], soft |-> v.soft]
        nv == [v EXCEPT !.owner = q, !.hop = v.hop + 1]
    IN
    /\ p # q
    /\ v.owner = p \/ Bug = "steal"
    /\ Accepts(q, s, v)
    /\ v.hop < MaxHops + 1          \* bound the model only
    /\ p \in Bad \/ Pos(r) \notin spent[p]
    /\ IF connected
       THEN /\ view' = [t \in Sites |-> [view[t] EXCEPT ![c] = nv]]
            /\ recs' = [t \in Sites |-> recs[t] \cup {r}]
       ELSE /\ view' = [view EXCEPT ![s][c] = nv]
            /\ recs' = [recs EXCEPT ![s] = @ \cup {r}]
    /\ everRecs' = everRecs \cup {r}
    /\ spent' = [spent EXCEPT ![p] = @ \cup {Pos(r)}]
    /\ UNCHANGED <<known, epochs, everEp, issSpent, connected, base, flagged>>

(* Swap with a swapper, online only: retire the coin, issue a fresh one    *)
(* with new expiries. The swapper's own presented terms: it takes coins    *)
(* up to their hard expiry (the redemption window after soft expiry).      *)
Swap(c) ==
    LET v == view["A"][c]
        n == known["A"]
    IN
    /\ connected
    /\ v.gen < 1                          \* bound the model: one swap per coin
    /\ n < v.hard
    /\ view' = [t \in Sites |-> [view[t] EXCEPT ![c] =
                  [owner |-> v.owner, hop |-> 0, gen |-> v.gen + 1,
                   soft |-> n + Life, hard |-> n + Life + Grace]]]
    /\ base' = base \cup {<<c, v.gen + 1, v.owner>>}
    /\ UNCHANGED <<known, epochs, everEp, issSpent, connected, recs, everRecs,
                   spent, flagged>>

Partition ==
    /\ connected
    /\ connected' = FALSE
    /\ UNCHANGED <<known, epochs, everEp, issSpent, view, recs, everRecs,
                   base, spent, flagged>>

AllRecs == recs["A"] \cup recs["B"]
AllEp == epochs["A"] \cup epochs["B"]

(* Coin evidence: the same signer using the same coin state twice. *)
Clash(r1, r2) ==
    /\ r1 # r2
    /\ Pos(r1) = Pos(r2)
    /\ (r1.from = r2.from \/ Bug = "positiononly")
Forked(c) == \E r1, r2 \in AllRecs : r1.c = c /\ Clash(r1, r2)
Winner(c) == IF Forked(c) \/ view["A"][c].hop >= view["B"][c].hop THEN "A" ELSE "B"

(* Epoch evidence: two different epochs at the same number, both spending *)
(* the one before. One signer (the issuer), so this is the same rule.      *)
EpClash(e1, e2) == e1 # e2 /\ e1.n = e2.n
EpForked == \E e1, e2 \in AllEp : EpClash(e1, e2)

Merge ==
    /\ ~connected
    /\ connected' = TRUE
    /\ view' = [t \in Sites |-> [c \in Coins |-> view[Winner(c)][c]]]
    /\ LET canon == {r \in AllRecs : r \in recs[Winner(r.c)]}
       IN recs' = [t \in Sites |-> canon]
    (* Fixed rule for epochs: the later number wins; on equal numbers with *)
    (* different content, site A's stands. Both records are kept.          *)
    /\ LET k == IF known["A"] >= known["B"] THEN known["A"] ELSE known["B"]
       IN known' = [t \in Sites |-> k]
    /\ epochs' = [t \in Sites |-> AllEp]
    /\ flagged' = flagged
         \cup (IF Bug = "noevidence" THEN {}
               ELSE {r1.from : r1 \in {r \in AllRecs : \E r2 \in AllRecs : Clash(r, r2)}})
         \cup (IF Bug = "flagrecipient"
               THEN {r1.to : r1 \in {r \in AllRecs : \E r2 \in AllRecs : Clash(r, r2)}}
               ELSE {})
         \cup (IF EpForked /\ Bug # "noepochevidence" THEN {Issuer} ELSE {})
    /\ UNCHANGED <<everEp, issSpent, everRecs, base, spent>>

Next ==
    \/ \E s \in Sites, t \in Tags : Roll(s, t)
    \/ \E s \in Sites, c \in Coins, p, q \in People : Transfer(s, c, p, q)
    \/ \E c \in Coins : Swap(c)
    \/ Partition \/ Merge

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* 2 Consent: every transfer was signed by whoever held that position. *)
Consent ==
    \A r \in everRecs :
        IF r.hop = 0 THEN <<r.c, r.gen, r.from>> \in base
        ELSE \E r0 \in everRecs : r0.c = r.c /\ r0.gen = r.gen
                                  /\ r0.hop = r.hop - 1 /\ r0.to = r.from

(* 1 Conservation, once merged: one view, one holder per coin. *)
OneView == connected => view["A"] = view["B"]

(* After merge every site has the same latest epoch. *)
OneEpoch == connected => known["A"] = known["B"]

(* 6 Detectable conflict, for coins: every double use flags its signer. *)
Detected == connected =>
    \A r1, r2 \in everRecs : Clash(r1, r2) => r1.from \in flagged

(* 6 Detectable conflict, for epochs: equivocation flags the issuer. *)
EpochDetected == connected =>
    ((\E e1, e2 \in everEp : EpClash(e1, e2)) => Issuer \in flagged)

(* No false flags: evidence never lands on an honest holder or issuer. *)
NoFalseFlag == flagged \subseteq Bad

(* C4: an honest party loses only what it signed away, or what it          *)
(* received on a fork whose double-signer was flagged.                      *)
HonestLossAccounted == connected =>
    \A r \in everRecs \ recs["A"] :
        r.to \in Honest =>
            \E f1, f2 \in everRecs : f1.c = r.c /\ f1.gen = r.gen
                /\ Clash(f1, f2) /\ f1.hop <= r.hop /\ f1.from \in flagged \cap Bad

(* Expiry and limit schema, held by honest recipients' policy: an honest   *)
(* recipient never took a coin past its soft expiry (by the epoch it knew) *)
(* or past its transfer limit.                                             *)
HonestAcceptsInDate ==
    \A r \in everRecs : r.to \in Honest => r.ep < r.soft /\ r.hop < MaxHops

(* Witness, expected to FAIL: the kernel itself does not stop expired      *)
(* coins from moving; a dishonest recipient may take one.                  *)
NoOneAcceptsExpired == \A r \in everRecs : r.ep < r.soft
=============================================================================
