--------------------------- MODULE CivicStandingMC ---------------------------
(* Constants for CivicStanding: two honest people (one per class), one      *)
(* cheat in the software class holding both coins, two ticket groups.      *)
EXTENDS CivicStanding, TLC
CONSTANTS a, b, m, c1, c2
MCClass == [p \in People |-> IF p = a THEN "hw" ELSE "sw"]
MCGroupClass == [g \in Groups |-> IF g = 1 THEN "hw" ELSE "sw"]
MCHolder0 == [c \in Coins |-> m]
\* Sites are interchangeable, and so are the cheat's two coins.
MCSym == Permutations(Sites) \cup Permutations(Coins)
=============================================================================
