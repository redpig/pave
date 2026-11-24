# CivicStanding TLA+ results (2026-11-24, TLC 1.8.0)

A cheat holds many coins, each under its own unlinkable credential, and evidence of a double spend names only one of them. This model checks how pave stops the rest, and how revocation by ticket group and by class behaves.

## What is modeled

- **Sites.** Two sites, each with its own view of every coin. A dishonest holder can sign one coin position at both.
- **Credentials.** Every holding is under a fresh credential `<<person, coin, hop>>`, in a ticket group of the holder's class, stamped with the epoch the site knows.
- **Evidence.** Evidence forms where both uses of a credential meet (`Detect`) and spreads by gossip.
- **Standing.** A recipient that holds evidence on any of a person's credentials refuses every credential of that person. In the code this is the non-revoked proof: only the cheat's key can't produce it.
- **The clerk.** One honest clerk rolls epochs, revoking any set of groups or closing a whole class (which revokes every group of that class). Sites learn its epochs by `Sync`.
- **Revocation window.** A revoked group always stops the coin's last hop; an earlier hop only if its ticket was issued within `W` epochs before the revocation.
- Expiry is left to CivicGossip.

## Properties

| Property | What it says |
|---|---|
| NoFalseFlag | Evidence only ever names a credential that signed one position twice. |
| CheatStopped | Wherever a site holds evidence on any of a cheat's credentials, honest recipients there take nothing from any of them. |
| Contained | Honest recipients never take a coin whose sender's ticket is in a revoked group, or with an earlier hop through a revoked group issued within W epochs before the revocation. |
| ClassContained | Once a site knows a class is closed, honest recipients there take nothing sent from that class's tickets. |
| NoStranding | An honest holder whose coin is clean (its own ticket not revoked, no recent hop through a revoked group) can always pay another honest person at its site. |

## Runs

Constants: People {a, b, m}, Bad {m}; a is in class hw, b and m in class sw; Groups {1 (hw), 2 (sw)}; m holds both coins; MaxEpoch 2, W 1; symmetry over sites and coins.

| Config | Result |
|---|---|
| Safe, MaxHops 3 | No error, 6,904,236 distinct states, depth 18 (exhaustive, 19 min on two cores) |
| Safe, MaxHops 2 (no symmetry) | No error, 210,446 distinct states (exhaustive) |
| Bug nostanding (refuse only the credential evidence names) | CheatStopped violated |
| Bug nowindow (a revoked group anywhere in the history stops the coin) | NoStranding violated |
| Bug nolasthop (the sender's own revoked ticket doesn't stop the coin) | Contained violated |
| Bug noclassrevoke (closing a class doesn't revoke its groups) | ClassContained violated |
| Bug fakeevidence (a site keeps evidence on an honest credential) | NoFalseFlag violated |

Five injected faults, each caught.

## Findings

1. **Standing stops the cheat everywhere evidence reaches, and only the cheat.** CheatStopped and NoFalseFlag hold together. Without standing (the nostanding fault), the cheat's other coins pass.
2. **The window is what keeps honest coins spendable.** Tainting the whole history (nowindow) strands an honest holder whose coin passed through a group long before it was revoked. The windowed rule contains recent hops and strands nobody clean.
3. **The last hop must always count.** Exempting the sender's own ticket (nolasthop) lets a revoked group keep paying out.
4. **Closing a class must revoke its groups.** Merely closing it to new tickets (noclassrevoke) lets its existing tickets keep sending.
