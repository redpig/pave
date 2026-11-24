# Simulations

Toy models for comparing designs. The parameters are invented, so read the results as relative, not absolute.

- **`gossip_sim.py`**: how many people a double-spender fools with no gossip, epoch gossip (as in Briolette) or epoch-plus-evidence gossip. The town is 96 wallets in 8 neighborhoods; the cheater either stays local or roams. Run `python3 gossip_sim.py [seeds]`.
- **`gossip_tiers_sim.py`**: bytes on the wire with six epoch sequences, comparing one-tier gossip, full gossip and the two-tier design (with and without holding off on unproven hints, and with wallets carrying sequences they don't rely on). Reports victims, bytes per frame, the share of frames that fit one Meshtastic packet, and epoch lag. Run `python3 gossip_tiers_sim.py [seeds]`; it imports the town from `gossip_sim.py`.
- **`prorata_sim.py`**: long-run economics of pro-rata cumulative reward shares. It shows why unbounded early-adopter shares reward fake early orders. It comes from an earlier rewards design and is kept as the reason for the "bounded, closed cohort" rule in the principles.

Results from the current runs are in [`../formal/CivicGossip-RESULTS.md`](../formal/CivicGossip-RESULTS.md) and [`../formal/CivicTiered-RESULTS.md`](../formal/CivicTiered-RESULTS.md).
