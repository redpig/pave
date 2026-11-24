#!/usr/bin/env python3
"""Gossip benefit: how many people a double-spender can fool, with and without gossip.

The TLA+ model (CivicGossip.tla) shows gossip can't make anything worse. This
measures how much better it makes things, under three regimes:

  none      no gossip. Wallets learn new epochs (which carry the issuer's
            revocation list) only when they sync online.
  epoch     Briolette-style: every transaction also exchanges the latest
            signed epoch, so revocations ride epochs peer to peer.
  evidence  epoch gossip plus evidence gossip (new here): a wallet that sees a
            coin meet its own fork holds self-certifying evidence (two signed
            uses of one coin state by one signer) and passes it on with every
            transaction, without waiting for the issuer's next epoch.

The world:
  - Neighborhood clusters with sparse links between them (a mesh-like town).
  - Each step a random edge transacts. Honest wallets pass on coins they hold
    and gossip as their regime allows.
  - One dishonest wallet m holds one coin. At every encounter it tries to spend
    that same coin to the neighbor (a fresh fork). It never gossips.
  - A neighbor refuses m if it holds evidence against m, or an epoch whose
    revocation list names m.
  - Evidence forms when a wallet receives a fork of a coin while holding the
    provenance of another fork, or when a holder swaps online and the swapper
    has already seen another fork. The swapper's evidence goes into the
    issuer's next epoch.

Metrics (median and 90th percentile over seeds):
  victims       honest wallets that accepted a fork from m
  late_victims  victims fooled after evidence already existed somewhere
  t_known90     steps until 90% of honest wallets would refuse m
"""
import random
import statistics
import sys


def make_town(rng, clusters=8, size=12, p_in=0.35, bridges=10):
    nodes = list(range(clusters * size))
    edges = set()
    for c in range(clusters):
        members = nodes[c * size:(c + 1) * size]
        for i in members:
            for j in members:
                if i < j and rng.random() < p_in:
                    edges.add((i, j))
        # keep each cluster connected with a ring
        for a, b in zip(members, members[1:] + members[:1]):
            edges.add((min(a, b), max(a, b)))
    for _ in range(bridges):
        a, b = rng.sample(nodes, 2)
        if a // size != b // size:
            edges.add((min(a, b), max(a, b)))
    return nodes, sorted(edges)


def run(regime, seed, steps=6000, epoch_every=400, p_sync=0.002, p_swap=0.002,
        p_pass=0.5, mobile=False, p_m=0.01):
    rng = random.Random(seed)
    nodes, edges = make_town(rng)
    m = rng.choice(nodes)
    honest = [n for n in nodes if n != m]
    adj_edges = edges

    issuer_epoch = 0
    issuer_revoked_at = None        # epoch number whose list first names m
    swapper_seen = set()            # fork ids the swapper has seen
    swapper_evidence = False

    epoch = {n: 0 for n in nodes}       # latest epoch each wallet holds
    evidence = {n: False for n in nodes}  # holds evidence against m
    seen_forks = {n: set() for n in nodes}  # provenance seen: fork ids
    holding = {n: [] for n in nodes}    # fork ids of m's coin each holds
    next_fork = 0
    victims = 0
    late_victims = 0
    evidence_exists = False
    t_known90 = None

    def knows(n):
        if evidence[n]:
            return True
        return issuer_revoked_at is not None and epoch[n] >= issuer_revoked_at

    def receive(n, fork):
        nonlocal evidence_exists
        if seen_forks[n] and fork not in seen_forks[n]:
            evidence[n] = True
            evidence_exists = True
        seen_forks[n].add(fork)
        holding[n].append(fork)

    for t in range(steps):
        # issuer rolls; the new epoch names m if the swapper had evidence
        if t > 0 and t % epoch_every == 0:
            issuer_epoch += 1
            if swapper_evidence and issuer_revoked_at is None:
                issuer_revoked_at = issuer_epoch
            # seed: a few online wallets fetch it straight away
            for n in rng.sample(honest, 3):
                epoch[n] = issuer_epoch

        # background online syncs and swaps
        for n in honest:
            if rng.random() < p_sync:
                epoch[n] = issuer_epoch
            if holding[n] and rng.random() < p_swap:
                for f in holding[n]:
                    if swapper_seen and f not in swapper_seen:
                        swapper_evidence = True
                        evidence_exists = True
                    swapper_seen.add(f)
                holding[n] = []

        a, b = rng.choice(adj_edges)
        if mobile and rng.random() < p_m:
            a, b = m, rng.choice(honest)   # m works the whole town
        if m in (a, b):
            v = b if a == m else a
            if not knows(v):
                victims += 1
                if evidence_exists:
                    late_victims += 1
                receive(v, next_fork)
                next_fork += 1
            continue  # m never gossips

        # honest transaction: maybe pass a held fork along
        for (u, w) in ((a, b), (b, a)):
            if holding[u] and rng.random() < p_pass:
                f = holding[u].pop()
                receive(w, f)
        # gossip
        if regime in ("epoch", "evidence"):
            e = max(epoch[a], epoch[b])
            epoch[a] = epoch[b] = e
        if regime == "evidence" and (evidence[a] or evidence[b]):
            evidence[a] = evidence[b] = True

        if t_known90 is None and evidence_exists:
            if sum(knows(n) for n in honest) >= 0.9 * len(honest):
                t_known90 = t
    return victims, late_victims, (t_known90 if t_known90 is not None else steps)


def summarize(xs):
    xs = sorted(xs)
    return statistics.median(xs), xs[int(0.9 * (len(xs) - 1))]


def main():
    seeds = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    for mobile in (False, True):
      who = "m moves around town" if mobile else "m stays in its neighborhood"
      print(f"\n{seeds} seeds, 96 wallets in 8 neighborhoods, 6000 steps, epoch every 400; {who}")
      print(f"{'regime':10} {'victims med/p90':>16} {'late med/p90':>14} {'t_known90 med/p90':>19}")
      for regime in ("none", "epoch", "evidence"):
        res = [run(regime, s, mobile=mobile) for s in range(seeds)]
        v = summarize([r[0] for r in res])
        lv = summarize([r[1] for r in res])
        tk = summarize([r[2] for r in res])
        print(f"{regime:10} {v[0]:>7.0f} / {v[1]:<6.0f} {lv[0]:>6.0f} / {lv[1]:<5.0f} {tk[0]:>8.0f} / {tk[1]:<8.0f}")


if __name__ == "__main__":
    main()
