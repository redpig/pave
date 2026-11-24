#!/usr/bin/env python3
"""Two-tier gossip: bytes on the wire and people fooled, by regime.

Same town as gossip_sim.py (96 wallets, 8 neighborhoods, sparse bridges),
now with several epoch sequences and byte accounting. Sizes follow Briolette
v1 where it has them:

  signed epoch (one sequence)   ~170 B  number 8, extended hash 32, ECDSA 64,
                                        key id 33, a 32-byte revoked-group bitfield
  evidence                      ~770 B  basename 32 + 2 x (336 B signature with
                                        nym + 32 B message digest)
  head hint (one sequence)        20 B  issuer id 8, epoch number 4, hash prefix 8
  fork hint                       10 B  coin-state hash prefix
  frame overhead                  10 B
  one short APDU                 255 B of data; one Meshtastic packet ~231 B

Regimes, each encounter, per direction:
  briolette  every signed epoch the sender holds (no evidence), Briolette's
             one-tier gossip extended to several sequences
  full       every signed epoch plus every piece of evidence it holds
  tiered     compressed: every head it knows plus its fork hints. Extended
             only when triggered: the peer has a newer signed epoch for a
             sequence the receiver relies on, or the receiver holds a coin a
             fork hint names and the peer has the proof
  tiered+wait  as tiered, and a recipient holds off a coin offline while an
             unproven fork hint names it
  tiered+wait+carry  as tiered+wait, and wallets also fetch signed epochs for
             sequences they don't rely on, so they can serve neighbors

Everyone relies on sequence 0 (the town's cash issuer, whose epochs carry the
revocation naming the cheater once a swapper sees a fork) plus one or two
others. One dishonest wallet m roams the town spending the same coin to
everyone it meets and never gossips.
"""
import random
import statistics
import sys

from gossip_sim import make_town

EPOCH_B, EVID_B, HEAD_B, FORK_B, FRAME_B, PACKET_B = 170, 770, 20, 10, 10, 231


def run(regime, seed, steps=6000, seqs=6, p_sync=0.002, p_swap=0.002,
        p_pass=0.5, p_m=0.01):
    rng = random.Random(seed)
    nodes, edges = make_town(rng)
    m = rng.choice(nodes)
    honest = [n for n in nodes if n != m]
    periods = [400] + [rng.randint(250, 700) for _ in range(seqs - 1)]
    relies = {n: {0} | set(rng.sample(range(1, seqs), rng.randint(1, 2)))
              for n in nodes}

    issuer = [0] * seqs                  # latest epoch per sequence
    revoked_at = None                    # seq-0 epoch that first names m
    swapper_seen, swapper_ev = set(), False

    signed = {n: [0] * seqs for n in nodes}   # signed epochs held
    head = {n: [0] * seqs for n in nodes}     # best head known (signed or hint)
    proof = {n: False for n in nodes}         # holds evidence against m's coin
    hint = {n: False for n in nodes}          # holds a fork hint for it
    seen = {n: set() for n in nodes}          # fork ids seen as provenance
    holding = {n: [] for n in nodes}
    next_fork = victims = 0
    bytes_dir, frames_fit, frames, extended = [], 0, 0, 0

    def knows_cheat(n):
        if proof[n]:
            return True
        return revoked_at is not None and signed[n][0] >= revoked_at

    def receive(n, f):
        if seen[n] and f not in seen[n]:
            proof[n] = hint[n] = True
        seen[n].add(f)
        holding[n].append(f)

    def send(u, w):
        """Bytes u sends w this encounter; applies what w learns."""
        nonlocal extended
        b = FRAME_B
        if regime == "briolette" or regime == "full":
            b += EPOCH_B * seqs
            for k in range(seqs):
                if signed[u][k] > signed[w][k]:
                    signed[w][k] = signed[u][k]
            head[w] = [max(a, c) for a, c in zip(head[w], signed[w])]
            if regime == "full" and proof[u]:
                b += EVID_B
                proof[w] = hint[w] = True
            return b
        # tiered: compressed tier first
        b += HEAD_B * seqs + (FORK_B if (hint[u] or proof[u]) else 0)
        head[w] = [max(a, c) for a, c in zip(head[w], head[u])]
        if hint[u] or proof[u]:
            hint[w] = True
        # extended tier, only when triggered
        ext = 0
        wanted = range(seqs) if regime.endswith("carry") else relies[w]
        for k in wanted:
            if signed[u][k] > signed[w][k]:
                signed[w][k] = signed[u][k]
                ext += EPOCH_B
        if hint[w] and not proof[w] and proof[u] and holding[w]:
            proof[w] = True
            ext += EVID_B
        if ext:
            extended += 1
            b += ext
        return b

    for t in range(steps):
        for k in range(seqs):
            if t > 0 and t % periods[k] == 0:
                issuer[k] += 1
                if k == 0 and swapper_ev and revoked_at is None:
                    revoked_at = issuer[0]
                for n in rng.sample(honest, 3):
                    signed[n][k] = head[n][k] = issuer[k]
        for n in honest:
            if rng.random() < p_sync:
                for k in relies[n]:
                    signed[n][k] = head[n][k] = max(head[n][k], issuer[k])
            if holding[n] and rng.random() < p_swap:
                for f in holding[n]:
                    if swapper_seen and f not in swapper_seen:
                        swapper_ev = True
                    swapper_seen.add(f)
                holding[n] = []

        a, b = rng.choice(edges)
        if rng.random() < p_m:
            a, b = m, rng.choice(honest)
        if m in (a, b):
            v = b if a == m else a
            refuse = knows_cheat(v) or ("wait" in regime and hint[v])
            if not refuse:
                victims += 1
                receive(v, next_fork)
                next_fork += 1
            continue

        for (u, w) in ((a, b), (b, a)):
            if holding[u] and rng.random() < p_pass:
                receive(w, holding[u].pop())
        for (u, w) in ((a, b), (b, a)):
            nb = send(u, w)
            bytes_dir.append(nb)
            frames += 1
            frames_fit += nb <= PACKET_B

    lag = statistics.mean(max(0, issuer[k] - signed[n][k])
                          for n in honest for k in relies[n])
    return dict(victims=victims, mean_b=statistics.mean(bytes_dir),
                p99_b=sorted(bytes_dir)[int(0.99 * (len(bytes_dir) - 1))],
                fit=frames_fit / frames, ext=extended / frames, lag=lag)


def main():
    seeds = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    print(f"{seeds} seeds; 96 wallets, 8 neighborhoods, 6 sequences, roaming cheater")
    print(f"{'regime':18} {'victims':>9} {'bytes/frame':>12} {'p99':>6} "
          f"{'1 packet':>9} {'extended':>9} {'epoch lag':>10}")
    for regime in ("briolette", "full", "tiered", "tiered+wait", "tiered+wait+carry"):
        rs = [run(regime, s) for s in range(seeds)]
        med = lambda key: statistics.median(r[key] for r in rs)
        print(f"{regime:18} {med('victims'):>9.0f} {med('mean_b'):>12.0f} "
              f"{med('p99_b'):>6.0f} {med('fit'):>8.0%} {med('ext'):>9.1%} "
              f"{med('lag'):>10.2f}")


if __name__ == "__main__":
    main()
