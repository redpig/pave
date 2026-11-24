#!/usr/bin/env python3
"""A neighborhood work board on pave, run as separate wallet processes.

Each person is a `pave-node` process with its own state file, talking to the
others only over local TCP when they "meet". No server is involved after
enrollment. Every step below is a JSON command on a node's stdin, which is
also how an agent would drive a wallet.

    cargo build --release -p pave-board
    python3 demo/board_demo.py [--bin target/release/pave-node]

Test credit only; it has no cash value.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

BOLD, DIM, RED, GREEN, OFF = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[0m"
if not sys.stdout.isatty():
    BOLD = DIM = RED = GREEN = OFF = ""


class Node:
    def __init__(self, binary, state, port, name):
        self.name, self.addr = name, f"127.0.0.1:{port}"
        self.p = subprocess.Popen([binary, "run", "--state", state, "--listen", self.addr],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        ready = json.loads(self.p.stdout.readline())
        self.me = ready["me"]

    def __call__(self, cmd, quiet=False, **kw):
        req = {"cmd": cmd, **kw}
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        r = json.loads(self.p.stdout.readline())
        if not quiet:
            shown = {k: (v[:12] + "…" if isinstance(v, str) and len(v) > 16 else v) for k, v in kw.items()}
            print(f"  {DIM}{self.name:>5} ▸ {cmd} {json.dumps(shown) if shown else ''}{OFF}")
        if not r.get("ok"):
            raise SystemExit(f"{RED}{self.name} {cmd} failed: {r.get('error')}{OFF}")
        return r

    def meet(self, other):
        r = self(("meet"), quiet=True, peer=other.addr)
        print(f"  {DIM}{self.name:>5} ⇄ {other.name} meet ({r['bytes']} B){OFF}")
        return r

    def stop(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


def say(text):
    print(f"\n{BOLD}{text}{OFF}")


def short(h):
    return h[:8]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/pave-node")
    ap.add_argument("--port", type=int, default=7400)
    args = ap.parse_args()
    d = tempfile.mkdtemp(prefix="pave-demo-")
    town_file = os.path.join(d, "town.pave")

    def cli(*a):
        out = subprocess.run([args.bin, *a], check=True, capture_output=True, text=True).stdout
        return json.loads(out)

    say("At the town office (online, once): create the town and enroll three neighbors")
    cli("init", "--town", town_file, "--label", "Elm Street")
    people = {}
    for name, credit in [("alice", 100), ("bob", 20), ("carol", 20)]:
        r = cli("enroll", "--town", town_file, "--name", name, "--out", os.path.join(d, f"{name}.pave"), "--credit", str(credit))
        print(f"  enrolled {name}: ticket + {credit} test credit")
    nodes = [Node(args.bin, town_file, args.port, "town")]
    for i, name in enumerate(["alice", "bob", "carol"]):
        people[name] = Node(args.bin, os.path.join(d, f"{name}.pave"), args.port + 1 + i, name)
    town, alice, bob, carol = nodes[0], people["alice"], people["bob"], people["carol"]
    nodes += [alice, bob, carol]

    try:
        say("1. Offline: Alice posts a job, with proof she holds the pay")
        job = alice("post", title="Fix the back fence", pay=30)["job"]
        alice.meet(bob)
        jobs = bob("board", quiet=True)["jobs"]
        print(f"  bob sees: “{jobs[0]['title']}”, pay {jobs[0]['pay']}, {jobs[0]['status']}")

        say("2. Bob replies; Alice accepts him; Bob finishes; Alice pays")
        bob("reply", job=job, note="I can do it Saturday")
        bob.meet(alice)
        alice("accept", job=job, worker=bob.me)
        alice.meet(bob)
        bob("done", job=job)
        bob.meet(alice)
        payment = alice("pay", job=job)["payment"]
        alice.meet(bob)
        check = bob("check", state=payment)
        status = bob("board", quiet=True)["jobs"][0]["status"]
        print(f"  job is {status}; bob's wallet would accept the payment: {GREEN}{check['accept']}{OFF}")
        print(f"  balances: alice {alice('whoami', quiet=True)['balance']}, bob {bob('whoami', quiet=True)['balance']}")

        say("3. Offline: Carol spends the same 20 twice, to Bob and to Alice")
        coin = carol("whoami", quiet=True)["coins"][0]["state"]
        to_bob = carol("cheat", state=coin, to=bob.me)["state"]
        carol.meet(bob)
        carol("cheat", state=coin, to=alice.me)
        carol.meet(alice)
        print(f"  bob and alice each hold a coin from carol; neither can tell yet")
        print(f"  evidence so far: bob {len(bob('evidence', quiet=True)['evidence'])}, alice {len(alice('evidence', quiet=True)['evidence'])}")

        say("4. Bob and Alice meet: the conflict surfaces, naming only Carol")
        r = alice.meet(bob)
        ev = alice("evidence", quiet=True)["evidence"]
        names = {alice.me: "alice", bob.me: "bob", carol.me: "carol"}
        for e in ev:
            print(f"  evidence: state {short(e['state'])} used twice by {RED}{names.get(e['signer'], '?')}{OFF}")
        print(f"  flagged at alice: {[names[c] for c in alice('whoami', quiet=True)['flagged']]}, at bob: {[names[c] for c in bob('whoami', quiet=True)['flagged']]}")
        r = bob("check", quiet=True, state=to_bob)
        print(f"  bob's wallet now refuses carol's coin: {RED}{r['refusal']}{OFF}")
        print(f"  first seen wins: each keeps the copy they saw first; the loser holds proof for a claim")

        say("5. The town learns, revokes Carol's ticket group, and the news spreads by two-tier gossip")
        bob.meet(town)  # Bob reports in when he's next online
        group = carol("whoami", quiet=True)["group"]
        epoch = town("roll", revoke=[group])["epoch"]
        print(f"  town rolls to epoch {epoch}, revoking group {group}")
        g = alice("gossip", quiet=True, peer=town.addr)
        print(f"  alice ⇄ town gossip: hints {g['compressed_bytes']} B (one packet), "
              f"{g['wants']} want(s), proofs {g['extended_bytes']} B")
        g = bob("gossip", quiet=True, peer=alice.addr)
        print(f"  bob ⇄ alice gossip: hints {g['compressed_bytes']} B, {g['wants']} want(s), proofs {g['extended_bytes']} B")
        print(f"  epoch now: alice {alice('whoami', quiet=True)['epoch']}, bob {bob('whoami', quiet=True)['epoch']}")
        g = bob("gossip", quiet=True, peer=alice.addr)
        print(f"  again: {g['wants']} wants — quiet once everyone is current")
    finally:
        for n in nodes:
            n.stop()
    print(f"\n{DIM}state files in {d}{OFF}")


if __name__ == "__main__":
    main()
