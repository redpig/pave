#!/usr/bin/env python3
"""A neighborhood work board on pave, run as separate wallet processes.

Each person is a `pave-node` process with its own state file, talking to the
others only over local TCP when they "meet". No server is involved after
enrollment. Every step below is a JSON command on a node's stdin, which is
also how an agent would drive a wallet.

    cargo build --release -p pave-board
    python3 demo/board_demo.py [--bin target/release/pave-node]

Credentials are Briolette v1 (ECDAA over BLS12-381): each holding and each
job role uses a fresh, unlinkable credential from the wallet's prefetched
tickets. Test credit only; it has no cash value.
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
        self.group = ready["group"]

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
    for name, credit in [("alice", "100"), ("bob", "20"), ("carol", "20,20")]:
        key, req, reply = (os.path.join(d, f"{name}.{x}") for x in ("key", "join", "reply"))
        cli("join", "--key", key, "--request", req)  # on the wallet: its key never leaves
        r = cli("enroll", "--town", town_file, "--request", req, "--reply", reply, "--credit", credit)
        cli("finish", "--key", key, "--reply", reply, "--name", name, "--out", os.path.join(d, f"{name}.pave"))
        os.remove(key)
        print(f"  enrolled {name}: group {r['group']}, {r['tickets']} prefetched tickets, test credit {credit}")
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
        worker = alice("board", quiet=True)["jobs"][0]["replies"][0]["from"]
        alice("accept", job=job, worker=worker)
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
        coins = carol("whoami", quiet=True)["coins"]
        coin, other = coins[0]["state"], coins[1]["state"]
        to_bob = carol("cheat", state=coin, to=bob("receive", quiet=True)["credential"])["state"]
        carol.meet(bob)
        carol("cheat", state=coin, to=alice("receive", quiet=True)["credential"])
        carol.meet(alice)
        print(f"  bob and alice each hold a coin from carol; neither can tell yet")
        print(f"  evidence so far: bob {len(bob('evidence', quiet=True)['evidence'])}, alice {len(alice('evidence', quiet=True)['evidence'])}")

        say("4. Bob and Alice meet: the conflict surfaces, and leads only to Carol's group")
        alice.meet(bob)
        names = {alice.group: "alice", bob.group: "bob", carol.group: "carol"}
        for e in alice("evidence", quiet=True)["evidence"]:
            print(f"  evidence: state {short(e['state'])} used twice by one credential "
                  f"(linked by a {e['nym_bytes']}-byte pseudonym), ticket group {e['group']} = {RED}{names.get(e['group'], '?')}{OFF}")
        r = bob("check", quiet=True, state=to_bob)
        print(f"  bob's wallet now refuses that coin: {RED}{r['refusal']}{OFF}")
        print(f"  first seen wins: each keeps the copy they saw first; the loser holds proof for a claim")

        say("5. Carol's other coin is unlinkable, but she can't prove she isn't the cheat")
        paid = carol("spend", state=other, to=alice("receive", quiet=True)["credential"])["state"]
        carol.meet(alice)
        r = alice("check", quiet=True, state=paid)
        print(f"  alice knows of a cheat, so she asks the sender to prove it isn't one")
        print(f"  carol can't, under any credential: {RED}{r['refusal']}{OFF}")
        bobs = bob("whoami", quiet=True)["coins"]
        from_bob = bob("spend", state=bobs[0]["state"], to=alice("receive", quiet=True)["credential"])["state"]
        bob.meet(alice)
        r = alice("check", quiet=True, state=from_bob)
        print(f"  bob pays alice; his 144-byte proof links him to nothing: accept {GREEN}{r['accept']}{OFF}")
        print(f"  no town and no revocation list, and nobody else is affected")

        say("6. The town also revokes Carol's ticket group; the epoch spreads by two-tier gossip")
        bob.meet(town)  # Bob reports in when he's next online
        epoch = town("roll", revoke=[carol.group])["epoch"]
        print(f"  town rolls to epoch {epoch}, revoking group {carol.group}, for wallets that only hear from the town")
        g = alice("gossip", quiet=True, peer=town.addr)
        print(f"  alice ⇄ town gossip: hints {g['compressed_bytes']} B (one packet), "
              f"{g['wants']} want(s), proofs {g['extended_bytes']} B")
        g = bob("gossip", quiet=True, peer=alice.addr)
        print(f"  bob ⇄ alice gossip: hints {g['compressed_bytes']} B, {g['wants']} want(s), proofs {g['extended_bytes']} B")
        g = bob("gossip", quiet=True, peer=alice.addr)
        print(f"  again: {g['wants']} wants — quiet once everyone is current")

        say("7. Bob tops up his tickets when he next sees the town")
        left = bob("whoami", quiet=True)["tickets_left"]
        got = bob("refill", quiet=True, peer=town.addr, count=8)["tickets"]
        print(f"  bob had {left} unused tickets, received {got} more in group {bob.group}")
    finally:
        for n in nodes:
            n.stop()
    print(f"\n{DIM}state files in {d}{OFF}")


if __name__ == "__main__":
    main()
