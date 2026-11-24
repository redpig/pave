#!/usr/bin/env python3
"""A neighborhood work board on pave, run as separate wallet processes.

Each person is a `pave-node` process with its own state file. Money moves
wallet to wallet when two people "meet" over local TCP, with no server.
Job posts are content, so they go to the board the town hosts, as posts to
any website would. Every step below is a JSON command on a node's stdin,
which is also how an agent would drive a wallet.

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

    def __call__(self, cmd, quiet=False, may_fail=False, **kw):
        req = {"cmd": cmd, **kw}
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        r = json.loads(self.p.stdout.readline())
        if not quiet:
            shown = {k: (v[:12] + "…" if isinstance(v, str) and len(v) > 16 else v) for k, v in kw.items()}
            print(f"  {DIM}{self.name:>5} ▸ {cmd} {json.dumps(shown) if shown else ''}{OFF}")
        if not r.get("ok") and not may_fail:
            raise SystemExit(f"{RED}{self.name} {cmd} failed: {r.get('error')}{OFF}")
        return r

    def meet(self, other):
        r = self(("meet"), quiet=True, peer=other.addr)
        print(f"  {DIM}{self.name:>5} ⇄ {other.name} meet ({r['bytes']} B){OFF}")
        return r

    def sync(self, host):
        r = self(("sync"), quiet=True, peer=host.addr)
        print(f"  {DIM}{self.name:>5} → {host.name} board: sent {r['sent']}, fetched {r['received']}{OFF}")
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

    say("At the town office (online, once): create the town and enroll four neighbors")
    cli("init", "--town", town_file, "--label", "Elm Street")
    people = {}
    for name, cls, credit in [("alice", "hardware", "100"), ("bob", "hardware", "20"), ("carol", "software", "20,20"), ("dave", "software", "")]:
        key, req, reply = (os.path.join(d, f"{name}.{x}") for x in ("key", "join", "reply"))
        cli("join", "--key", key, "--request", req)  # on the wallet: its key never leaves
        r = cli("enroll", "--town", town_file, "--request", req, "--reply", reply, "--class", cls, *(["--credit", credit] if credit else []))
        cli("finish", "--key", key, "--reply", reply, "--name", name, "--out", os.path.join(d, f"{name}.pave"))
        os.remove(key)
        print(f"  enrolled {name}: {cls} wallet, test credit {credit or 'none'}" + (f" (ticket group {r['group']})" if credit else ""))
    nodes = [Node(args.bin, town_file, args.port, "town")]
    for i, name in enumerate(["alice", "bob", "carol", "dave"]):
        people[name] = Node(args.bin, os.path.join(d, f"{name}.pave"), args.port + 1 + i, name)
    town, alice, bob, carol, dave = nodes[0], people["alice"], people["bob"], people["carol"], people["dave"]
    nodes += [alice, bob, carol, dave]

    try:
        say("0. Each wallet fetches tickets anonymously: the town sees only its class")
        for p in (alice, bob, carol, dave):
            got = p("refill", quiet=True, peer=town.addr, count=8)["tickets"]
            print(f"  {p.name}: {got} tickets, in a fresh random group, unlinkable to its enrollment")

        say("1. Alice posts a job to the town's board, with proof she holds the pay")
        alice.meet(bob)
        job = alice("post", title="Fix the back fence", pay=30)["job"]
        alice.sync(town)
        bob.sync(town)
        jobs = bob("board", quiet=True)["jobs"]
        print(f"  bob sees: “{jobs[0]['title']}”, pay {jobs[0]['pay']}, {jobs[0]['status']}")

        say("2. Bob replies; Alice accepts him; Bob finishes; Alice pays him wallet to wallet")
        bob("reply", job=job, note="I can do it Saturday")
        bob.sync(town)
        alice.sync(town)
        worker = alice("board", quiet=True)["jobs"][0]["replies"][0]["from"]
        alice("accept", job=job, worker=worker)
        alice.sync(town)
        bob.sync(town)
        bob("done", job=job)
        bob.sync(town)
        alice.sync(town)
        payment = alice("pay", job=job)["payment"]
        alice.meet(bob)
        alice.sync(town)
        bob.sync(town)
        check = bob("check", state=payment)
        status = bob("board", quiet=True)["jobs"][0]["status"]
        print(f"  job is {status}; bob's wallet would accept the payment: {GREEN}{check['accept']}{OFF}")
        print(f"  balances: alice {alice('whoami', quiet=True)['balance']}, bob {bob('whoami', quiet=True)['balance']}")

        say("2b. Bob pays Alice 10 directly: only that coin's provenance travels")
        r = bob("send", quiet=True, peer=alice.addr, amount=10, memo="fence paint")
        total = sum(x["bytes"] for x in r["steps"])
        detail = ", ".join(f"{x['step']} {x['bytes']} B" for x in r["steps"])
        print(f"  {detail}")
        print(f"  {total} B in all, about {-(-total // 244)} BLE packets; paid: {GREEN}{'paid' in r}{OFF}")
        r = bob("send", quiet=True, peer=alice.addr, amount=5, memo="more paint")
        total2 = sum(x["bytes"] for x in r["steps"])
        print(f"  a second payment from the same coin's change: {total2} B, since alice already has its history")

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
        honest = next(c for c in bobs if c["state"] != to_bob)  # not the copy carol double-spent to him
        from_bob = bob("spend", state=honest["state"], to=alice("receive", quiet=True)["credential"])["state"]
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

        say("7. Carol can't get new tickets: she can't prove she isn't the cheat")
        r = carol("refill", quiet=True, may_fail=True, peer=town.addr, count=8)
        print(f"  carol's refill: {RED}{r.get('error', r)}{OFF}")
        got = bob("refill", quiet=True, peer=town.addr, count=8)["tickets"]
        print(f"  bob's refill: {GREEN}{got} tickets{OFF}, with standing proofs that link him to nothing")

        say("8. A flaw is found in the software wallet: the town closes that class")
        r = town("roll", revoke_class=["software"])
        print(f"  epoch {r['epoch']}: every group ever given to software wallets is revoked ({r['revoked_groups']} groups so far)")
        r = dave("refill", quiet=True, may_fail=True, peer=town.addr, count=8)
        print(f"  dave's software wallet, honest but the same model: {RED}{r.get('error', r)}{OFF}")
        got = alice("refill", quiet=True, peer=town.addr, count=8)["tickets"]
        print(f"  alice's hardware wallet carries on: {GREEN}{got} tickets{OFF}")

        say("9. Weeks pass: Alice's coin reaches the end of its life, and she swaps it")
        for _ in range(8):
            town("roll", quiet=True)
        alice("gossip", quiet=True, peer=town.addr)
        coin = alice("whoami", quiet=True)["coins"][0]
        r = alice("check", quiet=True, state=coin["state"])
        print(f"  her {coin['amount']} is refused offline now: {RED}{r['refusal']}{OFF}")
        alice("refill", quiet=True, peer=town.addr, count=8)
        r = alice("swap", quiet=True, peer=town.addr, state=coin["state"])
        r2 = alice("check", quiet=True, state=r["paid"])
        print(f"  quote, transfer, retire, mint: a fresh {coin['amount']}, accepted again: {GREEN}{r2['accept']}{OFF}")
    finally:
        for n in nodes:
            n.stop()
    print(f"\n{DIM}state files in {d}{OFF}")


if __name__ == "__main__":
    main()
