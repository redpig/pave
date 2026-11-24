#!/usr/bin/env python3
"""Civic reports on pave: public, anonymous, counted once per person.

A town mirrors the city's published permits, neighbors report a sidewalk
blocked without one, and the thread shows what anyone can check: how many
distinct people saw it, whether a permit covers it, the subject's reply,
the 311 ticket it was forwarded to, and who confirmed it cleared. Nobody's
identity appears anywhere.

    cargo build --release -p pave-board
    python3 demo/reports_demo.py [--bin target/release/pave-node]

The permits are an invented sample in the shape a city publishes.
"""
import argparse
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from board_demo import BOLD, DIM, GREEN, OFF, RED, Node, say  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BLOCKED = (47.6150, -122.3380)      # no permit here
PERMITTED = (47.6101, -122.3421)    # SUP-0001 covers this block


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/pave-node")
    ap.add_argument("--port", type=int, default=7500)
    args = ap.parse_args()
    d = tempfile.mkdtemp(prefix="pave-reports-")
    town_file = os.path.join(d, "town.pave")

    def cli(*a):
        out = subprocess.run([args.bin, *a], check=True, capture_output=True, text=True).stdout
        import json
        return json.loads(out.strip().splitlines()[-1])

    say("At the town office: create the town and enroll four neighbors")
    cli("init", "--town", town_file, "--label", "Pine Street")
    for name, cls in [("alice", "hardware"), ("bob", "software"), ("carol", "hardware"), ("dave", "hardware")]:
        key, req, reply = (os.path.join(d, f"{name}.{x}") for x in ("key", "join", "reply"))
        cli("join", "--key", key, "--request", req)
        cli("enroll", "--town", town_file, "--request", req, "--reply", reply, "--class", cls)
        cli("finish", "--key", key, "--reply", reply, "--name", name, "--out", os.path.join(d, f"{name}.pave"))
        os.remove(key)
        print(f"  enrolled {name} ({cls} wallet)")

    nodes = []
    try:
        town = Node(args.bin, town_file, args.port, "town")
        nodes.append(town)
        people = {}
        for i, name in enumerate(["alice", "bob", "carol", "dave"]):
            people[name] = Node(args.bin, os.path.join(d, f"{name}.pave"), args.port + 1 + i, name)
            nodes.append(people[name])
        alice, bob, carol, dave = (people[n] for n in ("alice", "bob", "carol", "dave"))

        def sync(*ps):
            """Send queued posts straight to the board, and fetch it."""
            for p in ps:
                p.sync(town)

        def thread(issue):
            i = next(x for x in town("issues", quiet=True)["issues"] if x["issue"] == issue)
            permit = i["permit"] if isinstance(i["permit"], str) else ("found" if "found" in i["permit"] else "nearby")
            print(f"  {BOLD}{i['category']}{OFF} at cell {i['cell']}, opened {i['opened']}: "
                  f"{i['reporters']} people {i['by_class']}, permit: {permit}, cleared by {i['cleared']}"
                  + (f", {i['discounted']} not counted" if i["discounted"] else ""))
            for r in i["replies"]:
                print(f"    reply: “{r['text']}”" + (" (permit shown)" if r["permit"] else ""))
            for f in i["forwarded"]:
                print(f"    forwarded to {f['channel']}: {f['receipt']}")
            return i

        say("1. The town mirrors the city's published permits")
        r = town("mirror", quiet=True, file=os.path.join(HERE, "permits_sample.json"))
        print(f"  {r['mirrored']} permits signed into the reports scope by the mirror role")

        say("2. Alice reports a sidewalk fenced off; it goes straight to the board")
        r = alice("report", category="sidewalk blocked", lat=BLOCKED[0], lon=BLOCKED[1], observed="2026-11-24",
                  note="fencing across the whole sidewalk, no detour signs", photo="(photo bytes)")
        issue = r["issue"]
        sync(alice)
        thread(issue)

        say("3. Bob and Dave confirm it; Alice reporting again still counts once")
        sync(bob, dave)
        bob("report", issue=issue, observed="2026-11-24", note="still there at noon")
        dave("report", issue=issue, observed="2026-11-24", note="people walking in the street")
        alice("report", issue=issue, observed="2026-11-24", note="and again")
        sync(alice, bob, dave)
        thread(issue)
        r = alice("report", category="sidewalk blocked", lat=PERMITTED[0], lon=PERMITTED[1], observed="2026-11-24",
                  note="closed, but there's a sign")
        sync(alice)
        print("  a report two blocks over, where a permit exists:")
        thread(r["issue"])

        say("4. The crew replies, pointing to a permit for another block; a neighbor files it with 311")
        sync(carol)
        permits = town("issues", quiet=True)
        other = next(x for x in permits["issues"] if x["issue"] == r["issue"])
        carol("respond", issue=issue, text="we have a permit for this work", permit=other["permit"]["found"])
        carol("forward", issue=issue, channel="311", receipt="SR-2026-118823")
        sync(carol)
        thread(issue)
        print(f"  {DIM}a permit only counts if it covers the issue's block and day{OFF}")

        say("5. A false report is ruled malicious: it stops counting, and its author can't report again")
        fake = carol("report", category="sidewalk blocked", lat=47.6000, lon=-122.3300, observed="2026-11-24",
                     note="made up")["issue"]
        sync(carol)
        thread(fake)
        report = town("reports_on", quiet=True, issue=fake)["reports"][0]
        town("rule", quiet=True, report=report, malicious=True)
        thread(fake)
        sync(carol)
        r = carol("report", issue=issue, observed="2026-11-25", note="again", quiet=True, may_fail=True)
        print(f"  carol reports again: {RED}{r.get('error')}{OFF}")
        sync(bob)
        r = bob("report", issue=issue, observed="2026-11-25", note="still blocked", quiet=True)
        print(f"  bob still can: {GREEN}{'issue' in r}{OFF}; nothing in the ruling or the reports names carol")

        say("6. The fence comes down; people confirm it, each counted once")
        sync(alice, dave)
        alice("clear", issue=issue)
        dave("clear", issue=issue)
        dave("clear", issue=issue)
        sync(alice, bob, dave)
        thread(issue)
    finally:
        for n in nodes:
            n.stop()
    print(f"\n{DIM}state files in {d}{OFF}")


if __name__ == "__main__":
    main()
