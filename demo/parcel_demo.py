#!/usr/bin/env python3
"""Parcels and disputes on pave, across separate processes.

A shop ships packages through two co-op couriers to Zoe. Custody is a
coin: each courier takes the parcel with a record only it can sign, a
double handoff would be a double spend, and the shop pays per hop once
the parcel is delivered. Delivery is shown three ways: Zoe signs, Zoe
gives the courier a code, or the courier leaves it at the door. When Zoe
says a drop never arrived, the dispute is a job: arbiters offer, a panel
is drawn, the courier appeals and pays upfront into escrow, and reputation
follows the final ruling.

    cargo build --release -p pave-board
    python3 demo/parcel_demo.py [--bin target/release/pave-node]

All credit is test credit with no cash value.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from board_demo import BOLD, DIM, GREEN, OFF, RED, Node, say  # noqa: E402,F401


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/pave-node")
    ap.add_argument("--port", type=int, default=7600)
    args = ap.parse_args()
    d = tempfile.mkdtemp(prefix="pave-parcels-")
    town_file = os.path.join(d, "town.pave")

    def cli(*a):
        out = subprocess.run([args.bin, *a], check=True, capture_output=True, text=True).stdout
        return json.loads(out.strip().splitlines()[-1])

    say("At the town office: create the town and enroll a shop, two couriers, a customer and four arbiters")
    cli("init", "--town", town_file, "--label", "Pine Street")
    people = [("shop", "100"), ("ana", "30"), ("ben", None), ("zoe", "50"), ("arb1", None), ("arb2", None), ("arb3", None), ("arb4", None)]
    for name, credit in people:
        key, req, reply = (os.path.join(d, f"{name}.{x}") for x in ("key", "join", "reply"))
        cli("join", "--key", key, "--request", req)
        cli("enroll", "--town", town_file, "--request", req, "--reply", reply, "--class", "hardware", *(["--credit", credit] if credit else []))
        cli("finish", "--key", key, "--reply", reply, "--name", name, "--out", os.path.join(d, f"{name}.pave"))
        os.remove(key)
    print(f"  enrolled {', '.join(n for n, _ in people)}")

    nodes = []
    try:
        town = Node(args.bin, town_file, args.port, "town")
        nodes.append(town)
        n = {}
        for i, (name, _) in enumerate(people):
            n[name] = Node(args.bin, os.path.join(d, f"{name}.pave"), args.port + 1 + i, name)
            nodes.append(n[name])
        shop, ana, ben, zoe = n["shop"], n["ana"], n["ben"], n["zoe"]
        arbs = [n[f"arb{i}"] for i in range(1, 5)]
        for p in n.values():
            p("refill", quiet=True, peer=town.addr, count=16)

        def everyone_hears():
            town("roll", quiet=True)
            for p in n.values():
                p("gossip", quiet=True, peer=town.addr)

        def sync(*ps):
            """Send queued posts straight to the board, and fetch it."""
            for p in ps:
                p("sync", quiet=True, peer=town.addr)

        def balance(p):
            return p("whoami", quiet=True)["balance"]

        say("1. The town gives the shop a budget of 10 parcels")
        town("parcel_budget", to=shop("receive", quiet=True)["credential"], count=10)
        shop.meet(town)

        say("2. Signed delivery: shop → Ana → Ben → Zoe, each courier taking it offline")
        zoe_at = zoe("receive", quiet=True)["credential"]
        r = shop("ship", what="thai takeout", **{"from": "dn5bpsb", "to": "dn5bpth"}, addressee=zoe_at, pay=3, mode="signed")
        parcel, manifest = r["parcel"], r["manifest"]
        shop("handoff", parcel=parcel, to=ana("receive", quiet=True)["credential"])
        shop.meet(ana)
        ana("take", manifest=manifest)
        ana("handoff", parcel=parcel, to=ben("receive", quiet=True)["credential"])
        ana.meet(ben)
        ben("take", manifest=manifest)
        r = ben("deliver", manifest=manifest, may_fail=True)
        print(f"  ben tries to confirm delivery himself: {RED}{r.get('error')}{OFF}")
        ben("handoff", parcel=parcel, to=zoe_at)
        ben.meet(zoe)
        zoe("deliver", manifest=manifest)
        zoe.meet(ben)
        ben.meet(ana)
        ana.meet(shop)
        c = shop("custody", quiet=True, parcel=parcel)
        print(f"  custody: {' → '.join(next(iter(s)) for s in c['steps'])}; {GREEN}{c['delivery']}{OFF}")
        shop("pay_couriers", parcel=parcel)
        shop.meet(ana)
        shop.meet(ben)
        print(f"  ana has {balance(ana)}, ben has {balance(ben)}: 3 per hop")

        say("3. Code delivery: Zoe has no wallet at the door, only the code the shop sent her")
        r = shop("ship", what="medicine", **{"from": "dn5bpsb", "to": "dn5bpth"}, addressee=zoe("receive", quiet=True)["credential"], pay=3, mode="code")
        parcel, manifest, code = r["parcel"], r["manifest"], r["code"]
        print(f"  the shop texts Zoe her code: {code}")
        shop("handoff", parcel=parcel, to=ana("receive", quiet=True)["credential"])
        shop.meet(ana)
        ana("take", manifest=manifest)
        ana("deliver_code", manifest=manifest, code="000000" if code != "000000" else "111111")
        ana.meet(shop)
        print(f"  with a wrong code, the shop sees: {RED}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")
        ana("deliver_code", manifest=manifest, code=code)
        ana.meet(shop)
        print(f"  with Zoe's code: {GREEN}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")

        say("4. A drop at the door, and Zoe says it never came")
        ana_id = ana("trade", quiet=True)["contractor"]
        zoe_at = zoe("receive", quiet=True)["credential"]
        r = shop("ship", what="groceries", **{"from": "dn5bpsb", "to": "dn5bpth"}, addressee=zoe_at, pay=3, mode="drop", window=2)
        parcel, manifest = r["parcel"], r["manifest"]
        shop("handoff", parcel=parcel, to=ana("receive", quiet=True)["credential"])
        shop.meet(ana)
        ana("take", manifest=manifest)
        ana("drop", manifest=manifest, cell="dn5bpth", photo="(porch photo, salted)")
        ana.meet(shop)
        ana.meet(zoe)
        sync(ana, shop)
        print(f"  the shop sees: {shop('custody', quiet=True, parcel=parcel)['delivery']}")
        d0 = zoe("dispute", subject=parcel, question="was it delivered?", claim=False, panel=1, pay=2, against=ana_id, **{"as": zoe_at})["dispute"]
        sync(zoe, shop, ana)
        print(f"  the shop sees: {RED}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")
        ana("fund", dispute=d0)
        sync(ana)
        print("  Ana, the side disputed, funds the first round upfront into escrow")
        for a in arbs[:2]:
            sync(a)
            a("offer", dispute=d0)
            sync(a)
        everyone_hears()
        everyone_hears()
        sync(shop, ana, zoe, *arbs)
        ds = {x["id"]: x for x in shop("disputes", quiet=True)["disputes"]}
        drawn = ds[d0]["panel"][0]
        arb = next(a for a in arbs if a("trade", quiet=True)["contractor"] == drawn)
        print(f"  the panel of one is drawn, not chosen: {arb.name}")
        arb("arbitrate", dispute=d0, answer="no")
        sync(arb, shop, ana, zoe)
        print(f"  ruled: {RED}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")
        ana.meet(town)
        town("release_escrow", dispute=d0)
        print(f"  the town pays {arb.name} from Ana's deposit")

        say("5. Ana appeals: a bigger panel at double the pay, paid upfront into escrow")
        d1 = ana("dispute", subject=parcel, question="was it delivered?", claim=True, panel=3, pay=4, appeal_of=d0)["dispute"]
        ana.meet(town)
        sync(ana)
        for a in arbs:
            sync(a)
            a("offer", dispute=d1)
            sync(a)
        everyone_hears()
        everyone_hears()
        sync(shop, ana, zoe, *arbs)
        ds = {x["id"]: x for x in shop("disputes", quiet=True)["disputes"]}
        panel = ds[d1]["panel"]
        on = [a for a in arbs if a("trade", quiet=True)["contractor"] in panel]
        print(f"  drawn: {', '.join(a.name for a in on)} ({arb.name} ruled below, so can't sit)")
        for a, ans in zip(on, ["yes", "yes", "no"]):
            a("arbitrate", dispute=d1, answer=ans)
            sync(a)
        sync(shop, ana, zoe)
        print(f"  ruled on appeal: {GREEN}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")
        r = town("release_escrow", dispute=d1)
        print(f"  the town releases escrow: {len(r['minted'])} panelists paid 4 each")
        ds = shop("disputes", quiet=True)
        top = next(x for x in ds["disputes"] if x["id"] == d0)
        print(f"  loser pays, computed: {top['liability']}")
        print(f"  arbiter scores: {sorted(ds['arbiter_scores'].values())} (+1 upheld, -1 overturned)")
        recs = shop("dispute_records", quiet=True, against=ana_id)
        print(f"  Ana's record: {recs['counterparty']}; her filers, by pseudonym: {recs['filers']}")
    finally:
        for x in nodes:
            x.stop()


if __name__ == "__main__":
    main()
