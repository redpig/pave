#!/usr/bin/env python3
"""Parcels and disputes on pave, across separate processes.

A shop ships packages through two co-op couriers to Zoe. Custody is a
coin: each courier takes the parcel with a record only it can sign, a
double handoff would be a double spend, and the shop pays per hop once
the parcel is delivered. Delivery is shown three ways: Zoe signs, Zoe
gives the courier a code, or the courier leaves it at the door. When the
courier leaves one at the wrong door, Zoe disputes with her own photos and
public records of her address; the drawn panelist's wallet checks custody
and the courier's committed photo and lays the pictures side by side; the
courier appeals, paying upfront into escrow, and loses again.

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

        say("4. A drop at the wrong door: the courier photographs a porch two doors down")
        # Stand-in images (invented): a JPEG's structure with Exif and a C2PA
        # segment, and a line of text standing in for the pixels.
        def seg(marker, payload):
            return bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload

        def img(name, pixels, exif=None):
            data = b"\xff\xd8" + seg(0xE0, b"JFIF\0")
            if exif:
                data += seg(0xE1, b"Exif\0\0" + exif.encode()) + seg(0xEB, b"JP\0jumb c2pa: captured by camera app")
            data += seg(0xDA, b"scan") + pixels.encode() + b"\xff\xd9"
            path = os.path.join(d, name)
            with open(path, "wb") as f:
                f.write(data)
            return path

        def shows(path):
            """What a stand-in picture shows, and its Exif if it kept any."""
            data = open(path, "rb").read()
            i = data.find(b"\xff\xda")
            pixels = data[i + 2 + int.from_bytes(data[i + 2:i + 4], "big"):-2].decode()
            j = data.find(b"Exif\0\0")
            exif = data[j + 6:data.find(b"\xff", j)].decode() if j >= 0 else None
            return pixels, exif
        ana_id = ana("trade", quiet=True)["contractor"]
        zoe_at = zoe("receive", quiet=True)["credential"]
        r = shop("ship", what="books", **{"from": "dn5bpsb", "to": "dn5bpth"}, addressee=zoe_at, pay=3, mode="drop", window=2)
        parcel, manifest = r["parcel"], r["manifest"]
        shop("handoff", parcel=parcel, to=ana("receive", quiet=True)["credential"])
        shop.meet(ana)
        ana("take", manifest=manifest)
        ana("drop", manifest=manifest, cell="dn5bpth", photo_file=img("porch.jpg", "blue door, white railing, number 125", exif="GPS 36.1621,-86.7812 at 14:02"))
        ana.meet(shop)
        ana.meet(zoe)
        sync(ana, shop)
        d0 = zoe("dispute", subject=parcel, question="was it delivered?", claim=False, panel=1, pay=2, against=ana_id, **{"as": zoe_at})["dispute"]
        print("  Zoe disputes, and shows her own door and two public records of her address:")
        zoe("submit_evidence", subject=parcel, kind="image", caption="my front door", image_file=img("door.jpg", "red door, brick steps, number 123", exif="GPS 36.1624,-86.7809 at 18:30"), **{"as": zoe_at})
        zoe("submit_evidence", subject=parcel, kind="reference", source="street view", url="https://maps.example/123-pine", caption="123 Pine St", image_file=img("sv.jpg", "red door, number 123"), **{"as": zoe_at})
        zoe("submit_evidence", subject=parcel, kind="reference", source="city tax assessor", url="https://assessor.example/123-pine", caption="123 Pine St", image_file=img("tax.jpg", "brick house, red door"), **{"as": zoe_at})
        zoe("submit_evidence", subject=parcel, kind="statement", text="That photo is 125, two doors down. Mine is 123, the red door.", **{"as": zoe_at})
        print("  Ana shows custody and the photo she committed to at the drop:")
        ana("parcel_evidence", parcel=parcel, statement="left at the door of the address")
        sync(zoe, ana, shop)
        ana("fund", dispute=d0)
        sync(ana)
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
        r = arb("examine", quiet=True, subject=parcel, peer=town.addr)
        print(f"  {arb.name} is drawn and examines it. Its wallet checked:")
        print(f"    custody: {'; '.join(r['custody'])}")
        print(f"    the photo is the one committed at the drop: {r['photo_matches']}; left in the destination cell: {r['cell_matches']}")
        print("    so the question is the door. Side by side, metadata stripped:")
        for p in r["pictures"]:
            print(f"      {p['label']:<30} from {p['from']:<10} {shows(p['file'])[0]}")
        ana("reveal", subject=parcel)
        sync(ana)
        r = arb("examine", quiet=True, subject=parcel, peer=town.addr)
        o = next(p for p in r["pictures"] if p["label"] == "original of drop photo")
        print(f"  Ana reveals her original to show where she was. It matches her commitment ({o['original']}),")
        print(f"  carries {', '.join(o['metadata'])}, and its Exif says: {shows(o['file'])[1]}, Zoe's door is at 36.1624,-86.7809")
        arb("arbitrate", dispute=d0, answer="no")
        sync(arb, shop, ana, zoe)
        print(f"  ruled: {RED}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")
        r = shop("pay_couriers", parcel=parcel, may_fail=True)
        print(f"  the shop won't pay for the wrong door: {r.get('error')}")
        ana.meet(town)
        town("release_escrow", dispute=d0)

        say("5. Ana appeals anyway, paying upfront for a panel of three")
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
        print(f"  drawn: {', '.join(a.name for a in on)} ({arb.name} ruled below, so can't sit); each examines the same evidence")
        for a, ans in zip(on, ["no", "no", "yes"]):
            a("examine", quiet=True, subject=parcel, peer=town.addr)
            a("arbitrate", dispute=d1, answer=ans)
            sync(a)
        sync(shop, ana, zoe)
        print(f"  upheld on appeal, 2 to 1: {RED}{shop('custody', quiet=True, parcel=parcel)['delivery']}{OFF}")
        r = town("release_escrow", dispute=d1)
        print(f"  the town pays the appeal panel from Ana's deposit: {len(r['minted'])} panelists")
        ds = shop("disputes", quiet=True)
        top = next(x for x in ds["disputes"] if x["id"] == d0)
        print(f"  loser pays, computed: {top['liability']} (Ana's escalation was hers to pay)")
        print(f"  arbiter scores: {sorted(ds['arbiter_scores'].values())} (+1 upheld, -1 overturned)")
        recs = shop("dispute_records", quiet=True, against=ana_id)
        print(f"  Ana's record: {recs['counterparty']}")
    finally:
        for x in nodes:
            x.stop()


if __name__ == "__main__":
    main()
