#!/usr/bin/env python3
"""Food delivery by accountable couriers, across separate processes.

A cafe takes an order on its own system, a co-op offers the delivery as a
job for couriers it has badged, and a courier carries the bag to the
customer's door. Pave carries the order's binding and payment, custody of
the bag, the courier's pay and both kinds of vouch; the order and the
street address stay with the cafe and the courier. Then a courier doesn't
show and the bag is offered again; the next one takes it and goes quiet,
so the cafe refunds the customer and the co-op revokes that badge.

    cargo build --release -p pave-board
    python3 demo/food_demo.py [--bin target/release/pave-node]

All credit is test credit with no cash value; amounts are cents.
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
    ap.add_argument("--port", type=int, default=7700)
    args = ap.parse_args()
    d = tempfile.mkdtemp(prefix="pave-food-")
    town_file = os.path.join(d, "town.pave")

    def cli(*a):
        out = subprocess.run([args.bin, *a], check=True, capture_output=True, text=True).stdout
        return json.loads(out.strip().splitlines()[-1])

    say("At the town office: create the town and enroll a cafe, a customer, a co-op and two couriers")
    cli("init", "--town", town_file, "--label", "Pine Street")
    people = [("cafe", None), ("cust", "6000"), ("coop", "1000"), ("ana", None), ("bea", None)]
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
        cafe, cust, coop, ana, bea = (n[k] for k in ("cafe", "cust", "coop", "ana", "bea"))
        for p in n.values():
            p("refill", quiet=True, peer=town.addr, count=16)

        def sync(*ps):
            for p in ps:
                p("sync", quiet=True, peer=town.addr)

        def balance(p):
            return p("whoami", quiet=True)["balance"]

        say("1. The town gives the cafe a budget of bags; the co-op opens its dispatch and badges Ana")
        town("parcel_budget", to=cafe("receive", quiet=True)["credential"], count=10)
        cafe.meet(town)
        r = town("open_dispatch", label="Pine Co-op")
        dispatch, dispatch_id = r["dispatch"], r["id"]
        print("  the co-op vets Ana outside pave (who she is, insurance, a trial run), then badges her courier key")
        ana_key = ana("identity", quiet=True, label="courier")["credential"]
        badge = town("issue_badge", dispatch=dispatch_id, courier="courier-47", key=ana_key)["badge"]
        ana("take_badge", dispatch=dispatch, badge=badge)

        def order(text, total):
            """The customer orders on the cafe's own site; pave gets the binding."""
            deliver_to = cust("receive", quiet=True)["credential"]
            o = cust("food_order", restaurant=cafe("identity", quiet=True, label="public")["credential"], order=text,
                     total=total, fee=500, cell="dn5bpth", address="12 Elm St", deliver_to=deliver_to, provider=provider, due_in=45 * 60)
            cust("pay_to", to=cafe("receive", quiet=True)["credential"], amount=total, receipt=o["paid"])
            cust.meet(cafe)
            print(f"  the cafe sees {cafe('received', quiet=True, receipt=o['paid'])['amount']} paid against this order's binding")
            return deliver_to, o

        def ship(deliver_to, o):
            """The cafe bags it with a seal sticker and names the order, the co-op and its dispatch."""
            r = cafe("ship", what="order", **{"from": "dn5bpsb", "to": "dn5bpth"}, addressee=deliver_to, pay=0)
            parcel = r["parcel"]
            cafe("name_about", quiet=True, parcel=parcel, about=o["order"])
            cafe("name_provider", quiet=True, parcel=parcel, provider=provider)
            m = cafe("name_dispatch", parcel=parcel, dispatch=dispatch)["manifest"]
            return parcel, m

        def hire(courier, m, pickup_in):
            """The co-op offers the bag as a job for badged couriers; the courier replies anonymously
            and shows the co-op its badge; the co-op accepts it."""
            job = coop("offer_delivery", manifest=m, pay=400, pickup_in=pickup_in)["job"]
            sync(coop, courier)
            courier("reply", job=job, note="nearby")
            sync(courier, coop)
            s = courier("show_known", quiet=True, job=job)
            coop("accept_shown", job=job, worker=s["worker"], shown=s["shown"])
            sync(coop, cafe, courier)
            return job, s["key"]

        say("2. Cust orders pho for two; the binding commits to the order, the address and a deadline")
        provider = coop("receive", quiet=True)["credential"]
        deliver_to, o = order('{"items":[{"name":"pho","qty":2}],"total":2400,"deliveryFee":500}', 2400)
        parcel, m = ship(deliver_to, o)
        seal = cafe("seal", quiet=True, parcel=parcel)["code"]
        print(f"  the seal sticker on the bag reads {seal}")

        say("3. The co-op offers the delivery; Ana replies anonymously and is accepted on her badge")
        job, key = hire(ana, m, 15 * 60)
        r = cafe("assigned_courier", quiet=True, manifest=m)
        print(f"  the cafe reads who the co-op assigned: {'Ana' if r['courier'] == ana_key else r['courier']}")

        say("4. Pickup at the counter")
        bea_plain = bea("receive", quiet=True)["credential"]
        r = cafe("act", action="hand_off", manifest=m, to=bea_plain, may_fail=True)
        print(f"  Bea, a member with no badge, asks for the bag: {RED}refused{OFF} (not the addressee, no badge from this dispatch)" if "AnyOf" in r.get("error", "") else f"  unexpected: {r}")
        r = cafe("learn_ticket", ticket=ana("present", quiet=True, key=ana_key)["ticket"], dispatch=dispatch)
        print(f"  Ana shows her badge: {GREEN}{r['badge']}{OFF}, vetted by the co-op")
        cafe.meet(ana)
        cafe("act", action="hand_off", manifest=m, to=ana_key)
        cafe.meet(ana)
        ana("act", action="take", manifest=m)
        print("  the cafe tells Ana the address and salt, off the record; she checks them against the order:")
        for addr in ("12 Elm St", "14 Elm St"):
            ok = ana("check_address", quiet=True, binding=o["binding"], address=addr, salt=o["salt"])["matches"]
            print(f"    {addr}: {GREEN + 'matches' if ok else RED + 'not the one the customer paid for'}{OFF}")

        say("5. Ana delivers; Cust confirms and posts the seal code; the board's clock times it")
        ana.meet(cust)
        ana("act", action="hand_off", manifest=m, to=deliver_to)
        ana.meet(cust)
        cust("act", action="confirm", manifest=m)
        cust("note_delivered", manifest=m, order=o["order"], seal=seal)
        sync(cust, cafe)
        cust.meet(cafe)
        r = cafe("food_outcome", quiet=True, manifest=m, order=o["order"], due=o["due"])
        print(f"  outcome: {GREEN}{r['outcome']}{OFF}, {o['due'] - r['at']} s before the deadline")
        steps = cafe("food_custody", quiet=True, manifest=m)["steps"]
        print(f"  custody: {' → '.join(next(iter(s)) for s in steps)}; the take is on Ana's badge key")

        say("6. Pay: the cafe pays the co-op its fee; the co-op pays Ana through the job, with a vouch")
        ana("done", job=job)
        sync(ana, coop)
        cafe("pay_provider", parcel=parcel, price=500)
        cafe.meet(coop)
        coop("pay_delivery", manifest=m, note="quick, careful")
        coop.meet(ana)
        print(f"  balances: cust {balance(cust)}, cafe {balance(cafe)}, coop {balance(coop)}, ana {balance(ana)}")

        say("7. Cust vouches for the courier too; Bea, who took no part, checks both kinds from the board")
        cust("vouch_delivery", manifest=m, note="hot, and on time")
        sync(cust, coop, bea)
        bea.meet(cafe)
        r = bea("delivery_vouches", quiet=True, courier=ana_key)
        print(f"  from customers (posts carrying the bag's custody records): {r['people']} person, \"{r['vouches'][0]['note']}\"")
        rep = bea("reputation", quiet=True, contractor=r["contractor"])
        print(f"  from the co-op (riding on its payment, a coin Ana holds): {rep['people_by_type']}, \"{rep['vouches'][0]['note']}\"")

        say("8. A no-show: the co-op accepts Ana for the next bag, she doesn't come by the pickup deadline")
        deliver2, o2 = order('{"items":[{"name":"banh mi","qty":3}],"total":2400}', 2400)
        parcel2, m2 = ship(deliver2, o2)
        hire(ana, m2, -60)
        coop("release_delivery", manifest=m2)
        sync(coop, cafe)
        print(f"  released; the cafe sees the bag assigned to: {cafe('assigned_courier', quiet=True, manifest=m2)['courier']}")
        bea_key = bea("identity", quiet=True, label="courier")["credential"]
        badge = town("issue_badge", dispatch=dispatch_id, courier="courier-52", key=bea_key)["badge"]
        bea("take_badge", dispatch=dispatch, badge=badge)
        print("  the co-op badges Bea and offers the bag again")
        hire(bea, m2, -60)
        cafe("learn_ticket", quiet=True, ticket=bea("present", quiet=True, key=bea_key)["ticket"], dispatch=dispatch)
        cafe.meet(bea)
        cafe("act", action="hand_off", manifest=m2, to=bea_key)
        cafe.meet(bea)
        bea("act", action="take", manifest=m2)

        say("9. Bea takes the bag and goes quiet")
        bea.meet(coop)
        r = coop("release_delivery", manifest=m2, may_fail=True)
        print(f"  the co-op can't call it a no-show: {RED}{r.get('error')}{OFF}")
        print("  it's a dispute against courier-52, whom the co-op can name. Meanwhile the cafe refunds Cust:")
        cafe("refund", manifest=m2, amount=2400, receipt=o2["refund"])
        cafe.meet(cust)
        print(f"  Cust's wallet shows {cust('received', quiet=True, receipt=o2['refund'])['amount']} refunded against that order")
        town("revoke_badge", dispatch=dispatch_id, courier="courier-52")
        cafe.meet(town)
        deliver3, o3 = order('{"items":[{"name":"spring rolls","qty":1}],"total":900}', 900)
        _, m3 = ship(deliver3, o3)
        r = cafe("act", action="hand_off", manifest=m3, to=bea_key, may_fail=True)
        print(f"  with courier-52's badge revoked, the cafe won't hand Bea another bag: {RED}refused{OFF}" if "AnyOf" in r.get("error", "") else f"  unexpected: {r}")
        print(f"\n{BOLD}Done.{OFF} State is in {d}")
    finally:
        for p in nodes:
            try:
                p.stop()
            except Exception:
                p.p.kill()


if __name__ == "__main__":
    main()
