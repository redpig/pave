#!/usr/bin/env python3
"""Phones on the pave C library: a pickup at the counter over a radio, and
a handoff at the door by QR codes alone.

The cafe's tablet, Ana's phone and the customer's phone each hold their own
wallet through libpave_mobile, called through its C interface (pave.h) as
a Kotlin or Swift app would. Online steps (tickets, the town's records, the
co-op's badge) go to the town over the network. In person, the cafe shows a
QR invite (printed here), Ana's phone reads it, and the exchange runs over
a socket standing in for Wi-Fi Aware. At the door there is no radio: the
same sealed messages go as loops of QR frames.

    cargo build --release -p pave-board -p pave-mobile
    pip install qrcode   # optional: draws the invite in the terminal
    python3 demo/phone_demo.py

All credit is test credit with no cash value.
"""
import argparse
import ctypes
import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from board_demo import BOLD, DIM, GREEN, OFF, RED, Node, say  # noqa: E402,F401


class Phone:
    """One app's wallet, through pave.h."""

    def __init__(self, lib, path, name):
        self.lib, self.name = lib, name
        err = ctypes.c_void_p()
        self.h = lib.pave_open(path.encode(), ctypes.byref(err))
        if not self.h:
            raise SystemExit(f"{name}: {self._take(err.value)}")

    def _take(self, ptr):
        s = ctypes.string_at(ptr).decode()
        self.lib.pave_string_free(ptr)
        return json.loads(s)

    def __call__(self, cmd, quiet=False, may_fail=False, **kw):
        r = self._take(self.lib.pave_call(self.h, json.dumps({"cmd": cmd, **kw}).encode()))
        if not r.get("ok") and not may_fail:
            raise SystemExit(f"{self.name} {cmd}: {r.get('error')}")
        if not quiet:
            shown = {k: (v[:16] + "…" if isinstance(v, str) and len(v) > 24 else v) for k, v in kw.items()}
            print(f"  {DIM}{self.name} ▸ {cmd} {shown}{OFF}")
        return r

    def close(self):
        self.lib.pave_close(self.h)


def load(path):
    lib = ctypes.CDLL(path)
    lib.pave_open.restype = ctypes.c_void_p
    lib.pave_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.pave_call.restype = ctypes.c_void_p
    lib.pave_call.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pave_string_free.argtypes = [ctypes.c_void_p]
    lib.pave_close.argtypes = [ctypes.c_void_p]
    lib.pave_version.restype = ctypes.c_void_p
    return lib


class Radio:
    """Two ends of a socket, standing in for a Wi-Fi Aware data path."""

    def __init__(self):
        self.a, self.b = socket.socketpair()
        self.bytes = 0

    def send(self, end, data: bytes):
        (self.a if end == 0 else self.b).sendall(struct.pack(">I", len(data)) + data)
        self.bytes += len(data)

    def recv(self, end):
        s = self.a if end == 0 else self.b
        n = struct.unpack(">I", self._read(s, 4))[0]
        return self._read(s, n)

    @staticmethod
    def _read(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf


def show_qr(code):
    try:
        import qrcode
    except ImportError:
        print(f"    (pip install qrcode to draw it) {code[:40]}…")
        return
    q = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
    q.add_data(code, optimize=0)
    q.make(fit=True)
    print(f"    the tablet shows a version {q.version} QR code, {len(code)} characters:")
    m = q.get_matrix()
    for y in range(0, len(m), 2):
        top, bot = m[y], m[y + 1] if y + 1 < len(m) else [False] * len(m[y])
        print("    " + "".join("█" if t and b else "▀" if t else "▄" if b else " " for t, b in zip(top, bot)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/pave-node")
    ap.add_argument("--lib", default="target/release/libpave_mobile.so")
    ap.add_argument("--port", type=int, default=7800)
    args = ap.parse_args()
    d = tempfile.mkdtemp(prefix="pave-phones-")
    town_file = os.path.join(d, "town.pave")

    def cli(*a):
        return subprocess.run([args.bin, *a], check=True, capture_output=True, text=True).stdout

    say("At the town office: a town, and three devices enrolled")
    cli("init", "--town", town_file, "--label", "Pine Street")
    for name in ("cafe", "ana", "cust"):
        key, req, reply = (os.path.join(d, f"{name}.{x}") for x in ("key", "join", "reply"))
        cli("join", "--key", key, "--request", req)
        cli("enroll", "--town", town_file, "--request", req, "--reply", reply, "--class", "hardware")
        cli("finish", "--key", key, "--reply", reply, "--name", name, "--out", os.path.join(d, f"{name}.pave"))
        os.remove(key)
    town = Node(args.bin, town_file, args.port, "town")
    lib = load(args.lib)
    phones = {}
    try:
        say("Each device opens its wallet through the C library")
        for name in ("cafe", "ana", "cust"):
            phones[name] = Phone(lib, os.path.join(d, f"{name}.pave"), name)
        cafe, ana, cust = phones["cafe"], phones["ana"], phones["cust"]
        print(f"  libpave_mobile {cafe._take(lib.pave_version())['version']}; help lists {len(cafe('help', quiet=True)['commands'])} commands")

        say("Online: tickets from the town, a budget of bags for the cafe, and Ana's badge from the co-op")
        for p in phones.values():
            p("refill", peer=town.addr, count=16)
        town("parcel_budget", to=cafe("receive", quiet=True)["credential"], count=5)
        r = town("open_dispatch", label="Pine Co-op")
        dispatch, dispatch_id = r["dispatch"], r["id"]
        ana_key = ana("identity", quiet=True, label="courier")["credential"]
        ana("take_badge", dispatch=dispatch, badge=town("issue_badge", dispatch=dispatch_id, courier="courier-47", key=ana_key)["badge"])
        for p in phones.values():
            p("meet", peer=town.addr)
        deliver_to = cust("receive", quiet=True)["credential"]
        r = cafe("ship", what="order", **{"from": "dn5bpsb", "to": "dn5bpth"}, addressee=deliver_to, pay=0)
        m = cafe("name_dispatch", parcel=r["parcel"], dispatch=dispatch)["manifest"]

        def meet(a, la, b, lb, carry):
            """A meet over a link: each side sends what it has, then what the other lacks."""
            hb = carry(b, lb, a, la, "have", b("have", quiet=True)["have"])
            ha = carry(a, la, b, lb, "have", a("have", quiet=True)["have"])
            from_a = carry(a, la, b, lb, "bundle", a("bundle_for", quiet=True, have=hb)["bundle"])
            from_b = carry(b, lb, a, la, "bundle", b("bundle_for", quiet=True, have=ha)["bundle"])
            b("absorb", quiet=True, bundle=from_a)
            a("absorb", quiet=True, bundle=from_b)

        say("At the counter: the tablet shows an invite; Ana's phone scans it and connects over Wi-Fi Aware")
        inv = cafe("link_show", quiet=True, radios=[{"wifi_aware": "pave-pickup"}, {"ble": "6c8a3d2e0b7f4e1a9c5d2b8e7f6a1c3d"}], ttl=120)
        show_qr(inv["code"])
        scanned = ana("link_scan", quiet=True, code=inv["code"])
        print(f"  Ana's phone reads it: listen on {', '.join(next(iter(x)) for x in scanned['radios'])}")
        radio = Radio()
        ends = {cafe.name: 0, ana.name: 1}

        def over_radio(src, ls, dst, ld, kind, body):
            sealed = src("link_seal", quiet=True, link=ls, kind=kind, body=body)["sealed"]
            radio.send(ends[src.name], bytes.fromhex(sealed))
            got = radio.recv(1 - ends[src.name]).hex()
            r = dst("link_open", quiet=True, link=ld, sealed=got)
            assert r["kind"] == kind
            print(f"    {src.name} → {dst.name}: {kind}, {len(sealed) // 2} bytes sealed")
            return r["body"]

        lc, la = inv["link"], scanned["link"]
        ticket = over_radio(ana, la, cafe, lc, "badge", ana("present", quiet=True, key=ana_key)["ticket"])
        r = cafe("learn_ticket", quiet=True, ticket=ticket, dispatch=dispatch)
        print(f"  the tablet checks the badge: {GREEN}{r['badge']}{OFF}, from Pine Co-op")
        meet(cafe, lc, ana, la, over_radio)
        cafe("act", action="hand_off", manifest=m, to=ana_key)
        manifest = over_radio(cafe, lc, ana, la, "manifest", m)
        meet(cafe, lc, ana, la, over_radio)
        ana("act", action="take", manifest=manifest)
        print(f"  Ana has the bag; {radio.bytes} bytes crossed the radio in all")
        r = cafe("link_open", quiet=True, link=lc, sealed=os.urandom(400).hex(), may_fail=True)
        print(f"  a phone nearby without the code sends noise: {RED}{r.get('error')}{OFF}")

        say("At the door: no radio. Cust's phone shows an invite; the rest goes as QR frames")
        inv = cust("link_show", quiet=True, radios=[], ttl=120)
        lu, la2 = inv["link"], ana("link_scan", quiet=True, code=inv["code"])["link"]
        shown = {"frames": 0}

        def by_camera(src, ls, dst, ld, kind, body):
            sealed = src("link_seal", quiet=True, link=ls, kind=kind, body=body)["sealed"]
            loop = src("link_frames", quiet=True, link=ls, sealed=sealed)["frames"]
            shown["frames"] += len(loop)
            seen = loop * 2
            random.shuffle(seen)
            for f in seen:
                r = dst("link_collect", quiet=True, link=ld, frame=f)
                if r["sealed"]:
                    break
            r = dst("link_open", quiet=True, link=ld, sealed=r["sealed"])
            print(f"    {src.name} → {dst.name}: {kind}, {len(loop)} frame{'s' if len(loop) > 1 else ''}")
            return r["body"]

        meet(ana, la2, cust, lu, by_camera)
        ana("act", action="hand_off", manifest=manifest, to=deliver_to)
        meet(ana, la2, cust, lu, by_camera)
        cust("act", action="confirm", manifest=manifest)
        print(f"  delivered, in {shown['frames']} QR frames between the two screens")

        say("Back online: the cafe hears how it went")
        cust("meet", peer=town.addr)
        ana("meet", peer=town.addr)
        cafe("meet", peer=town.addr)
        c = cafe("food_custody", quiet=True, manifest=m)
        print(f"  custody: {' → '.join(next(iter(s)) for s in c['steps'])}; delivered: {GREEN if c['delivered'] else RED}{c['delivered']}{OFF}")
        print(f"\n{BOLD}Done.{OFF} State is in {d}")
    finally:
        for p in phones.values():
            p.close()
        town.stop()


if __name__ == "__main__":
    main()
