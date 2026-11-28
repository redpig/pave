#!/usr/bin/env python3
"""The UniFFI interface, from a host language: generate Python bindings
from the built library (UniFFI's Kotlin and Swift come from the same place),
then join a town with a keystore written in Python, use the wallet, and
reopen it. A stale copy of the state is refused, an attestation that isn't
one is refused, and so is a second finish of the same join.

    cargo build --release -p pave-board -p pave-mobile
    python3 mobile/tests/uniffi/check.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
rel = os.path.join(root, "target", "release")
d = tempfile.mkdtemp(prefix="pave-uniffi-")
subprocess.run(["cargo", "run", "--release", "-q", "-p", "pave-mobile", "--bin", "uniffi-bindgen", "--", "generate",
                "--library", os.path.join(rel, "libpave_mobile.so"), "--language", "python", "--out-dir", d],
               cwd=root, check=True, capture_output=True)
shutil.copy(os.path.join(rel, "libpave_mobile.so"), d)
sys.path.insert(0, d)
import pave  # noqa: E402


class Vault:
    """A stand-in for a platform keystore: "seals" by prefixing a key
    version, and retires old versions on commit."""

    def __init__(self):
        self.live, self.next, self.commits = set(), 1, 0

    def seal(self, data):
        v = self.next
        self.next += 1
        self.live.add(v)
        return bytes([v]) + bytes(data)

    def open(self, sealed):
        if not sealed or sealed[0] not in self.live:
            raise pave.PaveError.Failed("sealed under a retired key: an old copy")
        return bytes(sealed[1:])

    def commit(self):
        self.live = {self.next - 1}
        self.commits += 1

    def rollback_resistant(self):
        return True


class Handle(pave.Keystore):
    """One call's view of the vault. UniFFI 0.25's Python bindings key a
    callback object by its identity, so a failed call releasing its object
    would release the live wallet's too; a handle per call keeps them apart.
    (Kotlin's bindings give each call its own handle.)"""

    def __init__(self, vault):
        self.v = vault

    def seal(self, data):
        return self.v.seal(data)

    def open(self, sealed):
        return self.v.open(sealed)

    def commit(self):
        return self.v.commit()

    def rollback_resistant(self):
        return self.v.rollback_resistant()


node = os.path.join(rel, "pave-node")
town = os.path.join(d, "town.pave")
subprocess.run([node, "init", "--town", town, "--label", "UniFFI town"], check=True, capture_output=True)
print("version", pave.version())

join = pave.Join()
r = json.loads(join.request())
assert len(r["challenge"]) == 64
try:
    join.attest(json.dumps({"neither": {}}))
    raise SystemExit("an attestation that isn't one was taken")
except pave.PaveError.Failed as e:
    print("attest refused:", e)
req, reply = os.path.join(d, "req.bin"), os.path.join(d, "reply.bin")
open(req, "wb").write(bytes.fromhex(r["request"]))
subprocess.run([node, "enroll", "--town", town, "--request", req, "--reply", reply, "--class", "hardware", "--credit", "300"], check=True, capture_output=True)

vault = Vault()
state = os.path.join(d, "phone.pave")
w = join.finish(open(reply, "rb").read().hex(), "phone", state, Handle(vault))
who = json.loads(w.call(json.dumps({"cmd": "whoami"})))
print("whoami", who)
assert who["ok"] and who["balance"] == 300 and who["name"] == "phone"
assert json.loads(w.call("not json"))["ok"] is False
assert json.loads(w.call(json.dumps({"cmd": "no such command"})))["ok"] is False
try:
    join.finish("00", "again", state + "2", Handle(vault))
    raise SystemExit("a join finished twice")
except pave.PaveError.Failed as e:
    print("second finish refused:", e)

# Keep a stale copy, save again, and reopen: the current state opens, the
# stale copy doesn't.
shutil.copy(state, state + ".old")
w.save()
del w
w = pave.Wallet.open(state, Handle(vault))
assert json.loads(w.call(json.dumps({"cmd": "whoami"})))["balance"] == 300
try:
    pave.Wallet.open(state + ".old", Handle(vault))
    raise SystemExit("a stale copy opened")
except pave.PaveError.Failed as e:
    print("stale copy refused:", e)
assert vault.commits >= 2
print("ok: joined, used and reopened a wallet through the UniFFI interface with a host-language keystore; a stale copy is refused")
