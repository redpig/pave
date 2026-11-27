#!/usr/bin/env python3
"""Build smoke.c against pave.h and the library, and run it through a real
enrollment: the C program makes its keys and request, the town answers with
pave-node, and the program finishes joining, uses the wallet and reopens it
through its own keystore callbacks.

    cargo build --release -p pave-board -p pave-mobile
    python3 mobile/tests/c/check.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
rel = os.path.join(root, "target", "release")
d = tempfile.mkdtemp(prefix="pave-ffi-")
exe = os.path.join(d, "smoke")
subprocess.run(["clang", "-Wall", "-Wextra", "-Werror", "-std=c11", "-D_DEFAULT_SOURCE",
                "-I", os.path.join(root, "mobile", "include"), os.path.join(root, "mobile", "tests", "c", "smoke.c"),
                "-L", rel, "-lpave_mobile", "-Wl,-rpath," + rel, "-o", exe], check=True)

node = os.path.join(rel, "pave-node")
town = os.path.join(d, "town.pave")
subprocess.run([node, "init", "--town", town, "--label", "FFI town"], check=True, capture_output=True)
req_json, reply_hex, state = (os.path.join(d, x) for x in ("request.json", "reply.hex", "phone.pave"))
p = subprocess.Popen([exe, req_json, reply_hex, state], stdout=subprocess.PIPE, text=True)
for _ in range(100):
    if os.path.exists(req_json) and os.path.getsize(req_json):
        break
    time.sleep(0.1)
req = json.load(open(req_json))
req_bin, reply_bin = os.path.join(d, "request.bin"), os.path.join(d, "reply.bin")
open(req_bin, "wb").write(bytes.fromhex(req["request"]))
subprocess.run([node, "enroll", "--town", town, "--request", req_bin, "--reply", reply_bin, "--class", "hardware", "--credit", "250"], check=True, capture_output=True)
tmp = reply_hex + ".tmp"
open(tmp, "w").write(open(reply_bin, "rb").read().hex())
os.rename(tmp, reply_hex)
out, _ = p.communicate(timeout=120)
print(out)
lines = {l.split(" ", 1)[0]: l.split(" ", 1)[1] for l in out.splitlines() if " " in l}
who, again = json.loads(lines["whoami"]), json.loads(lines["again"])
assert p.returncode == 0, p.returncode
assert who["ok"] and who["balance"] == 250 and who["name"] == "phone", who
assert again["ok"] and again["balance"] == 250, again
assert json.loads(lines["bad"])["ok"] is False and json.loads(lines["json"])["ok"] is False
assert int(lines["commits"]) >= 1
assert json.loads(lines["stale"])["ok"] is False, lines["stale"]
print("ok: joined, used and reopened a wallet through pave.h with the app's keystore; a stale copy is refused")
