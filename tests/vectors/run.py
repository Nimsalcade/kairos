#!/usr/bin/env python3
"""
Run the Kairos conformance vectors.

    python3 tests/vectors/run.py                   # check the reference (Python) node
    python3 tests/vectors/run.py --external CMD    # check another implementation

With --external, CMD is run once per chain vector as `CMD path/to/vector.json`.
It must replay the steps in order on a fresh chain built from the vector's
params and print one JSON array to stdout with one object per step:

    {"status": "accepted" | "invalid: <reason>" | "orphan" | "duplicate" | "malformed" | ...,
     "tip": "<hex>", "height": n, "utxo_root": "<hex>", "next_base_fee": n,
     "deployments": {"<name>": "<state>", ...}}

`status` is required. The other fields are compared when present. The
reason after "invalid: " is compared too, unless --accept-any-reason is
given (an implementation may name its errors differently, but it must
reject the same block at the same step).

functions.json is checked against the reference only. Its format is documented
in README.md so another implementation can check its own functions.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import CHAINS, FUNCTIONS, replay, params_from_json  # noqa: E402

from kairos.auxpow import AuxPow, expected_index  # noqa: E402
from kairos.block import Block  # noqa: E402
from kairos.chain import Coin, coin_bytes  # noqa: E402
from kairos.crypto import MuHash, merkle_root, tagged_hash, bech32m_encode, lamport_keygen, pq_root  # noqa: E402
from kairos.params import asert_target, bits_to_target, generated_at, next_base_fee, subsidy, target_to_bits  # noqa: E402
from kairos.tx import OutPoint, Transaction, make_address, verify_witness  # noqa: E402
from dataclasses import replace  # noqa: E402
import io  # noqa: E402

def load(path):
    with open(path) as f:
        return json.load(f)


FIELDS = ("tip", "height", "utxo_root", "next_base_fee", "deployments")


def compare(step, got, i, name, any_reason=False):
    errs = []
    want = step["expect"]
    status = got.get("status")
    same = status == want or (any_reason and want.startswith("invalid") and str(status).startswith("invalid"))
    if not same:
        errs.append(f"{name} step {i} ({step['note']}): status {status!r}, expected {want!r}")
    for f in FIELDS:
        if f in got and got[f] != step[f]:
            errs.append(f"{name} step {i} ({step['note']}): {f} {got[f]!r}, expected {step[f]!r}")
    return errs


def run_reference(path):
    v = load(path)
    errs = []
    for i, step, status, seen in replay(v):
        seen["status"] = status
        errs += compare(step, seen, i, v["name"])
    return len(v["steps"]), errs


def run_external(path, cmd, any_reason):
    v = load(path)
    r = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=3600)
    if r.returncode != 0:
        return len(v["steps"]), [f"{v['name']}: external command failed: {r.stderr.strip()[:500]}"]
    try:
        results = json.loads(r.stdout)
    except ValueError:
        return len(v["steps"]), [f"{v['name']}: external command did not print a JSON array"]
    errs = []
    if len(results) != len(v["steps"]):
        errs.append(f"{v['name']}: {len(results)} results for {len(v['steps'])} steps")
    for i, (step, got) in enumerate(zip(v["steps"], results)):
        errs += compare(step, got, i, v["name"], any_reason)
    return len(v["steps"]), errs


def check_functions(path=FUNCTIONS):
    v = load(path)
    p = params_from_json(v["params"])
    errs, n = [], 0

    def eq(kind, got, want, ctx):
        nonlocal n
        n += 1
        if got != want:
            errs.append(f"functions.{kind}: {ctx}: got {got!r}, expected {want!r}")

    for x in v["tagged_hash"]:
        eq("tagged_hash", tagged_hash(x["tag"], bytes.fromhex(x["msg"])).hex(), x["out"], x["tag"])
    for x in v["bits"]:
        b = int(x["bits"], 16)
        eq("bits", f"{bits_to_target(b):064x}", x["target"], x["bits"])
        eq("bits", f"{target_to_bits(bits_to_target(b)):08x}", x["roundtrip"], x["bits"])
    for x in v["subsidy"]:
        eq("subsidy", subsidy(p, x["generated"]), x["subsidy"], x["generated"])
    for x in v["generated_at"]:
        eq("generated_at", generated_at(p, x["height"]), x["generated"], x["height"])
    for x in v["asert"]:
        tp = replace(p, pow_limit=int(x["pow_limit"], 16), target_spacing=x["target_spacing"],
                     asert_halflife=x["halflife"])
        got = asert_target(tp, int(x["anchor_bits"], 16), x["anchor_time"], x["parent_time"], x["parent_height"])
        eq("asert", f"{got:064x}", x["target"], (x["anchor_bits"], x["parent_time"], x["parent_height"]))
    for x in v["next_base_fee"]:
        tp = replace(p, target_block_size=x["target"], base_fee_change_denom=x["denom"], min_base_fee=x["min"])
        eq("next_base_fee", next_base_fee(tp, x["base_fee"], x["block_size"]), x["next"],
           (x["base_fee"], x["block_size"]))
    for x in v["merkle_root"]:
        eq("merkle_root", merkle_root([bytes.fromhex(h) for h in x["leaves"]]).hex(), x["root"], len(x["leaves"]))
    for x in v["muhash"]:
        m = MuHash()
        for h in x["insert"]:
            m.insert(bytes.fromhex(h))
        for h in x["remove"]:
            m.remove(bytes.fromhex(h))
        eq("muhash", m.digest().hex(), x["digest"], (len(x["insert"]), len(x["remove"])))
    for x in v["coin_bytes"]:
        c = Coin(x["value"], bytes.fromhex(x["address"]), x["height"], x["coinbase"])
        eq("coin_bytes", coin_bytes(OutPoint(bytes.fromhex(x["txid"]), x["index"]), c).hex(), x["bytes"],
           x["coinbase"])
    for x in v["address"]:
        a = make_address(bytes.fromhex(x["schnorr_pubkey"]), bytes.fromhex(x["pq_root"]))
        eq("address", a.hex(), x["address"], x["address"][:16])
        for hrp, s in x["bech32m"].items():
            eq("address", bech32m_encode(hrp, a), s, hrp)
    for x in v["sighash"]:
        tx = Transaction.deserialize(io.BytesIO(bytes.fromhex(x["tx_body"]) + b"\x00" * 2))
        spent = [(s["value"], bytes.fromhex(s["address"])) for s in x["spent"]]
        eq("sighash", tx.txid.hex(), x["txid"], "txid")
        eq("sighash", tx.sighash(bytes.fromhex(x["chain_id"]), spent).hex(), x["sighash"], x["chain_id"])
    for x in v["witness"]:
        got = verify_witness(bytes.fromhex(x["witness"]), bytes.fromhex(x["address"]),
                             bytes.fromhex(x["sighash"]), x["pq_only"])
        eq("witness", got, x["valid"], (x["what"], x["pq_only"]))
    for x in v["lamport"]:
        eq("lamport", pq_root(lamport_keygen(bytes.fromhex(x["seed"]))[1]).hex(), x["pq_root"], x["seed"][:16])
    for x in v["auxpow"]:
        a = AuxPow.deserialize(io.BytesIO(bytes.fromhex(x["auxpow"])))
        try:
            a.check(bytes.fromhex(x["aux_hash"]), x["chain_id"], int(x["target"], 16))
            res = "ok"
        except ValueError as e:
            res = str(e)
        eq("auxpow", res, x["result"], x["what"])
    for x in v["aux_slot"]:
        eq("aux_slot", expected_index(x["nonce"], x["chain_id"], x["height"]), x["index"],
           (x["nonce"], x["chain_id"], x["height"]))
    for x in v["genesis"]:
        eq("genesis", Block.deserialize(bytes.fromhex(x["block"])).hash.hex(), x["hash"], x["network"])
    return n, errs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--external", help="command that replays one chain vector (see above)")
    ap.add_argument("--accept-any-reason", action="store_true")
    ap.add_argument("files", nargs="*", help="chain vectors (default: all)")
    a = ap.parse_args(argv)
    files = a.files or sorted(glob.glob(os.path.join(CHAINS, "*.json")))
    total, errs = 0, []
    for f in files:
        n, e = (run_external(f, a.external.split(), a.accept_any_reason) if a.external else run_reference(f))
        total += n
        errs += e
        print(f"{os.path.basename(f)}: {n} steps, {'OK' if not e else f'{len(e)} mismatches'}")
    if not a.external and not a.files:
        n, e = check_functions()
        total += n
        errs += e
        print(f"functions.json: {n} checks, {'OK' if not e else f'{len(e)} mismatches'}")
    for e in errs[:50]:
        print("  " + e)
    print(f"{total} checks, {len(errs)} mismatches")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
