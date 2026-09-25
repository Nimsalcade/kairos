#!/usr/bin/env python3
"""
Post-quantum signature sizes for Kairos, measured rather than quoted.

For every candidate this script either produces and verifies real signatures
and measures them, or, where no implementation is available, computes the
size from the published parameter formulas (and says so). It then feeds the
resulting witness size into the node's own sweep model (kairos.pqstats) to get
block capacity and the time to move 1M and 100M coins.

    python3 tools/pq_sizes.py            # markdown tables, as in docs/pq-scaling.md
    python3 tools/pq_sizes.py --quick    # skip the slow library measurements

Measured here, with implementations in this file:
    Lamport as deployed; Lamport with key compression (and proof that it
    verifies against addresses that already exist); WOTS+ at several Winternitz
    parameters; WOTS+ under a small Merkle tree (XMSS-style, few-time).
Measured with reference libraries, when importable (pip install slh-dsa dilithium-py):
    SLH-DSA (FIPS 205), ML-DSA (FIPS 204).
Computed from formulas and checked against the standards' tables:
    SLH-DSA (all sets), ML-DSA, XMSS / XMSS^MT (RFC 8391), FN-DSA-512 (Falcon).
"""
import hashlib
import math
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos.crypto import (lamport_keygen, lamport_sign, lamport_verify, pq_root, tagged_hash,
                           LAMPORT_PUB_LEN, LAMPORT_SIG_LEN)
from kairos.params import TESTNET
from kairos import pqstats

SCHNORR_PK = 32           # every Kairos witness reveals the Schnorr key the address commits to
KIND = 1                  # witness kind byte


def sha256(b):
    return hashlib.sha256(b).digest()


def _bits(h32):
    v = int.from_bytes(h32, "big")
    return [(v >> (255 - i)) & 1 for i in range(256)]


# ------------------------------------------------ Lamport with key compression
def lamport_compressed_sign(msg, sk):
    """Reveal the chosen preimage and the *hash* of the other one for each bit.
    The verifier rebuilds the full 16 KiB public key and checks it against the
    pq_root the address already commits to: no new address type is needed."""
    h = tagged_hash("Kairos/lamport/msg", msg)
    return b"".join(sk[i][b] + sha256(sk[i][1 - b]) for i, b in enumerate(_bits(h)))


def lamport_compressed_verify(msg, sig, root):
    if len(sig) != 256 * 64:
        return False
    h = tagged_hash("Kairos/lamport/msg", msg)
    pub = []
    for i, b in enumerate(_bits(h)):
        chosen, other = sha256(sig[64 * i:64 * i + 32]), sig[64 * i + 32:64 * i + 64]
        pub.append(chosen + other if b == 0 else other + chosen)
    return pq_root(b"".join(pub)) == root


# ------------------------------------------------------------------ WOTS+
class Wots:
    """WOTS+ (RFC 8391 structure) with a tweakable hash: each chain step is
    hashed with the public seed and its (key, chain, step) address, as in
    SPHINCS+'s 'simple' instantiation. n-byte hashes, Winternitz parameter w."""

    def __init__(self, n=32, w=16):
        self.n, self.w, self.lg = n, w, int(math.log2(w))
        self.len1 = math.ceil(8 * n / self.lg)
        self.len2 = math.floor(math.log2(self.len1 * (w - 1)) / self.lg) + 1
        self.len = self.len1 + self.len2

    def f(self, seed, key, chain, step, x):
        adrs = key.to_bytes(4, "big") + chain.to_bytes(2, "big") + step.to_bytes(2, "big")
        return tagged_hash("Kairos/wots", seed + adrs + x)[:self.n]

    def chain(self, seed, key, i, x, start, steps):
        for s in range(start, start + steps):
            x = self.f(seed, key, i, s, x)
        return x

    def digits(self, msg):
        h = tagged_hash("Kairos/wots/msg", msg)[:self.n]
        v, d = int.from_bytes(h, "big"), []
        for _ in range(self.len1):
            d.append(v & (self.w - 1))
            v >>= self.lg
        d.reverse()
        csum = sum(self.w - 1 - x for x in d)
        cs = []
        for _ in range(self.len2):
            cs.append(csum & (self.w - 1))
            csum >>= self.lg
        return d + cs[::-1]

    def keygen(self, secret, seed, key=0):
        sk = [tagged_hash("Kairos/wots/sk", secret + key.to_bytes(4, "big") + i.to_bytes(2, "big"))[:self.n]
              for i in range(self.len)]
        ends = [self.chain(seed, key, i, sk[i], 0, self.w - 1) for i in range(self.len)]
        return sk, tagged_hash("Kairos/wots/pk", seed + b"".join(ends))[:self.n]

    def sign(self, msg, sk, seed, key=0):
        return b"".join(self.chain(seed, key, i, sk[i], 0, d) for i, d in enumerate(self.digits(msg)))

    def pk_from_sig(self, msg, sig, seed, key=0):
        n = self.n
        ends = [self.chain(seed, key, i, sig[i * n:(i + 1) * n], d, self.w - 1 - d)
                for i, d in enumerate(self.digits(msg))]
        return tagged_hash("Kairos/wots/pk", seed + b"".join(ends))[:n]


class WotsTree:
    """2^h WOTS+ keys under a Merkle root: an XMSS-style few-time key. The
    signature is the leaf index, the WOTS+ signature and the authentication path."""

    def __init__(self, h, n=32, w=16):
        self.h, self.wots, self.n = h, Wots(n, w), n

    def node(self, seed, a, b):
        return tagged_hash("Kairos/xmss/node", seed + a + b)[:self.n]

    def keygen(self, secret, seed):
        keys = [self.wots.keygen(secret, seed, k) for k in range(1 << self.h)]
        levels = [[pk for _, pk in keys]]
        while len(levels[-1]) > 1:
            lv = levels[-1]
            levels.append([self.node(seed, lv[i], lv[i + 1]) for i in range(0, len(lv), 2)])
        return keys, levels, levels[-1][0]

    def sign(self, msg, keys, levels, seed, idx):
        path = b"".join(levels[l][(idx >> l) ^ 1] for l in range(self.h))
        return idx.to_bytes(4, "big") + self.wots.sign(msg, keys[idx][0], seed, idx) + path

    def verify(self, msg, sig, seed, root):
        idx = int.from_bytes(sig[:4], "big")
        n, ws = self.n, self.wots.len * self.n
        x = self.wots.pk_from_sig(msg, sig[4:4 + ws], seed, idx)
        path = sig[4 + ws:]
        for l in range(self.h):
            sib = path[l * n:(l + 1) * n]
            x = self.node(seed, x, sib) if not (idx >> l) & 1 else self.node(seed, sib, x)
        return x == root


# ------------------------------------------------ published parameter formulas
# FIPS 205 Table 2: (n, h, d, h', a, k, lg_w) and the signature size the standard lists.
SLH_DSA = {
    "SLH-DSA-SHA2-128s": (16, 63, 7, 9, 12, 14, 4, 7856),
    "SLH-DSA-SHA2-128f": (16, 66, 22, 3, 6, 33, 4, 17088),
    "SLH-DSA-SHA2-192s": (24, 63, 7, 9, 14, 17, 4, 16224),
    "SLH-DSA-SHA2-192f": (24, 66, 22, 3, 8, 33, 4, 35664),
    "SLH-DSA-SHA2-256s": (32, 64, 8, 8, 14, 22, 4, 29792),
    "SLH-DSA-SHA2-256f": (32, 68, 17, 4, 9, 35, 4, 49856),
}


def slh_sizes(n, h, d, hp, a, k, lgw):
    w = 1 << lgw
    len1 = math.ceil(8 * n / lgw)
    ln = len1 + math.floor(math.log2(len1 * (w - 1)) / lgw) + 1
    sig = n + k * (1 + a) * n + (h + d * ln) * n
    verify_hashes = k * (1 + a) + 1 + d * (ln * (w - 1) + 1 + hp)          # worst case
    return sig, 2 * n, verify_hashes


# FIPS 204 Table 1/2: (k, l, eta, gamma1 bits, omega, lambda) and listed (pk, sig).
ML_DSA = {
    "ML-DSA-44": (4, 4, 17, 80, 128, 1312, 2420),
    "ML-DSA-65": (6, 5, 19, 55, 192, 1952, 3309),
    "ML-DSA-87": (8, 7, 19, 75, 256, 2592, 4627),
}


def mldsa_sizes(k, l, g1bits, omega, lam):
    pk = 32 + k * 256 * 10 // 8
    sig = lam // 4 + l * 256 * (g1bits + 1) // 8 + omega + k
    return pk, sig


def xmss_sig(n, h, d=1, wots_len=67):
    """RFC 8391: XMSS sig = idx(4) + r(n) + len*n + h*n; XMSS^MT idx is ceil(h/8)."""
    idx = 4 if d == 1 else math.ceil(h / 8)
    return idx + n + (h + d * wots_len) * n


FALCON_512 = (897, 666)     # pk = 1 + 512*14/8; 666 is the standard's padded signature length


# ------------------------------------------------------------------ report
def witness_row(name, pq_pk, sig, how, note=""):
    wit = KIND + SCHNORR_PK + pq_pk + sig
    return {"name": name, "pq_pk": pq_pk, "sig": sig, "witness": wit, "how": how, "note": note}


def capacity(rows, params=TESTNET):
    for r in rows:
        r["input"] = pqstats.input_bytes(r["witness"])
        one = pqstats.sweep_plan(params, 1_000_000, witness_len=r["witness"])
        hundred = pqstats.sweep_plan(params, 100_000_000, witness_len=r["witness"])
        r["per_block"] = one["inputs_per_block"]
        r["days_1m"] = one["days"]
        r["days_100m"] = hundred["days"]
    return rows


def measure(quick=False):
    rows, msg = [], tagged_hash("Kairos/test", b"sizes")
    seed, secret = b"\x07" * 32, b"\x09" * 32

    # Lamport as deployed
    sk, pub = lamport_keygen(seed)
    sig = lamport_sign(msg, sk)
    assert lamport_verify(msg, pub, sig) and len(pub) == LAMPORT_PUB_LEN and len(sig) == LAMPORT_SIG_LEN
    rows.append(witness_row("Lamport (deployed)", len(pub), len(sig), "measured",
                            "one-time; existing addresses"))
    # compressed, against the existing commitment
    csig = lamport_compressed_sign(msg, sk)
    assert lamport_compressed_verify(msg, csig, pq_root(pub))
    assert not lamport_compressed_verify(tagged_hash("Kairos/test", b"other"), csig, pq_root(pub))
    rows.append(witness_row("Lamport, compressed", 0, len(csig), "measured",
                            "one-time; verifies against existing addresses"))

    for n, w in ((32, 4), (32, 16), (32, 256), (16, 16)):
        wo = Wots(n, w)
        wsk, wpk = wo.keygen(secret, seed[:n])
        s = wo.sign(msg, wsk, seed[:n])
        assert wo.pk_from_sig(msg, s, seed[:n]) == wpk
        assert wo.pk_from_sig(tagged_hash("Kairos/test", b"other"), s, seed[:n]) != wpk
        lvl = "128-bit level" if n == 16 else "256-bit hash"
        rows.append(witness_row(f"WOTS+ n={n} w={w}", n, len(s), "measured",
                                f"one-time; {lvl}; verify ≤ {wo.len * (w - 1)} hashes"))
    for h in ((4,) if quick else (4, 10)):
        t = WotsTree(h)
        keys, levels, root = t.keygen(secret, seed)
        s = t.sign(msg, keys, levels, seed, 5)
        assert t.verify(msg, s, seed, root)
        assert not t.verify(tagged_hash("Kairos/test", b"other"), s, seed, root)
        rows.append(witness_row(f"WOTS+ tree h={h} (XMSS-style)", 32, len(s), "measured",
                                f"{1 << h} signatures per key; stateful"))

    # standards, from formulas (checked against the tables)
    for name, (n, h, d, hp, a, k, lgw, listed) in SLH_DSA.items():
        s, pk, vh = slh_sizes(n, h, d, hp, a, k, lgw)
        assert s == listed, (name, s, listed)
        rows.append(witness_row(name, pk, s, "formula = FIPS 205 table",
                                f"stateless; verify ≤ {vh:,} hashes"))
    for name, (k, l, g1, om, lam, lpk, lsig) in ML_DSA.items():
        pk, s = mldsa_sizes(k, l, g1, om, lam)
        assert (pk, s) == (lpk, lsig), (name, pk, s)
        rows.append(witness_row(name, pk, s, "formula = FIPS 204 table", "lattice; stateless"))
    rows.append(witness_row("FN-DSA-512 (Falcon)", *FALCON_512, "published sizes",
                            "lattice; floating-point signing"))
    for name, n, h, d in (("XMSS-SHA2_10_256", 32, 10, 1), ("XMSS-SHA2_20_256", 32, 20, 1),
                          ("XMSSMT-SHA2_20/2_256", 32, 20, 2), ("XMSSMT-SHA2_60/3_256", 32, 60, 3)):
        rows.append(witness_row(name, 2 * n, xmss_sig(n, h, d), "formula (RFC 8391)",
                                f"2^{h} signatures; stateful"))

    # reference libraries, when available: replace formula rows by real signatures
    if not quick:
        try:
            import slhdsa
            for name, attr in (("SLH-DSA-SHA2-128s", "sha2_128s"), ("SLH-DSA-SHA2-128f", "sha2_128f"),
                               ("SLH-DSA-SHA2-256s", "sha2_256s")):
                kp = slhdsa.KeyPair.gen(getattr(slhdsa, attr))
                t0 = time.time()
                s = kp.sign_pure(msg)
                t1 = time.time()
                assert kp.verify_pure(msg, s)
                t2 = time.time()
                row = next(r for r in rows if r["name"] == name)
                assert row["sig"] == len(s) and row["pq_pk"] == len(kp.pub.digest())
                row["how"] = "measured (slh-dsa library)"
                row["note"] += f"; sign {t1 - t0:.1f} s, verify {1000 * (t2 - t1):.0f} ms here"
        except ImportError:
            pass
        try:
            from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
            for name, alg in (("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)):
                pk, sk = alg.keygen()
                s = alg.sign(sk, msg)
                assert alg.verify(pk, msg, s)
                row = next(r for r in rows if r["name"] == name)
                assert (row["pq_pk"], row["sig"]) == (len(pk), len(s))
                row["how"] = "measured (dilithium-py)"
        except ImportError:
            pass
    return capacity(rows)


def commit_reveal_rows(params=TESTNET):
    """Commit-delay-reveal: coins whose Schnorr key has never been revealed move
    with an ordinary Schnorr witness, authorised by a 32-byte commitment mined
    earlier. Worst case one commitment per coin; best case one per transaction."""
    out = []
    schnorr = pqstats.SCHNORR_WITNESS
    for label, commit_per_coin in (("commit-delay-reveal, 1 commitment per coin", 32),
                                   ("commit-delay-reveal, 1 commitment per 32 coins", 1)):
        per_coin = pqstats.input_bytes(schnorr) + commit_per_coin
        room = pqstats.block_room(params)
        per_block = room // per_coin
        d1 = math.ceil(1_000_000 / per_block) * params.target_spacing / 86400
        d100 = math.ceil(100_000_000 / per_block) * params.target_spacing / 86400
        out.append({"name": label, "input": per_coin, "per_block": per_block,
                    "days_1m": round(d1, 2), "days_100m": round(d100, 2)})
    return out


def markdown(rows, cr):
    lines = ["| Scheme | PQ key in witness | Signature | Witness | Bytes per input | Inputs per 2 MB block "
             "| 1M coins (days) | 100M coins (days) | Source |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for r in rows:
        lines.append(f"| {r['name']} | {r['pq_pk']:,} | {r['sig']:,} | {r['witness']:,} | {r['input']:,} "
                     f"| {r['per_block']:,} | {r['days_1m']:,} | {r['days_100m']:,} | {r['how']} |")
    lines += ["", "| Non-signature option | Bytes per coin | Coins per 2 MB block | 1M coins (days) "
                  "| 100M coins (days) |", "|---|---:|---:|---:|---:|"]
    for r in cr:
        lines.append(f"| {r['name']} | {r['input']:,} | {r['per_block']:,} | {r['days_1m']:,} "
                     f"| {r['days_100m']:,} |")
    lines += ["", "Notes:"] + [f"- {r['name']}: {r['note']}" for r in rows if r["note"]]
    return "\n".join(lines)


if __name__ == "__main__":
    rows = measure(quick="--quick" in sys.argv)
    print(markdown(rows, commit_reveal_rows()))
