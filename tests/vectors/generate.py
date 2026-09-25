#!/usr/bin/env python3
"""
Generate the Kairos consensus conformance vectors from the reference node.

    python3 tests/vectors/generate.py          # rewrites tests/vectors/chains/*.json and functions.json

Generation is deterministic: the same code produces byte-identical files, so a
diff of the vectors shows exactly which consensus behaviour changed.

How the chain vectors are built. A *builder* chain only ever sees valid blocks
and is used to construct templates. Every invalid block is a valid template
with exactly one rule broken, so its expected result has a single, unambiguous
reason whatever order another implementation checks rules in. A *subject*
chain replays every step and records what the reference node returned; the
generator asserts that this is what the scenario intended.
"""
import json
import os
import struct
import sys
from dataclasses import replace

sys.path.insert(0, os.path.dirname(__file__))
from common import CHAINS, FUNCTIONS, FORMAT, Clock, params_to_json, observe  # noqa: E402

from kairos import crypto  # noqa: E402
from kairos.auxpow import AuxPow, MM_MAGIC, build_commitment, expected_index  # noqa: E402
from kairos.block import Block, BlockHeader, VERSION_AUXPOW, genesis_block, mine  # noqa: E402
from kairos.chain import Chain, UtxoView, ValidationError, coin_bytes, Coin  # noqa: E402
from kairos.crypto import (MuHash, lamport_sign, merkle_root, schnorr_sign, sha256d,  # noqa: E402
                           tagged_hash, bech32m_encode, pq_root, lamport_keygen)
from kairos.params import (MAX_MONEY, REGTEST, asert_target, bits_to_target, next_base_fee,  # noqa: E402
                           subsidy, target_to_bits, generated_at, Deployment)
from kairos.tx import (OutPoint, Transaction, TxIn, TxOut, lamport_witness, make_address,  # noqa: E402
                       make_coinbase, schnorr_witness, verify_witness)
from kairos.wallet import Key  # noqa: E402

SEED = b"Kairos conformance vectors v1...."


def aux_rand(sk: bytes, msg: bytes) -> bytes:
    return tagged_hash("Kairos/vectors/aux", sk + msg)


# ------------------------------------------------------------ merge-mining helpers
def _varint(n):
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)


def btc_coinbase(script: bytes) -> bytes:
    return (struct.pack("<I", 1) + b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff"
            + _varint(len(script)) + script + b"\xff\xff\xff\xff"
            + b"\x01" + struct.pack("<Q", 312_500_000) + b"\x01\x51" + struct.pack("<I", 0))


def make_auxpow(kairos_hash, target, script_extra=b"", chain_tree=None, weak=False, tamper_branch=False):
    """A Bitcoin parent block committing to `kairos_hash`, ground to meet
    `target` (or, with weak=True, to miss it)."""
    if chain_tree is None:
        commit, chain_branch, chain_index = build_commitment(kairos_hash), [], 0
    else:
        commit, chain_branch, chain_index = chain_tree
    cb = btc_coinbase(b"\x03\x01\x02\x03" + commit + script_extra)
    t1, t2 = b"\x11" * 32, b"\x22" * 32
    right = sha256d(t2 + t2)
    root = sha256d(sha256d(sha256d(cb) + t1) + right)
    hdr = struct.pack("<I", 0x20000000) + b"\x33" * 32 + root + struct.pack("<II", 1_800_000_000, 0x17034219)
    branch = [t1, right] if not tamper_branch else [b"\x44" * 32, right]
    for n in range(1 << 22):
        h = hdr + struct.pack("<I", n)
        ok = int.from_bytes(sha256d(h), "little") <= target
        if ok != weak:
            return AuxPow(cb, branch, chain_branch, chain_index, h)
    raise RuntimeError("could not grind parent")


# ------------------------------------------------------------ the scenario builder
class Scenario:
    def __init__(self, name, params, description, t0=None):
        self.name, self.params, self.description = name, params, description
        self.clock = Clock(t0 if t0 is not None else params.genesis_time + 1)
        self.b = Chain(params, now=self.clock)         # builder: valid blocks only
        self.s = Chain(params, now=self.clock)         # subject: replays everything
        self.steps = []
        self.keys = [Key(SEED, i) for i in range(12)]
        self.by_addr = {k.address: k for k in self.keys}
        self.rotate = 0

    # -- keys and coins
    def next_addr(self):
        k = self.keys[self.rotate % len(self.keys)]
        self.rotate += 1
        return k.address

    def big_coins(self):
        return [x for x in self.coins() if x[1].value >= 3 * 10 ** 8]

    def coins(self, chain=None):
        """Mature coins our keys own, oldest first (deterministic order)."""
        c = chain or self.b
        h = c.height + 1
        out = [(op, coin) for op, coin in c.utxos.items()
               if coin.address in self.by_addr and not (coin.coinbase and h - coin.height < c.params.coinbase_maturity)]
        return sorted(out, key=lambda x: (x[1].height, x[0].txid, x[0].index))

    # -- transactions
    def sign(self, tx, coins, pq=False, chain_id=None, spent=None, keys=None):
        sh = tx.sighash(chain_id or self.params.chain_id, spent or [(c.value, c.address) for _, c in coins])
        for n, (inp, (_, coin)) in enumerate(zip(tx.inputs, coins)):
            k = keys[n] if keys else self.by_addr[coin.address]
            if pq:
                sk, lpub = k.lamport
                inp.witness = lamport_witness(k.pubkey, lpub, lamport_sign(sh, sk))
            else:
                inp.witness = schnorr_witness(k.pubkey, k.pqroot, schnorr_sign(sh, k.seckey, aux_rand(k.seckey, sh)))
        tx.invalidate()
        return tx

    def pay(self, coins, outs=None, fee_rate=2, expiry=0, version=1, pq=False, n_outputs=None, **kw):
        """Spend `coins` to `outs` [(value, address)] plus change, paying
        fee_rate * base_fee per byte. With `outs` None, sweep to one output."""
        base = self.b.tip.next_base_fee
        wlen = (1 + 32 + crypto.LAMPORT_PUB_LEN + crypto.LAMPORT_SIG_LEN) if pq else (1 + 32 + 32 + 64)
        outs = list(outs or [])
        if n_outputs:
            outs += [(1_000_000, self.next_addr()) for _ in range(n_outputs)]
        total = sum(c.value for _, c in coins)
        draft = Transaction([TxIn(op, b"\x00" * wlen) for op, _ in coins],
                            [TxOut(v, a) for v, a in outs] + [TxOut(1, self.next_addr())], expiry, version)
        fee = fee_rate * base * draft.size
        change = total - sum(v for v, _ in outs) - fee
        tx = Transaction([TxIn(op) for op, _ in coins],
                         [TxOut(v, a) for v, a in outs] + ([TxOut(change, draft.outputs[-1].address)] if change > 0 else []),
                         expiry, version)
        return self.sign(tx, coins, pq=pq, **kw)

    # -- blocks
    def template(self, txs=(), t=None, extra=b"", cb_delta=0, version=None, chain=None, auxpow=False):
        c = chain or self.b
        p = c.params
        parent = c.tip
        height = parent.height + 1
        base_fee = parent.next_base_fee
        pq_only = c.pq_active(parent)
        view = UtxoView(c.utxos)
        tips = 0
        for tx in txs:
            try:
                fee, burn = c.check_tx(tx, view, height, base_fee, pq_only)
                tips += fee - burn
            except ValidationError:
                pass
            try:
                c.apply_tx(tx, view, height)
            except (ValidationError, KeyError):
                pass
        cb = make_coinbase(height, [TxOut(subsidy(p, parent.generated) + tips + cb_delta, self.next_addr())],
                           extra or b"vec")
        c.apply_tx(cb, view, height)
        root, _ = c.utxo_digest(parent.muhash, view)
        tm = t if t is not None else max(self.clock.t, c.median_time_past(parent) + 1)
        ver = version if version is not None else c.block_version(parent, auxpow)
        hdr = BlockHeader(ver, height, parent.hash, b"", root, tm, c.expected_bits(parent), 0, 0)
        return Block(hdr, [cb] + list(txs))

    def seal(self, blk, chain=None, root=True, fee=True, pow=True, weak=False):
        c = chain or self.b
        parent = c.index.get(blk.header.prev_hash)
        if root:
            blk.header.tx_root = blk.compute_tx_root()
        if fee and parent is not None:
            blk.header.fee = next_base_fee(c.params, parent.next_base_fee, blk.size)
        if pow:
            if blk.header.version & VERSION_AUXPOW:
                blk.auxpow = make_auxpow(blk.hash, bits_to_target(blk.header.bits), weak=weak)
            else:
                blk.header.nonce = 0
                if weak:
                    target = bits_to_target(blk.header.bits)
                    while int.from_bytes(blk.header.hash, "little") <= target:
                        blk.header.nonce += 1
                else:
                    assert mine(blk.header)
        return blk

    def step(self, blk_or_hex, expect, note, adopt=True):
        """Submit to the subject and record. Valid blocks also extend the builder."""
        hexs = blk_or_hex if isinstance(blk_or_hex, str) else blk_or_hex.serialize().hex()
        from common import submit
        status = submit(self.s, hexs)
        assert status == expect, f"{self.name}: {note}: got {status!r}, expected {expect!r}"
        if adopt and status == "accepted" and not isinstance(blk_or_hex, str):
            if blk_or_hex.header.prev_hash == self.b.tip.hash:
                assert self.b.submit_block(Block.deserialize(bytes.fromhex(hexs))) == "accepted"
        rec = {"note": note, "now": self.clock.t, "block": hexs, "expect": expect}
        rec.update(observe(self.s))
        self.steps.append(rec)
        return blk_or_hex

    def valid(self, txs=(), note="valid block", step=120, **kw):
        self.clock.t += step
        blk = self.seal(self.template(txs, **kw))
        return self.step(blk, "accepted", note)

    def invalid(self, reason, note, txs=(), mutate=None, seal_kw=None, **kw):
        """A template at the next height with one rule broken."""
        self.clock.t += 1
        blk = self.template(txs, **kw)
        if mutate:
            blk = mutate(blk) or blk
        self.seal(blk, **(seal_kw or {}))
        self.clock.t -= 1
        return self.step(blk, reason, note)

    def dump(self):
        os.makedirs(CHAINS, exist_ok=True)
        out = {"format": FORMAT, "name": self.name, "description": self.description,
               "params": params_to_json(self.params), "genesis": genesis_block(self.params).hash.hex(),
               "steps": self.steps}
        with open(os.path.join(CHAINS, self.name + ".json"), "w") as f:
            json.dump(out, f, indent=1)
            f.write("\n")


# ------------------------------------------------------------ scenarios
def core():
    """Transaction and block rules, coinbase rules, timestamps, reorg, malformed data."""
    p = replace(REGTEST, deployments=())
    s = Scenario("core", p, "Transaction rules, block rules, coinbase rules, timestamps, "
                             "a reorganisation and malformed encodings, on regtest parameters.")
    for i in range(4):
        s.valid(note=f"mine block {i + 1}")
    c1, c2 = s.coins()[0], s.coins()[1]
    s.valid([s.pay([c1], [(10 * 10 ** 8, s.keys[5].address)]), s.pay([c2])], note="two Schnorr spends")

    coins = s.coins()
    good = coins[0]
    base = s.b.tip.next_base_fee
    height = s.b.height + 1
    R = "invalid: "

    # --- witnesses and the signature hash
    def flip_sig(tx):
        w = bytearray(tx.inputs[0].witness)
        w[-1] ^= 1
        tx.inputs[0].witness = bytes(w)
        tx.invalidate()
        return tx
    s.invalid(R + "invalid signature", "Schnorr signature with one bit flipped", [flip_sig(s.pay([good]))])
    s.invalid(R + "invalid signature", "signature commits to a different spent amount",
              [s.pay([good], spent=[(good[1].value + 1, good[1].address)])])
    s.invalid(R + "invalid signature", "signature made for another chain id",
              [s.pay([good], chain_id=b"KRS\x01")])
    s.invalid(R + "invalid signature", "valid signature by a key the address does not commit to",
              [s.pay([good], keys=[s.keys[11] if s.keys[11].address != good[1].address else s.keys[10]])])

    def set_wit(w):
        def f(blk):
            tx = blk.txs[1]
            tx.inputs[0].witness = w
            tx.invalidate()
        return f
    for w, what in ((b"", "empty witness"), (b"\x03" + b"\x00" * 128, "unknown witness kind 3"),
                    (s.pay([good]).inputs[0].witness[:-1], "Schnorr witness one byte short")):
        s.invalid(R + "invalid signature", what, [s.pay([good])], mutate=set_wit(w))
    s.invalid(R + "invalid signature", "Lamport witness with the wrong Lamport key",
              [s.pay([good], pq=True, keys=[s.keys[10] if s.keys[10].address != good[1].address else s.keys[11]])])

    # --- inputs and outputs
    ghost = (OutPoint(b"\x42" * 32, 0), good[1])
    s.invalid(R + "missing or spent input", "spends an outpoint that never existed", [s.pay([ghost])])
    s.invalid(R + "missing or spent input", "spends a coin already spent in block 5", [s.pay([c1])])
    s.invalid(R + "missing or spent input", "two transactions in one block spend the same coin",
              [s.pay([good]), s.pay([good], fee_rate=3)])
    s.invalid(R + "duplicate input", "the same input twice in one transaction", [s.pay([good, good])])
    newest = [x for x in s.b.utxos.items() if x[1].coinbase and x[1].height == s.b.height][0]
    s.invalid(R + "immature coinbase spend", "coinbase spent one block after it was mined",
              [s.pay([newest])])
    s.invalid(R + "outputs exceed inputs", "outputs worth one mote more than the input",
              [s.sign(Transaction([TxIn(good[0])], [TxOut(good[1].value + 1, s.keys[6].address)]), [good])])
    shape = Transaction([TxIn(good[0], b"\x00" * 129)], [TxOut(1, s.keys[6].address)])
    burn = base * shape.size                      # output values do not change the size
    under = s.sign(Transaction([TxIn(good[0])], [TxOut(good[1].value - burn + 1, s.keys[6].address)]), [good])
    s.invalid(R + f"fee {burn - 1} below base fee burn {burn}", "fee one mote below the base-fee burn", [under])
    for outs, reason, what in (([(0, s.keys[6].address)], "bad output", "zero-value output"),
                               ([(MAX_MONEY + 1, s.keys[6].address)], "bad output", "output above MAX_MONEY"),
                               ([(MAX_MONEY, s.keys[6].address), (MAX_MONEY, s.keys[7].address)],
                                "output total overflow", "outputs summing above MAX_MONEY")):
        tx = s.sign(Transaction([TxIn(good[0])], [TxOut(v, a) for v, a in outs]), [good])
        s.invalid(R + reason, what, [tx])
    s.invalid(R + "empty inputs or outputs", "no outputs",
              [s.sign(Transaction([TxIn(good[0])], []), [good])])
    s.invalid(R + "empty inputs or outputs", "no inputs", [Transaction([], [TxOut(1000, s.keys[6].address)])])
    s.invalid(R + "unknown tx version", "transaction version 2", [s.pay([good], version=2)])
    s.invalid(R + "transaction expired", "expiry one below the block height", [s.pay([good], expiry=height - 1)])

    # --- block structure
    def swap(blk):
        blk.txs[0], blk.txs[1] = blk.txs[1], blk.txs[0]
    s.invalid(R + "first transaction must be coinbase", "coinbase is second", [s.pay([good])], mutate=swap)

    def two_cb(blk):
        blk.txs.append(make_coinbase(blk.header.height, [TxOut(1, s.keys[6].address)], b"x"))
    s.invalid(R + "multiple coinbases", "a second coinbase", mutate=two_cb)
    s.invalid(R + "unknown block version", "version low byte 2", version=2)
    s.invalid(R + "unknown block version", "version low byte 0 with a signal bit", version=1 << 16)

    def easy_bits(blk):
        blk.header.bits = target_to_bits(p.pow_limit) + 1
    s.invalid(R + "target above proof-of-work limit", "bits above the limit", mutate=easy_bits)
    s.invalid(R + "proof-of-work too weak", "header hash above its target", seal_kw={"weak": True})

    def bad_root(blk):
        blk.header.tx_root = b"\x55" * 32
    s.invalid(R + "tx_root mismatch", "tx_root that commits to nothing", mutate=bad_root, seal_kw={"root": False})

    def cb_wit(w):
        def f(blk):
            blk.txs[0].inputs[0].witness = w
            blk.txs[0].invalidate()
        return f
    s.invalid(R + "bad coinbase witness size", "3-byte coinbase witness",
              mutate=cb_wit(struct.pack("<I", height)[:3]))
    s.invalid(R + "bad coinbase witness size", "101-byte coinbase witness",
              mutate=cb_wit(struct.pack("<I", height) + b"\x00" * 97))
    s.invalid(R + "coinbase height mismatch", "coinbase commits to the wrong height",
              mutate=cb_wit(struct.pack("<I", height + 1) + b"vec"))

    def skip_height(blk):
        blk.header.height += 1
        blk.txs[0] = make_coinbase(blk.header.height, blk.txs[0].outputs, b"vec")
    s.invalid(R + "bad height", "height two above the parent", mutate=skip_height)

    def harder(blk):
        blk.header.bits -= 1
    s.invalid(R + "bad difficulty bits", "bits one below the expected value", mutate=harder)
    mtp = s.b.median_time_past(s.b.tip)
    s.invalid(R + "timestamp too early", "time equal to the median of the last 11 blocks", t=mtp)
    s.invalid(R + "timestamp too far in future", "time more than 2 hours past the node clock",
              t=s.clock.t + 1 + p.max_future_drift + 1)

    # --- coinbase value and fields
    def cb_field(**kw):
        def f(blk):
            cb = blk.txs[0]
            for k, v in kw.items():
                setattr(cb, k, v)
            cb.invalidate()
        return f
    s.invalid(R + "bad coinbase fields", "coinbase with an expiry", mutate=cb_field(expiry=5))
    s.invalid(R + "bad coinbase fields", "coinbase version 2", mutate=cb_field(version=2))

    def cb_value(v):
        def f(blk):
            blk.txs[0].outputs[0] = TxOut(v, blk.txs[0].outputs[0].address)
            blk.txs[0].invalidate()
        return f
    s.invalid(R + "bad coinbase output", "coinbase output above MAX_MONEY", mutate=cb_value(MAX_MONEY + 1))
    s.invalid(R + "coinbase pays too much", "coinbase one mote above subsidy plus tips",
              [s.pay([good])], cb_delta=1)

    def bad_utxo(blk):
        blk.header.utxo_root = bytes([blk.header.utxo_root[0] ^ 1]) + blk.header.utxo_root[1:]
    s.invalid(R + "utxo_root mismatch", "UTXO commitment with one bit flipped", mutate=bad_utxo)
    s.clock.t += 1
    blk = s.seal(s.template())
    blk.header.fee += 1
    s.seal(blk, fee=False)
    s.clock.t -= 1
    s.step(blk, R + "base fee mismatch", "header base fee one above the rule")

    # --- a block whose parent is invalid
    s.clock.t += 1
    bad = s.seal(s.template(cb_delta=1))
    s.step(bad, R + "coinbase pays too much", "invalid parent: stored, then rejected on connect")
    cb = make_coinbase(bad.header.height + 1, [TxOut(1, s.keys[6].address)], b"vec")
    hdr = BlockHeader(1, bad.header.height + 1, bad.hash, b"", b"\x00" * 32, s.clock.t + 1, bad.header.bits, 1, 0)
    child = s.seal(Block(hdr, [cb]), fee=False)
    s.clock.t -= 1
    s.step(child, R + "parent invalid", "child of an invalid block")

    # --- malformed encodings
    ok = s.seal(s.template()).serialize()
    s.step(ok[:-1].hex(), "malformed", "block truncated by one byte")
    s.step((ok + b"\x00").hex(), "malformed", "block with a trailing byte")
    s.step(ok[:50].hex(), "malformed", "block shorter than a header")

    # --- boundaries that must be accepted
    s.valid([s.pay([good], expiry=height)], note="expiry equal to the block height is still valid")
    fresh = s.coins()[0]
    shape = Transaction([TxIn(fresh[0], b"\x00" * 129)], [TxOut(1, s.keys[6].address)])
    burn = s.b.tip.next_base_fee * shape.size
    exact = s.sign(Transaction([TxIn(fresh[0])], [TxOut(fresh[1].value - burn, s.keys[6].address)]), [fresh])
    s.valid([exact], note="fee exactly equal to the base-fee burn")
    s.valid(note="coinbase paying less than allowed: the difference is burned", cb_delta=-10 ** 8)
    s.valid(note="unknown version bit 30 is ignored", version=1 | (1 << 30))
    s.valid(note="timestamp exactly 2 hours past the node clock", t=s.clock.t + 120 + p.max_future_drift)
    s.clock.t += p.max_future_drift
    s.valid(note="empty block", step=120)
    last = s.steps[-1]["block"]
    s.step(last, "duplicate", "the same block again")

    # --- reorganisation: a heavier branch that double-spends a coin
    fork_at = s.b.height - 2
    fb = Chain(p, now=s.clock)
    for idx in s.b.active[1:fork_at + 1]:
        assert fb.submit_block(s.b.blocks[idx.hash]) == "accepted"
    target = [x for x in s.coins() if x[1].height <= fork_at][0]
    main_spend = s.pay([target], [(10 ** 8, s.keys[8].address)])
    s.valid([main_spend], note="main chain spends a coin")
    fork_spend = s.pay([target], [(2 * 10 ** 8, s.keys[9].address)], fee_rate=3)
    branch = []
    for i in range(4):
        s.clock.t += 60
        blk = s.seal(s.template([fork_spend] if i == 0 else [], chain=fb), chain=fb)
        assert fb.submit_block(Block.deserialize(blk.serialize())) == "accepted"
        branch.append(blk)
    s.step(branch[1], "orphan", "fork block 2 before its parent: kept as an orphan", adopt=False)
    s.step(branch[0], "accepted", "fork block 1 connects the orphan; equal work keeps the first-seen tip",
           adopt=False)
    s.step(branch[2], "accepted", "fork block 3: equal work, the first-seen tip stays", adopt=False)
    s.step(branch[3], "accepted", "fork block 4: more work, the node reorganises and the double-spend wins",
           adopt=False)
    assert s.s.tip.hash == branch[3].hash
    s.b = fb
    s.valid(note="extend the new tip")
    return s


def limits():
    """Block and transaction size limits and the base-fee controller."""
    p = replace(REGTEST, deployments=(), max_block_size=20_000, target_block_size=10_000)
    s = Scenario("limits", p, "Size limits and the base fee, with a 20 kB block limit and a 10 kB target.")
    for i in range(10):
        s.valid(note=f"mine block {i + 1}")
    before = s.b.tip.next_base_fee
    cs = s.big_coins()[:2]
    s.valid([s.pay([cs[0]], n_outputs=124, fee_rate=1), s.pay([cs[1]], n_outputs=124, fee_rate=1)],
            note="block just above target: the proportional rise rounds to 0, so the +1 floor applies")
    assert s.s.tip.next_base_fee == before + 1 and s.b.blocks[s.b.tip.hash].size > p.target_block_size
    for i in range(6):
        cs = s.big_coins()[:2]
        s.valid([s.pay([cs[0]], n_outputs=200, fee_rate=1), s.pay([cs[1]], n_outputs=200, fee_rate=1)],
                note=f"about 16 kB: base fee rises ({i + 1})")
    cs = s.big_coins()
    base = s.b.tip.next_base_fee
    draft = s.pay([cs[0]], fee_rate=1)
    burn = base * draft.size
    tx = s.sign(Transaction([TxIn(cs[0][0])], [TxOut(cs[0][1].value - burn + 1, s.keys[6].address)]), [cs[0]])
    s.invalid(f"invalid: fee {burn - 1} below base fee burn {burn}", "fee one mote short of the raised burn", [tx])
    s.invalid("invalid: transaction too large", "a transaction above half the block limit",
              [s.pay([cs[0]], n_outputs=255)])
    s.invalid("invalid: block too large", "three 7 kB transactions",
              [s.pay([cs[i]], n_outputs=170) for i in range(3)])
    for i in range(8):
        s.valid(note=f"empty block: base fee falls ({i + 1})")
    return s


def asert():
    """Per-block difficulty: ASERT with a short half-life so it moves within a few blocks."""
    p = replace(REGTEST, deployments=(), no_retarget=False, asert_anchor_bits=0x1F0FFFFF, asert_halflife=1800)
    s = Scenario("asert", p, "ASERT difficulty with a 30-minute half-life: fast blocks raise the "
                             "target's difficulty, slow blocks lower it, clamped at the proof-of-work limit.")
    for i in range(12):
        s.valid(note=f"fast block {i + 1} (10 s)", step=10)
    s.invalid("invalid: bad difficulty bits", "the anchor bits instead of the raised difficulty",
              mutate=lambda blk: setattr(blk.header, "bits", p.asert_anchor_bits))
    for i in range(4):
        s.valid(note=f"on-schedule block {i + 1}", step=p.target_spacing)
    for i in range(3):
        s.valid(note=f"slow block {i + 1} (3 hours)", step=3 * 3600)
    s.valid(note="after a 30-hour gap the target is clamped at the proof-of-work limit", step=30 * 3600)
    return s


def softfork():
    """The version-bits state machine, and the quantum switch it controls."""
    deps = (Deployment("pq", 16, 0, 0, 8, 6),
            Deployment("test", 17, 8, 32, 8, 6),
            Deployment("late", 18, 0, 24, 8, 6))
    p = replace(REGTEST, deployments=deps)
    s = Scenario("softfork", p, "Version-bits deployments with 8-block windows and a threshold of 6. "
                                "'pq' locks in at 24 and activates at 32, after which Schnorr spends are "
                                "invalid and Lamport spends valid. 'test' starts at 8 and fails at its "
                                "timeout 32. 'late' reaches its threshold in the window ending at its "
                                "timeout 24 and still locks in.")
    plan = {}                       # height -> bits signalled
    for h in range(1, 8):
        plan[h] = [16] if h <= 3 else []                     # window 0 counts for nothing but a start
    for h in range(8, 16):
        plan[h] = ([16] if h < 13 else []) + ([17] if h < 11 else [])          # 5 pq, 3 test
    for h in range(16, 24):
        plan[h] = ([16] if h < 22 else []) + ([18] if h < 22 else [])          # 6 pq, 6 late
    for h in range(24, 32):
        plan[h] = [17] if h < 29 else []                                        # 5 test
    lam_before = None
    for h in range(1, 40):
        bits = plan.get(h, [])
        version = 1
        for b in bits:
            version |= 1 << b
        txs = []
        if h == 20:
            lam_before = s.pay([s.coins()[0]], pq=True)
            txs = [lam_before]
        note = f"height {h}" + (f", signals bits {bits}" if bits else "")
        if h == 20:
            note += "; a Lamport spend is valid before activation too"
        if h == 32:
            schnorr = s.pay([s.coins()[0]])
            s.invalid("invalid: invalid signature", "Schnorr spend in the first active block", [schnorr],
                      version=version)
            txs = [s.pay([s.coins()[0]], pq=True)]
            note += "; pq active: Lamport spend"
        s.valid(txs, note=note, version=version)
    return s


def flagday():
    """pq_emergency_height: activation by release, without signalling."""
    p = replace(REGTEST, deployments=(), pq_emergency_height=6)
    s = Scenario("flagday", p, "The emergency flag day: from height 6 Schnorr spends are invalid.")
    for i in range(4):
        s.valid(note=f"mine block {i + 1}")
    s.valid([s.pay([s.coins()[0]])], note="Schnorr spend at height 5, the last block before the flag day")
    s.invalid("invalid: invalid signature", "Schnorr spend at height 6", [s.pay([s.coins()[0]])])
    s.valid([s.pay([s.coins()[0]], pq=True)], note="Lamport spend at height 6")
    return s


def auxpow():
    """Merge-mined blocks."""
    p = replace(REGTEST, deployments=(), auxpow_start_height=3)
    s = Scenario("auxpow", p, "Merge-mining with a Bitcoin-style parent block, allowed from height 3. "
                              "Every broken proof is reported as 'proof-of-work too weak'; the specific "
                              "auxpow failures are in functions.json.")
    s.valid(note="height 1")
    s.invalid("invalid: proof-of-work too weak", "merge-mined block below the start height",
              version=1 | VERSION_AUXPOW)
    s.valid(note="height 2")
    target = bits_to_target(p.genesis_bits)

    def with_aux(**kw):
        def f(blk):
            blk.header.tx_root = blk.compute_tx_root()
            blk.header.fee = next_base_fee(p, s.b.tip.next_base_fee, blk.size)
            blk.auxpow = make_auxpow(blk.hash, target, **kw)
        return f
    for kw, what in (({"weak": True}, "parent header misses the target"),
                     ({"tamper_branch": True}, "parent coinbase not in the parent merkle root"),
                     ({"script_extra": MM_MAGIC + b"\x00" * 40}, "merge-mining marker twice"),
                     ({"chain_tree": (build_commitment(b"\x00" * 32, 0), [], 0)}, "commits to another block")):
        s.invalid("invalid: proof-of-work too weak", what, version=1 | VERSION_AUXPOW,
                  mutate=with_aux(**kw), seal_kw={"root": False, "fee": False, "pow": False})
    for i in range(3):
        s.valid(note=f"merge-mined block {i + 1}", version=1 | VERSION_AUXPOW)
    s.valid(note="an ordinary block after merge-mined ones")
    return s


def checkpoints():
    base = replace(REGTEST, deployments=())
    pre = Scenario("x", base, "")
    for _ in range(3):
        pre.valid()
    cp = pre.b.active[3].hash.hex()
    p = replace(base, checkpoints=((3, cp),))
    s = Scenario("checkpoints", p, "A checkpoint at height 3: a different block 3, or a fork below it, is rejected.")
    for i in range(5):
        s.valid(note=f"mine block {i + 1}")
    fb = Chain(p, now=s.clock)
    for idx in s.b.active[1:3]:
        fb.submit_block(s.b.blocks[idx.hash])
    s.clock.t += 1
    alt3 = s.seal(s.template(chain=fb, extra=b"alt"), chain=fb)
    s.step(alt3, "invalid: checkpoint mismatch", "a different block at the checkpoint height", adopt=False)
    fb2 = Chain(p, now=s.clock)
    alt1 = s.seal(s.template(chain=fb2, extra=b"alt"), chain=fb2)
    assert fb2.submit_block(Block.deserialize(alt1.serialize())) == "accepted"
    s.step(alt1, "accepted", "a side block at height 1: its parent (genesis) is on the active chain, "
                             "so it is stored", adopt=False)
    alt2 = s.seal(s.template(chain=fb2, extra=b"alt"), chain=fb2)
    s.step(alt2, "invalid: fork below last checkpoint",
           "the next block on that branch: at or below the checkpoint and its parent is off the active chain",
           adopt=False)
    return s


# ------------------------------------------------------------ function vectors
def functions():
    """Pure consensus functions: enough to port and test one piece at a time."""
    p = REGTEST
    v = {"format": FORMAT, "params": params_to_json(p)}
    v["tagged_hash"] = [{"tag": t, "msg": m.hex(), "out": tagged_hash(t, m).hex()}
                        for t, m in (("Kairos/txid", b""), ("Kairos/address", b"\x01" * 64),
                                     ("Kairos/sighash", b"abc"), ("BIP0340/challenge", b"\x00" * 96))]
    v["bits"] = [{"bits": f"{b:08x}", "target": f"{bits_to_target(b):064x}",
                  "roundtrip": f"{target_to_bits(bits_to_target(b)):08x}"}
                 for b in (0x1D00FFFF, 0x1E0FFFFF, 0x200FFFFF, 0x1F0FFFFF, 0x1B0404CB, 0x03123456, 0x04123456)]
    gens = [0, 10 ** 8, 21_000_000 * 10 ** 8 // 2, 21_000_000 * 10 ** 8 - (60_000_000 << 21),
            21_000_000 * 10 ** 8 - 1, 21_000_000 * 10 ** 8]
    v["subsidy"] = [{"generated": g, "subsidy": subsidy(p, g)} for g in gens]
    v["generated_at"] = [{"height": h, "generated": generated_at(p, h)} for h in (0, 1, 2, 1000, 262_800)]
    grid = []
    for anchor in (0x1D00FFFF, 0x1E03FFFF):
        for drift in (0, 1, -1, 7200, -7200, 172_800, -172_800, 10 ** 7, -10 ** 7, 12345, -54321):
            for height in (0, 1, 1000):
                pt = p.genesis_time + height * p.target_spacing + drift
                tp = replace(p, pow_limit=(1 << 236) - 1)
                grid.append({"anchor_bits": f"{anchor:08x}", "anchor_time": p.genesis_time, "parent_time": pt,
                             "parent_height": height, "target_spacing": tp.target_spacing,
                             "halflife": tp.asert_halflife, "pow_limit": f"{tp.pow_limit:064x}",
                             "target": f"{asert_target(tp, anchor, p.genesis_time, pt, height):064x}"})
    v["asert"] = grid
    v["next_base_fee"] = [{"base_fee": b, "block_size": sz, "target": p.target_block_size,
                           "denom": p.base_fee_change_denom, "min": p.min_base_fee,
                           "next": next_base_fee(p, b, sz)}
                          for b in (1, 2, 8, 9, 100, 10 ** 6) for sz in (0, 500, 999_999, 1_000_000, 1_000_001,
                                                                          1_500_000, 2_000_000)]
    leaves = [tagged_hash("Kairos/vectors/leaf", bytes([i])) for i in range(9)]
    v["merkle_root"] = [{"leaves": [x.hex() for x in leaves[:n]], "root": merkle_root(leaves[:n]).hex()}
                        for n in range(1, 10)]
    mh = []
    items = [tagged_hash("Kairos/vectors/item", bytes([i])) for i in range(4)]
    m = MuHash()
    mh.append({"insert": [], "remove": [], "digest": m.digest().hex()})
    for n in range(1, 5):
        m = MuHash()
        for x in items[:n]:
            m.insert(x)
        mh.append({"insert": [x.hex() for x in items[:n]], "remove": [], "digest": m.digest().hex()})
    m = MuHash()
    for x in items:
        m.insert(x)
    m.remove(items[1])
    mh.append({"insert": [x.hex() for x in items], "remove": [items[1].hex()], "digest": m.digest().hex()})
    v["muhash"] = mh
    op = OutPoint(b"\x07" * 32, 3)
    v["coin_bytes"] = [{"txid": op.txid.hex(), "index": 3, "value": 5 * 10 ** 8, "address": "aa" * 32,
                        "height": 17, "coinbase": cb,
                        "bytes": coin_bytes(op, Coin(5 * 10 ** 8, b"\xaa" * 32, 17, cb)).hex()}
                       for cb in (False, True)]

    keys = [Key(SEED, i) for i in range(3)]
    v["address"] = [{"schnorr_pubkey": k.pubkey.hex(), "pq_root": k.pqroot.hex(), "address": k.address.hex(),
                     "bech32m": {hrp: bech32m_encode(hrp, k.address) for hrp in ("krs", "tkrs", "krt")}}
                    for k in keys]
    tx = Transaction([TxIn(OutPoint(b"\x01" * 32, 0)), TxIn(OutPoint(b"\x02" * 32, 1))],
                     [TxOut(7 * 10 ** 8, keys[1].address), TxOut(123_456, keys[2].address)], 900)
    spent = [(5 * 10 ** 8, keys[0].address), (3 * 10 ** 8, keys[0].address)]
    sh = []
    for cid in (b"KRS\x01", b"KRS\x03", b"KRT\x01"):
        for sp in (spent, [(spent[0][0] + 1, spent[0][1]), spent[1]]):
            sh.append({"tx_body": tx.body().hex(), "chain_id": cid.hex(),
                       "spent": [{"value": a, "address": b.hex()} for a, b in sp],
                       "txid": tx.txid.hex(), "sighash": tx.sighash(cid, sp).hex()})
    v["sighash"] = sh
    msg = tx.sighash(b"KRT\x01", spent)
    k = keys[0]
    sig = schnorr_sign(msg, k.seckey, aux_rand(k.seckey, msg))
    sw = schnorr_witness(k.pubkey, k.pqroot, sig)
    lsk, lpub = k.lamport
    lw = lamport_witness(k.pubkey, lpub, lamport_sign(msg, lsk))
    wv = []

    def add(w, what, address=k.address, sighash=msg):
        for pq in (False, True):
            wv.append({"what": what, "witness": w.hex(), "address": address.hex(), "sighash": sighash.hex(),
                       "pq_only": pq, "valid": verify_witness(w, address, sighash, pq)})
    add(sw, "Schnorr witness")
    add(lw, "Lamport witness")
    add(sw, "Schnorr witness, other message", sighash=tagged_hash("x", b"y"))
    add(lw, "Lamport witness, other message", sighash=tagged_hash("x", b"y"))
    add(sw, "Schnorr witness, other address", address=keys[1].address)
    add(sw[:-1], "Schnorr witness, short")
    add(lw[:-1], "Lamport witness, short")
    add(b"\x03" + sw[1:], "unknown kind")
    add(b"", "empty")
    wv[0]["note"] = "the full Lamport witness is 24,609 bytes"
    v["witness"] = wv
    v["lamport"] = [{"seed": tagged_hash("Kairos/vectors/lamport", bytes([i])).hex(),
                     "pq_root": pq_root(lamport_keygen(tagged_hash("Kairos/vectors/lamport", bytes([i])))[1]).hex()}
                    for i in range(3)]

    aux = []
    target = bits_to_target(0x200FFFFF)
    h = tagged_hash("Kairos/vectors/auxhash", b"")
    good = make_auxpow(h, target)
    aux.append({"what": "valid", "aux_hash": h.hex(), "chain_id": REGTEST.mm_chain_id, "target": f"{target:064x}",
                "auxpow": good.serialize().hex(), "result": "ok"})
    for kw, what in (({"weak": True}, "parent proof-of-work too weak"),
                     ({"tamper_branch": True}, "coinbase not in parent merkle root"),
                     ({"script_extra": MM_MAGIC + b"\x00" * 40}, "merge-mining header twice")):
        a = make_auxpow(h, target, **kw)
        try:
            a.check(h, REGTEST.mm_chain_id, target)
            res = "ok"
        except ValueError as e:
            res = str(e)
        aux.append({"what": what, "aux_hash": h.hex(), "chain_id": REGTEST.mm_chain_id, "target": f"{target:064x}",
                    "auxpow": a.serialize().hex(), "result": res})
    v["auxpow"] = aux
    v["aux_slot"] = [{"nonce": n, "chain_id": c, "height": ht, "index": expected_index(n, c, ht)}
                     for n in (0, 1, 7, 0xFFFFFFFF) for c in (0x4B52, 1) for ht in (0, 3, 5)]
    g = genesis_block(REGTEST)
    v["genesis"] = [{"network": name, "block": genesis_block(pp).serialize().hex(), "hash": genesis_block(pp).hash.hex()}
                    for name, pp in (("regtest", REGTEST),)]
    assert g.hash.hex() == v["genesis"][0]["hash"]
    with open(FUNCTIONS, "w") as f:
        json.dump(v, f, indent=1)
        f.write("\n")


SCENARIOS = (core, limits, asert, softfork, flagday, auxpow, checkpoints)

if __name__ == "__main__":
    for fn in SCENARIOS:
        sc = fn()
        sc.dump()
        print(f"{sc.name}: {len(sc.steps)} steps")
    functions()
    print("functions.json written")
