"""
Kairos chain state and consensus validation.

This is the whole rulebook. A block is valid if and only if `Chain` accepts it.
"""
import os
import struct
import threading
import time as _time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .block import Block, BlockHeader, genesis_block, HEADER_SIZE, VERSION_AUXPOW
from .crypto import MuHash, sha256
from .params import (ChainParams, MAX_MONEY, subsidy, asert_target, target_to_bits,
                     block_work, next_base_fee)
from .tx import (OutPoint, Transaction, TxOut, make_coinbase, verify_witness,
                 write_varint, read_varint)


class ValidationError(Exception):
    pass


RECORD_MAGIC = b"KRSB"
MAX_SIG_CACHE = 200_000
MAX_ORPHANS = 256


@dataclass(frozen=True)
class Coin:
    value: int
    address: bytes
    height: int
    coinbase: bool


def coin_bytes(op: OutPoint, c: Coin) -> bytes:
    return op.serialize() + struct.pack("<Q", c.value) + c.address + struct.pack("<I?", c.height, c.coinbase)


class BlockIndex:
    __slots__ = ("hash", "header", "parent", "height", "chainwork", "invalid",
                 "muhash", "generated", "burned", "next_base_fee", "connected", "why")

    def __init__(self, header: BlockHeader, parent: Optional["BlockIndex"]):
        self.hash = header.hash
        self.header = header
        self.parent = parent
        self.height = header.height
        self.chainwork = (parent.chainwork if parent else 0) + block_work(header.bits)
        self.invalid = False
        self.why = ""
        self.connected = False      # state fields below are valid once True
        self.muhash = 1
        self.generated = 0
        self.burned = 0
        self.next_base_fee = 0

    def ancestor(self, height: int) -> Optional["BlockIndex"]:
        x = self
        while x is not None and x.height > height:
            x = x.parent
        return x


class UtxoView:
    """Copy-on-write overlay so a block is validated completely before
    a single byte of real state changes."""

    def __init__(self, base: Dict[OutPoint, Coin]):
        self.base = base
        self.added: Dict[OutPoint, Coin] = {}
        self.spent: Dict[OutPoint, Coin] = {}

    def get(self, op: OutPoint) -> Optional[Coin]:
        if op in self.added:
            return self.added[op]
        if op in self.spent:
            return None
        return self.base.get(op)

    def spend(self, op: OutPoint):
        if op in self.added:
            del self.added[op]
        else:
            self.spent[op] = self.base[op]

    def add(self, op: OutPoint, coin: Coin):
        if self.get(op) is not None:
            raise ValidationError("output already exists")
        self.added[op] = coin


class Chain:
    def __init__(self, params: ChainParams, datadir: Optional[str] = None, now=None):
        self.params = params
        self.now = now or (lambda: int(_time.time()))
        self.lock = threading.RLock()
        self.index: Dict[bytes, BlockIndex] = {}
        self.blocks: Dict[bytes, Block] = {}
        self.undo: Dict[bytes, Dict[OutPoint, Coin]] = {}
        self.utxos: Dict[OutPoint, Coin] = {}
        self.orphans: Dict[bytes, List[Block]] = {}
        self.mempool: Dict[bytes, Transaction] = {}
        self.mempool_fee: Dict[bytes, int] = {}
        self.mempool_spends: Dict[OutPoint, bytes] = {}
        self.sig_cache = set()
        self.listeners = []          # callables(event, obj)

        g = genesis_block(params)
        if not g.header.check_pow():
            raise RuntimeError("genesis block does not satisfy its own proof-of-work")
        gi = BlockIndex(g.header, None)
        gi.connected = True
        gi.muhash = MuHash().value()
        gi.next_base_fee = params.min_base_fee
        self.genesis = gi
        self.index[gi.hash] = gi
        self.blocks[gi.hash] = g
        self.active: List[BlockIndex] = [gi]
        self.candidates = {gi}

        self.max_mempool_bytes = 64 * 1024 * 1024
        self.mempool_bytes = 0
        self.datadir = datadir
        self._store = None
        if datadir:
            os.makedirs(datadir, exist_ok=True)
            path = os.path.join(datadir, "blocks-v2.dat")
            good = 0
            if os.path.exists(path):
                with open(path, "rb") as f:
                    while True:
                        hdr = f.read(12)
                        if len(hdr) < 12 or hdr[:4] != RECORD_MAGIC:
                            break
                        n = struct.unpack("<I", hdr[4:8])[0]
                        raw = f.read(n)
                        if len(raw) != n or sha256(raw)[:4] != hdr[8:12]:
                            break          # torn write from a crash: stop here
                        try:
                            self.submit_block(Block.deserialize(raw), persist=False)
                        except ValueError:
                            break
                        good = f.tell()
                if good != os.path.getsize(path):
                    with open(path, "r+b") as f:
                        f.truncate(good)   # drop the damaged tail, keep all good blocks
            self._store = open(path, "ab")

    def close(self):
        if self._store:
            self._store.close()
            self._store = None

    # ------------------------------------------------------------ helpers
    @property
    def tip(self) -> BlockIndex:
        return self.active[-1]

    @property
    def height(self) -> int:
        return self.tip.height

    def on_active_chain(self, idx: BlockIndex) -> bool:
        return idx.height < len(self.active) and self.active[idx.height] is idx

    def median_time_past(self, idx: BlockIndex) -> int:
        times = []
        x = idx
        while x is not None and len(times) < self.params.mtp_window:
            times.append(x.header.time)
            x = x.parent
        return sorted(times)[len(times) // 2]

    def expected_bits(self, parent: BlockIndex) -> int:
        p = self.params
        if p.no_retarget:
            return p.asert_anchor_bits or p.genesis_bits
        g = self.genesis.header
        anchor = p.asert_anchor_bits or g.bits
        return target_to_bits(asert_target(p, anchor, g.time, parent.header.time, parent.height))

    # ------------------------------------------------------ transactions
    def check_tx(self, tx: Transaction, view: UtxoView, height: int, base_fee: int):
        """Full contextual validation. Returns (fee, burn)."""
        p = self.params
        if tx.is_coinbase():
            raise ValidationError("unexpected coinbase")
        if not tx.inputs or not tx.outputs:
            raise ValidationError("empty inputs or outputs")
        if tx.version != 1:
            raise ValidationError("unknown tx version")
        if tx.expiry and height > tx.expiry:
            raise ValidationError("transaction expired")
        if tx.size > p.max_block_size // 2:
            raise ValidationError("transaction too large")
        ops = [i.prev for i in tx.inputs]
        if len(set(ops)) != len(ops):
            raise ValidationError("duplicate input")
        out_total = 0
        for o in tx.outputs:
            if not (0 < o.value <= MAX_MONEY) or len(o.address) != 32:
                raise ValidationError("bad output")
            out_total += o.value
            if out_total > MAX_MONEY:
                raise ValidationError("output total overflow")
        sh = tx.sighash(p.chain_id)
        pq_active = p.pq_emergency_height is not None and height >= p.pq_emergency_height
        cache_key = (tx.wtxid, pq_active)
        cached = cache_key in self.sig_cache
        in_total = 0
        for inp in tx.inputs:
            coin = view.get(inp.prev)
            if coin is None:
                raise ValidationError("missing or spent input")
            if coin.coinbase and height - coin.height < p.coinbase_maturity:
                raise ValidationError("immature coinbase spend")
            if not cached and not verify_witness(inp.witness, coin.address, sh, height,
                                                 p.pq_emergency_height):
                raise ValidationError("invalid signature")
            in_total += coin.value
        if len(self.sig_cache) >= MAX_SIG_CACHE:
            self.sig_cache.clear()
        self.sig_cache.add(cache_key)
        fee = in_total - out_total
        if fee < 0:
            raise ValidationError("outputs exceed inputs")
        burn = base_fee * tx.size
        if fee < burn:
            raise ValidationError(f"fee {fee} below base fee burn {burn}")
        return fee, burn

    @staticmethod
    def apply_tx(tx: Transaction, view: UtxoView, height: int):
        cb = tx.is_coinbase()
        if not cb:
            for inp in tx.inputs:
                view.spend(inp.prev)
        for i, o in enumerate(tx.outputs):
            view.add(OutPoint(tx.txid, i), Coin(o.value, o.address, height, cb))

    @staticmethod
    def utxo_digest(parent_muhash: int, view: UtxoView):
        mh = MuHash(parent_muhash)
        for op, c in view.spent.items():
            mh.remove(coin_bytes(op, c))
        for op, c in view.added.items():
            mh.insert(coin_bytes(op, c))
        d = mh.digest()
        return d, mh.value()

    # ------------------------------------------------------------ blocks
    def check_block(self, blk: Block):
        """Context-free checks: cheap, done before storing anything."""
        h = blk.header
        if h.version & 0xFF != 1:
            raise ValidationError("unknown block version")   # upper bits free for soft-fork signalling
        if not blk.check_pow(self.params):
            raise ValidationError("proof-of-work too weak")
        if not blk.txs or not blk.txs[0].is_coinbase():
            raise ValidationError("first transaction must be coinbase")
        if any(t.is_coinbase() for t in blk.txs[1:]):
            raise ValidationError("multiple coinbases")
        if blk.size > self.params.max_block_size:
            raise ValidationError("block too large")
        if blk.compute_tx_root() != h.tx_root:
            raise ValidationError("tx_root mismatch")
        cbw = blk.txs[0].inputs[0].witness
        if not 4 <= len(cbw) <= self.params.coinbase_witness_max:
            raise ValidationError("bad coinbase witness size")
        if blk.txs[0].coinbase_height() != h.height:
            raise ValidationError("coinbase height mismatch")

    def check_header_context(self, h: BlockHeader, parent: BlockIndex):
        if h.height != parent.height + 1:
            raise ValidationError("bad height")
        cps = dict(self.params.checkpoints)
        if h.height in cps and h.hash.hex() != cps[h.height]:
            raise ValidationError("checkpoint mismatch")
        if cps:
            last = max(cps)
            if h.height <= last and not self.on_active_chain(parent):
                raise ValidationError("fork below last checkpoint")
        if h.bits != self.expected_bits(parent):
            raise ValidationError("bad difficulty bits")
        if h.time <= self.median_time_past(parent):
            raise ValidationError("timestamp too early")
        if h.time > self.now() + self.params.max_future_drift:
            raise ValidationError("timestamp too far in future")

    def submit_block(self, blk: Block, persist: bool = True) -> str:
        with self.lock:
            hsh = blk.hash
            if hsh in self.index:
                return "duplicate"
            try:
                self.check_block(blk)
            except ValidationError as e:
                return f"invalid: {e}"
            parent = self.index.get(blk.header.prev_hash)
            if parent is None:
                if sum(len(v) for v in self.orphans.values()) < MAX_ORPHANS:
                    self.orphans.setdefault(blk.header.prev_hash, []).append(blk)
                return "orphan"
            if parent.invalid:
                return "invalid: parent invalid"
            try:
                self.check_header_context(blk.header, parent)
            except ValidationError as e:
                return f"invalid: {e}"
            idx = BlockIndex(blk.header, parent)
            self.index[hsh] = idx
            self.blocks[hsh] = blk
            self.candidates.add(idx)
            if persist and self._store:
                raw = blk.serialize()
                self._store.write(RECORD_MAGIC + struct.pack("<I", len(raw)) + sha256(raw)[:4] + raw)
                self._store.flush()
                os.fsync(self._store.fileno())
            self._activate_best_chain()
            status = f"invalid: {idx.why}" if idx.invalid else "accepted"
            for child in self.orphans.pop(hsh, []):
                self.submit_block(child, persist)
            return status

    def _connect(self, idx: BlockIndex, blk: Block):
        p = self.params
        parent = idx.parent
        height = idx.height
        view = UtxoView(self.utxos)
        base_fee = parent.next_base_fee
        tips = burns = 0
        for tx in blk.txs[1:]:
            fee, burn = self.check_tx(tx, view, height, base_fee)
            tips += fee - burn
            burns += burn
            self.apply_tx(tx, view, height)
        cb = blk.txs[0]
        if cb.expiry != 0 or cb.version != 1:
            raise ValidationError("bad coinbase fields")
        sub = subsidy(p, parent.generated)
        cb_total = 0
        for o in cb.outputs:
            if not (0 <= o.value <= MAX_MONEY) or len(o.address) != 32:
                raise ValidationError("bad coinbase output")
            cb_total += o.value
        if cb_total > sub + tips:
            raise ValidationError("coinbase pays too much")
        self.apply_tx(cb, view, height)
        digest, mh_value = self.utxo_digest(parent.muhash, view)
        if digest != blk.header.utxo_root:
            raise ValidationError("utxo_root mismatch")
        # --- commit (nothing below may fail)
        for op in view.spent:
            del self.utxos[op]
        self.utxos.update(view.added)
        self.undo[idx.hash] = view.spent
        idx.muhash = mh_value
        idx.generated = parent.generated + sub
        idx.burned = parent.burned + burns + (sub + tips - cb_total)
        idx.next_base_fee = next_base_fee(p, base_fee, blk.size)
        idx.connected = True
        self.active.append(idx)

    def _disconnect_tip(self) -> Block:
        idx = self.tip
        blk = self.blocks[idx.hash]
        for tx in blk.txs:
            for i in range(len(tx.outputs)):
                self.utxos.pop(OutPoint(tx.txid, i), None)
        self.utxos.update(self.undo.pop(idx.hash))
        self.active.pop()
        return blk

    def _mark_invalid(self, bad: BlockIndex, why: str):
        bad.invalid = True
        bad.why = why
        for idx in list(self.candidates):
            if idx.height >= bad.height and idx.ancestor(bad.height) is bad:
                idx.invalid = True
                self.candidates.discard(idx)

    def _activate_best_chain(self):
        disconnected = []
        while True:
            best = max(self.candidates, key=lambda i: i.chainwork)
            if best.chainwork <= self.tip.chainwork:
                break
            fork = best
            while not self.on_active_chain(fork):
                fork = fork.parent
            while self.tip is not fork:
                disconnected.append(self._disconnect_tip())
            path = []
            x = best
            while x is not fork:
                path.append(x)
                x = x.parent
            for idx in reversed(path):
                try:
                    self._connect(idx, self.blocks[idx.hash])
                    for fn in self.listeners:
                        fn("tip", idx)
                except ValidationError as e:
                    self._mark_invalid(idx, str(e))
                    break
        self._refresh_mempool(disconnected)

    # ------------------------------------------------------------ mempool
    def _refresh_mempool(self, disconnected_blocks=()):
        height = self.height + 1
        for txid, tx in list(self.mempool.items()):
            if any(i.prev not in self.utxos for i in tx.inputs) or (tx.expiry and height > tx.expiry):
                self._mempool_remove(txid)
        for blk in disconnected_blocks:
            for tx in blk.txs[1:]:
                try:
                    self.accept_tx(tx)
                except ValidationError:
                    pass

    def _mempool_remove(self, txid):
        tx = self.mempool.pop(txid)
        self.mempool_bytes -= tx.size
        self.mempool_fee.pop(txid, None)
        for i in tx.inputs:
            self.mempool_spends.pop(i.prev, None)

    def accept_tx(self, tx: Transaction) -> bool:
        with self.lock:
            if tx.txid in self.mempool:
                return False
            for i in tx.inputs:
                if i.prev in self.mempool_spends:
                    raise ValidationError("conflicts with mempool transaction")
            fee, _ = self.check_tx(tx, UtxoView(self.utxos), self.height + 1, self.tip.next_base_fee)
            rate = fee / tx.size
            # Bounded mempool: when full, a newcomer must outbid the cheapest resident.
            while self.mempool_bytes + tx.size > self.max_mempool_bytes:
                worst = min(self.mempool, key=lambda t: self.mempool_fee[t] / self.mempool[t].size)
                if self.mempool_fee[worst] / self.mempool[worst].size >= rate:
                    raise ValidationError("mempool full and fee rate too low")
                self._mempool_remove(worst)
            self.mempool[tx.txid] = tx
            self.mempool_fee[tx.txid] = fee
            self.mempool_bytes += tx.size
            for i in tx.inputs:
                self.mempool_spends[i.prev] = tx.txid
            return True

    # ------------------------------------------------------------ mining
    def create_block(self, reward_address: bytes, extra: bytes = b"", t: Optional[int] = None,
                     auxpow: bool = False) -> Block:
        with self.lock:
            p = self.params
            parent = self.tip
            height = parent.height + 1
            base_fee = parent.next_base_fee
            view = UtxoView(self.utxos)
            budget = p.max_block_size - HEADER_SIZE - 1024
            chosen, tips = [], 0
            order = sorted(self.mempool.values(),
                           key=lambda tx: (self.mempool_fee[tx.txid] - base_fee * tx.size) / tx.size,
                           reverse=True)
            for tx in order:
                if tx.size > budget:
                    continue
                try:
                    fee, burn = self.check_tx(tx, view, height, base_fee)
                except ValidationError:
                    continue
                self.apply_tx(tx, view, height)
                chosen.append(tx)
                tips += fee - burn
                budget -= tx.size
            cb = make_coinbase(height, [TxOut(subsidy(p, parent.generated) + tips, reward_address)], extra)
            self.apply_tx(cb, view, height)
            utxo_root, _ = self.utxo_digest(parent.muhash, view)
            tm = max(t if t is not None else self.now(), self.median_time_past(parent) + 1)
            version = 1 | (VERSION_AUXPOW if auxpow else 0)
            hdr = BlockHeader(version, height, parent.hash, b"", utxo_root, tm, self.expected_bits(parent), 0)
            blk = Block(hdr, [cb] + chosen)
            hdr.tx_root = blk.compute_tx_root()
            return blk

    # ------------------------------------------------------------ queries
    def locator(self) -> List[bytes]:
        out, step, h = [], 1, self.height
        while h > 0:
            out.append(self.active[h].hash)
            if len(out) >= 10:
                step *= 2
            h -= step
        out.append(self.genesis.hash)
        return out

    def blocks_after(self, locator: List[bytes], limit: int = 500) -> List[Block]:
        with self.lock:
            start = 0
            for h in locator:
                idx = self.index.get(h)
                if idx and self.on_active_chain(idx):
                    start = idx.height
                    break
            return [self.blocks[i.hash] for i in self.active[start + 1:start + 1 + limit]]

    def coins_for(self, addresses) -> Dict[OutPoint, Coin]:
        addresses = set(addresses)
        with self.lock:
            return {op: c for op, c in self.utxos.items() if c.address in addresses}

    def supply(self) -> dict:
        t = self.tip
        return {"height": t.height, "generated": t.generated, "burned": t.burned,
                "circulating": t.generated - t.burned, "next_base_fee": t.next_base_fee,
                "next_subsidy": subsidy(self.params, t.generated)}
