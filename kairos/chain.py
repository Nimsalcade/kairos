"""
Kairos chain state and consensus validation.

This is the whole rulebook. A block is valid if and only if `Chain` accepts it.
"""
import os
import struct
import threading
import time as _time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .block import Block, BlockHeader, genesis_block, HEADER_SIZE, VERSION_AUXPOW
from .crypto import MuHash, sha256
from .params import (ChainParams, Deployment, MAX_MONEY, subsidy, asert_target, target_to_bits,
                     bits_to_target, block_work, next_base_fee)
from .tx import (OutPoint, Transaction, TxOut, make_coinbase, verify_witness,
                 write_varint, read_varint)


class ValidationError(Exception):
    pass


RECORD_MAGIC = b"KRSB"
BLOCK_FILE = "blocks-v3.dat"
MAX_SIG_CACHE = 200_000
MAX_ORPHAN_BYTES = 8 * 1024 * 1024   # unknown-parent blocks kept while we fetch the gap
ORPHAN_TTL = 600                     # seconds
ORPHAN_WORK_SHIFT = 6                # an orphan must claim >= 1/64 of the tip's per-block work
BLOCK_CACHE = 128                    # recently used blocks kept decoded in memory

DEFINED, STARTED, LOCKED_IN, ACTIVE, FAILED = "defined", "started", "locked_in", "active", "failed"


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
                 "muhash", "generated", "burned", "next_base_fee", "connected", "why", "vbcache")

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
        self.vbcache = {}           # deployment name -> state of the window starting after this block

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


class BlockStore:
    """Blocks live in an append-only file (magic, length, checksum, raw) and are
    read back on demand through a small cache, so memory does not grow with
    chain history. Without a path everything stays in memory (tests, demo)."""

    def __init__(self, path: Optional[str]):
        self.path = path
        self.mem: Dict[bytes, Block] = {}
        self.offsets: Dict[bytes, Tuple[int, int]] = {}
        self.cache: "OrderedDict[bytes, Block]" = OrderedDict()
        self.f = None
        self.lock = threading.Lock()

    def scan(self):
        """Yield (block, offset, length) for every intact record; truncate a torn tail."""
        if not self.path or not os.path.exists(self.path):
            return
        good = 0
        with open(self.path, "rb") as f:
            while True:
                hdr = f.read(12)
                if len(hdr) < 12 or hdr[:4] != RECORD_MAGIC:
                    break
                n = struct.unpack("<I", hdr[4:8])[0]
                raw = f.read(n)
                if len(raw) != n or sha256(raw)[:4] != hdr[8:12]:
                    break              # torn write from a crash: stop here
                try:
                    blk = Block.deserialize(raw)
                except ValueError:
                    break
                yield blk, good + 12, n
                good = f.tell()
        if good != os.path.getsize(self.path):
            with open(self.path, "r+b") as f:
                f.truncate(good)       # drop the damaged tail, keep all good blocks

    def open(self):
        if self.path:
            self.f = open(self.path, "ab")

    def close(self):
        if self.f:
            self.f.close()
            self.f = None

    def remember(self, blk: Block, offset: int, length: int):
        self.offsets[blk.hash] = (offset, length)

    def put(self, blk: Block, persist: bool):
        h = blk.hash
        if not self.path:
            self.mem[h] = blk
            return
        if persist and self.f:
            raw = blk.serialize()
            with self.lock:
                self.f.write(RECORD_MAGIC + struct.pack("<I", len(raw)) + sha256(raw)[:4] + raw)
                self.f.flush()
                os.fsync(self.f.fileno())
                self.offsets[h] = (self.f.tell() - len(raw), len(raw))
        self._cache(h, blk)

    def _cache(self, h, blk):
        with self.lock:
            self.cache[h] = blk
            self.cache.move_to_end(h)
            while len(self.cache) > BLOCK_CACHE:
                self.cache.popitem(last=False)

    def get(self, h: bytes) -> Optional[Block]:
        if not self.path:
            return self.mem.get(h)
        with self.lock:
            blk = self.cache.get(h)
            if blk is not None:
                self.cache.move_to_end(h)
                return blk
            loc = self.offsets.get(h)
        if loc is None:
            return None
        with open(self.path, "rb") as f:
            f.seek(loc[0])
            raw = f.read(loc[1])
        blk = Block.deserialize(raw)
        self._cache(h, blk)
        return blk

    def __getitem__(self, h: bytes) -> Block:
        blk = self.get(h)
        if blk is None:
            raise KeyError(h)
        return blk

    def __contains__(self, h: bytes) -> bool:
        return h in self.mem if not self.path else h in self.offsets


class Chain:
    def __init__(self, params: ChainParams, datadir: Optional[str] = None, now=None):
        self.params = params
        self.now = now or (lambda: int(_time.time()))
        self.lock = threading.RLock()
        self.index: Dict[bytes, BlockIndex] = {}
        self.undo: Dict[bytes, Dict[OutPoint, Coin]] = {}
        self.utxos: Dict[OutPoint, Coin] = {}
        self.orphans: Dict[bytes, Dict[bytes, Block]] = {}      # prev_hash -> {hash: block}
        self.orphan_meta: Dict[bytes, Tuple[bytes, int, float]] = {}  # hash -> (prev, size, added)
        self.orphan_bytes = 0
        self.mempool: Dict[bytes, Transaction] = {}
        self.mempool_fee: Dict[bytes, int] = {}
        self.mempool_spends: Dict[OutPoint, bytes] = {}
        self.sig_cache = set()
        self.listeners = []          # callables(event, obj)
        self.signal = set()          # deployment names this miner signals for

        g = genesis_block(params)
        if not g.header.check_pow():
            raise RuntimeError("genesis block does not satisfy its own proof-of-work")
        gi = BlockIndex(g.header, None)
        gi.connected = True
        gi.muhash = MuHash().value()
        gi.next_base_fee = params.min_base_fee
        self.genesis = gi
        self.index[gi.hash] = gi
        self.active: List[BlockIndex] = [gi]
        self.candidates = {gi}
        self.best = gi               # most-work candidate seen so far

        self.max_mempool_bytes = 64 * 1024 * 1024
        self.mempool_bytes = 0
        self.datadir = datadir
        self.blocks = BlockStore(os.path.join(datadir, BLOCK_FILE) if datadir else None)
        self.blocks.put(g, persist=False)
        if datadir:
            os.makedirs(datadir, exist_ok=True)
            for blk, off, n in self.blocks.scan():
                if self.submit_block(blk, persist=False) in ("accepted", "duplicate") or blk.hash in self.index:
                    self.blocks.remember(blk, off, n)
            self.blocks.open()

    def close(self):
        self.blocks.close()

    # ------------------------------------------------------------ helpers
    @property
    def tip(self) -> BlockIndex:
        return self.active[-1]

    @property
    def height(self) -> int:
        return self.tip.height

    def get_block(self, h: bytes) -> Optional[Block]:
        return self.blocks.get(h)

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

    # ------------------------------------------------------- soft forks
    def deployment(self, name: str) -> Optional[Deployment]:
        for d in self.params.deployments:
            if d.name == name:
                return d
        return None

    def deployment_state(self, parent: BlockIndex, dep: Deployment) -> str:
        """State of `dep` for the block that would follow `parent`.
        Blocks in the same window share a state; a window's state is decided by
        the signalling in the window before it and cached on that window's last block."""
        w = dep.window
        k = (parent.height + 1) // w
        if k == 0:
            return self._first_window_state(dep)
        return self._window_state_after(parent.ancestor(k * w - 1), dep)

    def _first_window_state(self, dep: Deployment) -> str:
        if dep.timeout_height and 0 >= dep.timeout_height:
            return FAILED
        return STARTED if dep.start_height <= 0 else DEFINED

    def _window_state_after(self, last: BlockIndex, dep: Deployment) -> str:
        """State of the window that starts at last.height + 1."""
        w = dep.window
        todo = []
        cur = last
        while cur is not None and dep.name not in cur.vbcache:
            todo.append(cur)
            cur = cur.ancestor(cur.height - w) if cur.height >= w else None
        state = cur.vbcache[dep.name] if cur is not None else self._first_window_state(dep)
        for boundary in reversed(todo):
            start = boundary.height + 1                # first height of the new window
            if state == DEFINED:
                if dep.timeout_height and start >= dep.timeout_height:
                    state = FAILED
                elif start >= dep.start_height:
                    state = STARTED
            elif state == STARTED:
                count, x = 0, boundary
                for _ in range(w):
                    if x.header.version & 0xFF == 1 and (x.header.version >> dep.bit) & 1:
                        count += 1
                    x = x.parent
                if count >= dep.threshold:
                    state = LOCKED_IN
                elif dep.timeout_height and start >= dep.timeout_height:
                    state = FAILED
            elif state == LOCKED_IN:
                state = ACTIVE
            boundary.vbcache[dep.name] = state
        return state

    def deployment_info(self, parent: Optional[BlockIndex] = None) -> dict:
        parent = parent or self.tip
        out = {}
        for d in self.params.deployments:
            state = self.deployment_state(parent, d)
            info = {"bit": d.bit, "start_height": d.start_height, "timeout_height": d.timeout_height,
                    "window": d.window, "threshold": d.threshold, "state": state,
                    "since": ((parent.height + 1) // d.window) * d.window}
            if state == STARTED:
                count, x, n = 0, parent, (parent.height + 1) % d.window
                for _ in range(n):
                    count += (x.header.version >> d.bit) & 1
                    x = x.parent
                info["signalled"] = count
                info["elapsed"] = n
            out[d.name] = info
        return out

    def pq_active(self, parent: BlockIndex) -> bool:
        """Are elliptic-curve spends forbidden in the block after `parent`?"""
        p = self.params
        if p.pq_emergency_height is not None and parent.height + 1 >= p.pq_emergency_height:
            return True
        dep = self.deployment("pq")
        return dep is not None and self.deployment_state(parent, dep) == ACTIVE

    # ------------------------------------------------------ transactions
    def check_tx(self, tx: Transaction, view: UtxoView, height: int, base_fee: int, pq_only: bool = False):
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
        coins = []
        in_total = 0
        for inp in tx.inputs:
            coin = view.get(inp.prev)
            if coin is None:
                raise ValidationError("missing or spent input")
            if coin.coinbase and height - coin.height < p.coinbase_maturity:
                raise ValidationError("immature coinbase spend")
            coins.append(coin)
            in_total += coin.value
        # The witness check depends only on the tx bytes and the coins it names
        # (an outpoint identifies its coin), so it is safe to cache by wtxid.
        cache_key = (tx.wtxid, pq_only)
        if cache_key not in self.sig_cache:
            sh = tx.sighash(p.chain_id, [(c.value, c.address) for c in coins])
            for inp, coin in zip(tx.inputs, coins):
                if not verify_witness(inp.witness, coin.address, sh, pq_only):
                    raise ValidationError("invalid signature")
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
            raise ValidationError("unknown block version")   # bit 8 = auxpow, bits 16..28 = soft-fork signals
        if bits_to_target(h.bits) > self.params.pow_limit:
            raise ValidationError("target above proof-of-work limit")
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

    # -- orphans: blocks whose parent we have not seen yet. They are a cache, not
    #    state: bounded in bytes and age, and a block must claim a credible amount
    #    of work to get in, so a peer cannot fill memory with trivially mined junk.
    def _add_orphan(self, blk: Block):
        now = _time.time()
        for h, (prev, size, added) in list(self.orphan_meta.items()):
            if now - added > ORPHAN_TTL:
                self._drop_orphan(h)
        if block_work(blk.header.bits) << ORPHAN_WORK_SHIFT < block_work(self.expected_bits(self.tip)):
            return
        size = blk.size
        if size > MAX_ORPHAN_BYTES:
            return
        while self.orphan_bytes + size > MAX_ORPHAN_BYTES and self.orphan_meta:
            self._drop_orphan(min(self.orphan_meta, key=lambda k: self.orphan_meta[k][2]))
        self.orphans.setdefault(blk.header.prev_hash, {})[blk.hash] = blk
        self.orphan_meta[blk.hash] = (blk.header.prev_hash, size, now)
        self.orphan_bytes += size

    def _drop_orphan(self, h: bytes):
        prev, size, _ = self.orphan_meta.pop(h)
        self.orphan_bytes -= size
        fam = self.orphans.get(prev)
        if fam is not None:
            fam.pop(h, None)
            if not fam:
                del self.orphans[prev]

    def _take_orphans(self, parent_hash: bytes) -> List[Block]:
        fam = self.orphans.pop(parent_hash, None)
        if not fam:
            return []
        for h in fam:
            prev, size, _ = self.orphan_meta.pop(h)
            self.orphan_bytes -= size
        return list(fam.values())

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
                if hsh not in self.orphan_meta:
                    self._add_orphan(blk)
                return "orphan"
            if parent.invalid:
                return "invalid: parent invalid"
            try:
                self.check_header_context(blk.header, parent)
            except ValidationError as e:
                return f"invalid: {e}"
            idx = BlockIndex(blk.header, parent)
            self.index[hsh] = idx
            self.blocks.put(blk, persist)
            self.candidates.add(idx)
            if idx.chainwork > self.best.chainwork:
                self.best = idx
            self._activate_best_chain()
            status = f"invalid: {idx.why}" if idx.invalid else "accepted"
            for child in self._take_orphans(hsh):
                self.submit_block(child, persist)
            return status

    def _connect(self, idx: BlockIndex, blk: Block):
        p = self.params
        parent = idx.parent
        height = idx.height
        view = UtxoView(self.utxos)
        base_fee = parent.next_base_fee
        pq_only = self.pq_active(parent)
        tips = burns = 0
        for tx in blk.txs[1:]:
            fee, burn = self.check_tx(tx, view, height, base_fee, pq_only)
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
        for fn in self.listeners:
            fn("disconnect", idx)
        return blk

    def _mark_invalid(self, bad: BlockIndex, why: str):
        bad.invalid = True
        bad.why = why
        for idx in list(self.candidates):
            if idx.height >= bad.height and idx.ancestor(bad.height) is bad:
                idx.invalid = True
                self.candidates.discard(idx)
        self.best = max(self.candidates, key=lambda i: i.chainwork)

    def _activate_best_chain(self):
        disconnected = []
        while True:
            best = self.best
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
            fee, _ = self.check_tx(tx, UtxoView(self.utxos), self.height + 1, self.tip.next_base_fee,
                                   self.pq_active(self.tip))
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
    def block_version(self, parent: BlockIndex, auxpow: bool = False) -> int:
        version = 1 | (VERSION_AUXPOW if auxpow else 0)
        for d in self.params.deployments:
            if d.name in self.signal and self.deployment_state(parent, d) in (STARTED, LOCKED_IN):
                version |= 1 << d.bit
        return version

    def create_block(self, reward_address: bytes, extra: bytes = b"", t: Optional[int] = None,
                     auxpow: bool = False) -> Block:
        with self.lock:
            p = self.params
            parent = self.tip
            height = parent.height + 1
            base_fee = parent.next_base_fee
            pq_only = self.pq_active(parent)
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
                    fee, burn = self.check_tx(tx, view, height, base_fee, pq_only)
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
            hdr = BlockHeader(self.block_version(parent, auxpow), height, parent.hash, b"", utxo_root,
                              tm, self.expected_bits(parent), 0)
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
