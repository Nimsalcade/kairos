"""
Kairos peer-to-peer node (protocol 4).

Newline-delimited JSON over TCP. Every message carries the network magic.

    version    {proto, genesis, height, nonce, agent, port}   first message, both ways
    inv        {blocks:[hash], txs:[txid]}              announce, never push
    getdata    {blocks:[hash], txs:[txid]}              request announced items
    getheaders {locator:[hash]}                         answered with headers
    headers    {data:[hex]}                             <=2000 headers (+ merge-mining proofs)
    block      {data:hex}     tx {data:hex}
    ping {n} / pong {n}
    getaddr {}  /  addr {addrs:[[ "ip:port", seen ], ...]}

Sync is headers-first: a peer's whole chain of headers is validated (work,
difficulty schedule, timestamps) before any block body is requested, and
bodies are then fetched in order along the most-work header chain, from
several peers at once, with stalled requests re-issued elsewhere.

Hardening:
  * handshake binds the peer to our genesis block and magic; self-connections dropped
  * relay is announce-then-request, so nobody can push megabytes at us unasked
  * nobody can make us download a chain that does not carry the most work
  * misbehaviour score per peer; 100 points = disconnect + 24h IP ban
  * per-peer token-bucket message rate limit and a hard line-size cap
  * inbound peer cap, handshake timeout, idle timeout with pings
  * every exception while handling a message counts as misbehaviour, whatever
    its type (deep JSON nesting, numeric overflow...): a bad peer cannot crash
    the node or leave a dead connection holding a slot
"""
import json
import os
import queue
import random
import socket
import threading
import time

from .addrman import AddrMan, parse
from .block import Block, mine
from .chain import Chain, ValidationError
from .tx import Transaction

PROTOCOL_VERSION = 4              # 0.4.0: testnet 2 (new sighash, soft-fork signalling)
MIN_PROTOCOL_VERSION = 4          # older nodes are on another chain; they are disconnected, not banned
AGENT = "/kairos:0.4.0/"
MAX_OUTBOUND = 8
MAX_ADDR_PER_MSG = 1000
CONNMAN_INTERVAL = 2
MAX_LINE = 5 * 1024 * 1024
MAX_INBOUND = 32
MAX_INV = 500
HANDSHAKE_TIMEOUT = 30
IDLE_TIMEOUT = 180
PING_INTERVAL = 60
BAN_SECONDS = 24 * 3600
RATE_PER_SEC = 100
RATE_BURST = 1000
MAX_SEND_QUEUE = 64 * 1024 * 1024    # a peer that won't read this much is dropped
MAX_HEADERS = 2000
BLOCKS_IN_FLIGHT_PER_PEER = 16
BLOCK_STALL = 60                     # seconds before a requested block is asked from someone else
MAX_UNCONNECTING_HEADERS = 10
BENIGN_TX_ERRORS = ("conflicts", "mempool full", "below base fee", "missing or spent",
                    "expired", "immature")


def _int(v, lo=0, hi=1 << 62) -> int:
    """A JSON number that is really an integer in range. Floats (including the
    1e999 that json.loads turns into infinity) and bools are rejected."""
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ValueError("bad integer")
    return v


class Peer:
    def __init__(self, node, sock, addr, outbound):
        self.node, self.sock, self.addr, self.outbound = node, sock, addr, outbound
        self.f = sock.makefile("rb")
        self.wlock = threading.Lock()
        self.outq = queue.Queue()
        self.outbytes = 0
        self.expected = 0             # items we requested; their arrival is not "spam"
        self.alive = True
        self.ready = False            # handshake complete
        self.height = 0
        self.score = 0
        self.connected_at = time.time()
        self.last_recv = time.time()
        self.tokens = RATE_BURST
        self.last_refill = time.time()
        self.known = set()            # hashes this peer already has
        self.proto = 0
        self.listen_port = 0
        self.addr_key = None          # "ip:port" we dialled (outbound only)
        self.manual = False
        self.addr_msgs = 0
        self.sent_addr = False
        self.last_sync = 0.0
        self.sync_pending = False
        self.unconnecting = 0         # headers batches that did not attach to our index
        self.inflight = set()         # block hashes we asked this peer for

    @property
    def key(self):
        """Where this peer can be reached, if known."""
        if self.outbound:
            return self.addr_key
        return f"{self.addr[0]}:{self.listen_port}" if self.listen_port else None

    def send(self, msg: dict):
        """Queue a message. Never blocks: a dedicated writer thread does the I/O, so
        two nodes sending to each other at once can never deadlock."""
        if not self.alive:
            return
        msg["magic"] = self.node.magic_hex
        data = (json.dumps(msg) + "\n").encode()
        with self.wlock:
            if self.outbytes + len(data) > MAX_SEND_QUEUE:
                overflow = True
            else:
                overflow = False
                self.outbytes += len(data)
                self.outq.put(data)
        if overflow:
            self.close()              # peer is not reading; don't let it eat our memory

    def writer(self):
        while True:
            data = self.outq.get()
            if data is None:
                return
            try:
                self.sock.sendall(data)
            except OSError:
                self.close()
                return
            with self.wlock:
                self.outbytes -= len(data)

    def close(self):
        if self.alive:
            self.alive = False
            self.outq.put(None)
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.node._drop(self)

    def _rate_ok(self) -> bool:
        now = time.time()
        self.tokens = min(RATE_BURST, self.tokens + (now - self.last_refill) * RATE_PER_SEC)
        self.last_refill = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True

    def run(self):
        try:
            while self.alive:
                line = self.f.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    self.node.misbehave(self, 100, "oversized message")
                    break
                if not line.endswith(b"\n"):
                    break             # connection closed mid-message (peer restarted): not an attack
                self.last_recv = time.time()
                try:
                    msg = json.loads(line)
                    solicited = (isinstance(msg, dict) and msg.get("type") in ("block", "tx")
                                 and self.expected > 0)
                    if solicited:
                        self.expected -= 1
                    elif not self._rate_ok():
                        self.node.misbehave(self, 100, "message flood")
                        break
                    if not isinstance(msg, dict) or msg.get("magic") != self.node.magic_hex:
                        raise ValueError("bad envelope")
                    self.node._handle(self, msg)
                except Exception as e:                      # noqa: BLE001 - any failure is the peer's
                    self.node.misbehave(self, 100, f"malformed message: {type(e).__name__}: {e}")
        except Exception:                                   # noqa: BLE001 - socket gone, or a bug
            pass
        self.close()


class Node:
    def __init__(self, chain: Chain, host="127.0.0.1", port=0, wallet=None, log=None,
                 name="node", max_inbound=MAX_INBOUND, max_outbound=MAX_OUTBOUND,
                 use_seeds=True):
        self.chain = chain
        self.wallet = wallet
        self.name = name
        self.log = log or (lambda *a: None)
        self.magic_hex = chain.params.magic.hex()
        self.nonce = int.from_bytes(os.urandom(8), "big")
        self.max_inbound = max_inbound
        self.peers = []
        self.banned = {}              # ip -> unban time
        self.plock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.running = True
        self._mining = False
        self.max_outbound = max_outbound
        self.source = (host, 0) if host not in ("0.0.0.0", "", "::") else None
        self.use_seeds = use_seeds
        self.manual = set()           # "ip:port" peers we always keep connected
        self.pending = set()          # dials in progress
        self.inflight = {}            # block hash -> (peer, asked_at)
        self.queue = []               # blocks still to fetch on the best header chain, oldest first
        self.queue_for = None         # the best header the queue was computed for
        self.qlock = threading.Lock()
        path = os.path.join(chain.datadir, "peers.json") if chain.datadir else None
        self.addrman = AddrMan(path, allow_private=chain.params.name == "regtest")
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._maintenance_loop, daemon=True).start()
        self._last_announce = 0.0
        self._announce_pending = False
        threading.Thread(target=self._connman_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()

    # ------------------------------------------------------------ connections
    def is_banned(self, ip) -> bool:
        until = self.banned.get(ip)
        if until and until > time.time():
            return True
        self.banned.pop(ip, None)
        return False

    def _accept_loop(self):
        while self.running:
            try:
                s, a = self.srv.accept()
            except OSError:
                return
            inbound = sum(1 for p in self.peers if not p.outbound)
            if self.is_banned(a[0]) or inbound >= self.max_inbound:
                s.close()
                continue
            self._add_peer(s, a, False)

    def connect(self, host: str, port: int):
        if self.is_banned(host):
            raise OSError("peer is banned")
        s = socket.create_connection((host, port), timeout=10, source_address=self.source)
        s.settimeout(None)
        return self._add_peer(s, (host, port), True, key=f"{host}:{port}")

    def _add_peer(self, s, a, outbound, key=None, manual=False):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        p = Peer(self, s, a, outbound)
        p.addr_key, p.manual = key, manual
        # Our version MUST be the first bytes on the wire. Send it before the reader
        # thread starts, otherwise handling the peer's version could make us reply
        # (tip announcement, sync request) ahead of it, and the peer bans us.
        p.send({"type": "version", "proto": PROTOCOL_VERSION,
                "genesis": self.chain.genesis.hash.hex(), "height": self.chain.height,
                "nonce": self.nonce, "agent": AGENT, "port": self.port})
        with self.plock:
            self.peers.append(p)
        threading.Thread(target=p.writer, daemon=True).start()
        threading.Thread(target=p.run, daemon=True).start()
        return p

    def _drop(self, p):
        with self.plock:
            if p in self.peers:
                self.peers.remove(p)
                if p.ready and self.running:
                    self.log(f"[{self.name}] lost peer {p.key or p.addr[0]}")
        if p.inflight:
            with self.qlock:
                for h in p.inflight:
                    if self.inflight.get(h, (None,))[0] is p:
                        del self.inflight[h]
                p.inflight.clear()
            if self.running:
                self._fetch_blocks()

    def misbehave(self, peer, points, why):
        peer.score += points
        if points:
            self.log(f"[{self.name}] peer {peer.addr[0]} misbehaving (+{points}): {why}")
        if peer.score >= 100:
            if not peer.manual:       # peers the operator chose are dropped and retried, not banned
                self.banned[peer.addr[0]] = time.time() + BAN_SECONDS
            peer.close()

    def _maintenance_loop(self):
        while self.running:
            time.sleep(5)
            now = time.time()
            for p in list(self.peers):
                if not p.ready and now - p.connected_at > HANDSHAKE_TIMEOUT:
                    p.close()
                elif now - p.last_recv > IDLE_TIMEOUT:
                    p.close()
                elif now - p.last_recv > PING_INTERVAL:
                    p.send({"type": "ping", "n": int(now)})
            stalled, to_close = False, []
            with self.qlock:
                for h, (peer, asked) in list(self.inflight.items()):
                    if now - asked > BLOCK_STALL or not peer.alive:
                        del self.inflight[h]
                        peer.inflight.discard(h)
                        stalled = True
                        if peer.alive and peer not in to_close:
                            to_close.append(peer)
            for peer in to_close:                    # outside qlock: close() re-enters via _drop
                self.log(f"[{self.name}] peer {peer.key or peer.addr[0]} stalled; dropping")
                peer.close()
            if stalled:
                self._fetch_blocks()

    def broadcast_inv(self, blocks=(), txs=(), exclude=None):
        with self.plock:
            peers = [p for p in self.peers if p.ready and p is not exclude]
        for p in peers:
            b = [h for h in blocks if h not in p.known]
            t = [h for h in txs if h not in p.known]
            if b or t:
                p.known.update(b)
                p.known.update(t)
                p.send({"type": "inv", "blocks": b, "txs": t})

    def stop(self):
        self.running = False
        self._mining = False
        self.addrman.save()
        try:
            self.srv.shutdown(socket.SHUT_RDWR)   # wakes the blocked accept() so the port is freed
        except OSError:
            pass
        try:
            self.srv.close()
        except OSError:
            pass
        for p in list(self.peers):
            p.close()

    # ------------------------------------------------------------ protocol
    @staticmethod
    def _hashes(msg, key):
        items = msg.get(key, [])
        if not isinstance(items, list) or len(items) > MAX_INV:
            raise ValueError(f"bad {key} list")
        out = []
        for h in items:
            if not isinstance(h, str) or len(h) != 64:
                raise ValueError("bad hash")
            bytes.fromhex(h)
            out.append(h)
        return out

    def _handle(self, peer, msg):
        t = msg.get("type")
        if not peer.ready:
            if t != "version":
                self.misbehave(peer, 100, "message before handshake")
                return
            if msg.get("genesis") != self.chain.genesis.hash.hex():
                self.log(f"[{self.name}] peer {peer.addr[0]} is on another network; disconnecting")
                peer.close()
                return
            if msg.get("nonce") == self.nonce:
                if peer.addr_key:
                    self.addrman.mark_self(peer.addr_key)   # never dial it again
                peer.close()          # connected to ourselves
                return
            proto = _int(msg.get("proto", 0))
            if proto < MIN_PROTOCOL_VERSION:
                peer.close()
                return
            peer.proto = proto
            lp = msg.get("port")
            peer.listen_port = lp if isinstance(lp, int) and not isinstance(lp, bool) and 0 < lp < 65536 else 0
            peer.height = _int(msg.get("height", 0), 0, 1 << 32)
            peer.ready = True
            if peer.outbound and peer.addr_key:
                h, p = parse(peer.addr_key)
                self.addrman.add(h, p, manual=True)     # we reached it, so it is real
                self.addrman.success(peer.addr_key)
                self.log(f"[{self.name}] connected to {peer.addr_key}")
            elif peer.listen_port:
                self.addrman.add(peer.addr[0], peer.listen_port)
            if peer.outbound:
                peer.send({"type": "getaddr"})
            if peer.height > self.chain.best_header.height:
                self._request_headers(peer)
            # Blocks found while the handshake was in flight were not announced to
            # this peer (it was not ready yet). Announce our tip now; if the peer is
            # behind it will fetch it, find it orphaned, and sync the gap.
            if self.chain.height > 0:
                tip = self.chain.tip.hash.hex()
                peer.known.add(tip)
                peer.send({"type": "inv", "blocks": [tip], "txs": []})
            return

        if t == "inv":
            want_b = [h for h in self._hashes(msg, "blocks") if bytes.fromhex(h) not in self.chain.index]
            want_t = [h for h in self._hashes(msg, "txs") if bytes.fromhex(h) not in self.chain.mempool]
            peer.known.update(want_b)
            peer.known.update(want_t)
            if want_b or want_t:
                peer.expected = min(peer.expected + len(want_b) + len(want_t), 10 * MAX_INV)
                peer.send({"type": "getdata", "blocks": want_b, "txs": want_t})
        elif t == "getdata":
            for h in self._hashes(msg, "blocks"):
                b = self.chain.blocks.get(bytes.fromhex(h))
                if b is not None:
                    peer.send({"type": "block", "data": b.serialize().hex()})
            for h in self._hashes(msg, "txs"):
                tx = self.chain.mempool.get(bytes.fromhex(h))
                if tx is not None:
                    peer.send({"type": "tx", "data": tx.serialize().hex()})
        elif t == "getheaders":
            loc = [bytes.fromhex(h) for h in self._hashes(msg, "locator")[:64]]
            hdrs = self.chain.headers_after(loc, MAX_HEADERS)
            peer.send({"type": "headers", "data": [b.serialize().hex() for b in hdrs]})
        elif t == "headers":
            items = msg.get("data", [])
            if not isinstance(items, list) or len(items) > MAX_HEADERS:
                raise ValueError("bad headers list")
            last = None
            for hx in items:
                blk = Block.deserialize(bytes.fromhex(hx))
                if blk.txs:
                    raise ValueError("headers message carries transactions")
                status = self.chain.submit_header(blk.header, blk.auxpow)
                if status.startswith("invalid"):
                    reason = status[9:]
                    self.misbehave(peer, 0 if "future" in reason else 100, f"invalid header: {reason}")
                    return
                if status == "orphan":
                    # does not attach to anything we know: ask again from our locator
                    peer.unconnecting += 1
                    if peer.unconnecting > MAX_UNCONNECTING_HEADERS:
                        self.misbehave(peer, 100, "headers never connect")
                    else:
                        self._request_headers(peer)
                    return
                last = blk.header
            peer.unconnecting = 0
            if last is not None:
                peer.height = max(peer.height, last.height)
                peer.known.add(last.hash.hex())
            if len(items) == MAX_HEADERS:
                self._request_headers(peer)          # there is more where that came from
            self._fetch_blocks()
        elif t == "block":
            blk = Block.deserialize(bytes.fromhex(msg["data"]))
            h = blk.hash.hex()
            peer.known.add(h)
            with self.qlock:
                if self.inflight.get(blk.hash, (None,))[0] is peer:
                    del self.inflight[blk.hash]
                peer.inflight.discard(blk.hash)
            before = self.chain.tip
            status = self.chain.submit_block(blk)
            if status in ("accepted", "stored"):
                # Accepting one block can also connect waiting orphans behind it,
                # so announce the resulting tip too, not just the block we received.
                # Don't re-announce every block of a download burst (that looks like a flood
                # to our other peers). Announce the tip, at most twice a second; the final
                # tip of a burst is always announced by the announcer thread.
                if self.chain.tip is not before:
                    self._tip_changed()
                    self.log(f"[{self.name}] new tip {self.chain.height} {self.chain.tip.hash.hex()[:16]}")
                peer.height = max(peer.height, blk.header.height)
                self._fetch_blocks()
            elif status == "orphan":
                self._request_headers(peer)           # learn the chain it belongs to first
            elif status.startswith("invalid"):
                reason = status[9:]
                # a future timestamp may become valid later; everything else is provably bad
                self.misbehave(peer, 0 if "future" in reason else 100, f"invalid block: {reason}")
        elif t == "tx":
            tx = Transaction.deserialize(bytes.fromhex(msg["data"]))
            peer.known.add(tx.txid.hex())
            try:
                if self.chain.accept_tx(tx):
                    self.broadcast_inv(txs=[tx.txid.hex()], exclude=peer)
            except ValidationError as e:
                benign = any(b in str(e) for b in BENIGN_TX_ERRORS)
                self.misbehave(peer, 0 if benign else 20, f"invalid tx: {e}")
        elif t == "ping":
            peer.send({"type": "pong", "n": _int(msg.get("n", 0))})
        elif t == "getaddr":
            if not peer.sent_addr:
                peer.sent_addr = True          # answer once per connection
                sample = self.addrman.sample(250, exclude={peer.key})
                peer.send({"type": "addr", "addrs": [[k, int(seen)] for k, seen in sample]})
        elif t == "addr":
            addrs = msg.get("addrs", [])
            if not isinstance(addrs, list) or len(addrs) > MAX_ADDR_PER_MSG:
                self.misbehave(peer, 20, "oversized addr message")
                return
            peer.addr_msgs += 1
            if peer.addr_msgs > 10:
                return                          # ignore address spam, no need to punish
            for item in addrs:
                if not (isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)):
                    continue
                try:
                    host, port = parse(item[0])
                    seen = _int(item[1])
                except (ValueError, TypeError):
                    continue
                self.addrman.add(host, port, seen=seen)
        elif t in ("pong", "version"):
            pass
        # Unknown message types are ignored, so future versions can add messages
        # without older nodes banning them.

    # ------------------------------------------------------------ tip announcements
    def _tip_changed(self):
        now = time.time()
        if now - self._last_announce >= 0.5:
            self._last_announce = now
            self._announce_pending = False
            self.broadcast_inv(blocks=[self.chain.tip.hash.hex()])
        else:
            self._announce_pending = True

    def _announce_loop(self):
        while self.running:
            time.sleep(0.25)
            with self.plock:
                waiting = [p for p in self.peers if p.sync_pending and p.ready]
            for p in waiting:
                self._request_headers(p)
            if self._announce_pending and time.time() - self._last_announce >= 0.5:
                self._last_announce = time.time()
                self._announce_pending = False
                self.broadcast_inv(blocks=[self.chain.tip.hash.hex()])

    # ------------------------------------------------------------ connection manager
    def add_manual(self, key: str):
        """Keep a connection to this peer forever, reconnecting whenever it drops."""
        host, port = parse(key)
        self.manual.add(f"{host}:{port}")
        self.addrman.add(host, port, manual=True)

    def _connected_keys(self):
        with self.plock:
            return {p.key for p in self.peers if p.key}

    def _dial(self, key, manual):
        try:
            host, port = parse(key)
            self.addrman.attempt(key)
            if self.is_banned(host):
                return
            s = socket.create_connection((host, port), timeout=10, source_address=self.source)
            s.settimeout(None)
            self._add_peer(s, (host, port), True, key=key, manual=manual)
        except (OSError, ValueError):
            pass
        finally:
            self.pending.discard(key)

    def _start_dial(self, key, manual=False):
        self.pending.add(key)
        threading.Thread(target=self._dial, args=(key, manual), daemon=True).start()

    def _connman_loop(self):
        last_save = time.time()
        while self.running:
            time.sleep(CONNMAN_INTERVAL)
            if not self.running:
                return
            connected = self._connected_keys()
            busy = connected | self.pending
            for key in list(self.manual):                       # manual peers: always
                if key not in busy and self.addrman.ready(key, manual=True):
                    self._start_dial(key, manual=True)
            with self.plock:
                outbound = sum(1 for p in self.peers if p.outbound and not p.manual)
            outbound += sum(1 for k in self.pending if k not in self.manual)
            if self.use_seeds and not self.manual and (not len(self.addrman) or not (connected or self.pending)):
                for seed in self.chain.params.seeds:           # first start: ask the seeds
                    h, p = parse(seed)
                    self.addrman.add(h, p)
            tries = 0
            while outbound < self.max_outbound and tries < 3:
                key = self.addrman.select(exclude=busy | self.manual)
                if key is None:
                    break
                self._start_dial(key)
                busy.add(key)
                outbound += 1
                tries += 1
            if time.time() - last_save > 60:
                self.addrman.save()
                last_save = time.time()

    def _request_headers(self, peer, now=None):
        now = now or time.time()
        if now - peer.last_sync < 0.5:
            peer.sync_pending = True           # sent shortly by the announcer thread
            return
        peer.last_sync = now
        peer.sync_pending = False
        peer.send({"type": "getheaders", "locator": [h.hex() for h in self.chain.header_locator()]})

    def _fetch_blocks(self):
        """Ask for the block bodies we lack along the most-work header chain, in
        order, spread over the peers that have them, a bounded number in flight."""
        chain = self.chain
        with self.qlock:
            best = chain.best_header
            if self.queue_for is not best:
                self.queue = chain.missing_blocks(limit=1 << 30)
                self.queue_for = best
            while self.queue and (self.queue[0].has_data or self.queue[0].chain_data or self.queue[0].invalid):
                self.queue.pop(0)
            if not self.queue:
                return
            with self.plock:
                peers = [p for p in self.peers if p.ready]
            random.shuffle(peers)
            want = {}
            for idx in self.queue[:len(peers) * BLOCKS_IN_FLIGHT_PER_PEER + 64]:
                if idx.hash in self.inflight or idx.has_data or idx.chain_data:
                    continue
                for p in peers:
                    if len(p.inflight) < BLOCKS_IN_FLIGHT_PER_PEER and p.height >= idx.height:
                        want.setdefault(p, []).append(idx.hash)
                        p.inflight.add(idx.hash)
                        self.inflight[idx.hash] = (p, time.time())
                        break
        for p, hashes in want.items():
            p.expected = min(p.expected + len(hashes), 10 * MAX_INV)
            p.known.update(h.hex() for h in hashes)
            p.send({"type": "getdata", "blocks": [h.hex() for h in hashes], "txs": []})

    # ------------------------------------------------------------ local actions
    def submit_tx(self, tx: Transaction):
        self.chain.accept_tx(tx)
        self.broadcast_inv(txs=[tx.txid.hex()])

    def announce_block(self, blk: Block):
        self._tip_changed()

    def mine_one(self, address=None, extra=b"") -> Block:
        while self.running:
            blk = self.chain.create_block(address or self.wallet.mining_address, extra)
            start_tip = self.chain.tip
            if mine(blk.header, should_stop=lambda: self.chain.tip is not start_tip or not self.running):
                if self.chain.submit_block(blk) == "accepted":
                    self.announce_block(blk)
                    self.log(f"[{self.name}] mined block {blk.header.height} {blk.hash.hex()[:16]} "
                             f"({len(blk.txs) - 1} txs)")
                    return blk

    def start_mining(self, address=None):
        self._mining = True

        pause = float(os.environ.get("KAIROS_MINE_INTERVAL", "0.01"))   # test hook

        def loop():
            while self._mining and self.running:
                self.mine_one(address)
                time.sleep(pause)
        threading.Thread(target=loop, daemon=True).start()

    def stop_mining(self):
        self._mining = False
