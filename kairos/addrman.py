"""
Kairos address manager.

Remembers where other nodes can be reached, and chooses whom to connect to in
a way an attacker cannot easily steer (an "eclipse" attack surrounds a node
with the attacker's peers). The design follows Bitcoin Core's, which came
out of Heilman, Kendler, Zohar and Goldberg, "Eclipse Attacks on Bitcoin's
Peer-to-Peer Network" (USENIX Security 2015):

  * Two tables. NEW holds addresses we have only heard of; TRIED holds
    addresses we have connected to successfully.
  * Each table is split into buckets of fixed size. Where an address goes is
    decided by a keyed hash with a secret key that only this node knows, so an
    attacker cannot precompute addresses that land where it wants.
  * An address heard from a peer is placed by the /16 group of *that peer* as
    well as its own group, so one source can fill only a few NEW buckets no
    matter how many addresses it sends. In TRIED, one /16 group can occupy only
    a few buckets.
  * A newcomer never displaces a good entry: in NEW it takes a slot only if the
    occupant is stale or failing; in TRIED, an address that worked recently is
    kept and the newcomer waits in NEW.
  * The node makes at most one outbound connection per /16 group (see
    Node._connman_loop), so an attacker needs addresses in many groups.

Also: addresses come from --connect, built-in seeds, peers' `addr` answers
and inbound peers' listening ports; retries back off exponentially; addresses
that never worked are forgotten; on public networks only globally routable
IPv4 addresses are accepted; the table is persisted to <datadir>/peers.json
together with the secret key.
"""
import ipaddress
import json
import os
import random
import threading
import time

from .crypto import tagged_hash

NEW_BUCKETS = 256
TRIED_BUCKETS = 64
BUCKET_SIZE = 32
NEW_BUCKETS_PER_SOURCE_GROUP = 16     # one source group reaches at most 16 of 256 NEW buckets
TRIED_BUCKETS_PER_GROUP = 4           # one address group reaches at most 4 of 64 TRIED buckets
MAX_FAILURES = 8
MAX_BACKOFF = 30 * 60
MANUAL_MAX_BACKOFF = 60
HORIZON = 30 * 86400                  # not seen for this long: stale
KEEP_TRIED = 7 * 86400                # a TRIED entry that worked this recently is never displaced
FILE_VERSION = 2


def parse(key: str):
    host, _, port = key.rpartition(":")
    return host, int(port)


class AddrMan:
    def __init__(self, path=None, allow_private=False, now=time.time, key=None):
        self.path = path
        self.allow_private = allow_private
        self.now = now
        self.lock = threading.Lock()
        self.key = key or os.urandom(32)
        self.entries = {}          # "ip:port" -> dict
        self.new = {}              # (bucket, slot) -> "ip:port"
        self.tried = {}
        self._load()

    # ------------------------------------------------------------ validation
    def valid(self, host, port) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            port = int(port)
        except (ValueError, TypeError):
            return False
        if ip.version != 4 or not 0 < port < 65536:
            return False
        return self.allow_private or ip.is_global

    def group(self, addr: str) -> str:
        """The network group an address belongs to: its /16. On private test
        networks every node is on 127.0.0.1, so there each address is its own group."""
        host = addr.rpartition(":")[0] if ":" in addr else addr
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return addr
        if self.allow_private and not ip.is_global:
            return addr
        if ip.version == 4:
            return ".".join(host.split(".")[:2])
        return str(ipaddress.ip_network(f"{host}/32", strict=False))

    # ------------------------------------------------------------ placement
    def _h(self, *parts) -> int:
        data = b"\x00".join(p.encode() if isinstance(p, str) else p for p in parts)
        return int.from_bytes(tagged_hash("Kairos/addrman", self.key + data)[:8], "big")

    def _new_pos(self, addr, src_group):
        g = self.group(addr)
        b = self._h("new", src_group, str(self._h("new-g", g, src_group) % NEW_BUCKETS_PER_SOURCE_GROUP)) % NEW_BUCKETS
        return b, self._h("slot-new", str(b), addr) % BUCKET_SIZE

    def _tried_pos(self, addr):
        g = self.group(addr)
        b = self._h("tried", g, str(self._h("tried-k", addr) % TRIED_BUCKETS_PER_GROUP)) % TRIED_BUCKETS
        return b, self._h("slot-tried", str(b), addr) % BUCKET_SIZE

    def _terrible(self, e) -> bool:
        now = self.now()
        if e.get("manual"):
            return False
        if now - e["seen"] > HORIZON:
            return True
        if not e["ok"] and e["fails"] >= 3:
            return True
        return bool(e["ok"]) and now - e["ok"] > KEEP_TRIED and e["fails"] >= 10

    def _remove(self, addr):
        e = self.entries.pop(addr, None)
        if e and e.get("pos") is not None:
            table = self.new if e["table"] == "new" else self.tried
            if table.get(tuple(e["pos"])) == addr:
                del table[tuple(e["pos"])]

    def _place_new(self, addr, e) -> bool:
        pos = self._new_pos(addr, e["src"])
        other = self.new.get(pos)
        if other is not None and other != addr:
            if not self._terrible(self.entries[other]):
                return False
            self._remove(other)
        self.new[pos] = addr
        e["table"], e["pos"] = "new", pos
        return True

    # ------------------------------------------------------------ updates
    def add(self, host, port, seen=None, manual=False, source=None, verified=False) -> bool:
        """Learn an address. `source` is the IP of the peer that told us, if any.
        `manual` addresses (--connect) live outside the tables and are never
        evicted; `verified` ones were reached directly, so the public-address
        check is skipped."""
        if not (manual or verified) and not self.valid(host, port):
            return False
        key = f"{host}:{int(port)}"
        now = self.now()
        seen = min(seen or now, now)
        with self.lock:
            e = self.entries.get(key)
            if e:
                e["seen"] = max(e["seen"], seen)
                if manual:
                    e["manual"] = True
                return False
            e = {"seen": seen, "tried": 0, "ok": 0, "fails": 0, "self": False, "manual": manual,
                 "src": self.group(source) if source else "local", "table": None, "pos": None}
            if not manual:
                if not self._place_new(key, e):
                    return False                   # its slot is held by a good address
            self.entries[key] = e
            return True

    def attempt(self, key):
        with self.lock:
            e = self.entries.get(key)
            if e is None:
                return
            e["tried"] = self.now()
            e["fails"] += 1                 # cleared again by success()

    def success(self, key):
        """We connected: the address moves to TRIED, unless its TRIED slot holds
        an address that also worked recently, which keeps its place."""
        with self.lock:
            e = self.entries.get(key)
            if not e:
                return
            e["fails"] = 0
            e["ok"] = e["seen"] = self.now()
            if e.get("manual") or e["table"] == "tried":
                return
            pos = self._tried_pos(key)
            other = self.tried.get(pos)
            if other is not None and other != key:
                o = self.entries[other]
                if not self._terrible(o) and self.now() - o["ok"] <= KEEP_TRIED:
                    return                          # stays in NEW, still selectable
                del self.tried[pos]                 # the old one goes back to NEW
                o["table"], o["pos"] = None, None
                if not self._place_new(other, o):
                    self.entries.pop(other, None)
            if e["table"] == "new" and self.new.get(tuple(e["pos"])) == key:
                del self.new[tuple(e["pos"])]
            self.tried[pos] = key
            e["table"], e["pos"] = "tried", pos

    def mark_self(self, key):
        with self.lock:
            if key in self.entries:
                self.entries[key]["self"] = True

    def forget(self, key):
        with self.lock:
            self._remove(key)

    # ------------------------------------------------------------ selection
    def _backoff_ok(self, e, now, manual=False) -> bool:
        cap = MANUAL_MAX_BACKOFF if manual else MAX_BACKOFF
        wait = min(cap, 5 * 2 ** min(e["fails"], 12)) if e["fails"] else 0
        return now - e["tried"] >= wait

    def ready(self, key, manual=False) -> bool:
        with self.lock:
            e = self.entries.get(key)
            return e is None or self._backoff_ok(e, self.now(), manual)

    def select(self, exclude=(), exclude_groups=()):
        """An address worth trying now, or None: from TRIED or NEW with equal
        chance, never from a group we are already connected to."""
        with self.lock:
            now = self.now()
            for k in [k for k, e in self.entries.items()
                      if e["fails"] >= MAX_FAILURES and not e["ok"] and not e.get("manual")]:
                self._remove(k)
            pools = []
            for table in (self.tried, self.new):
                pool = [k for k in table.values()
                        if k not in exclude and not self.entries[k]["self"]
                        and self.group(k) not in exclude_groups and self._backoff_ok(self.entries[k], now)]
                pools.append(pool)
        tried, new = pools
        if tried and new:
            return random.choice(tried if random.random() < 0.5 else new)
        pool = tried or new
        return random.choice(pool) if pool else None

    def sample(self, n=250, exclude=()):
        """Addresses to share with a peer: recently seen, never our own."""
        with self.lock:
            now = self.now()
            good = [(k, e["seen"]) for k, e in self.entries.items()
                    if not e["self"] and k not in exclude and e["fails"] < 3 and e["table"]
                    and now - e["seen"] < 7 * 86400]
        random.shuffle(good)
        return good[:n]

    def __len__(self):
        return len(self.entries)

    def stats(self) -> dict:
        with self.lock:
            return {"new": len(self.new), "tried": len(self.tried),
                    "manual": sum(1 for e in self.entries.values() if e.get("manual"))}

    # ------------------------------------------------------------ persistence
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            if data.get("version") == FILE_VERSION:
                self.key = bytes.fromhex(data["key"])
                items = data["entries"].items()
            else:
                items = data.items()                 # 0.4 format: a flat table, all treated as NEW
            tried_first = sorted(items, key=lambda kv: kv[1].get("table") != "tried")
            for k, d in tried_first:
                host, port = parse(k)
                manual = bool(d.get("manual"))
                if not (self.valid(host, port) or manual):
                    continue
                e = {"seen": float(d.get("seen", 0)), "tried": 0, "ok": float(d.get("ok", 0)), "fails": 0,
                     "self": bool(d.get("self", False)), "manual": manual, "src": str(d.get("src", "file")),
                     "table": None, "pos": None}
                if not manual:
                    if d.get("table") == "tried" and e["ok"]:
                        pos = self._tried_pos(k)
                        if pos in self.tried:
                            continue
                        self.tried[pos] = k
                        e["table"], e["pos"] = "tried", pos
                    elif not self._place_new(k, e):
                        continue
                self.entries[k] = e
        except (ValueError, OSError, TypeError, AttributeError, KeyError):
            self.entries, self.new, self.tried = {}, {}, {}      # a damaged file is simply rebuilt

    def save(self):
        if not self.path:
            return
        with self.lock:
            data = {"version": FILE_VERSION, "key": self.key.hex(),
                    "entries": {k: {"seen": e["seen"], "ok": e["ok"], "self": e["self"],
                                    "manual": e.get("manual", False), "src": e["src"], "table": e["table"]}
                                for k, e in self.entries.items()}}
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError:
            pass
