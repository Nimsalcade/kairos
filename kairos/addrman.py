"""
Kairos address manager.

Remembers where other nodes can be reached, so the network can find and
re-find itself without anyone typing IP addresses:

  * addresses come from --connect, from built-in seed nodes, from peers'
    answers to `getaddr`, and from inbound peers' advertised listening port
  * each address tracks last seen / last tried / failed attempts; retries back
    off exponentially and addresses that keep failing are forgotten
  * on public networks only globally routable IPv4 addresses are accepted, so
    peers cannot steer us at private or loopback ranges
  * the table is bounded and persisted to <datadir>/peers.json
"""
import ipaddress
import json
import os
import random
import threading
import time

MAX_ADDRESSES = 2000
MAX_FAILURES = 8
MAX_BACKOFF = 30 * 60
MANUAL_MAX_BACKOFF = 60


def parse(key: str):
    host, _, port = key.rpartition(":")
    return host, int(port)


class AddrMan:
    def __init__(self, path=None, allow_private=False, now=time.time):
        self.path = path
        self.allow_private = allow_private
        self.now = now
        self.lock = threading.Lock()
        self.entries = {}          # "ip:port" -> dict
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

    # ------------------------------------------------------------ updates
    def add(self, host, port, seen=None, manual=False) -> bool:
        if not manual and not self.valid(host, port):
            return False
        key = f"{host}:{int(port)}"
        now = self.now()
        seen = min(seen or now, now)
        with self.lock:
            e = self.entries.get(key)
            if e:
                e["seen"] = max(e["seen"], seen)
                return False
            if len(self.entries) >= MAX_ADDRESSES:
                self._evict()
            self.entries[key] = {"seen": seen, "tried": 0, "ok": 0, "fails": 0, "self": False}
            return True

    def _evict(self):
        worst = max(self.entries, key=lambda k: (self.entries[k]["fails"], -self.entries[k]["seen"]))
        del self.entries[worst]

    def attempt(self, key):
        with self.lock:
            e = self.entries.setdefault(key, {"seen": 0, "tried": 0, "ok": 0, "fails": 0, "self": False})
            e["tried"] = self.now()
            e["fails"] += 1                 # cleared again by success()

    def success(self, key):
        with self.lock:
            e = self.entries.get(key)
            if e:
                e["fails"] = 0
                e["ok"] = e["seen"] = self.now()

    def mark_self(self, key):
        with self.lock:
            if key in self.entries:
                self.entries[key]["self"] = True

    def forget(self, key):
        with self.lock:
            self.entries.pop(key, None)

    # ------------------------------------------------------------ selection
    def ready(self, key, manual=False) -> bool:
        with self.lock:
            e = self.entries.get(key)
            if e is None:
                return True
            cap = MANUAL_MAX_BACKOFF if manual else MAX_BACKOFF
            wait = min(cap, 5 * 2 ** min(e["fails"], 12)) if e["fails"] else 0
            return self.now() - e["tried"] >= wait

    def select(self, exclude=()):
        """A random address worth trying now, or None."""
        with self.lock:
            now = self.now()
            dead = [k for k, e in self.entries.items() if e["fails"] >= MAX_FAILURES and not e["ok"]]
            for k in dead:
                del self.entries[k]
            pool = []
            for k, e in self.entries.items():
                if k in exclude or e["self"]:
                    continue
                wait = min(MAX_BACKOFF, 5 * 2 ** min(e["fails"], 12)) if e["fails"] else 0
                if now - e["tried"] >= wait:
                    pool.append(k)
        return random.choice(pool) if pool else None

    def sample(self, n=250, exclude=()):
        """Addresses to share with a peer: recently seen, never our own."""
        with self.lock:
            now = self.now()
            good = [(k, e["seen"]) for k, e in self.entries.items()
                    if not e["self"] and k not in exclude and e["fails"] < 3
                    and now - e["seen"] < 7 * 86400]
        random.shuffle(good)
        return good[:n]

    def __len__(self):
        return len(self.entries)

    # ------------------------------------------------------------ persistence
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            for k, e in list(data.items())[:MAX_ADDRESSES]:
                host, port = parse(k)
                if self.valid(host, port) or e.get("manual"):
                    self.entries[k] = {"seen": float(e.get("seen", 0)), "tried": 0, "ok": float(e.get("ok", 0)),
                                       "fails": 0, "self": bool(e.get("self", False))}
        except (ValueError, OSError, TypeError, AttributeError):
            self.entries = {}          # a damaged file is simply rebuilt

    def save(self):
        if not self.path:
            return
        with self.lock:
            data = {k: {"seen": e["seen"], "ok": e["ok"], "self": e["self"]} for k, e in self.entries.items()}
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError:
            pass
