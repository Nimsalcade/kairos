import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos.addrman import AddrMan, parse
from kairos.chain import Chain
from kairos.node import Node
from kairos.params import REGTEST, TESTNET
from kairos.wallet import Wallet

from test_kairos import wait


def mk(params=REGTEST, **kw):
    return Node(Chain(params), wallet=Wallet(params), **kw)


def peer_keys(node):
    return {p.key for p in node.peers if p.ready}


class TestAddrMan(unittest.TestCase):
    def test_public_networks_reject_private_addresses(self):
        a = AddrMan(allow_private=False)
        for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.9", "0.0.0.0", "not-an-ip", "::1"):
            self.assertFalse(a.add(bad, 19333), bad)
        self.assertFalse(a.add("8.8.8.8", 0))
        self.assertTrue(a.add("8.8.8.8", 19333))

    def test_backoff_and_forgetting_dead_addresses(self):
        clock = [1000.0]
        a = AddrMan(allow_private=True, now=lambda: clock[0])
        a.add("127.0.0.1", 1)
        key = "127.0.0.1:1"
        self.assertEqual(a.select(), key)
        a.attempt(key)
        self.assertIsNone(a.select())            # backing off
        clock[0] += 11
        self.assertEqual(a.select(), key)
        for _ in range(8):
            a.attempt(key)
        clock[0] += 10 ** 6
        self.assertIsNone(a.select())            # never worked, failed 9 times: forgotten
        self.assertEqual(len(a), 0)

    def test_persistence_and_damaged_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "peers.json")
            a = AddrMan(path)
            a.add("1.2.3.4", 19333)
            a.save()
            self.assertIn("1.2.3.4:19333", AddrMan(path).entries)
            with open(path, "w") as f:
                f.write("{garbage")
            self.assertEqual(len(AddrMan(path)), 0)

    def test_never_shares_own_address(self):
        a = AddrMan(allow_private=True)
        a.add("127.0.0.1", 5)
        a.add("127.0.0.1", 6)
        a.mark_self("127.0.0.1:5")
        self.assertEqual([k for k, _ in a.sample()], ["127.0.0.1:6"])
        self.assertEqual(a.select(), "127.0.0.1:6")


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.nodes = []

    def tearDown(self):
        for n in self.nodes:
            n.stop()

    def node(self, params=REGTEST, **kw):
        n = mk(params, **kw)
        self.nodes.append(n)
        return n

    def test_finds_peers_it_was_never_told_about(self):
        a, b, c = self.node(), self.node(), self.node()
        b.connect("127.0.0.1", c.port)                  # B knows C
        a.add_manual(f"127.0.0.1:{b.port}")             # A only knows B
        wait(lambda: f"127.0.0.1:{c.port}" in peer_keys(a), 20)   # ...and discovers C

    def test_reconnects_after_peer_restarts(self):
        b = self.node()
        port = b.port
        a = self.node()
        a.add_manual(f"127.0.0.1:{port}")
        wait(lambda: peer_keys(a), 10)
        b.stop()
        wait(lambda: not peer_keys(a), 10)
        b2 = Node(Chain(REGTEST), host="127.0.0.1", port=port, wallet=Wallet(REGTEST))
        self.nodes.append(b2)
        wait(lambda: peer_keys(a), 30)                  # healed without anyone intervening
        for _ in range(3):
            b2.mine_one()
        wait(lambda: a.chain.height == 3, 10)

    def test_new_node_bootstraps_from_seeds(self):
        seed = self.node()
        params = replace(REGTEST, seeds=(f"127.0.0.1:{seed.port}",))
        newbie = self.node(params)                      # no --connect at all
        wait(lambda: peer_keys(newbie), 15)

    def test_self_connection_is_remembered_not_repeated(self):
        a = self.node()
        a.addrman.add("127.0.0.1", a.port)
        wait(lambda: a.addrman.entries.get(f"127.0.0.1:{a.port}", {}).get("self"), 15)
        self.assertEqual(peer_keys(a), set())

    def test_addresses_survive_restart(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.node()
            chain = Chain(REGTEST, datadir=d)
            a = Node(chain, wallet=Wallet(REGTEST))
            a.connect("127.0.0.1", b.port)
            wait(lambda: peer_keys(a), 10)
            a.stop()
            chain.close()
            with open(os.path.join(d, "peers.json")) as f:
                self.assertIn(f"127.0.0.1:{b.port}", json.load(f)["entries"])


class TestProtocolFloor(unittest.TestCase):
    """0.4 is a new chain (testnet 2). Older nodes are disconnected politely, never banned."""

    def test_old_protocol_disconnected_not_banned(self):
        n = mk()
        try:
            s = socket.create_connection(("127.0.0.1", n.port), timeout=5)
            s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "version", "proto": 3,
                                   "genesis": n.chain.genesis.hash.hex(), "height": 0,
                                   "nonce": 42, "agent": "/kairos:0.3.0/"}) + "\n").encode())
            wait(lambda: not n.peers, 10)
            self.assertFalse(n.is_banned("127.0.0.1"))
            s.close()
        finally:
            n.stop()

    def test_unknown_message_types_are_ignored_not_punished(self):
        n = mk()
        try:
            s = socket.create_connection(("127.0.0.1", n.port), timeout=5)
            m = REGTEST.magic.hex()
            s.sendall((json.dumps({"magic": m, "type": "version", "proto": 4,
                                   "genesis": n.chain.genesis.hash.hex(), "height": 0, "nonce": 7}) + "\n").encode())
            for _ in range(20):
                s.sendall((json.dumps({"magic": m, "type": "some_future_message"}) + "\n").encode())
            time.sleep(1)
            self.assertFalse(n.is_banned("127.0.0.1"))
            self.assertTrue(any(p.ready for p in n.peers))
            s.close()
        finally:
            n.stop()

    def test_testnet_ignores_private_addresses_from_peers(self):
        n = mk(TESTNET, use_seeds=False)
        try:
            p = type("P", (), {"proto": 4, "addr_msgs": 0, "ready": True})()
            n._handle(p, {"type": "addr", "addrs": [["10.0.0.1:19333", 0], ["127.0.0.1:19333", 0],
                                                     ["203.0.113.9:19333", 0], ["8.8.4.4:19333", 0]]})
            self.assertEqual(set(n.addrman.entries), {"8.8.4.4:19333"})   # 203.0.113/24 is doc-only
        finally:
            n.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestEclipseResistance(unittest.TestCase):
    """The address manager limits what any one source or network group can
    occupy, and never lets newcomers displace addresses that work."""

    def addrs(self, first_octets, per=1, start=0):
        out = []
        for a in first_octets:
            for i in range(per):
                out.append(f"{a}.{(start + i) // 250 % 250 + 1}.{(start + i) % 250 + 1}.9")
        return out

    def test_one_source_fills_only_a_few_new_buckets(self):
        from kairos import addrman as A
        m = AddrMan(key=b"\x01" * 32)
        honest = 0
        for i, host in enumerate(self.addrs(range(1, 100), per=3)):
            honest += m.add(host, 19333, source=f"{100 + i % 50}.{i % 7}.0.1")
        # one attacker IP sends 20,000 addresses spread over 200 /16 groups
        flood = [f"{11 + i % 200}.{i // 200 % 250}.{i % 250}.7" for i in range(20_000)]
        for host in flood:
            m.add(host, 19333, source="6.6.6.6")
        buckets = {e["pos"][0] for k, e in m.entries.items() if e["src"] == m.group("6.6.6.6")}
        self.assertLessEqual(len(buckets), A.NEW_BUCKETS_PER_SOURCE_GROUP)
        attacker = sum(1 for e in m.entries.values() if e["src"] == m.group("6.6.6.6"))
        self.assertLessEqual(attacker, A.NEW_BUCKETS_PER_SOURCE_GROUP * A.BUCKET_SIZE)
        surviving = sum(1 for e in m.entries.values() if e["src"] != m.group("6.6.6.6"))
        self.assertGreater(surviving, honest * 0.9)       # honest addresses are not washed out

    def test_one_group_occupies_few_tried_buckets(self):
        from kairos import addrman as A
        m = AddrMan(key=b"\x02" * 32)
        for i in range(2000):
            host = f"66.66.{i // 250}.{i % 250 + 1}"
            m.add(host, 19333, source=f"{i % 200 + 1}.1.1.1")
            m.success(f"{host}:19333")
        buckets = {e["pos"][0] for e in m.entries.values() if e["table"] == "tried"}
        self.assertLessEqual(len(buckets), A.TRIED_BUCKETS_PER_GROUP)

    def test_working_tried_address_is_not_displaced(self):
        clock = [1_000_000.0]
        m = AddrMan(key=b"\x03" * 32, now=lambda: clock[0])
        m.add("8.8.8.8", 19333)
        m.success("8.8.8.8:19333")
        pos = m.entries["8.8.8.8:19333"]["pos"]
        rival = next(f"8.8.{i // 250}.{i % 250}:19333" for i in range(1, 60000)
                     if m._tried_pos(f"8.8.{i // 250}.{i % 250}:19333") == pos)
        host, port = parse(rival)
        clock[0] += 3600
        m.add(host, port)
        m.success(rival)
        self.assertEqual(m.tried[pos], "8.8.8.8:19333")          # the proven peer keeps its place
        self.assertEqual(m.entries[rival]["table"], "new")       # the newcomer waits in NEW
        clock[0] += 8 * 86400                                    # a week without contact
        m.success(rival)
        self.assertEqual(m.tried[pos], rival)
        self.assertEqual(m.entries["8.8.8.8:19333"]["table"], "new")   # demoted, not forgotten

    def test_placement_depends_on_a_secret_key(self):
        a, b = AddrMan(key=b"\x04" * 32), AddrMan(key=b"\x05" * 32)
        hosts = [f"9.{i}.1.1:19333" for i in range(40)]
        pa = [a._new_pos(h, "local") for h in hosts]
        pb = [b._new_pos(h, "local") for h in hosts]
        self.assertNotEqual(pa, pb)

    def test_select_avoids_connected_groups(self):
        # A fixed key: with a random one, two of these addresses share a NEW slot
        # about once in 250 runs, and the second is then not stored at all.
        m = AddrMan(key=b"\x06" * 32)
        for h in ("8.8.1.1", "8.8.2.2", "9.9.1.1"):
            self.assertTrue(m.add(h, 19333))
        for _ in range(50):
            self.assertEqual(m.select(exclude_groups={"8.8"}), "9.9.1.1:19333")
        self.assertEqual(m.group("8.8.200.1"), "8.8")

    def test_key_and_tables_survive_restart_and_old_files_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "peers.json")
            m = AddrMan(path)
            m.add("8.8.8.8", 19333, source="1.2.3.4")
            m.add("9.9.9.9", 19333)
            m.success("9.9.9.9:19333")
            m.save()
            m2 = AddrMan(path)
            self.assertEqual(m2.key, m.key)
            self.assertEqual(m2.entries["9.9.9.9:19333"]["table"], "tried")
            self.assertEqual(m2.entries["8.8.8.8:19333"]["table"], "new")
            with open(path, "w") as f:                          # a 0.4 peers.json
                json.dump({"8.8.4.4:19333": {"seen": time.time(), "ok": 0, "self": False}}, f)
            self.assertEqual(AddrMan(path).entries["8.8.4.4:19333"]["table"], "new")
