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

from kairos.addrman import AddrMan
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
                self.assertIn(f"127.0.0.1:{b.port}", json.load(f))


class TestCompatibilityWith022(unittest.TestCase):
    """0.3 must interoperate with the 0.2.2 seed nodes still running on the testnet."""

    def test_no_address_gossip_with_old_peers_and_no_ban(self):
        n = mk()
        seen, stop = [], threading.Event()
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def old_peer():                                    # behaves like a 0.2.2 node
            conn, _ = srv.accept()
            conn.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "version", "proto": 2,
                                      "genesis": n.chain.genesis.hash.hex(), "height": 0,
                                      "nonce": 42, "agent": "/kairos:0.2.2/"}) + "\n").encode())
            conn.settimeout(0.5)
            buf = b""
            while not stop.is_set():
                try:
                    d = conn.recv(65536)
                    if not d:
                        break
                    buf += d
                except socket.timeout:
                    pass
            for line in buf.splitlines():
                seen.append(json.loads(line)["type"])
            conn.close()
        t = threading.Thread(target=old_peer, daemon=True)
        t.start()
        try:
            n.add_manual(f"127.0.0.1:{port}")
            wait(lambda: peer_keys(n), 10)
            time.sleep(1.5)
        finally:
            stop.set()
            t.join(5)
            n.stop()
            srv.close()
        self.assertIn("version", seen)
        self.assertNotIn("getaddr", seen)                  # 0.2.2 would penalise it
        self.assertNotIn("addr", seen)

    def test_unknown_message_types_are_ignored_not_punished(self):
        n = mk()
        try:
            s = socket.create_connection(("127.0.0.1", n.port), timeout=5)
            m = REGTEST.magic.hex()
            s.sendall((json.dumps({"magic": m, "type": "version", "proto": 3,
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
            p = type("P", (), {"proto": 3, "addr_msgs": 0, "ready": True})()
            n._handle(p, {"type": "addr", "addrs": [["10.0.0.1:19333", 0], ["127.0.0.1:19333", 0],
                                                     ["203.0.113.9:19333", 0], ["8.8.4.4:19333", 0]]})
            self.assertEqual(set(n.addrman.entries), {"8.8.4.4:19333"})   # 203.0.113/24 is doc-only
        finally:
            n.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
