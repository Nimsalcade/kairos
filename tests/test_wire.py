import json
import os
import random
import socket
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos import wire
from kairos.chain import Chain
from kairos.node import Node
from kairos.params import REGTEST, COIN
from kairos.wallet import Wallet

from test_kairos import wait

MAGIC = REGTEST.magic


def mk(**kw):
    return Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=os.urandom(32)), use_seeds=False, **kw)


def ready_peers(n):
    return [p for p in n.peers if p.ready]


class TestCodec(unittest.TestCase):
    def test_every_message_round_trips(self):
        h = [os.urandom(32).hex() for _ in range(3)]
        msgs = [{"type": "inv", "blocks": h[:2], "txs": h[2:]},
                {"type": "getdata", "blocks": [], "txs": h},
                {"type": "getheaders", "locator": h},
                {"type": "headers", "data": [os.urandom(140).hex(), os.urandom(300).hex()]},
                {"type": "block", "data": os.urandom(1000).hex()},
                {"type": "tx", "data": os.urandom(250).hex()},
                {"type": "ping", "n": 2 ** 63}, {"type": "pong", "n": 7},
                {"type": "getaddr"},
                {"type": "addr", "addrs": [["8.8.8.8:19333", 1790000000], ["1.2.3.4:1", 0]]}]
        for m in msgs:
            frame = wire.encode(MAGIC, dict(m))
            import io
            cmd, payload = wire.read_frame(io.BytesIO(frame), MAGIC)
            self.assertEqual(wire.decode_payload(cmd, payload), m)

    def test_raw_bytes_halve_block_traffic(self):
        data = os.urandom(100_000).hex()
        frame = wire.encode(MAGIC, {"type": "block", "data": data})
        line = (json.dumps({"type": "block", "data": data, "magic": MAGIC.hex()}) + "\n").encode()
        self.assertEqual(len(frame), 100_000 + wire.HEADER_SIZE)
        self.assertLess(len(frame), len(line) * 0.51)

    def test_malformed_frames_are_rejected(self):
        import io
        good = wire.encode(MAGIC, {"type": "ping", "n": 1})
        bad = [b"XXXX" + good[4:],                                   # wrong magic
               good[:4] + b"PING".ljust(12, b"\x00") + good[16:],     # upper case command
               good[:4] + b"pi\x00ng".ljust(12, b"\x00") + good[16:], # embedded zero
               good[:16] + struct.pack("<I", 10 ** 8) + good[20:]]    # oversized length
        for b in bad:
            with self.assertRaises(wire.FrameError):
                wire.read_frame(io.BytesIO(b), MAGIC)
        with self.assertRaises(EOFError):
            wire.read_frame(io.BytesIO(good[:-1]), MAGIC)            # closed mid-frame
        for cmd, payload in (("inv", b"\x01" + b"\x00" * 31), ("ping", b"\x00" * 7),
                             ("addr", b"\x02" + b"\x00" * 14), ("getaddr", b"\x00"),
                             ("headers", b"\xfd\xff\xff")):
            with self.assertRaises(ValueError):
                wire.decode_payload(cmd, payload)
        self.assertEqual(wire.decode_payload("somefuture", b"\x01\x02"), {"type": "somefuture"})


class TestNegotiation(unittest.TestCase):
    def setUp(self):
        self.nodes = []

    def tearDown(self):
        for n in self.nodes:
            n.stop()

    def node(self, **kw):
        n = mk(**kw)
        self.nodes.append(n)
        return n

    def test_new_nodes_switch_to_binary_and_sync(self):
        a, b = self.node(), self.node()
        b.connect("127.0.0.1", a.port)
        wait(lambda: ready_peers(a) and ready_peers(b), 10)
        self.assertTrue(all(p.binary for p in ready_peers(a) + ready_peers(b)))
        for _ in range(5):
            a.mine_one()
        wait(lambda: b.chain.height == 5, 15)
        tx = a.wallet.create_tx(a.chain, b.wallet.mining_address, COIN)
        a.submit_tx(tx)
        wait(lambda: tx.txid in b.chain.mempool, 10)

    def test_old_json_node_still_works_both_ways(self):
        new, old = self.node(), self.node(binary=False)
        old.connect("127.0.0.1", new.port)
        wait(lambda: ready_peers(new) and ready_peers(old), 10)
        self.assertFalse(any(p.binary for p in ready_peers(new) + ready_peers(old)))
        for _ in range(3):
            new.mine_one()
        wait(lambda: old.chain.height == 3, 15)
        for _ in range(2):
            old.mine_one()
        wait(lambda: new.chain.height == 5, 15)

    def raw_binary_peer(self, n):
        s = socket.create_connection(("127.0.0.1", n.port), timeout=5)
        s.sendall((json.dumps({"magic": MAGIC.hex(), "type": "version", "proto": 5, "binary": 1,
                               "genesis": n.chain.genesis.hash.hex(), "height": 0,
                               "nonce": random.randrange(1 << 40)}) + "\n").encode())
        f = s.makefile("rb")
        version = json.loads(f.readline())
        self.assertEqual(version.get("binary"), 1)
        wait(lambda: ready_peers(n), 5)
        return s, f

    def test_hostile_frames_ban_without_crashing(self):
        n = self.node()
        for payload in (b"XXXX" + b"\x00" * 16,                                     # bad magic
                        MAGIC + b"block".ljust(12, b"\x00") + struct.pack("<I", 10 ** 9),   # huge
                        wire.encode(MAGIC, {"type": "block", "data": "00" * 40})):          # junk block
            s, f = self.raw_binary_peer(n)
            s.sendall(payload)
            wait(lambda: n.is_banned("127.0.0.1"), 10)
            n.banned.clear()
            s.close()
            wait(lambda: not n.peers, 10)
        rng = random.Random(5)
        for _ in range(30):                         # random frames: the node survives them all
            s, f = self.raw_binary_peer(n)
            cmd = rng.choice([b"inv", b"headers", b"addr", b"tx", b"ping", b"getdata"])
            body = rng.randbytes(rng.randrange(0, 200))
            s.sendall(MAGIC + cmd.ljust(12, b"\x00") + struct.pack("<I", len(body)) + body)
            time.sleep(0.02)
            s.close()
            n.banned.clear()
        other = self.node()
        other.connect("127.0.0.1", n.port)
        wait(lambda: any(p.binary for p in ready_peers(other)), 10)


if __name__ == "__main__":
    unittest.main()
