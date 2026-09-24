import json
import os
import random
import socket
import struct
import sys
import tempfile
import time
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos import crypto
from kairos.auxpow import AuxPow, build_commitment, expected_index, MM_MAGIC
from kairos.block import Block, mine
from kairos.chain import Chain, ValidationError
from kairos.crypto import sha256d
from kairos.node import Node
from kairos.params import REGTEST, COIN, bits_to_target
from kairos.tx import Transaction
from kairos.wallet import Wallet

from test_kairos import Clock, new_chain, mine_block, wait


# ------------------------------------------------------------ helpers
def varint(n):
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)


def btc_coinbase(script: bytes) -> bytes:
    return (struct.pack("<I", 1) + b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff"
            + varint(len(script)) + script + b"\xff\xff\xff\xff"
            + b"\x01" + struct.pack("<Q", 312_500_000) + b"\x01\x51" + struct.pack("<I", 0))


def make_auxpow(kairos_hash: bytes, target: int, script_extra=b"", chain_tree=None) -> AuxPow:
    """Simulate a Bitcoin pool merge-mining Kairos."""
    if chain_tree is None:
        commit, chain_branch, chain_index = build_commitment(kairos_hash), [], 0
    else:
        commit, chain_branch, chain_index = chain_tree
    cb = btc_coinbase(b"\x03\x01\x02\x03" + commit + script_extra)
    t1, t2 = b"\x11" * 32, b"\x22" * 32
    right = sha256d(t2 + t2)                       # Bitcoin duplicates the odd last node
    root = sha256d(sha256d(sha256d(cb) + t1) + right)
    hdr = struct.pack("<I", 0x20000000) + b"\x33" * 32 + root + struct.pack("<II", 1_800_000_000, 0x17034219)
    for n in range(1 << 20):
        h = hdr + struct.pack("<I", n)
        if int.from_bytes(sha256d(h), "little") <= target:
            return AuxPow(cb, [t1, right], chain_branch, chain_index, h)
    raise RuntimeError("could not grind parent")


def aux_block(chain, clock, addr):
    clock.t += 120
    blk = chain.create_block(addr, auxpow=True)
    blk.auxpow = make_auxpow(blk.hash, bits_to_target(blk.header.bits))
    return blk


# ------------------------------------------------------------ tests
class TestBackendAgreement(unittest.TestCase):
    """Two nodes with different crypto backends must never disagree."""

    def test_differential(self):
        if not crypto.HARDENED:
            self.skipTest("coincurve not installed")
        rng = random.Random(7)
        cases = []
        for i in range(40):
            sk = rng.randrange(1, crypto.N).to_bytes(32, "big")
            msg = rng.randbytes(32)
            pk = crypto._py_pubkey(sk)
            self.assertEqual(pk, crypto.pubkey_from_seckey(sk))
            sig = crypto._py_sign(msg, sk, rng.randbytes(32))
            cases.append((msg, pk, sig))
            bad = bytearray(sig)
            bad[rng.randrange(64)] ^= 1 << rng.randrange(8)
            cases.append((msg, pk, bytes(bad)))
            cases.append((rng.randbytes(32), pk, sig))
            # edge cases: r >= p, s >= n, x not on curve, x >= p
            cases.append((msg, pk, (crypto.P + 1).to_bytes(32, "big") + sig[32:]))
            cases.append((msg, pk, sig[:32] + crypto.N.to_bytes(32, "big")))
            cases.append((msg, rng.randbytes(32), sig))
            cases.append((msg, b"\xff" * 32, sig))
        for msg, pk, sig in cases:
            self.assertEqual(crypto._py_verify(msg, pk, sig), crypto.schnorr_verify(msg, pk, sig),
                             f"backend disagreement on {sig.hex()}")


class TestMergeMining(unittest.TestCase):
    def setUp(self):
        self.chain, self.clock = new_chain()
        self.w = Wallet(self.chain.params, seed=b"m" * 32)

    def test_merge_mined_block_accepted(self):
        blk = aux_block(self.chain, self.clock, self.w.mining_address)
        blk2 = Block.deserialize(blk.serialize())         # survives the wire
        self.assertEqual(self.chain.submit_block(blk2), "accepted")
        self.assertEqual(self.chain.height, 1)

    def test_multi_chain_tree_slot(self):
        clock = self.clock
        clock.t += 120
        blk = self.chain.create_block(self.w.mining_address, auxpow=True)
        nonce, height = 5, 2
        slot = expected_index(nonce, self.chain.params.mm_chain_id, height)
        leaves = [os.urandom(32) for _ in range(4)]
        leaves[slot] = blk.hash
        l01, l23 = sha256d(leaves[0] + leaves[1]), sha256d(leaves[2] + leaves[3])
        root = sha256d(l01 + l23)
        branch = [leaves[slot ^ 1], l23 if slot < 2 else l01]
        commit = MM_MAGIC + root[::-1] + struct.pack("<II", 4, nonce)
        blk.auxpow = make_auxpow(blk.hash, bits_to_target(blk.header.bits),
                                 chain_tree=(commit, branch, slot))
        self.assertEqual(self.chain.submit_block(blk), "accepted")
        # same proof claiming the wrong slot is rejected
        bad = self.chain.create_block(self.w.mining_address, auxpow=True)
        bad.auxpow = make_auxpow(bad.hash, bits_to_target(bad.header.bits),
                                 chain_tree=(commit, branch, (slot + 1) % 4))
        self.assertIn("invalid", self.chain.submit_block(bad))

    def test_bad_proofs_rejected_without_poisoning(self):
        blk = aux_block(self.chain, self.clock, self.w.mining_address)
        good = blk.auxpow
        attacks = [
            replace(good, coinbase_tx=btc_coinbase(b"\x01\x02")),                       # no commitment
            replace(good, parent_header=good.parent_header[:36] + b"\x00" * 32 + good.parent_header[68:]),
            replace(good, coinbase_index=1),
            make_auxpow(blk.hash, bits_to_target(blk.header.bits), script_extra=build_commitment(blk.hash)),
        ]
        for a in attacks:
            blk.auxpow = a
            self.assertIn("invalid", self.chain.submit_block(blk))
        # A relayer who corrupted the proof must not get the real block blacklisted:
        blk.auxpow = good
        self.assertEqual(self.chain.submit_block(blk), "accepted")

    def test_flag_and_proof_must_agree(self):
        self.clock.t += 120
        blk = self.chain.create_block(self.w.mining_address, auxpow=True)
        mine(blk.header)                                   # native work but auxpow flag set
        self.assertIn("invalid", self.chain.submit_block(blk))


class TestWalletSecurity(unittest.TestCase):
    def test_encryption_roundtrip_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            w = Wallet.load_or_create(REGTEST, path, "correct horse battery")
            with open(path) as f:
                blob = f.read()
            self.assertNotIn(w.seed.hex(), blob)
            self.assertEqual(Wallet.load(REGTEST, path, "correct horse battery").seed, w.seed)
            with self.assertRaises(PermissionError):
                Wallet.load(REGTEST, path, "wrong passphrase!!")
            d2 = json.loads(blob)
            d2["ct"] = ("0" if d2["ct"][0] != "0" else "1") + d2["ct"][1:]
            with open(path, "w") as f:
                json.dump(d2, f)
            with self.assertRaises(PermissionError):
                Wallet.load(REGTEST, path, "correct horse battery")

    def test_backup_restore_and_typo_detection(self):
        with tempfile.TemporaryDirectory() as d:
            w = Wallet(REGTEST, n_keys=3)
            code = w.backup_code()
            r = Wallet.restore(REGTEST, code, os.path.join(d, "r.json"), n_keys=3)
            self.assertEqual([k.address for k in r.keys], [k.address for k in w.keys])
            typo = code[:-3] + ("q" if code[-3] != "q" else "p") + code[-2:]
            with self.assertRaises(ValueError):
                Wallet.restore(REGTEST, typo, os.path.join(d, "t.json"))

    def test_mainnet_refuses_unhardened_signing(self):
        from kairos.params import MAINNET
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"h" * 32)
        for _ in range(3):
            mine_block(chain, clock, w.mining_address)
        w.params = replace(chain.params, name="main")
        saved = crypto.HARDENED
        try:
            crypto.HARDENED = False
            with self.assertRaisesRegex(RuntimeError, "libsecp256k1"):
                w.create_tx(chain, w.mining_address, COIN)
        finally:
            crypto.HARDENED = saved


class TestStorage(unittest.TestCase):
    def test_crash_recovery_truncates_torn_tail(self):
        with tempfile.TemporaryDirectory() as d:
            clock = Clock(REGTEST.genesis_time + 1)
            c1 = Chain(REGTEST, datadir=d, now=clock)
            w = Wallet(REGTEST, seed=b"s" * 32)
            for _ in range(5):
                mine_block(c1, clock, w.mining_address)
            c1.close()
            path = os.path.join(d, "blocks-v3.dat")
            good = os.path.getsize(path)
            with open(path, "ab") as f:
                f.write(b"KRSB\x00\x10\x00\x00junk")        # power cut mid-write
            c2 = Chain(REGTEST, datadir=d, now=clock)
            self.assertEqual(c2.height, 5)
            self.assertEqual(os.path.getsize(path), good)
            mine_block(c2, clock, w.mining_address)            # keeps working after recovery
            c2.close()
            c3 = Chain(REGTEST, datadir=d, now=clock)
            self.assertEqual(c3.height, 6)
            c3.close()


class TestConsensusLimits(unittest.TestCase):
    def test_checkpoint(self):
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"c" * 32)
        b1 = mine_block(chain, clock, w.mining_address)
        cp_chain, cp_clock = new_chain(checkpoints=((1, "00" * 32),))
        self.assertEqual(cp_chain.submit_block(b1), "invalid: checkpoint mismatch")

    def test_mempool_cap_evicts_cheapest(self):
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"e" * 32)
        for _ in range(6):
            mine_block(chain, clock, w.mining_address)
        cheap = w.create_tx(chain, w.mining_address, COIN, tip_per_byte=0)
        chain.accept_tx(cheap)
        chain.max_mempool_bytes = cheap.size + 10
        rich = w.create_tx(chain, w.mining_address, COIN, tip_per_byte=50)
        self.assertTrue(chain.accept_tx(rich))
        self.assertNotIn(cheap.txid, chain.mempool)
        poor = w.create_tx(chain, w.mining_address, COIN, tip_per_byte=0)
        with self.assertRaisesRegex(ValidationError, "mempool full"):
            chain.accept_tx(poor)

    def test_coinbase_witness_limit(self):
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"l" * 32)
        clock.t += 120
        blk = chain.create_block(w.mining_address)
        blk.txs[0].inputs[0].witness += b"x" * 200
        blk.txs[0].invalidate()
        blk.header.tx_root = blk.compute_tx_root()
        mine(blk.header)
        self.assertEqual(chain.submit_block(blk), "invalid: bad coinbase witness size")


class TestFuzz(unittest.TestCase):
    def test_mutated_blocks_and_txs_never_crash(self):
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"f" * 32)
        for _ in range(3):
            mine_block(chain, clock, w.mining_address)
        tx = w.create_tx(chain, w.mining_address, COIN)
        clock.t += 120
        chain.accept_tx(tx)
        blk = chain.create_block(w.mining_address)
        mine(blk.header)
        raw_b, raw_t = blk.serialize(), tx.serialize()
        rng = random.Random(1)
        tip = chain.tip
        for i in range(600):
            raw = bytearray(raw_b if i % 2 else raw_t)
            for _ in range(rng.randrange(1, 4)):
                op = rng.randrange(3)
                pos = rng.randrange(len(raw))
                if op == 0:
                    raw[pos] ^= 1 << rng.randrange(8)
                elif op == 1:
                    del raw[pos:pos + rng.randrange(1, 40)]
                else:
                    raw[pos:pos] = rng.randbytes(rng.randrange(1, 20))
            try:
                if i % 2:
                    b = Block.deserialize(bytes(raw))
                    if chain.submit_block(b) == "accepted":
                        # Regtest PoW is trivial (1 in 16), so a mutated *header* can be a
                        # genuinely valid block. Transaction content must never change.
                        self.assertEqual([t.serialize() for t in b.txs], [t.serialize() for t in blk.txs])
                else:
                    chain.accept_tx(Transaction.deserialize(bytes(raw)))
            except (ValueError, ValidationError):
                pass
        from kairos.chain import coin_bytes
        from kairos.crypto import MuHash
        mh = MuHash()
        for op, c in chain.utxos.items():
            mh.insert(coin_bytes(op, c))
        self.assertEqual(mh.digest(), chain.tip.header.utxo_root)     # state is exactly committed
        total = sum(c.value for c in chain.utxos.values())
        self.assertEqual(total, chain.supply()["circulating"])          # no coins created from nothing


class TestNetworkHardening(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(REGTEST)
        self.node = Node(self.chain, wallet=Wallet(REGTEST, seed=b"n" * 32))

    def tearDown(self):
        self.node.stop()

    def raw_peer(self):
        s = socket.create_connection(("127.0.0.1", self.node.port), timeout=5)
        return s

    def send(self, s, obj):
        s.sendall((json.dumps(obj) + "\n").encode())

    def test_garbage_gets_banned(self):
        s = self.raw_peer()
        s.sendall(b"this is not json\n")
        wait(lambda: self.node.is_banned("127.0.0.1"), 5)
        s.close()
        with self.assertRaises(OSError):
            s2 = self.raw_peer()
            s2.settimeout(2)
            if not s2.recv(1):
                raise OSError("closed")

    def test_message_before_handshake_banned(self):
        s = self.raw_peer()
        self.send(s, {"magic": REGTEST.magic.hex(), "type": "getblocks", "locator": []})
        wait(lambda: self.node.is_banned("127.0.0.1"), 5)

    def test_wrong_network_disconnected_not_banned(self):
        s = self.raw_peer()
        self.send(s, {"magic": REGTEST.magic.hex(), "type": "version", "proto": 4,
                      "genesis": "00" * 32, "height": 0, "nonce": 1})
        wait(lambda: not self.node.peers, 5)
        self.assertFalse(self.node.is_banned("127.0.0.1"))

    def test_invalid_block_bans_sender(self):
        other, clock = new_chain()
        w = Wallet(REGTEST, seed=b"x" * 32)
        clock.t = int(time.time())
        blk = other.create_block(w.mining_address)
        blk.txs[0].outputs[0].value += 1                    # inflation attempt
        blk.txs[0].invalidate()
        blk.header.tx_root = blk.compute_tx_root()
        mine(blk.header)
        s = self.raw_peer()
        self.send(s, {"magic": REGTEST.magic.hex(), "type": "version", "proto": 4,
                      "genesis": self.chain.genesis.hash.hex(), "height": 0, "nonce": 99})
        self.send(s, {"magic": REGTEST.magic.hex(), "type": "block", "data": blk.serialize().hex()})
        wait(lambda: self.node.is_banned("127.0.0.1"), 5)
        self.assertEqual(self.chain.height, 0)


class TestSlowNetwork(unittest.TestCase):
    """Regression for two relay races found on a slow VPS (0.2.0 -> 0.2.1):
    blocks mined during a handshake, and orphans connected but never announced."""

    def test_sync_with_slow_handshakes(self):
        import kairos.node as N
        orig = N.Node._handle

        def slow(node, peer, msg):
            if msg.get("type") == "version":
                time.sleep(0.4)
            return orig(node, peer, msg)
        N.Node._handle = slow
        try:
            for _ in range(5):
                chains = [Chain(REGTEST) for _ in range(3)]
                ws = [Wallet(REGTEST, seed=bytes([70 + i]) * 32) for i in range(3)]
                nodes = [Node(c, wallet=w) for c, w in zip(chains, ws)]
                try:
                    nodes[0].connect("127.0.0.1", nodes[1].port)
                    nodes[1].connect("127.0.0.1", nodes[2].port)
                    for _ in range(4):
                        nodes[0].mine_one()
                    wait(lambda: all(c.height == 4 for c in chains), 10)
                finally:
                    for n in nodes:
                        n.stop()
        finally:
            N.Node._handle = orig


class TestHandshakeOrdering(unittest.TestCase):
    """Regression (0.2.1 -> 0.2.2): a node's version must be the first message it sends,
    even when the peer's version arrives instantly. Violations got nodes banned."""

    def test_version_is_always_first(self):
        chain = Chain(REGTEST)
        node = Node(chain, wallet=Wallet(REGTEST, seed=b"o" * 32))
        try:
            for _ in range(3):
                node.mine_one()                  # a tip exists, so it will be announced
            for i in range(200):
                s = socket.create_connection(("127.0.0.1", node.port), timeout=5)
                s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "version", "proto": 4,
                                       "genesis": chain.genesis.hash.hex(), "height": 0,
                                       "nonce": 5000 + i}) + "\n").encode())
                first = json.loads(s.makefile().readline())
                s.close()
                self.assertEqual(first["type"], "version", f"connection {i}")
        finally:
            node.stop()


class TestRPC(unittest.TestCase):
    def test_rpc_and_merge_mining_via_pool_interface(self):
        from kairos.rpc import RPCServer, call
        with tempfile.TemporaryDirectory() as d:
            chain = Chain(REGTEST)
            w = Wallet(REGTEST, seed=b"r" * 32)
            node = Node(chain, wallet=w)
            rpc = RPCServer(node, d)
            try:
                c = lambda m, *p: call(d, rpc.port, m, list(p))
                self.assertEqual(c("getblockcount")["result"], 0)
                self.assertEqual(c("nosuchmethod")["error"]["code"], -32601)
                for _ in range(3):
                    tpl = c("getauxblock")["result"]
                    kh = bytes.fromhex(tpl["kairoshash"])
                    self.assertEqual(bytes.fromhex(tpl["hash"])[::-1], kh)
                    target = int.from_bytes(bytes.fromhex(tpl["_target"]), "little")
                    ap = make_auxpow(kh, target)
                    self.assertTrue(c("getauxblock", tpl["hash"], ap.serialize().hex())["result"])
                self.assertEqual(c("getblockcount")["result"], 3)
                info = c("getblockchaininfo")["result"]
                self.assertEqual(info["utxo_root"], chain.tip.header.utxo_root.hex())
                txid = c("sendtoaddress", w.encode(w.new_address() and w.keys[-1].address), 1.5)["result"]
                self.assertIn(txid, c("getrawmempool")["result"])
                self.assertFalse(c("validateaddress", "krt1invalid")["result"]["isvalid"])
                # wrong credentials are refused
                import urllib.request, urllib.error
                req = urllib.request.Request(f"http://127.0.0.1:{rpc.port}/", data=b"{}",
                                             headers={"Authorization": "Basic eDp5"})
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req, timeout=5)
                self.assertEqual(cm.exception.code, 401)
            finally:
                rpc.stop()
                node.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPeerParsing(unittest.TestCase):
    """Every failure while handling a message is the peer's fault and ends the
    connection with a ban; nothing may escape the reader thread (0.3.0 leaked
    RecursionError and OverflowError, leaving zombie connections)."""

    def setUp(self):
        self.chain = Chain(REGTEST)
        self.node = Node(self.chain, wallet=Wallet(REGTEST, seed=b"n" * 32))
        self.m = REGTEST.magic.hex()

    def tearDown(self):
        self.node.stop()

    def raw(self, payload: bytes):
        s = socket.create_connection(("127.0.0.1", self.node.port), timeout=5)
        s.sendall(payload)
        wait(lambda: self.node.is_banned("127.0.0.1"), 5)
        wait(lambda: not any(p.alive for p in self.node.peers), 5)
        s.close()
        self.node.banned.clear()

    def test_deep_nesting_is_banned_not_crashed(self):
        self.raw(b"[" * 100_000 + b"]" * 100_000 + b"\n")

    def test_infinite_height_is_banned(self):
        v = {"type": "version", "magic": self.m, "genesis": self.chain.genesis.hash.hex(),
             "proto": 4, "nonce": 1, "agent": "x", "port": 1}
        line = json.dumps(v).replace('"proto": 4', '"proto": 4, "height": 1e999')
        self.raw((line + "\n").encode())

    def test_float_and_bool_numbers_rejected(self):
        for bad in ('"proto": 4.0', '"proto": true', '"proto": -1', '"proto": 4, "height": -5'):
            line = json.dumps({"type": "version", "magic": self.m, "genesis": self.chain.genesis.hash.hex(),
                               "nonce": 1, "port": 1}).replace('"nonce": 1', bad + ', "nonce": 1')
            self.raw((line + "\n").encode())


class TestOrphanPool(unittest.TestCase):
    def test_bounded_by_bytes_work_and_age(self):
        import kairos.chain as C
        # Regtest's schedule is already the easiest target there is, so use a
        # 256x harder one (still ~4k hashes per block) to leave room below it.
        chain, clock = new_chain(asert_anchor_bits=0x1F0FFFFF)
        w = Wallet(REGTEST, seed=b"o" * 32)
        # Orphans from a real fork are kept and connected once the parent arrives.
        other, oclock = new_chain(asert_anchor_bits=0x1F0FFFFF)
        b1 = mine_block(other, oclock, w.mining_address)
        b2 = mine_block(other, oclock, w.mining_address)
        self.assertEqual(chain.submit_block(b2), "orphan")
        self.assertEqual(chain.orphan_bytes, b2.size)
        self.assertEqual(chain.submit_block(b1), "accepted")
        self.assertEqual(chain.height, 2)
        self.assertEqual(chain.orphan_bytes, 0)
        # Junk with a trivial self-chosen difficulty is not even stored.
        junk = other.create_block(w.mining_address)
        junk.header.prev_hash = b"\x77" * 32
        junk.header.bits = 0x200FFFFF                       # 256x easier than the schedule
        mine(junk.header)
        self.assertEqual(chain.submit_block(junk), "orphan")
        self.assertEqual(chain.orphan_bytes, 0)
        # Legitimate-looking orphans are capped in total bytes: oldest evicted first.
        saved = C.MAX_ORPHAN_BYTES
        C.MAX_ORPHAN_BYTES = 3 * b2.size
        try:
            made = []
            for i in range(5):
                b = other.create_block(w.mining_address)
                b.header.prev_hash = bytes([i + 1]) * 32
                mine(b.header)
                self.assertEqual(chain.submit_block(b), "orphan")
                made.append(b)
            self.assertLessEqual(chain.orphan_bytes, C.MAX_ORPHAN_BYTES)
            self.assertNotIn(made[0].hash, chain.orphan_meta)
            self.assertIn(made[-1].hash, chain.orphan_meta)
        finally:
            C.MAX_ORPHAN_BYTES = saved
        # And they expire.
        for h in list(chain.orphan_meta):
            prev, size, added = chain.orphan_meta[h]
            chain.orphan_meta[h] = (prev, size, added - C.ORPHAN_TTL - 1)
        b = other.create_block(w.mining_address)
        b.header.prev_hash = b"\x99" * 32
        mine(b.header)
        chain.submit_block(b)
        self.assertEqual(set(chain.orphan_meta), {b.hash})


class TestWalletHygiene(unittest.TestCase):
    def test_lamport_reveal_is_persisted_before_signing(self):
        """A crash between signing and saving must not allow a second Lamport signature."""
        import kairos.wallet as W
        with tempfile.TemporaryDirectory() as d:
            chain, clock = new_chain(pq_emergency_height=1)
            w = Wallet.load_or_create(REGTEST, os.path.join(d, "w.json"))
            addr = w.mining_address
            for _ in range(3):
                mine_block(chain, clock, addr)
            orig = W.lamport_sign

            def crash(*a, **k):
                raise KeyboardInterrupt("power cut while signing")
            W.lamport_sign = crash
            try:
                with self.assertRaises(KeyboardInterrupt):
                    w.create_tx(chain, addr, COIN, post_quantum=True)
            finally:
                W.lamport_sign = orig
            reloaded = Wallet.load(REGTEST, os.path.join(d, "w.json"))
            self.assertIn(0, reloaded.pq_revealed)              # on disk before any signature existed
            with self.assertRaisesRegex(RuntimeError, "already used"):
                reloaded.create_tx(chain, addr, COIN, post_quantum=True)

    def test_mining_address_rotates_and_restore_finds_everything(self):
        with tempfile.TemporaryDirectory() as d:
            chain, clock = new_chain()
            w = Wallet.load_or_create(REGTEST, os.path.join(d, "w.json"))
            w.attach(chain)
            first = w.mining_address
            addrs = set()
            for _ in range(30):                     # more blocks than the gap limit
                addrs.add(w.mining_address)
                mine_block(chain, clock, w.mining_address)
            self.assertEqual(len(addrs), 30)         # a fresh address for every block
            self.assertNotEqual(w.mining_address, first)
            self.assertEqual(len(w.balance(chain)["immature"] and [1] or []), 1)
            # Restore from the backup code alone, then rescan: all 30 coinbases are found.
            r = Wallet.restore(REGTEST, w.backup_code(), os.path.join(d, "r.json"))
            self.assertLess(len(r.keys), 30)
            r.attach(chain)
            self.assertEqual(r.balance(chain), w.balance(chain))
            self.assertEqual(len(r.coins(chain, True)), 30)
            # reload keeps the used-set, so no address is handed out twice
            r2 = Wallet.load(REGTEST, os.path.join(d, "r.json"))
            self.assertEqual(r2.used, r.used)
            self.assertNotIn(r2.mining_address, addrs)

    def test_encrypted_saves_do_not_rerun_kdf(self):
        with tempfile.TemporaryDirectory() as d:
            w = Wallet.load_or_create(REGTEST, os.path.join(d, "w.json"), "correct horse battery")
            calls = []
            orig = Wallet._kdf
            Wallet._kdf = staticmethod(lambda *a: calls.append(1) or orig(*a))
            try:
                for _ in range(5):
                    w.new_address()
            finally:
                Wallet._kdf = staticmethod(orig)
            self.assertEqual(calls, [])
            self.assertEqual(len(Wallet.load(REGTEST, os.path.join(d, "w.json"), "correct horse battery").keys), 6)
