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
from kairos.tx import Transaction, WIT_LAMPORT, WIT_SCHNORR
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
        for kind in ("legacy", "hd"):          # format 2 keeps ct at the top, format 3 under "hd"
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "w.json")
                if kind == "legacy":
                    w = Wallet(REGTEST, path=path)
                    w.passphrase = "correct horse battery"
                    w.save()
                else:
                    w = Wallet.load_or_create(REGTEST, path, "correct horse battery")
                with open(path) as f:
                    blob = f.read()
                self.assertNotIn(w.seed.hex(), blob)
                self.assertEqual(Wallet.load(REGTEST, path, "correct horse battery").seed, w.seed)
                with self.assertRaises(PermissionError):
                    Wallet.load(REGTEST, path, "wrong passphrase!!")
                d2 = json.loads(blob)
                box = d2 if kind == "legacy" else d2["hd"]
                box["ct"] = ("0" if box["ct"][0] != "0" else "1") + box["ct"][1:]
                with open(path, "w") as f:
                    json.dump(d2, f)
                with self.assertRaises(PermissionError, msg=kind):
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


class TestHeadersFirst(unittest.TestCase):
    """Sync validates a chain of headers before fetching any body, fetches bodies
    in order from whoever has them, and never downloads a chain with less work."""

    def raw_peer(self, node, height=0):
        s = socket.create_connection(("127.0.0.1", node.port), timeout=5)
        s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "version", "proto": 4,
                               "genesis": node.chain.genesis.hash.hex(), "height": height,
                               "nonce": random.randrange(1 << 40)}) + "\n").encode())
        return s

    @staticmethod
    def messages(s, seconds):
        s.settimeout(seconds)
        buf, out = b"", []
        try:
            while True:
                d = s.recv(1 << 20)
                if not d:
                    break
                buf += d
        except socket.timeout:
            pass
        for line in buf.splitlines():
            out.append(json.loads(line))
        return out

    def test_sync_in_several_header_batches(self):
        import kairos.node as N
        saved = N.MAX_HEADERS
        N.MAX_HEADERS = 5                       # 23 blocks -> 5 batches
        try:
            src = Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=b"s" * 32))
            dst = Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=b"d" * 32))
            try:
                for _ in range(23):
                    src.mine_one()
                dst.connect("127.0.0.1", src.port)
                wait(lambda: dst.chain.height == 23, 20)
                self.assertEqual(dst.chain.tip.hash, src.chain.tip.hash)
                self.assertEqual(dst.chain.best_header, dst.chain.tip)
                self.assertEqual(dst.inflight, {})
            finally:
                src.stop()
                dst.stop()
        finally:
            N.MAX_HEADERS = saved

    def test_less_work_chain_is_never_downloaded(self):
        node = Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=b"a" * 32))
        try:
            for _ in range(5):
                node.mine_one()
            fork, fclock = new_chain()
            fclock.t = int(time.time())
            w = Wallet(REGTEST, seed=b"f" * 32)
            blocks = [mine_block(fork, fclock, w.mining_address) for _ in range(8)]
            hdr = lambda b: Block(b.header, [], None).serialize().hex()
            s = self.raw_peer(node, height=8)
            self.messages(s, 0.5)                                      # drain version/getheaders
            # 3 headers of a fork: less work than our 5 blocks -> indexed, never fetched
            s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "headers",
                                   "data": [hdr(b) for b in blocks[:3]]}) + "\n").encode())
            got = self.messages(s, 1.0)
            self.assertFalse([m for m in got if m["type"] == "getdata"], got)
            self.assertEqual(node.chain.height, 5)
            self.assertIn(blocks[2].hash, node.chain.index)
            # 5 more headers make it the most-work chain -> bodies requested, in order
            s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "headers",
                                   "data": [hdr(b) for b in blocks[3:]]}) + "\n").encode())
            got = self.messages(s, 1.0)
            asked = [h for m in got if m["type"] == "getdata" for h in m["blocks"]]
            self.assertEqual(asked, [b.hash.hex() for b in blocks])
            for b in blocks:
                s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "block",
                                       "data": b.serialize().hex()}) + "\n").encode())
            wait(lambda: node.chain.height == 8, 10)
            self.assertEqual(node.chain.tip.hash, blocks[-1].hash)
            self.assertFalse(node.is_banned("127.0.0.1"))
            s.close()
        finally:
            node.stop()

    def test_invalid_header_chain_bans_without_download(self):
        node = Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=b"a" * 32))
        try:
            fork, fclock = new_chain()
            fclock.t = int(time.time())
            b = mine_block(fork, fclock, Wallet(REGTEST, seed=b"f" * 32).mining_address)
            b.header.bits = 0x207FFFFF                     # not the schedule; still passes its own PoW
            mine(b.header)
            s = self.raw_peer(node, height=1)
            s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "headers",
                                   "data": [Block(b.header, [], None).serialize().hex()]}) + "\n").encode())
            wait(lambda: node.is_banned("127.0.0.1"), 5)
            self.assertNotIn(b.hash, node.chain.index)
            s.close()
        finally:
            node.stop()

    def test_stalled_download_moves_to_another_peer(self):
        import kairos.node as N
        saved = N.BLOCK_STALL
        N.BLOCK_STALL = 1
        try:
            good = Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=b"g" * 32))
            node = Node(Chain(REGTEST), wallet=Wallet(REGTEST, seed=b"n" * 32))
            try:
                for _ in range(6):
                    good.mine_one()
                blocks = good.chain.blocks_after([good.chain.genesis.hash])
                # a silent peer that advertises the chain's headers but never serves bodies
                s = self.raw_peer(node, height=6)
                s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "headers",
                                       "data": [Block(b.header, [], None).serialize().hex()
                                                for b in blocks]}) + "\n").encode())
                wait(lambda: node.inflight, 5)                 # bodies requested from the silent peer
                node.connect("127.0.0.1", good.port)
                wait(lambda: node.chain.height == 6, 25)       # ...then re-requested from the good one
                self.assertEqual(node.chain.tip.hash, good.chain.tip.hash)
                s.close()
            finally:
                good.stop()
                node.stop()
        finally:
            N.BLOCK_STALL = saved


class TestFastRestart(unittest.TestCase):
    def test_snapshot_skips_revalidation_and_survives_corruption(self):
        import kairos.chain as C
        with tempfile.TemporaryDirectory() as d:
            clock = Clock(REGTEST.genesis_time + 1)
            c1 = Chain(REGTEST, datadir=d, now=clock)
            w = Wallet(REGTEST, seed=b"s" * 32)
            addr = w.mining_address
            for _ in range(8):
                mine_block(c1, clock, addr)
            tx = w.create_tx(c1, Wallet(REGTEST, seed=b"t" * 32).mining_address, COIN)
            c1.accept_tx(tx)
            mine_block(c1, clock, addr)
            c1.close()                                          # writes chainstate.dat
            self.assertTrue(os.path.exists(os.path.join(d, "chainstate.dat")))

            connects = []
            orig = C.Chain._connect
            C.Chain._connect = lambda self, idx, blk: connects.append(idx.height) or orig(self, idx, blk)
            try:
                c2 = Chain(REGTEST, datadir=d, now=clock)
            finally:
                C.Chain._connect = orig
            self.assertEqual(connects, [])                      # nothing re-validated
            self.assertEqual(c2.tip.hash, c1.tip.hash)
            self.assertEqual(c2.utxos, c1.utxos)
            self.assertEqual(c2.tip.muhash, c1.tip.muhash)
            self.assertEqual(c2.tip.generated, c1.tip.generated)
            self.assertEqual(c2.tip.next_base_fee, c1.tip.next_base_fee)
            mine_block(c2, clock, addr)                          # and it keeps working
            self.assertEqual(c2.height, 10)
            c2.close()

            # A damaged snapshot is ignored and the chain is rebuilt from blocks.
            path = os.path.join(d, "chainstate.dat")
            with open(path, "r+b") as f:
                f.seek(100)
                f.write(b"\xff")
            c3 = Chain(REGTEST, datadir=d, now=clock)
            self.assertEqual(c3.height, 10)
            self.assertEqual(c3.utxos, c2.utxos)
            c3.close()

    def test_reorg_across_snapshot_boundary(self):
        """After a restart the node must still be able to undo snapshot-covered
        blocks (stored undo data) and recompute the UTXO commitment on the way."""
        with tempfile.TemporaryDirectory() as d:
            clock = Clock(REGTEST.genesis_time + 1)
            c1 = Chain(REGTEST, datadir=d, now=clock)
            w = Wallet(REGTEST, seed=b"s" * 32)
            for _ in range(6):
                mine_block(c1, clock, w.mining_address)
            common = c1.blocks_after([c1.genesis.hash])[:3]
            c1.close()
            c2 = Chain(REGTEST, datadir=d, now=clock)
            self.assertEqual(c2.height, 6)
            rival, rclock = new_chain()
            for b in common:
                rival.submit_block(b)
            rclock.t = clock.t
            for _ in range(5):                                   # 3 + 5 = 8 > 6
                b = mine_block(rival, rclock, Wallet(REGTEST, seed=b"r" * 32).mining_address, step=60)
                c2.submit_block(b)
            self.assertEqual(c2.tip.hash, rival.tip.hash)
            self.assertEqual(c2.utxos, rival.utxos)
            self.assertEqual(c2.tip.muhash, rival.tip.muhash)
            c2.close()
            c3 = Chain(REGTEST, datadir=d, now=clock)
            self.assertEqual(c3.tip.hash, rival.tip.hash)
            self.assertEqual(c3.utxos, rival.utxos)
            c3.close()


class TestFastSync(unittest.TestCase):
    """A new node adopts a UTXO snapshot only if it matches the utxo_root of a
    header whose proof-of-work it has verified, then downloads only newer blocks."""

    @staticmethod
    def write_snapshot(path, chain_id, block_hash, height, coins):
        from kairos.chain import UTXO_MAGIC, coin_bytes
        from kairos.crypto import sha256
        body = UTXO_MAGIC + chain_id + block_hash + struct.pack("<IQ", height, len(coins))
        body += b"".join(coin_bytes(op, c) for op, c in coins.items())
        with open(path, "wb") as f:
            f.write(body + sha256(body))

    def build_source(self, d, n=12):
        clock = Clock(REGTEST.genesis_time + 1)
        a = Chain(REGTEST, datadir=d, now=clock)
        w = Wallet(REGTEST, seed=b"a" * 32)
        w.attach(a)
        for i in range(n):
            if i >= 6:
                a.accept_tx(w.create_tx(a, Wallet(REGTEST, seed=b"z" * 32).mining_address, COIN, tip_per_byte=3))
            mine_block(a, clock, w.mining_address)
        return a, clock, w

    def test_offline_import_verifies_commitment(self):
        with tempfile.TemporaryDirectory() as d:
            a, clock, w = self.build_source(os.path.join(d, "a"))
            snap = os.path.join(d, "utxo.snap")
            info = a.export_utxo_snapshot(snap)
            self.assertEqual(info["height"], 12)
            self.assertEqual(info["utxo_root"], a.tip.header.utxo_root.hex())

            b = Chain(REGTEST, datadir=os.path.join(d, "b"), now=clock)
            with self.assertRaisesRegex(ValueError, "unknown"):
                b.import_utxo_snapshot(snap)                 # headers first
            blocks = a.blocks_after([a.genesis.hash])
            for blk in blocks:
                self.assertEqual(b.submit_header(blk.header, blk.auxpow), "accepted")
            self.assertEqual((b.height, b.best_header.height), (0, 12))

            # wrong coins for that header: refused
            bad = os.path.join(d, "bad.snap")
            coins = dict(a.utxos)
            op = next(iter(coins))
            coins[op] = replace(coins[op], value=coins[op].value + 1)
            self.write_snapshot(bad, REGTEST.chain_id, a.tip.hash, 12, coins)
            with self.assertRaisesRegex(ValueError, "commitment"):
                b.import_utxo_snapshot(bad)
            # damaged file: refused
            with open(snap, "rb") as f:
                raw = bytearray(f.read())
            raw[60] ^= 1
            with open(bad, "wb") as f:
                f.write(raw)
            with self.assertRaisesRegex(ValueError, "checksum"):
                b.import_utxo_snapshot(bad)
            # other network: refused
            self.write_snapshot(bad, b"XXXX", a.tip.hash, 12, a.utxos)
            with self.assertRaisesRegex(ValueError, "another network"):
                b.import_utxo_snapshot(bad)
            self.assertEqual(b.height, 0)

            target = b.import_utxo_snapshot(snap)
            self.assertEqual(b.height, 12)
            self.assertEqual(b.tip.hash, a.tip.hash)
            self.assertEqual(b.utxos, a.utxos)
            self.assertEqual(b.tip.muhash, a.tip.muhash)
            self.assertEqual((b.tip.generated, b.tip.burned, b.tip.next_base_fee),
                             (a.tip.generated, a.tip.burned, a.tip.next_base_fee))
            self.assertEqual(b.supply(), a.supply())
            self.assertIsNone(b.blocks.get(blocks[3].hash))     # history was never downloaded
            self.assertEqual(b.assumed_height, 12)
            with self.assertRaisesRegex(ValueError, "already past"):
                b.import_utxo_snapshot(snap)

            # the chain continues normally from the snapshot
            for _ in range(3):
                blk = mine_block(a, clock, w.mining_address)
                self.assertEqual(b.submit_block(blk), "accepted")
            self.assertEqual(b.utxos, a.utxos)
            self.assertEqual(b.tip.header.utxo_root, a.tip.header.utxo_root)
            # a wallet attached afterwards finds its coins from the UTXO set alone
            w2 = Wallet(REGTEST, seed=b"a" * 32)
            w2.attach(b)
            self.assertEqual(w2.balance(b), w.balance(a))

            # nothing below the snapshot can be reorganised
            rival, rclock = new_chain()
            for blk in blocks[:11]:
                rival.submit_block(blk)
            rclock.t = clock.t
            fork = mine_block(rival, rclock, Wallet(REGTEST, seed=b"r" * 32).mining_address)
            self.assertEqual(b.submit_block(fork), "invalid: fork below the UTXO snapshot this node started from")

            # restart: assumed history comes back from headers.dat, state from chainstate.dat
            b.close()
            b2 = Chain(REGTEST, datadir=os.path.join(d, "b"), now=clock)
            self.assertEqual(b2.height, 15)
            self.assertEqual(b2.assumed_height, 12)
            self.assertEqual(b2.utxos, a.utxos)
            self.assertEqual(b2.tip.muhash, a.tip.muhash)
            blk = mine_block(a, clock, w.mining_address)
            self.assertEqual(b2.submit_block(blk), "accepted")
            b2.close()
            # without headers.dat the snapshot cannot be trusted: node restarts from genesis
            os.remove(os.path.join(d, "b", "headers.dat"))
            b3 = Chain(REGTEST, datadir=os.path.join(d, "b"), now=clock)
            self.assertEqual(b3.height, 0)
            b3.close()
            a.close()

    def test_fast_sync_over_the_network(self):
        from kairos.rpc import RPCServer, call
        with tempfile.TemporaryDirectory() as d:
            src = Node(Chain(REGTEST, datadir=os.path.join(d, "a")), wallet=Wallet(REGTEST, seed=b"s" * 32))
            src.wallet.attach(src.chain)
            dst_chain = Chain(REGTEST, datadir=os.path.join(d, "b"))
            dst = Node(dst_chain, wallet=Wallet(REGTEST, seed=b"d" * 32))
            rpc = RPCServer(dst, os.path.join(d, "b"))
            try:
                for _ in range(10):
                    src.mine_one()
                snap = os.path.join(d, "utxo.snap")
                src.chain.export_utxo_snapshot(snap)
                # a peer that only serves headers, so the new node knows the chain but has no blocks
                hdrs = [Block(b.header, [], None).serialize().hex()
                        for b in src.chain.blocks_after([src.chain.genesis.hash])]
                s = socket.create_connection(("127.0.0.1", dst.port), timeout=5)
                s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "version", "proto": 4,
                                       "genesis": dst_chain.genesis.hash.hex(), "height": 10,
                                       "nonce": 77}) + "\n").encode())
                s.sendall((json.dumps({"magic": REGTEST.magic.hex(), "type": "headers", "data": hdrs}) + "\n").encode())
                wait(lambda: dst_chain.best_header.height == 10, 10)
                self.assertEqual(dst_chain.height, 0)
                c = lambda m, *p: call(os.path.join(d, "b"), rpc.port, m, list(p))
                r = c("loadutxoset", snap)["result"]
                self.assertEqual(r["height"], 10)
                self.assertEqual(dst_chain.height, 10)
                s.close()
                info = c("getblockchaininfo")["result"]
                self.assertEqual((info["blocks"], info["assumed_height"]), (10, 10))
                # now talk to the real node: only newer blocks are downloaded
                dst.connect("127.0.0.1", src.port)
                for _ in range(4):
                    src.mine_one()
                wait(lambda: dst_chain.height == 14, 20)
                self.assertEqual(dst_chain.tip.hash, src.chain.tip.hash)
                self.assertEqual(dst_chain.utxos, src.chain.utxos)
                old = src.chain.active[5].hash
                self.assertIsNone(dst_chain.blocks.get(old))
                self.assertIsNotNone(dst_chain.blocks.get(src.chain.active[12].hash))
                self.assertEqual(dst.inflight, {})
            finally:
                rpc.stop()
                dst.stop()
                src.stop()
                dst_chain.close()
                src.chain.close()


class TestPostQuantumSpending(unittest.TestCase):
    """After the quantum switch, ordinary sends keep working: the wallet takes
    the Lamport path by itself, splits large payments under the transaction
    size cap, and never lets a one-time key sign twice."""

    def activated(self, n_blocks, seed=b"p" * 32):
        chain, clock = new_chain()
        w = Wallet(REGTEST, seed=seed)
        w.attach(chain)                              # a fresh address for every reward
        chain.signal.add("pq")
        for _ in range(n_blocks):
            mine_block(chain, clock, w.mining_address)
        self.assertTrue(chain.pq_active(chain.tip))
        return chain, clock, w

    def test_send_takes_the_lamport_path_automatically(self):
        chain, clock, w = self.activated(20)
        bob = Wallet(REGTEST, seed=b"b" * 32)
        with self.assertRaisesRegex(ValidationError, "signature"):
            chain.accept_tx(w.create_tx(chain, bob.mining_address, COIN, post_quantum=False))
        txs = w.create_txs(chain, bob.mining_address, COIN)          # no flag: wallet decides
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].inputs[0].witness[0], WIT_LAMPORT)
        self.assertTrue(chain.accept_tx(txs[0]))
        mine_block(chain, clock, w.mining_address)
        self.assertEqual(bob.balance(chain)["spendable"], COIN)
        # before activation the same call signs with Schnorr
        pre, pclock = new_chain()
        w2 = Wallet(REGTEST, seed=b"q" * 32)
        for _ in range(3):
            mine_block(pre, pclock, w2.mining_address)
        self.assertEqual(w2.create_txs(pre, bob.mining_address, COIN)[0].inputs[0].witness[0], WIT_SCHNORR)

    def test_large_payment_is_split_under_the_size_cap(self):
        chain, clock, w = self.activated(48)                            # 46 mature coins, one per address
        cap = w._pq_inputs_per_tx(0)
        self.assertLess(cap, len(w.coins(chain)))
        bob = Wallet(REGTEST, seed=b"b" * 32)
        amount = w.balance(chain)["spendable"] - 5 * COIN
        txs = w.create_txs(chain, bob.mining_address, amount)
        self.assertGreater(len(txs), 1)
        swept = set()
        for tx in txs:
            self.assertLessEqual(tx.size, Wallet.MAX_TX_BYTES)
            self.assertLessEqual(tx.size, REGTEST.max_block_size // 2)
            self.assertLessEqual(len(tx.inputs), cap)
            addrs = {chain.utxos[i.prev].address for i in tx.inputs}
            self.assertFalse(addrs & swept)                             # one-time keys: one tx each
            swept |= addrs
            self.assertTrue(chain.accept_tx(tx))
        paid = sum(o.value for tx in txs for o in tx.outputs if o.address == bob.mining_address)
        self.assertEqual(paid, amount)
        for _ in range(4):
            if not chain.mempool:
                break
            mine_block(chain, clock, w.mining_address)
        self.assertFalse(chain.mempool)
        self.assertEqual(bob.balance(chain)["spendable"], amount)
        self.assertTrue(all(self_idx in w.pq_revealed
                            for self_idx, k in enumerate(w.keys) if k.address in swept))

    def test_address_with_too_many_coins_is_refused(self):
        chain, clock = new_chain()
        w = Wallet(REGTEST, seed=b"r" * 32)                             # not attached: rewards pile up
        chain.signal.add("pq")
        addr = w.mining_address
        for _ in range(w._pq_inputs_per_tx(0) + 3):
            mine_block(chain, clock, addr)
        self.assertTrue(chain.pq_active(chain.tip))
        with self.assertRaisesRegex(ValueError, "cannot be swept safely"):
            w.create_txs(chain, Wallet(REGTEST, seed=b"b" * 32).mining_address, COIN)

    def test_console_and_rpc_send_after_activation(self):
        from kairos.rpc import RPCServer, call
        from kairos.__main__ import run_command
        with tempfile.TemporaryDirectory() as d:
            chain, clock, w = self.activated(20)
            bob = Wallet(REGTEST, seed=b"b" * 32)
            node = Node(chain, wallet=w)
            rpc = RPCServer(node, d)
            try:
                run_command(["send", w.encode(bob.mining_address), "1.5"], chain, w, node)
                self.assertEqual(len(chain.mempool), 1)
                self.assertEqual(next(iter(chain.mempool.values())).inputs[0].witness[0], WIT_LAMPORT)
                r = call(d, rpc.port, "sendtoaddress", [w.encode(bob.mining_address), 2.0])
                self.assertIsNone(r["error"])
                self.assertIn(r["result"], [t.hex() for t in chain.mempool])
                node.mine_one()
                self.assertEqual(bob.balance(chain)["spendable"], int(3.5 * COIN))
            finally:
                rpc.stop()
                node.stop()


class TestTipLogging(unittest.TestCase):
    """Each new tip is logged once, even when several peer threads deliver blocks
    at the same moment (the testnet log showed one height up to three times)."""

    def test_tip_reported_once_when_threads_interleave(self):
        import threading
        from kairos.node import Peer
        src, sclock = new_chain()
        w = Wallet(src.params, seed=b"t" * 32)
        blocks = [mine_block(src, sclock, w.mining_address) for _ in range(3)]
        chain, clock = new_chain()
        clock.t = sclock.t
        for b in blocks:                              # headers first, bodies later
            self.assertEqual(chain.submit_header(b.header), "accepted")
        logs = []
        node = Node(chain, use_seeds=False, log=logs.append)
        pairs = [socket.socketpair() for _ in range(2)]
        try:
            a, b = (Peer(node, s[0], ("127.0.0.1", 1000 + i), False) for i, s in enumerate(pairs))
            a.ready = b.ready = True
            real = chain.submit_block
            fired = threading.Event()

            def interleaved(blk, *args, **kw):
                # Peer b's block 3 arrives while peer a's block 1 connects: 3 has no
                # parent data yet, so it is only stored and does not move the tip.
                if blk.header.height == 3 and not fired.is_set():
                    fired.set()
                    node._handle(a, {"type": "block", "data": blocks[0].serialize().hex()})
                return real(blk, *args, **kw)
            chain.submit_block = interleaved
            node._handle(b, {"type": "block", "data": blocks[2].serialize().hex()})
            node._handle(a, {"type": "block", "data": blocks[1].serialize().hex()})
            self.assertEqual(chain.height, 3)
            tips = [line for line in logs if "new tip" in line]
            heights = [int(line.split()[3]) for line in tips]
            self.assertEqual(sorted(set(heights)), heights, tips)   # no height twice
            self.assertEqual(heights[-1], 3)

            # a block this node mined is reported as mined, never again as a new tip
            logs.clear()
            chain.submit_block = real
            node.wallet = w
            clock.t += 120
            node.mine_one()
            node._handle(a, {"type": "block", "data": chain.blocks.get(chain.tip.hash).serialize().hex()})
            self.assertFalse([line for line in logs if "new tip" in line], logs)
        finally:
            node.running = False
            node.srv.close()
            for s in pairs:
                s[0].close()
                s[1].close()


class TestPqStats(unittest.TestCase):
    """The post-quantum measurement tool reports what the chain really contains,
    and its sweep model agrees with the transactions the wallet really builds."""

    def test_measure_and_sweep_model(self):
        from kairos import pqstats
        from kairos.rpc import RPCServer, call
        chain, clock, w = TestPostQuantumSpending.activated(self, 48)
        start = chain.height + 1
        bob = Wallet(REGTEST, seed=b"b" * 32)
        txs = w.create_txs(chain, bob.mining_address, w.balance(chain)["spendable"] - 5 * COIN)
        for tx in txs:
            chain.accept_tx(tx)
        while chain.mempool:
            mine_block(chain, clock, w.mining_address)
        m = pqstats.measure(chain, start, chain.height)
        self.assertEqual(m["pq_txs"]["count"], len(txs))
        self.assertEqual(m["inputs"]["lamport"], sum(len(t.inputs) for t in txs))
        self.assertEqual(m["pq_txs"]["max"], max(t.size for t in txs))
        self.assertTrue(m["pq_active_at_end"])
        # observed bytes per input = model plus the transaction's fixed overhead
        self.assertGreaterEqual(m["observed_bytes_per_pq_input"], m["model_bytes_per_pq_input"])
        self.assertLess(m["observed_bytes_per_pq_input"] - m["model_bytes_per_pq_input"], 200)
        self.assertEqual(sum(b["pq_txs"] for b in m["blocks_with_pq_txs"]), len(txs))

        # the size model is exact, not an estimate
        sel = [(t.inputs[i].prev, None) for t in txs[:1] for i in range(len(t.inputs))]
        self.assertEqual(pqstats.tx_size(len(sel), 2, pqstats.LAMPORT_WITNESS), w._size(sel, 2, 0, True))
        n = pqstats.max_inputs(pqstats.MAX_TX_BYTES, 1, pqstats.LAMPORT_WITNESS)
        self.assertLessEqual(pqstats.tx_size(n, 1, pqstats.LAMPORT_WITNESS), pqstats.MAX_TX_BYTES)
        self.assertGreater(pqstats.tx_size(n + 1, 1, pqstats.LAMPORT_WITNESS), pqstats.MAX_TX_BYTES)
        plan = pqstats.sweep_plan(REGTEST, 1_000_000)
        self.assertLessEqual(plan["inputs_per_block"] * plan["bytes_per_input"], pqstats.block_room(REGTEST))
        self.assertEqual(plan["blocks"], -(-1_000_000 // plan["inputs_per_block"]))
        half = pqstats.sweep_plan(REGTEST, 1_000_000, share=0.5)
        self.assertGreater(half["blocks"], plan["blocks"] * 1.9)

        with tempfile.TemporaryDirectory() as d:
            node = Node(chain, wallet=w, use_seeds=False)
            rpc = RPCServer(node, d)
            try:
                r = call(d, rpc.port, "getpqstats", [start, chain.height, [100, 1000]])
                self.assertIsNone(r["error"])
                self.assertEqual(r["result"]["pq_txs"]["count"], len(txs))
                self.assertEqual([s["coins"] for s in r["result"]["sweep"]], [100, 1000])
                self.assertIsNone(call(d, rpc.port, "getpqstats", [])["error"])   # defaults
                for bad in ([5, 1], [0, 1, 0], [0, 1, 10, 2.0], [0, 1, "x"]):
                    self.assertIsNotNone(call(d, rpc.port, "getpqstats", bad)["error"], bad)
            finally:
                rpc.stop()
                node.stop()


class TestMinerTemplateRefresh(unittest.TestCase):
    """A transaction that arrives while a block is being mined goes into that
    block after a short delay, instead of waiting a whole extra block (on
    testnet 2 a send made during block 6054 was mined only in 6055)."""

    def setUp(self):
        self.chain, clock = new_chain()
        self.w = Wallet(REGTEST, seed=b"m" * 32)
        for _ in range(4):
            mine_block(self.chain, clock, self.w.mining_address)
        clock.t += 120
        self.tx = self.w.create_txs(self.chain, Wallet(REGTEST, seed=b"b" * 32).mining_address, COIN)[0]
        self.node = Node(self.chain, wallet=self.w, use_seeds=False)

    def tearDown(self):
        self.node.stop()

    def mine_with_arrival(self, refresh):
        import kairos.node as node_mod
        real_mine, templates = node_mod.mine, []

        def fake_mine(header, should_stop=None, **kw):
            templates.append(header)
            if len(templates) == 1:
                self.assertFalse(should_stop())          # nothing new yet: keep mining
                self.node.submit_tx(self.tx)             # arrives mid-block
                if not should_stop():
                    return real_mine(header, should_stop=should_stop)
                return False
            return real_mine(header, should_stop=should_stop)
        old = node_mod.TEMPLATE_REFRESH
        node_mod.mine, node_mod.TEMPLATE_REFRESH = fake_mine, refresh
        try:
            return self.node.mine_one(), templates
        finally:
            node_mod.mine, node_mod.TEMPLATE_REFRESH = real_mine, old

    def test_new_transaction_is_added_to_the_block_being_mined(self):
        blk, templates = self.mine_with_arrival(refresh=0)
        self.assertEqual(len(templates), 2)                  # rebuilt once
        self.assertIn(self.tx.txid, [t.txid for t in blk.txs])
        self.assertEqual(self.chain.mempool, {})

    def test_template_is_not_rebuilt_before_the_delay(self):
        blk, templates = self.mine_with_arrival(refresh=3600)
        self.assertEqual(len(templates), 1)
        self.assertNotIn(self.tx.txid, [t.txid for t in blk.txs])
        self.assertIn(self.tx.txid, self.chain.mempool)


class TestCliPipe(unittest.TestCase):
    def test_rpc_output_into_a_closed_pipe_is_not_an_error(self):
        # `kairos rpc listunspent | head` printed a BrokenPipeError traceback
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = "from kairos.__main__ import print_result; print_result([{'n': i} for i in range(200000)])"
        p = subprocess.Popen([sys.executable, "-c", code], cwd=root, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.stdout.readline()
        p.stdout.close()                                     # what `head` does after its lines
        err = p.stderr.read().decode()
        p.stderr.close()
        self.assertEqual(p.wait(timeout=30), 0, err)
        self.assertNotIn("Traceback", err)
