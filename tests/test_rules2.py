"""Rules 2 (testnet 3, mainnet): SLH-DSA, versioned outputs, commit-delay-reveal
and Core's MuHash3072. See docs/rules-v2.md."""
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos import slhdsa
from kairos.block import Block, mine
from kairos.chain import (Chain, UtxoView, ValidationError, COMMIT_INDEX, REVEAL_INDEX)
from kairos.crypto import MuHash3072, muhash3072_element, chacha20_block, chacha20_keystream, MUHASH_P
from kairos.node import Node
from kairos.params import REGTEST, REGTEST2, TESTNET2, TESTNET3, MAINNET, COIN
from kairos.tx import (Transaction, TxIn, TxOut, OutPoint, commit_script, spend_commitment,
                       WIT_SLHDSA, SLHDSA_WITNESS_LEN)
from kairos.wallet import Wallet

from test_kairos import Clock, mine_block, wait

HERE = os.path.dirname(os.path.abspath(__file__))


def new_chain2(**kw):
    params = replace(REGTEST2, **kw)
    clock = Clock(params.genesis_time + 1)
    return Chain(params, now=clock), clock


class TestSlhDsa(unittest.TestCase):
    """FIPS 205 SLH-DSA-SHA2-128s against NIST's ACVP vectors."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "data", "slhdsa_sha2_128s_acvp.json")) as f:
            cls.v = json.load(f)

    def test_keygen(self):
        for t in self.v["keyGen"]:
            sk, pk = slhdsa.keygen_internal(bytes.fromhex(t["skSeed"]), bytes.fromhex(t["skPrf"]),
                                            bytes.fromhex(t["pkSeed"]))
            self.assertEqual(sk.hex().upper(), t["sk"].upper())
            self.assertEqual(pk.hex().upper(), t["pk"].upper())

    def test_verify(self):
        n = 0
        for iface, tests in self.v["sigVer"].items():
            for t in tests:
                msg, sig, pk = bytes.fromhex(t["message"]), bytes.fromhex(t["signature"]), bytes.fromhex(t["pk"])
                got = (slhdsa.verify(msg, sig, pk, bytes.fromhex(t["context"])) if iface == "external"
                       else slhdsa.verify_internal(msg, sig, pk))
                self.assertEqual(got, t["testPassed"], (iface, t["tcId"], t["reason"]))
                n += 1
        self.assertGreaterEqual(n, 10)

    def test_sign(self):
        for t in self.v["sigGen"]:
            sk, msg = bytes.fromhex(t["sk"]), bytes.fromhex(t["message"])
            rnd = None if t["deterministic"] else bytes.fromhex(t["additionalRandomness"])
            sig = (slhdsa.sign(msg, sk, bytes.fromhex(t["context"]), rnd) if t["interface"] == "external"
                   else slhdsa.sign_internal(msg, sk, rnd))
            self.assertEqual(sig.hex().upper(), t["signature"].upper(), t["tcId"])

    def test_sizes(self):
        self.assertEqual(slhdsa.SIG_BYTES, 7856)
        self.assertEqual(slhdsa.PK_BYTES, 32)
        self.assertEqual(SLHDSA_WITNESS_LEN, 7953)


class TestCoreMuHash(unittest.TestCase):
    """Bitcoin Core's MuHash3072 (src/test/crypto_tests.cpp) and ChaCha20 (RFC 8439)."""

    def test_chacha20(self):
        k = bytes(range(32))
        self.assertEqual(chacha20_block(k, 1, bytes.fromhex("000000090000004a00000000")).hex(),
                         "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                         "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
        self.assertEqual(chacha20_keystream(b"\x00" * 32, 64).hex(),
                         "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                         "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")

    def test_core_vectors(self):
        def from_int(i):
            return bytes([i]) + bytes(31)
        acc = MuHash3072(muhash3072_element(from_int(0)))
        acc.insert(from_int(1))
        acc.remove(from_int(2))
        # Core prints uint256 byte-reversed
        self.assertEqual(acc.digest()[::-1].hex(),
                         "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863")
        prod = muhash3072_element(from_int(1)) * muhash3072_element(from_int(2)) % MUHASH_P
        self.assertTrue(prod.to_bytes(384, "little").hex().startswith(
            "1fa093295ea30a6a3acdc7b3f770fa538eff537528e990e2910e40bbcfd7f669"))

    def test_rules2_genesis_commits_to_core_empty_set(self):
        c = Chain(REGTEST2)
        g = c.blocks[c.genesis.hash]
        self.assertEqual(g.header.utxo_root, MuHash3072().digest())


class Rules2Case(unittest.TestCase):
    def setUp(self):
        self.chain, self.clock = new_chain2()
        self.w = Wallet(self.chain.params, seed=b"a" * 32)
        self.w.attach(self.chain)
        self.bob = Wallet(self.chain.params, seed=b"b" * 32)

    def mine(self, n=1, txs=()):
        for tx in txs:
            self.chain.accept_tx(tx)
        for _ in range(n):
            mine_block(self.chain, self.clock, self.w.mining_address)

    def activate(self):
        self.chain.signal.add("pq")
        while not self.chain.pq_active(self.chain.tip):
            self.mine()

    def block_with(self, *txs):
        """A block containing exactly `txs` (bypassing mempool policy)."""
        c = self.chain
        self.clock.t += 120
        saved = dict(c.mempool), dict(c.mempool_fee), dict(c.mempool_spends)
        c.mempool.clear(); c.mempool_fee.clear(); c.mempool_spends.clear()
        try:
            view = UtxoView(c.utxos)
            fee = 0
            for tx in txs:
                f, _ = c.check_tx(tx, view, c.height + 1, c.tip.next_base_fee, c.pq_active(c.tip))
                c.apply_tx(tx, view, c.height + 1)
                c.mempool[tx.txid] = tx
                c.mempool_fee[tx.txid] = f
            blk = c.create_block(self.w.mining_address)
        finally:
            c.mempool.clear(); c.mempool_fee.clear(); c.mempool_spends.clear()
            c.mempool.update(saved[0]); c.mempool_fee.update(saved[1]); c.mempool_spends.update(saved[2])
        self.assertEqual(len(blk.txs), len(txs) + 1)
        self.assertTrue(mine(blk.header))
        return blk


class TestFormat(Rules2Case):
    def test_rules1_parsing_is_unchanged(self):
        # A rules-1 node parses a version-2 transaction with 32-byte outputs, as 0.4
        # does, and rejects it for its version: never "malformed" on one version
        # and "invalid" on another.
        c1 = Chain(REGTEST)
        tx = Transaction([TxIn(OutPoint(b"\x01" * 32, 0), b"")], [TxOut(5, b"\x02" * 32)], 0, 2)
        raw = tx.serialize()
        self.assertEqual(Transaction.deserialize(raw).outputs[0].address, b"\x02" * 32)
        with self.assertRaisesRegex(ValidationError, "unknown tx version"):
            c1.check_tx(Transaction.deserialize(raw), UtxoView({}), 1, 1)

    def test_v2_round_trip_and_version(self):
        self.mine(3)
        tx = self.w.create_tx(self.chain, self.bob.mining_address, COIN)
        self.assertEqual(tx.version, 2)
        self.assertEqual(len(tx.outputs[0].address), 33)
        again = Transaction.deserialize(tx.serialize(), 2)
        self.assertEqual(again.wtxid, tx.wtxid)
        v1 = Transaction(tx.inputs, tx.outputs, 0, 1)
        with self.assertRaisesRegex(ValidationError, "unknown tx version"):
            self.chain.check_tx(v1, UtxoView(self.chain.utxos), self.chain.height + 1, 1)

    def test_networks(self):
        self.assertEqual((MAINNET.rules, TESTNET3.rules, REGTEST2.rules), (2, 2, 2))
        self.assertEqual((TESTNET2.rules, REGTEST.rules), (1, 1))
        self.assertEqual(TESTNET3.script_len, 33)
        from kairos.__main__ import net, main  # noqa: F401
        import argparse
        for flag, name in (("testnet", "test3"), ("testnet2", "test"), ("regtest", "regtest2"),
                           ("regtest1", "regtest")):
            self.assertEqual(net(argparse.Namespace(**{flag: True})).name, name)


class TestOutputs(Rules2Case):
    def spend(self, outs, value=None):
        """A signed Schnorr transaction spending one of our coins into `outs`."""
        coins = self.w._free_coins(self.chain)
        op, c = max(coins.items(), key=lambda kv: kv[1].value)
        tx = Transaction([TxIn(op, b"\x00" * 129)], outs, 0, 2)
        self.w._sign(tx, [(op, c)], False)
        return tx

    def test_output_versions(self):
        self.mine(3)
        v = UtxoView(self.chain.utxos)
        h, bf = self.chain.height + 1, self.chain.tip.next_base_fee
        bad = self.spend([TxOut(COIN, b"\x81" + b"\x00" * 32)])
        with self.assertRaisesRegex(ValidationError, "unknown output version"):
            self.chain.check_tx(bad, v, h, bf)
        paid_commit = self.spend([TxOut(1, commit_script(b"\x05" * 32))])
        with self.assertRaisesRegex(ValidationError, "value 0"):
            self.chain.check_tx(paid_commit, v, h, bf)
        twice = self.spend([TxOut(0, commit_script(b"\x05" * 32)), TxOut(0, commit_script(b"\x05" * 32))])
        with self.assertRaisesRegex(ValidationError, "duplicate commitment"):
            self.chain.check_tx(twice, v, h, bf)

    def test_future_versions_are_anyone_can_spend_but_not_relayed(self):
        self.mine(3)
        future = b"\x01" + b"\x07" * 32
        tx = self.spend([TxOut(2 * COIN, future)])
        with self.assertRaisesRegex(ValidationError, "non-standard"):
            self.chain.accept_tx(tx)
        self.chain.submit_block(self.block_with(tx))
        op = OutPoint(tx.txid, 0)
        self.assertIn(op, self.chain.utxos)
        # consensus: any witness spends it (here: none at all)
        grab = Transaction([TxIn(op, b"")], [TxOut(COIN, self.bob.mining_address)], 0, 2)
        with self.assertRaisesRegex(ValidationError, "non-standard"):
            self.chain.accept_tx(grab)
        self.assertEqual(self.chain.submit_block(self.block_with(grab)), "accepted")

    def test_records_cannot_be_spent(self):
        self.mine(3)
        commit = self.spend([TxOut(0, commit_script(b"\x09" * 32))])
        self.mine(txs=[commit])
        rec = OutPoint(b"\x09" * 32, COMMIT_INDEX)
        self.assertIn(rec, self.chain.utxos)
        steal = Transaction([TxIn(rec, b"")], [TxOut(1, self.bob.mining_address)], 0, 2)
        with self.assertRaisesRegex(ValidationError, "missing or spent input"):
            self.chain.check_tx(steal, UtxoView(self.chain.utxos), self.chain.height + 1, 1)

    def test_coinbase_pays_key_outputs_only(self):
        self.clock.t += 120
        blk = self.chain.create_block(b"\x80" + b"\x00" * 32)
        self.assertTrue(mine(blk.header))
        self.assertIn("bad coinbase output", self.chain.submit_block(blk))


class TestCommitDelayReveal(Rules2Case):
    def test_schnorr_needs_an_aged_commitment_after_activation(self):
        self.mine(3)
        self.activate()
        tx = self.w.create_tx(self.chain, self.bob.mining_address, COIN, post_quantum=False)
        with self.assertRaisesRegex(ValidationError, "without a commitment"):
            self.chain.accept_tx(tx)
        commit, reveal = self.w.create_commit_reveal(self.chain, self.bob.mining_address, 2 * COIN)
        self.assertEqual(commit.inputs[0].witness[0], WIT_SLHDSA)     # paid for with SLH-DSA
        self.assertLess(reveal.size, 400)
        self.mine(txs=[commit])
        for _ in range(self.chain.params.reveal_delay - 1):
            with self.assertRaisesRegex(ValidationError, "younger than"):
                self.chain.accept_tx(reveal)
            self.mine()
        self.assertEqual(self.w.due_reveals(self.chain), [reveal])
        self.mine(txs=[reveal])
        self.assertEqual(self.bob.balance(self.chain)["spendable"], 2 * COIN)
        self.assertEqual(self.w.due_reveals(self.chain), [])
        self.assertEqual(self.w.pending, [])

    def test_commitment_made_before_activation_counts(self):
        self.mine(3)
        commit, reveal = self.w.create_commit_reveal(self.chain, self.bob.mining_address, COIN)
        self.assertNotEqual(commit.inputs[0].witness[0], WIT_SLHDSA)   # before the switch: Schnorr
        self.mine(txs=[commit])
        self.activate()
        self.mine(txs=self.w.due_reveals(self.chain))
        self.assertEqual(self.bob.balance(self.chain)["spendable"], COIN)

    def test_key_revealed_before_the_commitment_cannot_use_it(self):
        # Two coins at one address. Spending the first reveals the key; an attacker
        # who then commits to a theft of the second coin must be refused.
        self.mine(3)
        reuse = self.w.keys[0].address
        pay = self.w.create_txs(self.chain, reuse, 3 * COIN)
        self.mine(txs=pay)
        pay2 = self.w.create_txs(self.chain, reuse, 3 * COIN)
        self.mine(txs=pay2)
        at_reuse = sorted((op for op, c in self.chain.utxos.items() if c.address == reuse),
                          key=lambda op: (op.txid, op.index))
        self.assertGreaterEqual(len(at_reuse), 2)
        first = [(at_reuse[0], self.chain.utxos[at_reuse[0]])]
        spend1 = self.w._assemble(self.chain, first, [TxOut(COIN, self.bob.mining_address)],
                                  first[0][1].value, 3, 0, False)
        self.mine(txs=[spend1])                         # the key of `reuse` is now public
        self.assertTrue(self.chain.key_revealed(reuse))
        second = [(at_reuse[1], self.chain.utxos[at_reuse[1]])]
        theft = self.w._assemble(self.chain, second, [TxOut(COIN, self.bob.mining_address)],
                                 second[0][1].value, 3, 0, False)
        c = spend_commitment(theft.txid, [theft.inputs[0].witness[1:33]])
        # commit to the theft with a plain Schnorr spend of another coin (before activation)
        fund = max(((op, cc) for op, cc in self.w._free_coins(self.chain).items() if op != at_reuse[1]),
                   key=lambda kv: kv[1].value)
        marker = self.w._assemble(self.chain, [fund], [TxOut(0, commit_script(c))], fund[1].value, 3, 0, False)
        self.mine(txs=[marker])
        self.activate()
        with self.assertRaisesRegex(ValidationError, "revealed before its commitment"):
            self.chain.accept_tx(theft)
        # the SLH-DSA path still moves the coin
        rescue = self.w._assemble(self.chain, second, [TxOut(COIN, self.bob.mining_address)],
                                  second[0][1].value, 3, 0, True)
        self.chain.accept_tx(rescue)

    def test_commitment_binds_the_keys(self):
        # A commitment computed without the right Schnorr key (what an attacker can
        # compute before the key is public) does not authorise the spend.
        self.mine(6)
        commit, reveal = self.w.create_commit_reveal(self.chain, self.bob.mining_address, COIN)
        wrong = spend_commitment(reveal.txid, [b"\x02" * 32])
        self.assertNotEqual(wrong.hex(), self.w.pending[0]["commitment"])
        fund = max(((op, cc) for op, cc in self.w._free_coins(self.chain).items()
                    if op not in {i.prev for i in commit.inputs}), key=lambda kv: kv[1].value)
        fake = self.w._assemble(self.chain, [fund], [TxOut(0, commit_script(wrong))], fund[1].value, 3, 0, False)
        self.mine(txs=[fake])
        self.activate()
        with self.assertRaisesRegex(ValidationError, "without a commitment"):
            self.chain.accept_tx(reveal)

    def test_slhdsa_spend_shares_one_signature(self):
        self.mine(6)
        self.activate()
        txs = self.w.create_txs(self.chain, self.bob.mining_address, 25 * COIN)
        tx = txs[0]
        self.assertGreater(len(tx.inputs), 1)
        self.assertEqual(len({i.witness[97:] for i in tx.inputs}), 1)
        self.mine(txs=txs)
        self.assertEqual(self.bob.balance(self.chain)["spendable"], 25 * COIN)
        # a flipped bit anywhere in the signature is rejected
        more = self.w.create_txs(self.chain, self.bob.mining_address, COIN)[0]
        w = bytearray(more.inputs[0].witness)
        w[500] ^= 1
        more.inputs[0].witness = bytes(w)
        more.invalidate()
        with self.assertRaisesRegex(ValidationError, "invalid signature"):
            self.chain.accept_tx(more)


class TestState(Rules2Case):
    def build_history(self):
        self.mine(3)
        commit, reveal = self.w.create_commit_reveal(self.chain, self.bob.mining_address, COIN)
        self.mine(txs=[commit])
        self.activate()
        self.mine(txs=self.w.due_reveals(self.chain))
        self.assertEqual(self.bob.balance(self.chain)["spendable"], COIN)

    def test_reorg_removes_records_and_restores_muhash(self):
        self.build_history()
        records = {op for op in self.chain.utxos if op.index in (COMMIT_INDEX, REVEAL_INDEX)}
        self.assertTrue(any(op.index == COMMIT_INDEX for op in records))
        self.assertTrue(any(op.index == REVEAL_INDEX for op in records))
        roots = {i.height: i.muhash for i in self.chain.active}
        blocks = self.chain.blocks_after([self.chain.genesis.hash], limit=1000)
        replay = Chain(self.chain.params, now=self.clock)
        for b in blocks:
            self.assertEqual(replay.submit_block(b), "accepted")
        self.assertEqual(replay.utxos, self.chain.utxos)
        for idx in self.chain.active[1:-1]:
            idx.muhash = None                      # force the arithmetic undo path
        while self.chain.height:
            self.chain._disconnect_tip()
            self.assertEqual(self.chain.tip.muhash, roots[self.chain.height])
        self.assertEqual(self.chain.utxos, {})

    def test_restart_and_utxo_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            self.clock = Clock(REGTEST2.genesis_time + 1)
            self.chain = Chain(REGTEST2, datadir=os.path.join(d, "a"), now=self.clock)
            self.w = Wallet(self.chain.params, seed=b"a" * 32)
            self.w.attach(self.chain)
            self.build_history()
            utxos, tip = dict(self.chain.utxos), self.chain.tip.hash
            self.chain.close()
            again = Chain(REGTEST2, datadir=os.path.join(d, "a"), now=self.clock)
            self.assertEqual((again.utxos, again.tip.hash), (utxos, tip))
            snap = os.path.join(d, "u.snap")
            again.export_utxo_snapshot(snap)
            fresh = Chain(REGTEST2, datadir=os.path.join(d, "b"), now=self.clock)
            for b in again.headers_after(fresh.header_locator(), 1000):
                self.assertEqual(fresh.submit_header(b.header, b.auxpow), "accepted")
            fresh.import_utxo_snapshot(snap)
            self.assertEqual((fresh.utxos, fresh.tip.hash), (utxos, tip))
            again.close()
            fresh.close()


class TestWalletRules2(unittest.TestCase):
    def test_addresses_are_unlinkable_and_hd_works(self):
        w = Wallet(REGTEST2, seed=b"c" * 32, n_keys=3)
        leaves = {k.pqroot for k in w.keys}
        self.assertEqual(len(leaves), 3)                  # one SLH-DSA key, three different leaves
        self.assertEqual(len({k.slh_pk for k in w.keys}), 1)
        hd, words = Wallet.create_hd(TESTNET3, n_keys=2)
        again = Wallet.restore_mnemonic(TESTNET3, words, n_keys=2)
        self.assertEqual([k.address for k in hd.keys], [k.address for k in again.keys])
        self.assertTrue(hd.encode(hd.keys[0].address).startswith("tkr31"))
        self.assertEqual(hd.decode(hd.encode(hd.keys[0].address)), hd.keys[0].address)
        with self.assertRaises(ValueError):
            hd.decode(Wallet(TESTNET2, seed=b"d" * 32).encode(b"\x00" * 32))

    def test_pending_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            chain, clock = new_chain2()
            w = Wallet(REGTEST2, seed=b"e" * 32, path=path)
            w.attach(chain)
            for _ in range(3):
                mine_block(chain, clock, w.mining_address)
            commit, reveal = w.create_commit_reveal(chain, Wallet(REGTEST2, seed=b"f" * 32).mining_address, COIN)
            w2 = Wallet.load(REGTEST2, path)
            self.assertEqual(len(w2.pending), 1)
            self.assertEqual(w2.due_reveals(chain), [commit])       # commitment not mined yet


class TestNodes(unittest.TestCase):
    def test_nodes_relay_and_reveal_by_themselves(self):
        chains = [new_chain2() for _ in range(2)]
        for c, clock in chains:
            clock.t += 100_000
        wa = Wallet(REGTEST2, seed=b"g" * 32)
        wa.attach(chains[0][0])
        bob = Wallet(REGTEST2, seed=b"h" * 32)
        nodes = [Node(chains[0][0], wallet=wa, use_seeds=False), Node(chains[1][0], use_seeds=False)]
        try:
            nodes[1].connect("127.0.0.1", nodes[0].port)
            wait(lambda: all(p.ready for n in nodes for p in n.peers) and all(n.peers for n in nodes))
            for _ in range(4):
                nodes[0].mine_one()
            wait(lambda: chains[1][0].height == 4)
            commit, reveal = wa.create_commit_reveal(chains[0][0], bob.mining_address, COIN)
            nodes[0].submit_tx(commit)
            wait(lambda: commit.txid in chains[1][0].mempool)
            for _ in range(REGTEST2.reveal_delay + 1):
                nodes[0].mine_one()
            nodes[0].wallet_tick()
            wait(lambda: reveal.txid in chains[1][0].mempool)
            nodes[0].mine_one()
            wait(lambda: chains[1][0].tip.hash == chains[0][0].tip.hash)
            self.assertEqual(bob.balance(chains[1][0])["spendable"], COIN)
        finally:
            for n in nodes:
                n.stop()


if __name__ == "__main__":
    unittest.main()
