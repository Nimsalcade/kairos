import os
import sys
import tempfile
import time
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos.block import Block, mine
from kairos.chain import Chain, ValidationError, UtxoView
from kairos.crypto import (pubkey_from_seckey, schnorr_sign, schnorr_verify, MuHash,
                           merkle_root, merkle_proof, merkle_verify, bech32m_encode, bech32m_decode)
from kairos.node import Node
from kairos.params import (REGTEST, MAINNET, COIN, subsidy, asert_target, bits_to_target,
                           target_to_bits, next_base_fee)
from kairos.tx import Transaction, TxOut
from kairos.wallet import Wallet


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def new_chain(**kw):
    params = replace(REGTEST, **kw)
    clock = Clock(params.genesis_time + 1)
    return Chain(params, now=clock), clock


def mine_block(chain, clock, addr, step=120, txs_extra=b""):
    clock.t += step
    blk = chain.create_block(addr, txs_extra)
    assert mine(blk.header)
    status = chain.submit_block(blk)
    assert status == "accepted", status
    return blk


class TestCrypto(unittest.TestCase):
    def test_bip340_vector0(self):
        sk = (3).to_bytes(32, "big")
        pk = pubkey_from_seckey(sk)
        self.assertEqual(pk.hex().upper(),
                         "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        sig = schnorr_sign(b"\x00" * 32, sk, b"\x00" * 32)
        self.assertEqual(sig.hex().upper(),
                         "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                         "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        self.assertTrue(schnorr_verify(b"\x00" * 32, pk, sig))
        self.assertFalse(schnorr_verify(b"\x01" * 32, pk, sig))

    def test_muhash_order_independent(self):
        a, b = MuHash(), MuHash()
        for x in (b"1", b"2", b"3"):
            a.insert(x)
        for x in (b"3", b"4", b"1", b"2"):
            b.insert(x)
        b.remove(b"4")
        self.assertEqual(a.digest(), b.digest())

    def test_merkle_no_duplicate_ambiguity(self):
        leaves = [bytes([i]) * 32 for i in range(5)]
        self.assertNotEqual(merkle_root(leaves), merkle_root(leaves + leaves[-1:]))
        r = merkle_root(leaves)
        for i in range(5):
            self.assertTrue(merkle_verify(leaves[i], merkle_proof(leaves, i), r))

    def test_bech32m(self):
        a = bech32m_encode("krs", b"\x07" * 32)
        self.assertEqual(bech32m_decode("krs", a), b"\x07" * 32)
        bad = a[:-1] + ("q" if a[-1] != "q" else "p")
        with self.assertRaises(ValueError):
            bech32m_decode("krs", bad)


class TestMonetaryPolicy(unittest.TestCase):
    def test_emission_smooth_and_tail(self):
        p = MAINNET
        s0 = subsidy(p, 0)
        self.assertAlmostEqual(s0 / COIN, 10.01, places=2)
        # no halving cliffs: consecutive rewards differ by < 0.0001%
        g, prev = 0, s0
        for _ in range(1000):
            g += prev
            cur = subsidy(p, g)
            self.assertLess(prev - cur, prev // 1_000_000 + 1)
            prev = cur
        self.assertEqual(subsidy(p, p.emission_supply), p.tail_reward)

    def test_base_fee_controller(self):
        p = MAINNET
        self.assertEqual(next_base_fee(p, 800, p.max_block_size), 900)      # full: +12.5%
        self.assertEqual(next_base_fee(p, 800, 0), 700)                     # empty: -12.5%
        self.assertEqual(next_base_fee(p, 800, p.target_block_size), 800)  # target: steady
        self.assertEqual(next_base_fee(p, 1, 0), 1)                         # floor


class TestASERT(unittest.TestCase):
    def test_on_schedule_is_stable(self):
        p = MAINNET
        t = asert_target(p, p.genesis_bits, p.genesis_time, p.genesis_time + 120 * 5000, 5000)
        self.assertEqual(target_to_bits(t), p.genesis_bits)

    def test_halflife_doubles_and_halves(self):
        p = replace(MAINNET, pow_limit=(1 << 255) - 1)
        base = bits_to_target(p.genesis_bits)
        slow = asert_target(p, p.genesis_bits, p.genesis_time, p.genesis_time + 120 * 100 + p.asert_halflife, 100)
        fast = asert_target(p, p.genesis_bits, p.genesis_time, p.genesis_time + 120 * 100 - p.asert_halflife, 100)
        self.assertAlmostEqual(slow / base, 2.0, places=3)
        self.assertAlmostEqual(fast / base, 0.5, places=3)

    def test_compact_roundtrip(self):
        for bits in (0x1E0FFFFF, 0x1D00FFFF, 0x200FFFFF, 0x1B0404CB):
            self.assertEqual(target_to_bits(bits_to_target(bits)), bits)


class TestChain(unittest.TestCase):
    def setUp(self):
        self.chain, self.clock = new_chain()
        self.alice = Wallet(self.chain.params, seed=b"a" * 32)
        self.bob = Wallet(self.chain.params, seed=b"b" * 32)
        self.carol = Wallet(self.chain.params, seed=b"z" * 32)   # an unrelated miner

    def fund_alice(self, n=3):
        for _ in range(n):
            mine_block(self.chain, self.clock, self.alice.mining_address)

    def test_payment_fee_burn_and_supply(self):
        self.fund_alice()
        bal = self.alice.balance(self.chain)
        self.assertGreater(bal["spendable"], 0)
        tx = self.alice.create_tx(self.chain, self.bob.mining_address, 3 * COIN, tip_per_byte=5)
        self.assertTrue(self.chain.accept_tx(tx))
        mine_block(self.chain, self.clock, self.carol.mining_address)
        self.assertEqual(self.bob.balance(self.chain)["spendable"], 3 * COIN)
        s = self.chain.supply()
        self.assertEqual(s["burned"], tx.size * 1)          # base fee 1 mote/byte burned
        total_utxo = sum(c.value for c in self.chain.utxos.values())
        self.assertEqual(total_utxo, s["circulating"])      # conservation of money

    def test_utxo_commitment_matches_fresh_snapshot(self):
        self.fund_alice(4)
        tx = self.alice.create_tx(self.chain, self.bob.mining_address, COIN)
        self.chain.accept_tx(tx)
        mine_block(self.chain, self.clock, self.alice.mining_address)
        from kairos.chain import coin_bytes
        mh = MuHash()
        for op, c in self.chain.utxos.items():
            mh.insert(coin_bytes(op, c))
        self.assertEqual(mh.digest(), self.chain.tip.header.utxo_root)

    def test_double_spend_rejected(self):
        self.fund_alice()
        tx1 = self.alice.create_tx(self.chain, self.bob.mining_address, COIN)
        self.chain.accept_tx(tx1)
        tx2 = Transaction(tx1.inputs, [TxOut(COIN, self.alice.mining_address)])
        with self.assertRaises(ValidationError):
            self.chain.accept_tx(tx2)

    def test_signature_tamper_rejected(self):
        self.fund_alice()
        tx = self.alice.create_tx(self.chain, self.bob.mining_address, COIN)
        tx.outputs[0].value += 1           # thief edits the amount after signing
        tx.invalidate()
        with self.assertRaisesRegex(ValidationError, "signature"):
            self.chain.accept_tx(tx)

    def test_cross_chain_replay_rejected(self):
        self.fund_alice()
        other = Wallet(replace(REGTEST, chain_id=b"FORK"), seed=b"a" * 32)
        tx = other.create_tx(self.chain, self.bob.mining_address, COIN)
        with self.assertRaisesRegex(ValidationError, "signature"):
            self.chain.accept_tx(tx)

    def test_expiry(self):
        self.fund_alice()
        tx = self.alice.create_tx(self.chain, self.bob.mining_address, COIN, expiry_blocks=1)
        self.chain.accept_tx(tx)
        # Nobody mines it in time; after two blocks the tx is permanently dead.
        self.chain._mempool_remove(tx.txid)
        mine_block(self.chain, self.clock, self.alice.mining_address)
        mine_block(self.chain, self.clock, self.alice.mining_address)
        with self.assertRaisesRegex(ValidationError, "expired"):
            self.chain.accept_tx(tx)

    def test_coinbase_overpay_rejected(self):
        self.fund_alice(1)
        blk = self.chain.create_block(self.alice.mining_address)
        blk.txs[0].outputs[0].value += 1
        blk.txs[0].invalidate()
        blk.header.tx_root = blk.compute_tx_root()
        mine(blk.header)
        self.assertIn("invalid", self.chain.submit_block(blk))

    def test_false_utxo_root_rejected(self):
        self.fund_alice(1)
        self.clock.t += 120
        blk = self.chain.create_block(self.alice.mining_address)
        blk.header.utxo_root = b"\x11" * 32
        mine(blk.header)
        self.assertEqual(self.chain.submit_block(blk), "invalid: utxo_root mismatch")

    def test_false_base_fee_rejected(self):
        """The header commits to the base fee of the next block (fast-sync state)."""
        self.fund_alice(1)
        self.clock.t += 120
        blk = self.chain.create_block(self.alice.mining_address)
        self.assertEqual(blk.header.fee, self.chain.params.min_base_fee)
        blk.header.fee += 1
        mine(blk.header)
        self.assertEqual(self.chain.submit_block(blk), "invalid: base fee mismatch")

    def test_immature_coinbase(self):
        chain, clock = new_chain(coinbase_maturity=5)
        w = Wallet(chain.params, seed=b"c" * 32)
        mine_block(chain, clock, w.mining_address)
        self.assertEqual(w.balance(chain)["spendable"], 0)
        with self.assertRaises(ValueError):
            w.create_tx(chain, self.bob.mining_address, COIN)

    def test_reorg_to_more_work_and_mempool_resurrection(self):
        self.fund_alice(3)
        fork_point = self.chain.tip
        tx = self.alice.create_tx(self.chain, self.bob.mining_address, 2 * COIN)
        self.chain.accept_tx(tx)
        mine_block(self.chain, self.clock, self.alice.mining_address)   # A-chain: contains tx
        self.assertEqual(self.bob.balance(self.chain)["spendable"], 2 * COIN)
        a_tip = self.chain.tip

        # Rival miner builds a longer branch from the fork point, without the tx.
        rival, rclock = new_chain()
        for b in self.chain.blocks_after([self.chain.genesis.hash]):
            if b.header.height <= fork_point.height:
                rival.submit_block(b)
        rclock.t = self.clock.t
        for _ in range(2):
            rival._refresh_mempool()
            rival.mempool.clear(); rival.mempool_spends.clear()
            b = mine_block(rival, rclock, self.carol.mining_address, step=60)
            self.chain.submit_block(b)
        self.assertEqual(self.chain.tip.hash, rival.tip.hash)
        self.assertIsNot(self.chain.tip, a_tip)
        self.assertEqual(self.bob.balance(self.chain)["spendable"], 0)
        self.assertIn(tx.txid, self.chain.mempool)          # tx returned to mempool
        mine_block(self.chain, self.clock, self.alice.mining_address)
        self.assertEqual(self.bob.balance(self.chain)["spendable"], 2 * COIN)

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            params = REGTEST
            clock = Clock(params.genesis_time + 1)
            c1 = Chain(params, datadir=d, now=clock)
            w = Wallet(params, seed=b"p" * 32)
            for _ in range(3):
                mine_block(c1, clock, w.mining_address)
            c1.close()
            c2 = Chain(params, datadir=d, now=clock)
            c2.close()
            self.assertEqual(c2.tip.hash, c1.tip.hash)
            self.assertEqual(c2.utxos, c1.utxos)
            # blocks are read back from disk, not held in memory (only genesis is pinned)
            self.assertEqual(set(c2.blocks.mem), {c2.genesis.hash})
            self.assertEqual(c2.blocks[c2.tip.hash].hash, c1.tip.hash)

    def test_sighash_commits_to_spent_amounts(self):
        """A signer cannot be lied to about what it spends (BIP143's lesson)."""
        self.fund_alice()
        tx = self.alice.create_tx(self.chain, self.bob.mining_address, COIN)
        coins = [self.chain.utxos[i.prev] for i in tx.inputs]
        good = tx.sighash(REGTEST.chain_id, [(c.value, c.address) for c in coins])
        lied = tx.sighash(REGTEST.chain_id, [(c.value + 1, c.address) for c in coins])
        self.assertNotEqual(good, lied)
        other = tx.sighash(REGTEST.chain_id, [(c.value, b"\x01" * 32) for c in coins])
        self.assertNotEqual(good, other)
        self.assertTrue(self.chain.accept_tx(tx))

    def test_best_chain_is_tracked_incrementally(self):
        self.fund_alice(5)
        self.assertIs(self.chain.best, self.chain.tip)
        # a shorter side branch never becomes best
        side, sclock = new_chain()
        for b in self.chain.blocks_after([self.chain.genesis.hash])[:2]:
            side.submit_block(b)
        sclock.t = self.clock.t
        b = mine_block(side, sclock, self.carol.mining_address)
        self.assertEqual(self.chain.submit_block(b), "accepted")
        self.assertIs(self.chain.best, self.chain.tip)
        self.assertEqual(self.chain.height, 5)


class TestMainnetGenesis(unittest.TestCase):
    def test_genesis_and_fair_launch(self):
        c = Chain(MAINNET)
        self.assertEqual(c.genesis.hash.hex(),
                         "00000d5c177c8ee763ea601553a3248f2bbec871c4968770e009edcc32111aea")
        self.assertEqual(c.expected_bits(c.tip), 0x1D00FFFF)
        self.assertIn(b"money should outlive", c.blocks[c.genesis.hash].txs[0].inputs[0].witness)

    def test_testnet2_genesis(self):
        from kairos.params import TESTNET
        c = Chain(TESTNET)
        self.assertEqual(c.genesis.hash.hex(),
                         "000008fa96a695a8e30751146a123e55ee730693362e0acba2c43ce704b73c51")
        self.assertNotEqual(TESTNET.chain_id, MAINNET.chain_id)
        self.assertNotEqual(TESTNET.magic, MAINNET.magic)


class TestSoftForks(unittest.TestCase):
    """BIP8-style version-bit activation on regtest: window 8, threshold 6."""

    def states(self, chain):
        return chain.deployment_info(chain.tip)["pq"]["state"]

    def test_lifecycle_started_locked_in_active(self):
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"v" * 32)
        self.assertEqual(self.states(chain), "started")     # start_height 0
        chain.signal.add("pq")
        for _ in range(7):                                   # heights 1..7 signal: 7 >= 6
            mine_block(chain, clock, w.mining_address)
        self.assertTrue(chain.tip.header.version >> 16 & 1)
        self.assertEqual(self.states(chain), "locked_in")    # window 1 (heights 8..15)
        self.assertFalse(chain.pq_active(chain.tip))
        for _ in range(8):
            mine_block(chain, clock, w.mining_address)
        self.assertEqual(chain.height, 15)
        self.assertEqual(self.states(chain), "active")       # window 2 (heights 16..)
        self.assertTrue(chain.pq_active(chain.tip))
        # a miner that keeps signalling after activation is harmless; the bit is dropped
        mine_block(chain, clock, w.mining_address)
        self.assertFalse(chain.tip.header.version >> 16 & 1)

    def test_below_threshold_stays_started(self):
        chain, clock = new_chain()
        w = Wallet(chain.params, seed=b"v" * 32)
        chain.signal.add("pq")
        for i in range(7):
            if i == 4:
                chain.signal.discard("pq")                    # only 4 of the 7 signal
            mine_block(chain, clock, w.mining_address)
        self.assertEqual(self.states(chain), "started")
        info = chain.deployment_info(chain.tip)["pq"]
        self.assertEqual(info["state"], "started")

    def test_timeout_fails_and_state_survives_reload(self):
        from kairos.params import Deployment
        dep = Deployment("pq", 16, start_height=8, timeout_height=24, window=8, threshold=6)
        chain, clock = new_chain(deployments=(dep,))
        w = Wallet(chain.params, seed=b"v" * 32)
        self.assertEqual(self.states(chain), "defined")
        for _ in range(8):
            mine_block(chain, clock, w.mining_address)
        self.assertEqual(self.states(chain), "started")     # from height 8
        for _ in range(16):
            mine_block(chain, clock, w.mining_address)       # nobody signals
        self.assertEqual(self.states(chain), "failed")       # timeout at 24
        with tempfile.TemporaryDirectory() as d:
            c1 = Chain(chain.params, datadir=d, now=clock)
            for b in chain.blocks_after([chain.genesis.hash]):
                c1.submit_block(b)
            c1.close()
            c2 = Chain(chain.params, datadir=d, now=clock)   # recomputed from headers
            self.assertEqual(self.states(c2), "failed")
            c2.close()


class TestQuantumEmergency(unittest.TestCase):
    def test_lamport_spend_and_schnorr_shutdown(self):
        chain, clock = new_chain()
        alice = Wallet(chain.params, seed=b"q" * 32)
        bob = Wallet(chain.params, seed=b"r" * 32)
        addr = alice.mining_address
        for _ in range(4):
            mine_block(chain, clock, addr)
        # Soft fork activated by miner signalling: after it, elliptic-curve spends are invalid.
        chain.signal.add("pq")
        while not chain.pq_active(chain.tip):
            mine_block(chain, clock, alice._derive().address)
        ec_tx = alice.create_tx(chain, bob.mining_address, COIN)
        with self.assertRaisesRegex(ValidationError, "signature"):
            chain.accept_tx(ec_tx)
        pq_tx = alice.create_tx(chain, bob.mining_address, COIN, post_quantum=True)
        self.assertGreater(pq_tx.size, 24_000)
        # The sweep took every coin at the address: its Lamport key is now retired.
        self.assertEqual(len(pq_tx.inputs), len([c for c in alice.coins(chain).values() if c.address == addr]))
        self.assertTrue(chain.accept_tx(pq_tx))
        mine_block(chain, clock, alice._derive().address)
        self.assertEqual(bob.balance(chain)["spendable"], COIN)
        # the Lamport key is retired: the wallet refuses to ever sign with it again
        self.assertIn(0, alice.pq_revealed)
        self.assertNotEqual(alice.mining_address, addr)

    def test_flag_day_override(self):
        chain, clock = new_chain(pq_emergency_height=3)
        self.assertFalse(chain.pq_active(chain.tip))
        w = Wallet(chain.params, seed=b"q" * 32)
        mine_block(chain, clock, w.mining_address)
        mine_block(chain, clock, w.mining_address)
        self.assertTrue(chain.pq_active(chain.tip))


class TestNetwork(unittest.TestCase):
    def test_three_node_gossip_and_sync(self):
        params = REGTEST
        chains = [Chain(params) for _ in range(3)]
        wallets = [Wallet(params, seed=bytes([65 + i]) * 32) for i in range(3)]
        nodes = [Node(c, wallet=w, name=f"n{i}") for i, (c, w) in enumerate(zip(chains, wallets))]
        try:
            nodes[0].connect("127.0.0.1", nodes[1].port)
            nodes[1].connect("127.0.0.1", nodes[2].port)
            for _ in range(4):
                nodes[0].mine_one()
            wait(lambda: all(c.height == 4 for c in chains))
            tx = wallets[0].create_tx(chains[0], wallets[2].mining_address, 5 * COIN)
            nodes[0].submit_tx(tx)
            wait(lambda: tx.txid in chains[2].mempool)
            nodes[2].mine_one()
            wait(lambda: all(c.height == 5 for c in chains))
            self.assertEqual(len({c.tip.hash for c in chains}), 1)
            self.assertEqual(wallets[2].balance(chains[1])["immature"] > 0, True)
            self.assertIn(5 * COIN, [c.value for c in wallets[2].coins(chains[1]).values()])
        finally:
            for n in nodes:
                n.stop()


def wait(cond, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.05)
    raise AssertionError("timed out waiting for network")


if __name__ == "__main__":
    unittest.main(verbosity=2)
