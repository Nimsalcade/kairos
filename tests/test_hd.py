import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos import hd
from kairos.chain import Chain
from kairos.params import REGTEST, COIN
from kairos.tx import WIT_LAMPORT, WIT_SCHNORR
from kairos.wallet import Wallet, Key, GAP_LIMIT

from test_kairos import new_chain, mine_block

with open(os.path.join(os.path.dirname(__file__), "data", "hd_vectors.json")) as f:
    V = json.load(f)


class TestStandards(unittest.TestCase):
    """hd.py reproduces the official BIP32 and BIP39 test vectors exactly."""

    def test_bip32_vectors(self):
        n = 0
        for vec in V["bip32"]:
            root = hd.ExtKey.from_seed(bytes.fromhex(vec["seed"]))
            prev = None
            for c in vec["chains"]:
                k = root.derive_path(c["path"])
                self.assertEqual(k.serialize(), c["xprv"], c["path"])
                self.assertEqual(k.neuter().serialize(), c["xpub"], c["path"])
                self.assertEqual(hd.ExtKey.parse(c["xprv"]).serialize(), c["xprv"])
                self.assertEqual(hd.ExtKey.parse(c["xpub"]).serialize(), c["xpub"])
                last = c["path"].split("/")[-1]
                if prev is not None and not last.endswith("'"):         # public derivation agrees
                    self.assertEqual(prev.neuter().derive(int(last)).serialize(), c["xpub"])
                prev = k
                n += 1
        self.assertEqual(n, 17)

    def test_bip32_invalid_keys_rejected(self):
        self.assertEqual(len(V["bip32_invalid"]), 16)
        for x in V["bip32_invalid"]:
            with self.assertRaises(ValueError, msg=x["why"]):
                hd.ExtKey.parse(x["key"])

    def test_bip39_vectors(self):
        for x in V["bip39"]:
            self.assertEqual(hd.entropy_to_mnemonic(bytes.fromhex(x["entropy"])), x["mnemonic"])
            self.assertEqual(hd.mnemonic_to_entropy(x["mnemonic"]).hex(), x["entropy"])
            seed = hd.mnemonic_to_seed(x["mnemonic"], "TREZOR")
            self.assertEqual(seed.hex(), x["seed"])
            self.assertEqual(hd.ExtKey.from_seed(seed).serialize(), x["xprv"])

    def test_wordlist_and_checksum(self):
        import hashlib
        from kairos.bip39_words import WORDS
        self.assertEqual(hashlib.sha256(("\n".join(WORDS) + "\n").encode()).hexdigest(),
                         "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
        words = V["bip39"][0]["mnemonic"].split()
        words[3] = "zoo" if words[3] != "zoo" else "abandon"
        with self.assertRaisesRegex(ValueError, "checksum"):
            hd.mnemonic_to_entropy(" ".join(words))
        with self.assertRaisesRegex(ValueError, "unknown word"):
            hd.mnemonic_to_entropy("kairos " + " ".join(words[1:]))

    def test_ripemd160_fallback(self):
        for m, h in ((b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
                     (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
                     (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
                     (b"a" * 1_000_000, "52783243c1697bdbe16d37f97f68f08325dc1528")):
            self.assertEqual(hd._ripemd160_py(m).hex(), h)


class TestHdWallet(unittest.TestCase):
    """New wallets derive their keys by BIP32 from BIP39 words, so a hardware
    wallet holding the same words holds the same keys. Old wallets are untouched."""

    def test_keys_follow_the_standard_path(self):
        w, words = Wallet.create_hd(REGTEST, n_keys=3)
        self.assertEqual(len(words.split()), 24)
        root = hd.ExtKey.from_seed(hd.mnemonic_to_seed(words))
        for i in range(3):
            child = root.derive_path(f"m/44'/1'/0'/0/{i}")
            self.assertEqual(w.keys[i].seckey, child.secret)
            self.assertEqual(w.keys[i].pubkey, child.pub33[1:])      # BIP340 x-only = BIP32 key's x
            self.assertEqual(w.keys[i]._pq_seed, hd.pq_seed(child.secret))
        main = Wallet(replace(REGTEST, name="main"), w.seed, 1, scheme="bip32")
        self.assertEqual(main.keys[0].seckey, root.derive_path("m/44'/19282'/0'/0/0").secret)

    def test_restore_from_words_and_typo(self):
        w, words = Wallet.create_hd(REGTEST, n_keys=5)
        r = Wallet.restore(REGTEST, words, None, n_keys=5)
        self.assertEqual([k.address for k in r.keys], [k.address for k in w.keys])
        self.assertEqual(r.backup_code(), words)
        bad = words.split()
        bad[0], bad[1] = bad[1], bad[0]
        if bad != words.split():
            with self.assertRaises(ValueError):
                Wallet.restore(REGTEST, " ".join(bad), None)
        p = Wallet.restore_mnemonic(REGTEST, words, None, bip39_passphrase="extra", n_keys=1)
        self.assertNotEqual(p.keys[0].address, w.keys[0].address)   # a BIP39 passphrase is another wallet
        with self.assertRaisesRegex(ValueError, "passphrase"):
            p.backup_code()

    def test_files_roundtrip_plain_and_encrypted_and_legacy_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            w, words = Wallet.create_hd(REGTEST, path, n_keys=4)
            again = Wallet.load(REGTEST, path)
            self.assertEqual((again.scheme, again.backup_code()), ("bip32", words))
            self.assertEqual([k.address for k in again.keys], [k.address for k in w.keys])
            w.encrypt("correct horse battery")
            with open(path) as f:
                raw = f.read()
            self.assertNotIn(w.seed.hex()[:40], raw)
            self.assertNotIn(w.seed.hex()[-40:], raw)                  # all 64 bytes are encrypted
            enc = Wallet.load(REGTEST, path, "correct horse battery")
            self.assertEqual([k.address for k in enc.keys], [k.address for k in w.keys])
            self.assertEqual(enc.backup_code(), words)
            # a 0.4 wallet file has no scheme: same derivation as before
            legacy_path = os.path.join(d, "old.json")
            seed = b"\x11" * 32
            with open(legacy_path, "w") as f:
                json.dump({"format": 2, "network": "regtest", "n_keys": 3, "pq_revealed": [], "used": [],
                           "encrypted": False, "seed": seed.hex()}, f)
            old = Wallet.load(REGTEST, legacy_path)
            self.assertEqual(old.scheme, "legacy")
            self.assertEqual([k.address for k in old.keys], [Key(seed, i).address for i in range(3)])
            self.assertTrue(old.backup_code().startswith("krsseed1"))

    def test_new_wallets_are_hd(self):
        with tempfile.TemporaryDirectory() as d:
            w = Wallet.load_or_create(REGTEST, os.path.join(d, "w.json"))
            self.assertEqual(w.scheme, "bip32")
            self.assertEqual(len(w.backup_code().split()), 24)

    def test_xpub_gives_keys_but_not_addresses(self):
        w, _ = Wallet.create_hd(REGTEST, n_keys=2)
        xpub = hd.ExtKey.parse(w.xpub())
        self.assertTrue(w.xpub().startswith("tpub"))
        for i in range(2):
            self.assertEqual(xpub.derive(0).derive(i).pub33[1:], w.keys[i].pubkey)

    def test_hd_wallet_spends_with_schnorr_and_lamport(self):
        chain, clock = new_chain()
        w, _ = Wallet.create_hd(REGTEST)
        w.attach(chain)
        chain.signal.add("pq")
        bob = Wallet(REGTEST, seed=b"b" * 32)
        for _ in range(4):
            mine_block(chain, clock, w.mining_address)
        tx = w.create_txs(chain, bob.mining_address, COIN)[0]
        self.assertEqual(tx.inputs[0].witness[0], WIT_SCHNORR)
        self.assertTrue(chain.accept_tx(tx))
        while not chain.pq_active(chain.tip):
            mine_block(chain, clock, w.mining_address)
        tx = w.create_txs(chain, bob.mining_address, COIN)[0]
        self.assertEqual(tx.inputs[0].witness[0], WIT_LAMPORT)
        self.assertTrue(chain.accept_tx(tx))
        mine_block(chain, clock, w.mining_address)
        self.assertEqual(bob.balance(chain)["spendable"], 2 * COIN)


if __name__ == "__main__":
    unittest.main()
