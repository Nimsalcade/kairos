"""Wallet files across versions.

A 0.4.1 node must never open an HD wallet: it ignores "scheme", derives legacy
keys from the BIP39 seed and shows addresses the HD wallet never scans, so
coins received meanwhile would seem lost. And legacy wallets must keep opening
in 0.4.1 after 0.4.2 has saved them. tests/data/wallet_v0_4_1.py is the
released 0.4.1 wallet module, frozen, standing in for a 0.4.1 node.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))

from kairos import hd
from kairos.params import TESTNET, REGTEST
from kairos.wallet import Wallet

FROZEN = os.path.join(HERE, "data", "wallet_v0_4_1.py")
V041_BLOB = "159a9db742bbbf242a69ec1f1ec9b180d28f84bb"     # git rev-parse v0.4.1:kairos/wallet.py
SUBSTITUTIONS = [("from . import crypto as _crypto", "from kairos import crypto as _crypto"),
                 ("from .crypto import (", "from kairos.crypto import ("),
                 ("from .params import ", "from kairos.params import "),
                 ("from .tx import (", "from kairos.tx import (")]


def load_frozen():
    spec = importlib.util.spec_from_file_location("wallet_v0_4_1", FROZEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Wallet


Old = load_frozen()
PW = "correct horse battery"


def addrs(w, n=3):
    return [w.keys[i].address for i in range(n)]


def read(path):
    with open(path, "rb") as f:
        return f.read()


class TestWalletCompatibility(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.d, name)

    def test_frozen_copy_is_the_released_file(self):
        with open(FROZEN) as f:
            text = f.read()
        body = text[text.index('"""'):]                     # drop the provenance comment
        for released, frozen in SUBSTITUTIONS:
            self.assertEqual(body.count(frozen), 1)
            body = body.replace(frozen, released)
        data = body.encode()
        self.assertEqual(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(), V041_BLOB)

    def test_0_4_1_refuses_new_hd_wallets(self):
        for pw in (None, PW):
            p = self.path(f"hd-{bool(pw)}.json")
            w, _ = Wallet.create_hd(TESTNET, p, passphrase=pw, n_keys=3)
            before = read(p)
            with open(p) as f:
                self.assertEqual(json.load(f)["format"], 3)
            with self.assertRaises(KeyError):
                Old.load(TESTNET, p, pw)
            with self.assertRaises(KeyError):
                Old.load_or_create(TESTNET, p, pw)
            self.assertEqual(read(p), before)                  # refused, and left untouched
            self.assertEqual(addrs(Wallet.load(TESTNET, p, pw)), addrs(w))

    def test_legacy_files_open_both_ways(self):
        for pw in (None, PW):
            p = self.path(f"legacy-{bool(pw)}.json")
            old = Old(TESTNET, n_keys=3, path=p)
            old.passphrase = pw
            old.save()
            with open(p) as f:
                fields_041 = set(json.load(f))
            new = Wallet.load(TESTNET, p, pw)                  # 0.4.2 opens a 0.4.1 file
            self.assertEqual((new.scheme, addrs(new)), ("legacy", addrs(old)))
            new.new_address()                                  # ...and saves it
            with open(p) as f:
                d = json.load(f)
            self.assertEqual((d["format"], set(d)), (2, fields_041))
            again = Old.load(TESTNET, p, pw)                   # 0.4.1 still opens it
            self.assertEqual(again.seed, old.seed)
            self.assertEqual(addrs(again, 4), addrs(new, 4))

    def interim_hd_file(self, p, pw):
        """An HD wallet as this PR wrote it before format 3: format 2, secrets
        under the legacy field names, which 0.4.1 reads."""
        entropy = os.urandom(32)
        seed = hd.mnemonic_to_seed(hd.entropy_to_mnemonic(entropy))
        blob = seed + entropy
        d = {"format": 2, "network": "test", "n_keys": 3, "pq_revealed": [], "used": [],
             "scheme": "bip32", "account": 0}
        if pw:
            n, r, q = Wallet.KDF_N, Wallet.KDF_R, Wallet.KDF_P
            salt, nonce = os.urandom(16), os.urandom(16)
            k = Wallet._kdf(pw, salt, n, r, q)
            ct = bytes(a ^ b for a, b in zip(blob, Wallet._stream(k[:32], nonce, len(blob))))
            tag = hmac.new(k[32:], f"{n}:{r}:{q}".encode() + salt + nonce + ct, hashlib.sha256).digest()
            d.update(encrypted=True, n=n, r=r, p=q, salt=salt.hex(), nonce=nonce.hex(), ct=ct.hex(), tag=tag.hex())
        else:
            d.update(encrypted=False, seed=seed.hex(), entropy=entropy.hex())
        with open(p, "w") as f:
            json.dump(d, f)
        return seed

    def test_interim_hd_file_is_rewritten_so_0_4_1_refuses_it(self):
        for pw in (None, PW):
            p = self.path(f"interim-{bool(pw)}.json")
            seed = self.interim_hd_file(p, pw)
            right = addrs(Wallet(TESTNET, seed, 3, scheme="bip32"))
            self.assertNotEqual(addrs(Old.load(TESTNET, p, pw)), right)    # the hazard: wrong addresses
            w = Wallet.load(TESTNET, p, pw)
            self.assertEqual(addrs(w), right)
            with open(p) as f:
                self.assertEqual(json.load(f)["format"], 3)                # rewritten on first open
            with self.assertRaises(KeyError):
                Old.load(TESTNET, p, pw)

    def test_future_formats_and_tampering_are_refused(self):
        p = self.path("future.json")
        Wallet.create_hd(REGTEST, p)
        with open(p) as f:
            d = json.load(f)
        d["format"] = 4
        with open(p, "w") as f:
            json.dump(d, f)
        with self.assertRaisesRegex(ValueError, "newer version"):
            Wallet.load(REGTEST, p)
        p = self.path("tamper.json")
        Wallet.create_hd(REGTEST, p, passphrase=PW)
        with open(p) as f:
            d = json.load(f)
        d["account"] = 1                                   # would derive other keys
        with open(p, "w") as f:
            json.dump(d, f)
        with self.assertRaises(PermissionError):
            Wallet.load(REGTEST, p, PW)


if __name__ == "__main__":
    unittest.main()
