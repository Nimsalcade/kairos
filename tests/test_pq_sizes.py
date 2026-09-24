import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import pq_sizes
from kairos.crypto import tagged_hash
from kairos.params import REGTEST
from kairos.tx import make_address
from kairos.wallet import Wallet


class TestPqSizes(unittest.TestCase):
    """The figures in docs/pq-scaling.md come from tools/pq_sizes.py. These
    checks keep them honest: every in-tool scheme signs and verifies, the
    standards' formulas reproduce their published tables, and compressed
    Lamport verifies against addresses that already exist."""

    def test_compressed_lamport_fits_existing_addresses(self):
        w = Wallet(REGTEST, seed=b"c" * 32)
        key = w.keys[0]
        sk, pub = key.lamport
        msg = tagged_hash("Kairos/test", b"spend")
        sig = pq_sizes.lamport_compressed_sign(msg, sk)
        self.assertEqual(len(sig), 16_384)
        self.assertTrue(pq_sizes.lamport_compressed_verify(msg, sig, key.pqroot))
        self.assertEqual(make_address(key.pubkey, key.pqroot), key.address)
        bad = bytearray(sig)
        bad[100] ^= 1
        self.assertFalse(pq_sizes.lamport_compressed_verify(msg, bytes(bad), key.pqroot))

    def test_every_row_is_measured_or_checked(self):
        rows = pq_sizes.measure(quick=True)
        names = {r["name"] for r in rows}
        for want in ("Lamport (deployed)", "WOTS+ n=32 w=16", "SLH-DSA-SHA2-128s", "ML-DSA-44"):
            self.assertIn(want, names)
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["Lamport (deployed)"]["witness"], 24_609)
        self.assertEqual(by["WOTS+ n=32 w=16"]["sig"], 67 * 32)
        self.assertEqual(by["SLH-DSA-SHA2-128s"]["sig"], 7_856)
        self.assertEqual(by["Lamport (deployed)"]["per_block"], 81)
        # smaller witnesses always fit more inputs per block
        rows.sort(key=lambda r: r["witness"])
        self.assertEqual([r["per_block"] for r in rows], sorted((r["per_block"] for r in rows), reverse=True))
        cr = pq_sizes.commit_reveal_rows()
        self.assertGreater(cr[0]["per_block"], 100 * by["Lamport (deployed)"]["per_block"])


if __name__ == "__main__":
    unittest.main()
