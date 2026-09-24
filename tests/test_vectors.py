import glob
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "vectors"))

import run as vectors  # noqa: E402
import kairos.chain as chainmod  # noqa: E402
from kairos.tx import Transaction  # noqa: E402


def all_mismatches():
    errs = []
    for f in sorted(glob.glob(os.path.join(HERE, "vectors", "chains", "*.json"))):
        errs += vectors.run_reference(f)[1]
    return errs + vectors.check_functions()[1]


class TestConformanceVectors(unittest.TestCase):
    """tests/vectors is the contract a second implementation must meet. The
    reference must pass it, the files must be exactly what the generator
    produces, and a consensus bug must make it fail."""

    def test_reference_passes(self):
        self.assertEqual(all_mismatches(), [])

    def test_files_match_the_generator(self):
        def digests(root):
            files = sorted(glob.glob(os.path.join(root, "chains", "*.json"))) + [os.path.join(root, "functions.json")]
            out = {}
            for f in files:
                with open(f, "rb") as fh:
                    out[os.path.relpath(f, root)] = hashlib.sha256(fh.read()).hexdigest()
            return out
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, KAIROS_VECTORS_DIR=d)
            subprocess.run([sys.executable, os.path.join(HERE, "vectors", "generate.py")], env=env,
                           check=True, capture_output=True, timeout=600)
            self.assertEqual(digests(d), digests(os.path.join(HERE, "vectors")),
                             "vectors are stale: run python3 tests/vectors/generate.py")

    def test_consensus_bugs_are_caught(self):
        real_verify, real_subsidy = chainmod.verify_witness, chainmod.subsidy
        real_mtp = chainmod.Chain.median_time_past
        real_sighash, real_state = Transaction.sighash, chainmod.Chain._window_state_after

        def no_floor(p, base, size):
            t = p.target_block_size
            return max(p.min_base_fee, base + base * (size - t) // (t * p.base_fee_change_denom))

        def threshold_off_by_one(self, last, dep):
            return real_state(self, last, type(dep)(dep.name, dep.bit, dep.start_height, dep.timeout_height,
                                                    dep.window, dep.threshold + 1))
        bugs = {
            "base fee without the +1 floor": mock.patch.object(chainmod, "next_base_fee", no_floor),
            "Schnorr still valid after activation": mock.patch.object(
                chainmod, "verify_witness", lambda w, a, s, pq=False: real_verify(w, a, s, False)),
            "subsidy one mote higher": mock.patch.object(chainmod, "subsidy", lambda p, g: real_subsidy(p, g) + 1),
            "timestamp equal to the median accepted": mock.patch.object(
                chainmod.Chain, "median_time_past", lambda self, idx: real_mtp(self, idx) - 1),
            "difficulty never retargets": mock.patch.object(
                chainmod.Chain, "expected_bits", lambda self, parent: self.params.asert_anchor_bits
                or self.params.genesis_bits),
            "sighash ignores spent amounts": mock.patch.object(
                Transaction, "sighash", lambda self, cid, spent: real_sighash(self, cid, [(0, a) for _, a in spent])),
            "signalling threshold off by one": mock.patch.object(chainmod.Chain, "_window_state_after",
                                                                 threshold_off_by_one),
        }
        for what, patch in bugs.items():
            with self.subTest(bug=what), patch:
                self.assertNotEqual(all_mismatches(), [], f"vectors did not catch: {what}")


if __name__ == "__main__":
    unittest.main()
