import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kairos import musig as M
from kairos.crypto import schnorr_verify, tagged_hash
from kairos.params import REGTEST, COIN
from kairos.tx import OutPoint, Transaction, TxIn, TxOut, schnorr_witness
from kairos.wallet import Wallet

from test_kairos import new_chain, mine_block

D = os.path.join(os.path.dirname(__file__), "data", "bip327")


def load(name):
    with open(os.path.join(D, name + "_vectors.json")) as f:
        return json.load(f)


def h(x):
    return bytes.fromhex(x)


class TestBip327Vectors(unittest.TestCase):
    """kairos/musig.py against every official BIP327 test vector."""

    def check_error(self, err, fn):
        if err["type"] == "invalid_contribution":
            with self.assertRaises(M.InvalidContributionError) as cm:
                fn()
            self.assertEqual(cm.exception.signer, err.get("signer"))
            self.assertEqual(cm.exception.contrib, err["contrib"])
        else:
            with self.assertRaises(ValueError):
                fn()

    def test_key_sort(self):
        v = load("key_sort")
        self.assertEqual(M.key_sort([h(x) for x in v["pubkeys"]]), [h(x) for x in v["sorted_pubkeys"]])

    def test_key_agg(self):
        v = load("key_agg")
        pks = [h(x) for x in v["pubkeys"]]
        for c in v["valid_test_cases"]:
            self.assertEqual(M.get_xonly_pubkey(M.key_agg([pks[i] for i in c["key_indices"]])), h(c["expected"]))
        tw = [h(x) for x in v["tweaks"]]
        for c in v["error_test_cases"]:
            def run(c=c):
                ctx = M.key_agg([pks[i] for i in c["key_indices"]])
                for i, x in zip(c["tweak_indices"], c["is_xonly"]):
                    ctx = M.apply_tweak(ctx, tw[i], x)
            self.check_error(c["error"], run)

    def test_nonce_gen(self):
        for c in load("nonce_gen")["test_cases"]:
            get = lambda k: h(c[k]) if c[k] is not None else None  # noqa: E731
            sec, pub = M.nonce_gen_internal(h(c["rand_"]), get("sk"), h(c["pk"]), get("aggpk"), get("msg"),
                                            get("extra_in"))
            self.assertEqual(bytes(sec), h(c["expected_secnonce"]))
            self.assertEqual(pub, h(c["expected_pubnonce"]))

    def test_nonce_agg(self):
        v = load("nonce_agg")
        pn = [h(x) for x in v["pnonces"]]
        for c in v["valid_test_cases"]:
            self.assertEqual(M.nonce_agg([pn[i] for i in c["pnonce_indices"]]), h(c["expected"]))
        for c in v["error_test_cases"]:
            self.check_error(c["error"], lambda c=c: M.nonce_agg([pn[i] for i in c["pnonce_indices"]]))

    def test_sign_and_verify(self):
        v = load("sign_verify")
        sk, pks = h(v["sk"]), [h(x) for x in v["pubkeys"]]
        secnonces, pnonces = [h(x) for x in v["secnonces"]], [h(x) for x in v["pnonces"]]
        aggnonces, msgs = [h(x) for x in v["aggnonces"]], [h(x) for x in v["msgs"]]
        for c in v["valid_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            nonces = [pnonces[i] for i in c["nonce_indices"]]
            self.assertEqual(M.nonce_agg(nonces), aggnonces[c["aggnonce_index"]])
            s = M.SessionContext(aggnonces[c["aggnonce_index"]], keys, [], [], msgs[c["msg_index"]])
            psig = M.sign(bytearray(secnonces[0]), sk, s)
            self.assertEqual(psig, h(c["expected"]))
            self.assertTrue(M.partial_sig_verify(psig, nonces, keys, [], [], msgs[c["msg_index"]],
                                                 c["signer_index"]))
        for c in v["sign_error_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            s = M.SessionContext(aggnonces[c["aggnonce_index"]], keys, [], [], msgs[c["msg_index"]])
            self.check_error(c["error"], lambda s=s, c=c: M.sign(bytearray(secnonces[c["secnonce_index"]]), sk, s))
        for c in v["verify_fail_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            nonces = [pnonces[i] for i in c["nonce_indices"]]
            self.assertFalse(M.partial_sig_verify(h(c["sig"]), nonces, keys, [], [], msgs[c["msg_index"]],
                                                  c["signer_index"]))
        for c in v["verify_error_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            nonces = [pnonces[i] for i in c["nonce_indices"]]
            self.check_error(c["error"], lambda c=c, keys=keys, nonces=nonces: M.partial_sig_verify(
                h(c["sig"]), nonces, keys, [], [], msgs[c["msg_index"]], c["signer_index"]))

    def test_tweaks(self):
        v = load("tweak")
        sk, pks, pn = h(v["sk"]), [h(x) for x in v["pubkeys"]], [h(x) for x in v["pnonces"]]
        tw, msg, agg = [h(x) for x in v["tweaks"]], h(v["msg"]), h(v["aggnonce"])
        self.assertEqual(M.nonce_agg(pn), agg)
        for c in v["valid_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            tws = [tw[i] for i in c["tweak_indices"]]
            s = M.SessionContext(agg, keys, tws, c["is_xonly"], msg)
            psig = M.sign(bytearray(h(v["secnonce"])), sk, s)
            self.assertEqual(psig, h(c["expected"]), c.get("comment"))
            self.assertTrue(M.partial_sig_verify(psig, [pn[i] for i in c["nonce_indices"]], keys, tws,
                                                 c["is_xonly"], msg, c["signer_index"]))
        for c in v["error_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            s = M.SessionContext(agg, keys, [tw[i] for i in c["tweak_indices"]], c["is_xonly"], msg)
            self.check_error(c["error"], lambda s=s: M.sign(bytearray(h(v["secnonce"])), sk, s))

    def test_sig_agg(self):
        v = load("sig_agg")
        pks, pn = [h(x) for x in v["pubkeys"]], [h(x) for x in v["pnonces"]]
        tw, ps, msg = [h(x) for x in v["tweaks"]], [h(x) for x in v["psigs"]], h(v["msg"])
        for c in v["valid_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            self.assertEqual(M.nonce_agg([pn[i] for i in c["nonce_indices"]]), h(c["aggnonce"]))
            tws = [tw[i] for i in c["tweak_indices"]]
            s = M.SessionContext(h(c["aggnonce"]), keys, tws, c["is_xonly"], msg)
            sig = M.partial_sig_agg([ps[i] for i in c["psig_indices"]], s)
            self.assertEqual(sig, h(c["expected"]))
            ctx = M.key_agg(keys)
            for t, x in zip(tws, c["is_xonly"]):
                ctx = M.apply_tweak(ctx, t, x)
            self.assertTrue(schnorr_verify(msg, M.get_xonly_pubkey(ctx), sig))
        for c in v["error_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            s = M.SessionContext(h(c["aggnonce"]), keys, [tw[i] for i in c["tweak_indices"]], c["is_xonly"], msg)
            self.check_error(c["error"], lambda s=s, c=c: M.partial_sig_agg([ps[i] for i in c["psig_indices"]], s))

    def test_deterministic_sign(self):
        v = load("det_sign")
        sk, pks, msgs = h(v["sk"]), [h(x) for x in v["pubkeys"]], [h(x) for x in v["msgs"]]
        for c in v["valid_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            rand = h(c["rand"]) if c["rand"] is not None else None
            pub, psig = M.deterministic_sign(sk, h(c["aggothernonce"]), keys, [h(t) for t in c["tweaks"]],
                                             c["is_xonly"], msgs[c["msg_index"]], rand)
            self.assertEqual((pub, psig), (h(c["expected"][0]), h(c["expected"][1])))
        for c in v["error_test_cases"]:
            keys = [pks[i] for i in c["key_indices"]]
            rand = h(c["rand"]) if c["rand"] is not None else None
            self.check_error(c["error"], lambda c=c, keys=keys, rand=rand: M.deterministic_sign(
                sk, h(c["aggothernonce"]), keys, [h(t) for t in c["tweaks"]], c["is_xonly"],
                msgs[c["msg_index"]], rand))


class TestMusigOnKairos(unittest.TestCase):
    """A 3-of-3 MuSig2 output is an ordinary Kairos address: it is paid, then
    spent with one 64-byte Schnorr signature, with no consensus change."""

    def test_three_party_output_spent_on_chain(self):
        chain, clock = new_chain()
        funder = Wallet(REGTEST, seed=b"f" * 32)
        for _ in range(3):
            mine_block(chain, clock, funder.mining_address)
        sks = [tagged_hash("Kairos/test/musig", bytes([i])) for i in range(3)]
        pks = M.key_sort([M.individual_pubkey(sk) for sk in sks])
        addr, agg = M.musig_address(pks, M.UNSPENDABLE_PQ_ROOT)
        pay = funder.create_tx(chain, addr, 5 * COIN)
        self.assertTrue(chain.accept_tx(pay))
        mine_block(chain, clock, funder.mining_address)
        op = OutPoint(pay.txid, [o.address for o in pay.outputs].index(addr))
        coin = chain.utxos[op]
        bob = Wallet(REGTEST, seed=b"b" * 32)
        tx = Transaction([TxIn(op)], [TxOut(coin.value - 10_000, bob.mining_address)])
        tx.inputs[0].witness = b"\x00" * 129
        msg = tx.sighash(REGTEST.chain_id, [(coin.value, coin.address)])
        by_pk = {M.individual_pubkey(sk): sk for sk in sks}
        rounds = [M.nonce_gen(by_pk[pk], pk, agg, msg) for pk in pks]
        session = M.SessionContext(M.nonce_agg([p for _, p in rounds]), pks, [], [], msg)
        psigs = [M.sign(sec, by_pk[pk], session) for (sec, _), pk in zip(rounds, pks)]
        with self.assertRaises(ValueError):
            M.sign(rounds[0][0], by_pk[pks[0]], session)          # a secret nonce signs once
        sig = M.partial_sig_agg(psigs, session)
        tx.inputs[0].witness = schnorr_witness(agg, M.UNSPENDABLE_PQ_ROOT, sig)
        tx.invalidate()
        self.assertTrue(chain.accept_tx(tx))
        mine_block(chain, clock, funder.mining_address)
        self.assertEqual(bob.balance(chain)["spendable"], coin.value - 10_000)


if __name__ == "__main__":
    unittest.main()
