"""
Kairos wallet.

Keys are derived deterministically from a single 32-byte seed, so one backup
restores everything. Each receive address gets its own Schnorr key AND its own
Lamport one-time key; the Lamport key is never revealed unless used.
"""
import hashlib
import hmac
import json
import os
from typing import Dict, List, Optional

from . import crypto as _crypto

from .crypto import (tagged_hash, pubkey_from_seckey, schnorr_sign, lamport_keygen,
                     lamport_sign, pq_root, bech32m_encode, bech32m_decode, N,
                     LAMPORT_PUB_LEN, LAMPORT_SIG_LEN)
from .params import ChainParams, COIN
from .tx import (Transaction, TxIn, TxOut, OutPoint, make_address,
                 schnorr_witness, lamport_witness)


class Key:
    def __init__(self, seed: bytes, i: int):
        ib = i.to_bytes(4, "big")
        d = int.from_bytes(tagged_hash("Kairos/wallet/sk", seed + ib), "big") % (N - 1) + 1
        self.seckey = d.to_bytes(32, "big")
        self.pubkey = pubkey_from_seckey(self.seckey)
        self._pq_seed = tagged_hash("Kairos/wallet/pq", seed + ib)
        self._lamport = None
        self.pqroot = pq_root(self.lamport[1])
        self.address = make_address(self.pubkey, self.pqroot)

    @property
    def lamport(self):
        if self._lamport is None:
            self._lamport = lamport_keygen(self._pq_seed)
        return self._lamport


class Wallet:
    def __init__(self, params: ChainParams, seed: Optional[bytes] = None,
                 n_keys: int = 0, path: Optional[str] = None):
        self.params = params
        self.seed = seed or os.urandom(32)
        self.path = path
        self.passphrase = None
        self.pq_revealed = set()
        self.keys: List[Key] = []
        self.by_addr: Dict[bytes, Key] = {}
        for _ in range(max(n_keys, 1)):
            self._derive()

    # ------------------------------------------------------ persistence
    # File format v2. The seed is encrypted with a passphrase-derived key:
    # scrypt(N=2^17, r=8, p=1) -> 64 bytes = encryption key || MAC key;
    # keystream = HMAC-SHA256(enc_key, nonce || counter) (a PRF in counter mode);
    # tag = HMAC-SHA256(mac_key, header || ciphertext) (encrypt-then-MAC).
    # Only standard-library primitives, each used in its textbook role.

    KDF_N, KDF_R, KDF_P = 2 ** 17, 8, 1

    @staticmethod
    def _kdf(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
        return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                              maxmem=256 * 1024 * 1024, dklen=64)

    @staticmethod
    def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
        out, ctr = b"", 0
        while len(out) < n:
            out += hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
            ctr += 1
        return out[:n]

    @classmethod
    def load(cls, params: ChainParams, path: str, passphrase: Optional[str] = None) -> "Wallet":
        with open(path) as f:
            d = json.load(f)
        if d.get("encrypted"):
            if passphrase is None:
                raise PermissionError("wallet is encrypted: passphrase required")
            salt, nonce = bytes.fromhex(d["salt"]), bytes.fromhex(d["nonce"])
            ct, tag = bytes.fromhex(d["ct"]), bytes.fromhex(d["tag"])
            k = cls._kdf(passphrase, salt, d["n"], d["r"], d["p"])
            header = f"{d['n']}:{d['r']}:{d['p']}".encode() + salt + nonce
            if not hmac.compare_digest(hmac.new(k[32:], header + ct, hashlib.sha256).digest(), tag):
                raise PermissionError("wrong passphrase or corrupted wallet file")
            seed = bytes(a ^ b for a, b in zip(ct, cls._stream(k[:32], nonce, len(ct))))
        else:
            seed = bytes.fromhex(d["seed"])
        w = cls(params, seed, d["n_keys"], path)
        w.passphrase = passphrase
        w.pq_revealed = set(d.get("pq_revealed", []))
        return w

    @classmethod
    def load_or_create(cls, params: ChainParams, path: str, passphrase: Optional[str] = None) -> "Wallet":
        if os.path.exists(path):
            return cls.load(params, path, passphrase)
        w = cls(params, path=path)
        w.passphrase = passphrase
        w.save()
        return w

    def save(self):
        if not self.path:
            return
        d = {"format": 2, "network": self.params.name, "n_keys": len(self.keys),
             "pq_revealed": sorted(self.pq_revealed)}
        if getattr(self, "passphrase", None):
            salt, nonce = os.urandom(16), os.urandom(16)
            n, r, p = self.KDF_N, self.KDF_R, self.KDF_P
            k = self._kdf(self.passphrase, salt, n, r, p)
            ct = bytes(a ^ b for a, b in zip(self.seed, self._stream(k[:32], nonce, 32)))
            header = f"{n}:{r}:{p}".encode() + salt + nonce
            tag = hmac.new(k[32:], header + ct, hashlib.sha256).digest()
            d.update(encrypted=True, n=n, r=r, p=p, salt=salt.hex(), nonce=nonce.hex(),
                     ct=ct.hex(), tag=tag.hex())
        else:
            d.update(encrypted=False, seed=self.seed.hex())
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)          # atomic: never a half-written wallet

    def encrypt(self, passphrase: str):
        if len(passphrase) < 10:
            raise ValueError("passphrase must be at least 10 characters")
        self.passphrase = passphrase
        self.save()

    # ------------------------------------------------------ backup
    def backup_code(self) -> str:
        """Seed as bech32m: any single typo is detected on restore."""
        return bech32m_encode("krsseed", self.seed)

    @classmethod
    def restore(cls, params: ChainParams, code: str, path: str, n_keys: int = 20,
                passphrase: Optional[str] = None) -> "Wallet":
        seed = bech32m_decode("krsseed", code.strip())
        if len(seed) != 32:
            raise ValueError("bad backup code")
        w = cls(params, seed, n_keys, path)
        w.passphrase = passphrase
        w.save()
        return w

    # ------------------------------------------------------ addresses
    def _derive(self) -> Key:
        k = Key(self.seed, len(self.keys))
        self.keys.append(k)
        self.by_addr[k.address] = k
        return k

    def new_address(self) -> str:
        k = self._derive()
        self.save()
        return self.encode(k.address)

    @property
    def mining_address(self) -> bytes:
        """First address whose one-time post-quantum key is still unrevealed."""
        for i, k in enumerate(self.keys):
            if i not in self.pq_revealed:
                return k.address
        return self._derive().address

    def encode(self, addr: bytes) -> str:
        return bech32m_encode(self.params.hrp, addr)

    def decode(self, s: str) -> bytes:
        a = bech32m_decode(self.params.hrp, s)
        if len(a) != 32:
            raise ValueError("bad address length")
        return a

    # ------------------------------------------------------ balance
    def coins(self, chain, include_immature=False):
        coins = chain.coins_for(self.by_addr)
        h = chain.height + 1
        return {op: c for op, c in coins.items()
                if include_immature or not c.coinbase
                or h - c.height >= self.params.coinbase_maturity}

    def balance(self, chain) -> dict:
        spendable = sum(c.value for c in self.coins(chain).values())
        total = sum(c.value for c in self.coins(chain, True).values())
        return {"spendable": spendable, "immature": total - spendable}

    # ------------------------------------------------------ spending
    def create_tx(self, chain, to: bytes, amount: int, tip_per_byte: int = 1,
                  expiry_blocks: int = 0, post_quantum: bool = False) -> Transaction:
        if amount <= 0:
            raise ValueError("amount must be positive")
        coins = {op: c for op, c in self.coins(chain).items() if op not in chain.mempool_spends}
        base_fee = chain.tip.next_base_fee
        ordered = sorted(coins.items(), key=lambda kv: -kv[1].value)
        selected = []
        for op, c in ordered:
            selected.append((op, c))
            if post_quantum:
                # A Lamport key may sign only one message ever, so an emergency
                # spend must sweep EVERY coin at each address it touches.
                addrs = {x[1].address for x in selected}
                selected = [(o, cc) for o, cc in ordered if cc.address in addrs]
            total = sum(cc.value for _, cc in selected)
            tx = self._build(chain, selected, to, amount, total, base_fee, tip_per_byte,
                             expiry_blocks, post_quantum)
            if tx is not None:
                if post_quantum:
                    self.save()
                return tx
        raise ValueError("insufficient funds")

    def _build(self, chain, selected, to, amount, total, base_fee, tip, expiry_blocks, pq):
        exp = chain.height + expiry_blocks if expiry_blocks else 0
        # Witness sizes are fixed, so size the tx with placeholders and sign
        # exactly once. (A Lamport key must never sign two different messages.)
        wit_len = (1 + 32 + LAMPORT_PUB_LEN + LAMPORT_SIG_LEN) if pq else (1 + 32 + 32 + 64)
        change_key = None
        fee = 0
        for _ in range(4):   # fee depends on size, size depends on change output
            change = total - amount - fee
            if change < 0:
                return None
            outs = [TxOut(amount, to)]
            if change > 0:
                if change_key is None:
                    change_key = self._derive()     # always a fresh, never-revealed key
                    self.save()
                outs.append(TxOut(change, change_key.address))
            tx = Transaction([TxIn(op, b"\x00" * wit_len) for op, _ in selected], outs, exp)
            need = (base_fee + tip) * tx.size
            if fee >= need:
                self._sign(tx, selected, pq)
                return tx
            fee = need
        return None

    def _sign(self, tx: Transaction, selected, pq: bool):
        if self.params.name == "main" and not _crypto.HARDENED:
            raise RuntimeError("refusing to sign on mainnet without libsecp256k1: "
                               "pip install coincurve")
        sh = tx.sighash(self.params.chain_id)
        for inp, (op, c) in zip(tx.inputs, selected):
            k = self.by_addr[c.address]
            if pq:
                idx = self.keys.index(k)
                if idx in self.pq_revealed and getattr(k, "_pq_signed", None) != sh:
                    raise RuntimeError("this address's one-time key was already used")
                sk, lpub = k.lamport
                inp.witness = lamport_witness(k.pubkey, lpub, lamport_sign(sh, sk))
                k._pq_signed = sh
                self.pq_revealed.add(idx)
            else:
                inp.witness = schnorr_witness(k.pubkey, k.pqroot, schnorr_sign(sh, k.seckey, os.urandom(32)))
        tx.invalidate()


def fmt(motes: int) -> str:
    return f"{motes / COIN:,.8f} KRS"
