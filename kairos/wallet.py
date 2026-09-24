"""
Kairos wallet.

Keys are derived deterministically from a single 32-byte seed, so one backup
restores everything. Each receive address gets its own Schnorr key AND its own
Lamport one-time key; the Lamport key is never revealed unless used.

Address hygiene: every mined block, every payment and every change output goes
to a fresh address, so a Schnorr public key is revealed on the wire at most
once (when its coins are spent). A restored wallet finds its addresses again
by scanning the chain with a gap limit, like BIP44 wallets do.
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

GAP_LIMIT = 20


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
        self._enc = None             # (salt, derived key) cached so saves do not re-run scrypt
        self.pq_revealed = set()     # key indices whose Lamport key has signed (never again)
        self.used = set()            # key indices that have received coins on chain
        self.chain = None
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
        enc = None
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
            if (d["n"], d["r"], d["p"]) == (cls.KDF_N, cls.KDF_R, cls.KDF_P):
                enc = (salt, k)
        else:
            seed = bytes.fromhex(d["seed"])
        w = cls(params, seed, d["n_keys"], path)
        w.passphrase = passphrase
        w._enc = enc
        w.pq_revealed = set(d.get("pq_revealed", []))
        w.used = set(d.get("used", []))
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
             "pq_revealed": sorted(self.pq_revealed), "used": sorted(self.used)}
        if getattr(self, "passphrase", None):
            n, r, p = self.KDF_N, self.KDF_R, self.KDF_P
            if self._enc is None:
                salt = os.urandom(16)
                self._enc = (salt, self._kdf(self.passphrase, salt, n, r, p))
            salt, k = self._enc
            nonce = os.urandom(16)
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
        self._enc = None
        self.save()

    # ------------------------------------------------------ backup
    def backup_code(self) -> str:
        """Seed as bech32m: any single typo is detected on restore."""
        return bech32m_encode("krsseed", self.seed)

    @classmethod
    def restore(cls, params: ChainParams, code: str, path: str, n_keys: int = GAP_LIMIT,
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

    def _unused_index(self) -> int:
        for i in range(len(self.keys)):
            if i not in self.used and i not in self.pq_revealed:
                return i
        self._derive()
        self.save()
        return len(self.keys) - 1

    @property
    def mining_address(self) -> bytes:
        """A fresh address: never paid, its one-time post-quantum key unrevealed.
        Once a block or payment lands on it, the next call moves to the next one."""
        return self.keys[self._unused_index()].address

    receive_address = mining_address

    def encode(self, addr: bytes) -> str:
        return bech32m_encode(self.params.hrp, addr)

    def decode(self, s: str) -> bytes:
        a = bech32m_decode(self.params.hrp, s)
        if len(a) != 32:
            raise ValueError("bad address length")
        return a

    # ------------------------------------------------------ chain tracking
    def attach(self, chain, gap: int = GAP_LIMIT):
        """Follow a chain: rescan history for our addresses (deriving past the
        gap limit until `gap` consecutive addresses are unused) and keep the
        used-set current as blocks connect."""
        self.chain = chain
        self.rescan(chain, gap)
        chain.listeners.append(self._on_chain_event)

    def rescan(self, chain, gap: int = GAP_LIMIT):
        with chain.lock:
            seen = {c.address for c in chain.utxos.values()}
            for idx in chain.active[1:]:
                blk = chain.blocks.get(idx.hash)          # None below a fast-sync snapshot
                if blk is None:
                    continue
                for tx in blk.txs:
                    for o in tx.outputs:
                        seen.add(o.address)
            while True:
                for i, k in enumerate(self.keys):
                    if k.address in seen:
                        self.used.add(i)
                last_used = max(self.used) if self.used else -1
                if len(self.keys) - 1 - last_used >= gap:
                    break
                self._derive()
        self.save()

    def _on_chain_event(self, event, idx):
        if event != "tip":
            return
        blk = self.chain.blocks.get(idx.hash)
        if blk is None:                                    # a fast-sync snapshot was adopted
            self.rescan(self.chain)
            return
        hit = False
        for tx in blk.txs:
            for o in tx.outputs:
                k = self.by_addr.get(o.address)
                if k is not None:
                    i = self.keys.index(k)
                    if i not in self.used:
                        self.used.add(i)
                        hit = True
        if hit:
            if len(self.keys) - 1 - max(self.used) < GAP_LIMIT:
                self._derive()
            self.save()

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
                    change_key = self.keys[self._unused_index()]   # fresh, never-revealed key
                    self.used.add(self.keys.index(change_key))     # reserve it now
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
        sh = tx.sighash(self.params.chain_id, [(c.value, c.address) for _, c in selected])
        if pq:
            # Record every one-time key as spent BEFORE any signature exists, so a
            # crash between signing and saving can never lead to a second signature.
            idxs = []
            for _, c in selected:
                k = self.by_addr[c.address]
                i = self.keys.index(k)
                if i in self.pq_revealed and getattr(k, "_pq_signed", None) != sh:
                    raise RuntimeError("this address's one-time key was already used")
                idxs.append(i)
            self.pq_revealed.update(idxs)
            self.save()
        for inp, (op, c) in zip(tx.inputs, selected):
            k = self.by_addr[c.address]
            if pq:
                sk, lpub = k.lamport
                inp.witness = lamport_witness(k.pubkey, lpub, lamport_sign(sh, sk))
                k._pq_signed = sh
            else:
                inp.witness = schnorr_witness(k.pubkey, k.pqroot, schnorr_sign(sh, k.seckey, os.urandom(32)))
        tx.invalidate()


def fmt(motes: int) -> str:
    return f"{motes / COIN:,.8f} KRS"
