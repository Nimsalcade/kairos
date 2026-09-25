# FROZEN COPY of kairos/wallet.py as released in Kairos 0.4.1 (git tag v0.4.1,
# blob 159a9db742bbbf242a69ec1f1ec9b180d28f84bb). Only its four relative imports are rewritten as absolute
# ones (see SUBSTITUTIONS in tests/test_wallet_compat.py, which checks the blob
# hash). Never edit this file: it stands in for a 0.4.1 node reading wallet files.
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

from kairos import crypto as _crypto

from kairos.crypto import (tagged_hash, pubkey_from_seckey, schnorr_sign, lamport_keygen,
                     lamport_sign, pq_root, bech32m_encode, bech32m_decode, N,
                     LAMPORT_PUB_LEN, LAMPORT_SIG_LEN)
from kairos.params import ChainParams, COIN
from kairos.tx import (Transaction, TxIn, TxOut, OutPoint, make_address,
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
    # A transaction may not exceed half the block size (consensus). A Lamport
    # witness is about 24.6 KB, so a post-quantum payment that needs many
    # inputs is split into several transactions, each under this wallet cap.
    MAX_TX_BYTES = 950_000
    DUST = 1_000                  # change smaller than this is left to the miner

    def create_tx(self, chain, to: bytes, amount: int, tip_per_byte: int = 1,
                  expiry_blocks: int = 0, post_quantum: Optional[bool] = None) -> Transaction:
        """One transaction paying `amount` to `to`. Raises if the payment cannot
        fit in a single transaction (see create_txs)."""
        txs = self.create_txs(chain, to, amount, tip_per_byte, expiry_blocks, post_quantum)
        if len(txs) != 1:
            raise ValueError(f"payment needs {len(txs)} transactions; use create_txs")
        return txs[0]

    def create_txs(self, chain, to: bytes, amount: int, tip_per_byte: int = 1,
                   expiry_blocks: int = 0, post_quantum: Optional[bool] = None) -> List[Transaction]:
        """Transactions paying `amount` to `to` in total. Uses the Lamport path
        automatically once the quantum switch is active on `chain`, unless
        `post_quantum` says otherwise. Schnorr payments are always one
        transaction; Lamport payments may be several."""
        if amount <= 0:
            raise ValueError("amount must be positive")
        pq = chain.pq_active(chain.tip) if post_quantum is None else post_quantum
        coins = {op: c for op, c in self.coins(chain).items() if op not in chain.mempool_spends}
        base_fee = chain.tip.next_base_fee
        if not pq:
            ordered = sorted(coins.items(), key=lambda kv: -kv[1].value)
            selected = []
            for op, c in ordered:
                selected.append((op, c))
                total = sum(cc.value for _, cc in selected)
                tx = self._build(chain, selected, to, amount, total, base_fee, tip_per_byte, expiry_blocks, False)
                if tx is not None:
                    return [tx]
            raise ValueError("insufficient funds")
        # Post-quantum: a Lamport key signs exactly one message, so every coin at an
        # address must be swept in the same transaction. Group by address, fill
        # transactions up to the size cap, stop once the groups cover the amount.
        groups: Dict[bytes, list] = {}
        for op, c in coins.items():
            groups.setdefault(c.address, []).append((op, c))
        ordered = sorted(groups.values(), key=lambda g: -sum(c.value for _, c in g))
        cap = self._pq_inputs_per_tx(expiry_blocks)
        plan, cur = [], []
        for g in ordered:
            if len(g) > cap:
                raise ValueError(f"address {self.encode(g[0][1].address)} holds {len(g)} coins, more "
                                 f"than fit in one post-quantum transaction ({cap}); they cannot be "
                                 f"swept safely (a Lamport key may sign only once)")
            if cur and len(cur) + len(g) > cap:
                plan.append(cur)
                cur = []
            cur.extend(g)
            if self._pq_net(plan + [cur], base_fee, tip_per_byte, expiry_blocks) >= amount:
                plan.append(cur)
                break
        else:
            raise ValueError("insufficient funds")
        txs, left = [], amount
        for i, sel in enumerate(plan):
            total = sum(c.value for _, c in sel)
            if i < len(plan) - 1:
                net = total - (base_fee + tip_per_byte) * self._size(sel, 1, expiry_blocks, True)
                pay = min(net, left)
            else:
                pay = left
            tx = self._build(chain, sel, to, pay, total, base_fee, tip_per_byte, expiry_blocks, True)
            if tx is None:
                raise ValueError("insufficient funds")
            txs.append(tx)
            left -= pay
        assert left == 0
        return txs

    def _size(self, selected, n_outputs: int, expiry_blocks: int, pq: bool) -> int:
        wit_len = (1 + 32 + LAMPORT_PUB_LEN + LAMPORT_SIG_LEN) if pq else (1 + 32 + 32 + 64)
        return Transaction([TxIn(op, b"\x00" * wit_len) for op, _ in selected],
                           [TxOut(1, b"\x00" * 32)] * n_outputs, 1 if expiry_blocks else 0).size

    def _pq_inputs_per_tx(self, expiry_blocks: int) -> int:
        one = self._size([(OutPoint(b"\x00" * 32, 0), None)], 2, expiry_blocks, True)
        two = self._size([(OutPoint(b"\x00" * 32, 0), None), (OutPoint(b"\x00" * 32, 1), None)], 2, expiry_blocks, True)
        return max(1, (self.MAX_TX_BYTES - one) // (two - one) + 1)

    def _pq_net(self, plan, base_fee, tip, expiry_blocks) -> int:
        """What a set of planned sweeps can pay out after fees (two outputs each,
        the conservative case)."""
        rate = base_fee + tip
        return sum(sum(c.value for _, c in sel) - rate * self._size(sel, 2, expiry_blocks, True) for sel in plan)

    def _build(self, chain, selected, to, amount, total, base_fee, tip, expiry_blocks, pq):
        """A signed transaction spending exactly `selected`, or None if they do not
        cover `amount` plus fees. Change below DUST is left to the miner."""
        exp = chain.height + expiry_blocks if expiry_blocks else 0
        rate = base_fee + tip
        # Witness sizes are fixed, so the fee follows from the input and output
        # counts alone and the transaction is signed exactly once. (A Lamport key
        # must never sign two different messages.)
        fee_one = rate * self._size(selected, 1, expiry_blocks, pq)
        excess = total - amount - fee_one
        if excess < 0:
            return None
        outs = [TxOut(amount, to)]
        if excess >= self.DUST:
            change = total - amount - rate * self._size(selected, 2, expiry_blocks, pq)
            if change >= self.DUST:
                change_key = self.keys[self._unused_index()]     # fresh, never-revealed key
                self.used.add(self.keys.index(change_key))       # reserve it now
                self.save()
                outs.append(TxOut(change, change_key.address))
        wit_len = (1 + 32 + LAMPORT_PUB_LEN + LAMPORT_SIG_LEN) if pq else (1 + 32 + 32 + 64)
        tx = Transaction([TxIn(op, b"\x00" * wit_len) for op, _ in selected], outs, exp)
        self._sign(tx, selected, pq)
        return tx

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
