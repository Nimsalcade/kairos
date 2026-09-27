"""
Kairos wallet.

Keys are derived deterministically from a single 32-byte seed, so one backup
restores everything. Each receive address gets its own Schnorr key AND its own
Lamport one-time key; the Lamport key is never revealed unless used.

Rules-2 networks (testnet 3, mainnet) replace the Lamport key with one
SLH-DSA key per wallet (per account for HD wallets): it is stateless, so it
can sign any number of times. Each address commits to it through its own salt,
so addresses stay unlinkable until an SLH-DSA spend reveals the key. Once the
quantum switch is active a payment either signs with SLH-DSA (immediate, about
8 KB per input) or goes through commit-delay-reveal (two transactions, cheap
Schnorr inputs, `reveal_delay` blocks apart); see create_commit_reveal.

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
from . import hd as _hd

from .crypto import (tagged_hash, pubkey_from_seckey, schnorr_sign, lamport_keygen,
                     lamport_sign, pq_root, bech32m_encode, bech32m_decode, N,
                     LAMPORT_PUB_LEN, LAMPORT_SIG_LEN)
from . import slhdsa
from .params import ChainParams, COIN
from .tx import (Transaction, TxIn, TxOut, OutPoint, make_address, make_script, slh_leaf,
                 schnorr_witness, lamport_witness, slhdsa_witness, commit_script, spend_commitment,
                 SLHDSA_WITNESS_LEN, SCHNORR_WITNESS_LEN, OUT_KEY, TX_VERSION_V1, TX_VERSION_V2)

GAP_LIMIT = 20


class Key:
    def __init__(self, seed: Optional[bytes], i: int, seckey: Optional[bytes] = None,
                 pq_seed: Optional[bytes] = None, slh=None):
        """`slh` is the wallet's (secret, public) SLH-DSA key on rules-2 networks;
        without it the key is a rules-1 Schnorr+Lamport key."""
        if seckey is None:                     # legacy (0.4) derivation
            ib = i.to_bytes(4, "big")
            d = int.from_bytes(tagged_hash("Kairos/wallet/sk", seed + ib), "big") % (N - 1) + 1
            seckey = d.to_bytes(32, "big")
            pq_seed = tagged_hash("Kairos/wallet/pq", seed + ib)
        self.seckey = seckey
        self.pubkey = pubkey_from_seckey(self.seckey)
        self._pq_seed = pq_seed
        self._lamport = None
        if slh is None:
            self.pqroot = pq_root(self.lamport[1])
            self.address = make_address(self.pubkey, self.pqroot)
        else:
            self.slh_sk, self.slh_pk = slh
            self.salt = tagged_hash("Kairos/wallet/slh-salt", pq_seed)
            self.pqroot = slh_leaf(self.slh_pk, self.salt)    # what a Schnorr witness carries
            self.address = make_script(self.pubkey, self.pqroot)

    @property
    def lamport(self):
        if self._lamport is None:
            self._lamport = lamport_keygen(self._pq_seed)
        return self._lamport


class Wallet:
    def __init__(self, params: ChainParams, seed: Optional[bytes] = None,
                 n_keys: int = 0, path: Optional[str] = None, scheme: str = "legacy",
                 entropy: Optional[bytes] = None, account: int = 0):
        """`scheme` "legacy" derives keys from a 32-byte seed as 0.4 did; "bip32"
        derives them from a 64-byte BIP39 seed at m/44'/coin'/account'/0/i (see hd.py),
        so hardware wallets holding the same mnemonic derive the same keys."""
        if scheme not in ("legacy", "bip32"):
            raise ValueError("unknown key scheme")
        self.params = params
        self.scheme = scheme
        self.account = account
        self.entropy = entropy           # BIP39 entropy, kept so the words can be shown again
        self.seed = seed or os.urandom(32 if scheme == "legacy" else 64)
        self._chain_key = None
        if scheme == "bip32":
            root = _hd.ExtKey.from_seed(self.seed)
            self._account_key = root.derive_path(_hd.account_path(params.name, account))
            self._chain_key = self._account_key.derive(0)
        self.path = path
        self.passphrase = None
        self._enc = None             # (salt, derived key) cached so saves do not re-run scrypt
        self.pq_revealed = set()     # key indices whose Lamport key has signed (never again)
        self.used = set()            # key indices that have received coins on chain
        self.pending: List[dict] = []    # rules 2: commit-delay-reveal payments not yet revealed
        self.rules2 = params.rules >= 2
        self._slh = None
        self.chain = None
        self.keys: List[Key] = []
        self.by_addr: Dict[bytes, Key] = {}
        for _ in range(max(n_keys, 1)):
            self._derive()

    # ------------------------------------------------------ persistence
    # File format 2 (legacy wallets). The seed is encrypted with a passphrase-derived key:
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

    # File format 3 (HD wallets only). Format 2 is kept, unchanged, for legacy
    # wallets, so 0.4.x can still open them. An HD wallet must never open in 0.4.1:
    # that version ignores "scheme", would derive legacy keys from the BIP39 seed
    # and show addresses the HD wallet never scans. So format 3 keeps every secret
    # under "hd", where 0.4.1 does not look: its loader raises KeyError instead of
    # deriving anything. The encryption MAC also covers the scheme and account.
    FORMAT_LEGACY, FORMAT_HD = 2, 3

    @staticmethod
    def _hd_header(scheme: str, account: int, n: int, r: int, p: int, salt: bytes, nonce: bytes) -> bytes:
        return f"kairos-wallet-3:{scheme}:{account}:{n}:{r}:{p}".encode() + salt + nonce

    @classmethod
    def _decrypt(cls, passphrase, salt, nonce, ct, tag, n, r, p, header):
        """(plaintext, cached key or None). Raises PermissionError on a wrong passphrase."""
        if passphrase is None:
            raise PermissionError("wallet is encrypted: passphrase required")
        k = cls._kdf(passphrase, salt, n, r, p)
        if not hmac.compare_digest(hmac.new(k[32:], header + ct, hashlib.sha256).digest(), tag):
            raise PermissionError("wrong passphrase or corrupted wallet file")
        blob = bytes(a ^ b for a, b in zip(ct, cls._stream(k[:32], nonce, len(ct))))
        return blob, ((salt, k) if (n, r, p) == (cls.KDF_N, cls.KDF_R, cls.KDF_P) else None)

    @classmethod
    def load(cls, params: ChainParams, path: str, passphrase: Optional[str] = None) -> "Wallet":
        with open(path) as f:
            d = json.load(f)
        fmt = d.get("format", 2)
        if not isinstance(fmt, int) or fmt > cls.FORMAT_HD:
            raise ValueError(f"wallet file format {fmt} needs a newer version of Kairos")
        scheme = d.get("scheme", "legacy")
        account = d.get("account", 0)
        enc = None
        if fmt >= cls.FORMAT_HD:
            if scheme != "bip32":
                raise ValueError(f"unknown key scheme {scheme!r} in wallet file")
            h = d["hd"]
            if d.get("encrypted"):
                n, r, p = h["kdf"]
                salt, nonce = bytes.fromhex(h["salt"]), bytes.fromhex(h["nonce"])
                blob, enc = cls._decrypt(passphrase, salt, nonce, bytes.fromhex(h["ct"]), bytes.fromhex(h["tag"]),
                                         n, r, p, cls._hd_header(scheme, account, n, r, p, salt, nonce))
            else:
                blob = bytes.fromhex(h["seed"]) + bytes.fromhex(h.get("entropy", ""))
        elif d.get("encrypted"):
            salt, nonce = bytes.fromhex(d["salt"]), bytes.fromhex(d["nonce"])
            blob, enc = cls._decrypt(passphrase, salt, nonce, bytes.fromhex(d["ct"]), bytes.fromhex(d["tag"]),
                                     d["n"], d["r"], d["p"], f"{d['n']}:{d['r']}:{d['p']}".encode() + salt + nonce)
        else:
            blob = bytes.fromhex(d["seed"]) + bytes.fromhex(d.get("entropy", ""))
        n = 32 if scheme == "legacy" else 64
        seed, entropy = blob[:n], blob[n:] or None
        w = cls(params, seed, d["n_keys"], path, scheme=scheme, entropy=entropy, account=account)
        w.passphrase = passphrase
        w._enc = enc
        w.pq_revealed = set(d.get("pq_revealed", []))
        w.used = set(d.get("used", []))
        w.pending = list(d.get("pending", []))
        if scheme != "legacy" and fmt < cls.FORMAT_HD:
            w.save()            # an HD wallet written before format 3 existed: 0.4.1 must refuse it
        return w

    @classmethod
    def load_or_create(cls, params: ChainParams, path: str, passphrase: Optional[str] = None) -> "Wallet":
        """Existing wallets keep their scheme; new ones are BIP39/BIP32 wallets."""
        if os.path.exists(path):
            return cls.load(params, path, passphrase)
        w, _ = cls.create_hd(params, path, passphrase=passphrase)
        return w

    @classmethod
    def create_hd(cls, params: ChainParams, path: Optional[str] = None, words: int = 24,
                  passphrase: Optional[str] = None, n_keys: int = 0):
        """A new BIP39/BIP32 wallet. Returns (wallet, mnemonic)."""
        strength = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}[words]
        entropy = os.urandom(strength)
        mnemonic = _hd.entropy_to_mnemonic(entropy)
        w = cls(params, _hd.mnemonic_to_seed(mnemonic), n_keys, path, scheme="bip32", entropy=entropy)
        w.passphrase = passphrase
        w.save()
        return w, mnemonic

    @classmethod
    def restore_mnemonic(cls, params: ChainParams, mnemonic: str, path: Optional[str] = None,
                         bip39_passphrase: str = "", passphrase: Optional[str] = None,
                         n_keys: int = GAP_LIMIT) -> "Wallet":
        """Restore from BIP39 words (the checksum catches a wrong word). The same
        words on a hardware wallet give the same keys."""
        entropy = _hd.mnemonic_to_entropy(mnemonic)
        seed = _hd.mnemonic_to_seed(" ".join(mnemonic.split()), bip39_passphrase)
        w = cls(params, seed, n_keys, path, scheme="bip32",
                entropy=None if bip39_passphrase else entropy)
        w.passphrase = passphrase
        w.save()
        return w

    def xpub(self) -> str:
        """The account's extended public key. It identifies the Schnorr keys but
        cannot produce addresses on its own: every address also commits to a
        post-quantum key that only the seed can derive (see hd.py)."""
        if self.scheme != "bip32":
            raise ValueError("legacy wallets have no BIP32 keys")
        net = "main" if self.params.name == "main" else "test"
        return self._account_key.neuter().serialize(net)

    def save(self):
        if not self.path:
            return
        d = {"format": self.FORMAT_LEGACY, "network": self.params.name, "n_keys": len(self.keys),
             "pq_revealed": sorted(self.pq_revealed), "used": sorted(self.used)}
        if self.pending:
            d["pending"] = self.pending
        encrypt = bool(getattr(self, "passphrase", None))
        if encrypt:
            n, r, p = self.KDF_N, self.KDF_R, self.KDF_P
            if self._enc is None:
                salt = os.urandom(16)
                self._enc = (salt, self._kdf(self.passphrase, salt, n, r, p))
            salt, k = self._enc
            nonce = os.urandom(16)
        if self.scheme == "legacy":
            # exactly what 0.4.1 writes, so 0.4.1 keeps opening legacy wallets
            if encrypt:
                ct = bytes(a ^ b for a, b in zip(self.seed, self._stream(k[:32], nonce, len(self.seed))))
                header = f"{n}:{r}:{p}".encode() + salt + nonce
                tag = hmac.new(k[32:], header + ct, hashlib.sha256).digest()
                d.update(encrypted=True, n=n, r=r, p=p, salt=salt.hex(), nonce=nonce.hex(),
                         ct=ct.hex(), tag=tag.hex())
            else:
                d.update(encrypted=False, seed=self.seed.hex())
        else:
            d.update(format=self.FORMAT_HD, scheme=self.scheme, account=self.account,
                     note="HD wallet (BIP39/BIP32): needs Kairos 0.4.2 or later. Older versions refuse it.")
            blob = self.seed + (self.entropy or b"")
            if encrypt:
                ct = bytes(a ^ b for a, b in zip(blob, self._stream(k[:32], nonce, len(blob))))
                header = self._hd_header(self.scheme, self.account, n, r, p, salt, nonce)
                tag = hmac.new(k[32:], header + ct, hashlib.sha256).digest()
                d.update(encrypted=True, hd={"kdf": [n, r, p], "salt": salt.hex(), "nonce": nonce.hex(),
                                             "ct": ct.hex(), "tag": tag.hex()})
            else:
                hd = {"seed": self.seed.hex()}
                if self.entropy:
                    hd["entropy"] = self.entropy.hex()
                d.update(encrypted=False, hd=hd)
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
        """What to write down. BIP32 wallets: the BIP39 words. Legacy wallets: the
        seed as bech32m. Either way a typo is detected on restore."""
        if self.scheme == "bip32":
            if not self.entropy:
                raise ValueError("this wallet was restored with a BIP39 passphrase: its backup is the "
                                 "words you restored from, plus that passphrase")
            return _hd.entropy_to_mnemonic(self.entropy)
        return bech32m_encode("krsseed", self.seed)

    @classmethod
    def restore(cls, params: ChainParams, code: str, path: str, n_keys: int = GAP_LIMIT,
                passphrase: Optional[str] = None) -> "Wallet":
        if len(code.split()) > 1:                         # BIP39 words
            return cls.restore_mnemonic(params, code, path, passphrase=passphrase, n_keys=n_keys)
        seed = bech32m_decode("krsseed", code.strip())
        if len(seed) != 32:
            raise ValueError("bad backup code")
        w = cls(params, seed, n_keys, path)
        w.passphrase = passphrase
        w.save()
        return w

    # ------------------------------------------------------ addresses
    @property
    def slh(self):
        """Rules 2: the wallet's SLH-DSA key pair (secret, public), derived from the
        seed (HD wallets: from the hardened account key, which an xpub does not reveal)."""
        if self._slh is None:
            if self.scheme == "bip32":
                tag, secret = "Kairos/hd/slh", self._account_key.secret
            else:
                tag, secret = "Kairos/wallet/slh", self.seed
            material = tagged_hash(tag, secret + b"\x00") + tagged_hash(tag, secret + b"\x01")
            self._slh = slhdsa.keygen(material[:3 * slhdsa.N])
        return self._slh

    def _derive(self) -> Key:
        i = len(self.keys)
        slh = self.slh if self.rules2 else None
        if self.scheme == "bip32":
            child = self._chain_key.derive(i)
            k = Key(None, i, child.secret, _hd.pq_seed(child.secret), slh)
        elif slh is not None:                  # the legacy derivation, with an SLH-DSA leaf
            ib = i.to_bytes(4, "big")
            d = int.from_bytes(tagged_hash("Kairos/wallet/sk", self.seed + ib), "big") % (N - 1) + 1
            k = Key(None, i, d.to_bytes(32, "big"), tagged_hash("Kairos/wallet/pq", self.seed + ib), slh)
        else:
            k = Key(self.seed, i)
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
        if len(a) != self.params.script_len:
            raise ValueError("bad address length")
        if self.rules2 and a[0] != OUT_KEY:
            raise ValueError("address version not supported by this wallet")
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
    # A transaction may not exceed half the block size (consensus). Post-quantum
    # witnesses are large (Lamport about 24.6 KB, SLH-DSA about 8 KB), so a
    # post-quantum payment that needs many inputs is split into several
    # transactions, each under this wallet cap.
    MAX_TX_BYTES = 950_000
    DUST = 1_000                  # change smaller than this is left to the miner
    REVEAL_FEE_MARGIN = 4         # a revealed payment pays this multiple of today's base fee

    def create_tx(self, chain, to: bytes, amount: int, tip_per_byte: int = 1,
                  expiry_blocks: int = 0, post_quantum: Optional[bool] = None) -> Transaction:
        """One transaction paying `amount` to `to`. Raises if the payment cannot
        fit in a single transaction (see create_txs)."""
        txs = self.create_txs(chain, to, amount, tip_per_byte, expiry_blocks, post_quantum)
        if len(txs) != 1:
            raise ValueError(f"payment needs {len(txs)} transactions; use create_txs")
        return txs[0]

    def _free_coins(self, chain):
        """Spendable coins not already spent in the mempool or reserved by a pending reveal."""
        reserved = {OutPoint(bytes.fromhex(t), i) for p in self.pending for t, i in p["inputs"]}
        return {op: c for op, c in self.coins(chain).items()
                if op not in chain.mempool_spends and op not in reserved}

    def create_txs(self, chain, to: bytes, amount: int, tip_per_byte: int = 1,
                   expiry_blocks: int = 0, post_quantum: Optional[bool] = None) -> List[Transaction]:
        """Transactions paying `amount` to `to` in total. Uses the post-quantum
        path automatically once the quantum switch is active on `chain`, unless
        `post_quantum` says otherwise. Schnorr payments are always one
        transaction; post-quantum payments may be several."""
        if amount <= 0:
            raise ValueError("amount must be positive")
        pq = chain.pq_active(chain.tip) if post_quantum is None else post_quantum
        coins = self._free_coins(chain)
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
        # Post-quantum. Rules 1: a Lamport key signs exactly one message, so every coin
        # at an address must be swept in the same transaction. Rules 2: SLH-DSA has no
        # such limit. Group, fill transactions up to the size cap, stop once the groups
        # cover the amount.
        groups: Dict[bytes, list] = {}
        for op, c in coins.items():
            groups.setdefault(op.serialize() if self.rules2 else c.address, []).append((op, c))
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

    def _witness_len(self, pq: bool) -> int:
        if not pq:
            return SCHNORR_WITNESS_LEN
        return SLHDSA_WITNESS_LEN if self.rules2 else 1 + 32 + LAMPORT_PUB_LEN + LAMPORT_SIG_LEN

    def _tx_version(self) -> int:
        return TX_VERSION_V2 if self.rules2 else TX_VERSION_V1

    def _size(self, selected, n_outputs: int, expiry_blocks: int, pq: bool) -> int:
        return Transaction([TxIn(op, b"\x00" * self._witness_len(pq)) for op, _ in selected],
                           [TxOut(1, b"\x00" * self.params.script_len)] * n_outputs,
                           1 if expiry_blocks else 0, self._tx_version()).size

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
        return self._assemble(chain, selected, [TxOut(amount, to)], total, base_fee + tip, expiry_blocks, pq)

    def _covers(self, selected, outs, total, rate, pq) -> bool:
        """Do `selected` pay for `outs` and the fee, without change?"""
        size = Transaction([TxIn(op, b"\x00" * self._witness_len(pq)) for op, _ in selected], list(outs),
                           0, self._tx_version()).size
        return total - sum(o.value for o in outs) - rate * size >= 0

    def _assemble(self, chain, selected, outs, total, rate, expiry_blocks, pq, sign=True):
        """A signed transaction spending exactly `selected` into `outs` plus change,
        or None if they do not cover the outputs plus fees. Change below DUST is
        left to the miner."""
        exp = chain.height + expiry_blocks if expiry_blocks else 0
        paid = sum(o.value for o in outs)
        wl = self._witness_len(pq)

        def size(extra):
            return Transaction([TxIn(op, b"\x00" * wl) for op, _ in selected],
                               outs + [TxOut(1, b"\x00" * self.params.script_len)] * extra,
                               exp, self._tx_version()).size
        # Witness sizes are fixed, so the fee follows from the input and output
        # counts alone and the transaction is signed exactly once. (A Lamport key
        # must never sign two different messages.)
        excess = total - paid - rate * size(0)
        if excess < 0:
            return None
        outs = list(outs)
        if excess >= self.DUST:
            change = total - paid - rate * size(1)
            if change >= self.DUST:
                change_key = self.keys[self._unused_index()]     # fresh, never-revealed key
                self.used.add(self.keys.index(change_key))       # reserve it now
                self.save()
                outs.append(TxOut(change, change_key.address))
        tx = Transaction([TxIn(op, b"\x00" * wl) for op, _ in selected], outs, exp, self._tx_version())
        if sign:
            self._sign(tx, selected, pq)
        return tx

    def _sign(self, tx: Transaction, selected, pq: bool):
        if self.params.name == "main" and not _crypto.HARDENED:
            raise RuntimeError("refusing to sign on mainnet without libsecp256k1: "
                               "pip install coincurve")
        sh = tx.sighash(self.params.chain_id, [(c.value, c.address) for _, c in selected])
        if pq and not self.rules2:
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
        slh_sig = None
        for inp, (op, c) in zip(tx.inputs, selected):
            k = self.by_addr[c.address]
            if pq and self.rules2:
                if slh_sig is None:        # one key and one sighash per transaction: sign once
                    slh_sig = slhdsa.sign(sh, k.slh_sk)
                inp.witness = slhdsa_witness(k.pubkey, k.slh_pk, k.salt, slh_sig)
            elif pq:
                sk, lpub = k.lamport
                inp.witness = lamport_witness(k.pubkey, lpub, lamport_sign(sh, sk))
                k._pq_signed = sh
            else:
                inp.witness = schnorr_witness(k.pubkey, k.pqroot, schnorr_sign(sh, k.seckey, os.urandom(32)))
        tx.invalidate()

    # ------------------------------------------------------ commit-delay-reveal (rules 2)
    def create_commit_reveal(self, chain, to: bytes, amount: int, tip_per_byte: int = 1):
        """A payment that stays cheap after the quantum switch: a Schnorr-signed
        transaction (the reveal) plus a small transaction carrying its commitment.
        The reveal becomes valid `reveal_delay` blocks after the commitment is mined;
        the wallet keeps it and `due_reveals` hands it out then. Returns
        (commit_tx, reveal_tx). The commitment is paid from a separate coin, with
        SLH-DSA if the switch is active (the only spend that needs no commitment).
        Works before activation too: a commitment made early is already old enough
        on the day of an emergency."""
        if not self.rules2:
            raise ValueError("commit-delay-reveal needs a rules-2 network")
        if amount <= 0:
            raise ValueError("amount must be positive")
        pq = chain.pq_active(chain.tip)
        base_fee = chain.tip.next_base_fee
        coins = self._free_coins(chain)
        # only coins whose key has never been revealed can take the Schnorr path
        fresh = sorted(((op, c) for op, c in coins.items() if not chain.key_revealed(c.address)),
                       key=lambda kv: -kv[1].value)
        rate = base_fee * self.REVEAL_FEE_MARGIN + tip_per_byte
        pay = [TxOut(amount, to)]
        selected = []
        for op, c in fresh:
            selected.append((op, c))
            if self._covers(selected, pay, sum(x.value for _, x in selected), rate, False):
                break
        else:
            raise ValueError("insufficient funds in coins whose keys are still unrevealed")
        reveal = self._assemble(chain, selected, pay, sum(x.value for _, x in selected), rate, 0, False)
        c_hash = spend_commitment(reveal.txid, [self.by_addr[c.address].pubkey for _, c in selected])
        used = {op for op, _ in selected}
        funding = sorted(((op, c) for op, c in coins.items() if op not in used), key=lambda kv: kv[1].value)
        marker = [TxOut(0, commit_script(c_hash))]
        pick = next(((op, c) for op, c in funding
                     if self._covers([(op, c)], marker, c.value, base_fee + tip_per_byte, pq)), None)
        if pick is None:
            raise ValueError("no separate coin to pay for the commitment")
        commit = self._assemble(chain, [pick], marker, pick[1].value, base_fee + tip_per_byte, 0, pq)
        self.pending.append({"reveal": reveal.serialize().hex(), "commit": commit.serialize().hex(),
                             "commitment": c_hash.hex(),
                             "inputs": [[op.txid.hex(), op.index] for op, _ in selected]})
        self.save()
        return commit, reveal

    def due_reveals(self, chain):
        """What a node should broadcast now: reveals whose commitment is old
        enough, and commitments not yet mined. Finished payments are dropped."""
        out, keep = [], []
        next_height = chain.height + 1
        for p in self.pending:
            reveal = Transaction.deserialize(bytes.fromhex(p["reveal"]), 2)
            if not any(i.prev in chain.utxos for i in reveal.inputs):
                continue                                   # revealed and mined (or spent otherwise)
            keep.append(p)
            h = chain.commitment_height(bytes.fromhex(p["commitment"]))
            if h is None:
                out.append(Transaction.deserialize(bytes.fromhex(p["commit"]), 2))
            elif next_height - h >= self.params.reveal_delay:
                out.append(reveal)
        if len(keep) != len(self.pending):
            self.pending = keep
            self.save()
        return out


def fmt(motes: int) -> str:
    return f"{motes / COIN:,.8f} KRS"
