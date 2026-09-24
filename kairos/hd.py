"""
Hierarchical deterministic keys: BIP39 mnemonics and BIP32 derivation.

A hardware wallet or any BIP32 software given the same mnemonic derives the
same secp256k1 keys, so Kairos keys can live on standard signing devices.

Kairos key path, per BIP44's account structure (which most non-Bitcoin
chains use as a generic layout):

    m / 44' / coin' / account' / 0 / index

    coin = 19282' on mainnet ("KR", 0x4B52; not yet registered in SLIP-44)
           1'     on testnet and regtest (the SLIP-44 convention for all testnets)

Every address uses the external chain (0); Kairos wallets rotate addresses for
receiving, mining and change alike.

The post-quantum key of an address cannot be derived from an xpub: hash-based
keys have no public derivation. It is derived from the address's private key,

    lamport_seed = tagged_hash("Kairos/hd/pq", child_private_key)

so a signing device can compute it, but a watch-only wallet holding only the
account xpub cannot compute the address (address = H(schnorr_pk || pq_root)).
A watch-only wallet must be given the pq_root of each index by the signer.
"""
import hashlib
import hmac
import struct
import unicodedata

from . import crypto
from .crypto import G, N, P, point_add, point_mul, tagged_hash

HARDENED = 0x80000000
COIN_TYPE = {"main": 19282, "test": 1, "regtest": 1}
VERSIONS = {"main": (0x0488ADE4, 0x0488B21E), "test": (0x04358394, 0x043587CF),
            "regtest": (0x04358394, 0x043587CF)}             # (private, public): xprv/xpub, tprv/tpub


# ------------------------------------------------------------ RIPEMD-160
def _ripemd160_py(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160, for Python builds whose OpenSSL lacks it."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    fs = [lambda x, y, z: x ^ y ^ z, lambda x, y, z: (x & y) | (~x & z), lambda x, y, z: (x | ~y) ^ z,
          lambda x, y, z: (x & z) | (y & ~z), lambda x, y, z: x ^ (y | ~z)]
    kl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    rl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", 8 * len(data))
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = (rol((al + (fs[r](bl, cl, dl) & 0xFFFFFFFF) + x[rl[j]] + kl[r]) & 0xFFFFFFFF, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + (fs[4 - r](br, cr, dr) & 0xFFFFFFFF) + x[rr[j]] + kr[r]) & 0xFFFFFFFF, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return struct.pack("<5I", *h)


def ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160_py(data)


def hash160(data: bytes) -> bytes:
    return ripemd160(hashlib.sha256(data).digest())


# ------------------------------------------------------------ base58check
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload: bytes) -> str:
    data = payload + crypto.sha256d(payload)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def b58check_decode(s: str) -> bytes:
    n = 0
    for c in s:
        i = _B58.find(c)
        if i < 0:
            raise ValueError("invalid base58 character")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 4 or crypto.sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ValueError("bad base58 checksum")
    return raw[:-4]


# ------------------------------------------------------------ points
def _pub33_from_secret(k: int) -> bytes:
    if crypto.HARDENED:
        from coincurve import PrivateKey
        return PrivateKey(k.to_bytes(32, "big")).public_key.format(compressed=True)
    x, y = point_mul(G, k)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _point_from33(b: bytes):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("bad public key")
    x = int.from_bytes(b[1:], "big")
    if x >= P:
        raise ValueError("bad public key")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y * y - x ** 3 - 7) % P:
        raise ValueError("point not on curve")
    if (y & 1) != (b[0] & 1):
        y = P - y
    return x, y


# ------------------------------------------------------------ BIP32
class ExtKey:
    """A BIP32 extended key, private or public."""

    def __init__(self, key: bytes, chain: bytes, depth=0, parent_fp=b"\x00" * 4, child=0, private=True):
        self.key, self.chain, self.depth = key, chain, depth
        self.parent_fp, self.child, self.private = parent_fp, child, private

    @classmethod
    def from_seed(cls, seed: bytes) -> "ExtKey":
        if not 16 <= len(seed) <= 64:
            raise ValueError("seed must be 16 to 64 bytes")
        i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        k = int.from_bytes(i[:32], "big")
        if not 0 < k < N:
            raise ValueError("invalid master key (probability below 2^-127)")
        return cls(i[:32], i[32:])

    @property
    def secret(self) -> bytes:
        if not self.private:
            raise ValueError("public key has no secret")
        return self.key

    @property
    def pub33(self) -> bytes:
        return _pub33_from_secret(int.from_bytes(self.key, "big")) if self.private else self.key

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.pub33)[:4]

    def neuter(self) -> "ExtKey":
        return ExtKey(self.pub33, self.chain, self.depth, self.parent_fp, self.child, False)

    def derive(self, i: int) -> "ExtKey":
        if not 0 <= i < 1 << 32:
            raise ValueError("child index out of range")
        if i >= HARDENED:
            if not self.private:
                raise ValueError("cannot derive a hardened child from a public key")
            data = b"\x00" + self.key + struct.pack(">I", i)
        else:
            data = self.pub33 + struct.pack(">I", i)
        out = hmac.new(self.chain, data, hashlib.sha512).digest()
        il = int.from_bytes(out[:32], "big")
        if il >= N:
            return self.derive(i + 1)             # BIP32: invalid, proceed with the next index
        if self.private:
            k = (il + int.from_bytes(self.key, "big")) % N
            if k == 0:
                return self.derive(i + 1)
            return ExtKey(k.to_bytes(32, "big"), out[32:], self.depth + 1, self.fingerprint, i, True)
        pt = point_add(point_mul(G, il), _point_from33(self.key))
        if pt is None:
            return self.derive(i + 1)
        x, y = pt
        return ExtKey(bytes([2 + (y & 1)]) + x.to_bytes(32, "big"), out[32:], self.depth + 1,
                      self.fingerprint, i, False)

    def derive_path(self, path: str) -> "ExtKey":
        parts = path.strip().split("/")
        if parts[0] not in ("m", "M"):
            raise ValueError("path must start with m")
        k = self
        for p in parts[1:]:
            hard = p.endswith(("'", "h", "H"))
            n = int(p.rstrip("'hH"))
            if not 0 <= n < HARDENED:
                raise ValueError("path index out of range")
            k = k.derive(n + HARDENED if hard else n)
        return k

    def serialize(self, network="main") -> str:
        ver = VERSIONS[network][0 if self.private else 1]
        key = (b"\x00" + self.key) if self.private else self.key
        return b58check_encode(struct.pack(">IB", ver, self.depth) + self.parent_fp
                               + struct.pack(">I", self.child) + self.chain + key)

    @classmethod
    def parse(cls, s: str) -> "ExtKey":
        raw = b58check_decode(s)
        if len(raw) != 78:
            raise ValueError("extended key must be 78 bytes")
        ver, depth = struct.unpack(">IB", raw[:5])
        private = ver in (v[0] for v in VERSIONS.values())
        if not private and ver not in (v[1] for v in VERSIONS.values()):
            raise ValueError("unknown extended key version")
        fp, child, chain, key = raw[5:9], struct.unpack(">I", raw[9:13])[0], raw[13:45], raw[45:]
        if depth == 0 and (fp != b"\x00" * 4 or child):
            raise ValueError("master key with a parent")
        if private:
            if key[0] != 0 or not 0 < int.from_bytes(key[1:], "big") < N:
                raise ValueError("bad private key")
            return cls(key[1:], chain, depth, fp, child, True)
        _point_from33(key)
        return cls(key, chain, depth, fp, child, False)


def account_path(network: str, account: int = 0) -> str:
    return f"m/44'/{COIN_TYPE[network]}'/{account}'"


def key_path(network: str, index: int, account: int = 0) -> str:
    return f"{account_path(network, account)}/0/{index}"


def pq_seed(child_secret: bytes) -> bytes:
    """The Lamport key seed of an address, from its private key (never from an xpub)."""
    return tagged_hash("Kairos/hd/pq", child_secret)


# ------------------------------------------------------------ BIP39
def _words():
    from .bip39_words import WORDS
    return WORDS


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 128 to 256 bits in steps of 32")
    bits = int.from_bytes(entropy, "big")
    cs = len(entropy) // 4
    bits = (bits << cs) | (hashlib.sha256(entropy).digest()[0] >> (8 - cs))
    n = (len(entropy) * 8 + cs) // 11
    words = _words()
    return " ".join(words[(bits >> (11 * (n - 1 - i))) & 0x7FF] for i in range(n))


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Checks the words and the checksum; raises ValueError on any typo."""
    words = unicodedata.normalize("NFKD", mnemonic).split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("a mnemonic has 12, 15, 18, 21 or 24 words")
    index = {w: i for i, w in enumerate(_words())}
    bits = 0
    for w in words:
        if w not in index:
            raise ValueError(f"unknown word: {w}")
        bits = (bits << 11) | index[w]
    cs = len(words) * 11 // 33
    ent = (bits >> cs).to_bytes(len(words) * 11 * 32 // 33 // 8, "big")
    if hashlib.sha256(ent).digest()[0] >> (8 - cs) != bits & ((1 << cs) - 1):
        raise ValueError("mnemonic checksum mismatch (a word is wrong)")
    return ent


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    m = unicodedata.normalize("NFKD", mnemonic)
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), salt.encode(), 2048)
