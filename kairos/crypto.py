"""
Kairos cryptographic primitives.

Everything here is pure Python on top of hashlib so the reference
implementation has zero third-party dependencies. It is written for
clarity and auditability, not speed, and is NOT constant-time.
"""
import hashlib

# ---------------------------------------------------------------- hashing

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


_TAG_CACHE = {}


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP340-style domain-separated hash: SHA256(SHA256(tag)||SHA256(tag)||msg).
    Every hash in Kairos that means something different uses a different tag,
    so no value can ever be reinterpreted as another kind of value."""
    t = _TAG_CACHE.get(tag)
    if t is None:
        t = _TAG_CACHE[tag] = sha256(tag.encode())
    return sha256(t + t + msg)


# ------------------------------------------------ secp256k1 / BIP340 Schnorr

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _jac_double(p):
    X, Y, Z = p
    if Y == 0:
        return (0, 0, 0)
    S = 4 * X * Y * Y % P
    M = 3 * X * X % P
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * Y ** 4) % P
    Z3 = 2 * Y * Z % P
    return (X3, Y3, Z3)


def _jac_add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    Z1Z1, Z2Z2 = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2Z2 % P, X2 * Z1Z1 % P
    S1, S2 = Y1 * Z2 * Z2Z2 % P, Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        return _jac_double(p) if S1 == S2 else (0, 0, 0)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    U1H2 = U1 * H2 % P
    X3 = (R * R - H3 - 2 * U1H2) % P
    Y3 = (R * (U1H2 - X3) - S1 * H3) % P
    Z3 = H * Z1 * Z2 % P
    return (X3, Y3, Z3)


def _to_affine(p):
    if p[2] == 0:
        return None
    zi = pow(p[2], -1, P)
    zi2 = zi * zi % P
    return (p[0] * zi2 % P, p[1] * zi2 * zi % P)


def point_mul(pt, n):
    R = (0, 0, 0)
    A = (pt[0], pt[1], 1)
    while n:
        if n & 1:
            R = _jac_add(R, A)
        A = _jac_double(A)
        n >>= 1
    return _to_affine(R)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    return _to_affine(_jac_add((p1[0], p1[1], 1), (p2[0], p2[1], 1)))


def lift_x(x: int):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def _i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _b(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _py_pubkey(seckey: bytes) -> bytes:
    d = _i(seckey)
    if not 1 <= d < N:
        raise ValueError("invalid secret key")
    return _b(point_mul(G, d)[0])


def _py_sign(msg: bytes, seckey: bytes, aux: bytes = b"\x00" * 32) -> bytes:
    d0 = _i(seckey)
    if not 1 <= d0 < N:
        raise ValueError("invalid secret key")
    Pp = point_mul(G, d0)
    d = d0 if Pp[1] % 2 == 0 else N - d0
    t = bytes(a ^ b for a, b in zip(_b(d), tagged_hash("BIP0340/aux", aux)))
    k0 = _i(tagged_hash("BIP0340/nonce", t + _b(Pp[0]) + msg)) % N
    if k0 == 0:
        raise RuntimeError("nonce is zero")
    R = point_mul(G, k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = _i(tagged_hash("BIP0340/challenge", _b(R[0]) + _b(Pp[0]) + msg)) % N
    sig = _b(R[0]) + _b((k + e * d) % N)
    if not _py_verify(msg, _b(Pp[0]), sig):
        raise RuntimeError("self-verification failed")
    return sig


def _py_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    Pp = lift_x(_i(pubkey))
    r, s = _i(sig[:32]), _i(sig[32:])
    if Pp is None or r >= P or s >= N:
        return False
    e = _i(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg)) % N
    R = point_add(point_mul(G, s), point_mul(Pp, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


# ---------------------------------------------- backend selection
# libsecp256k1 (via the `coincurve` package) is constant-time, audited and
# ~100x faster. The pure-Python code above is the readable reference and the
# fallback; it is NOT side-channel safe and must not sign for real value.

import os as _os

try:
    if _os.environ.get("KAIROS_FORCE_PY_CRYPTO"):
        raise ImportError("forced pure-Python backend")
    from coincurve import PrivateKey as _CCPriv
    from coincurve.keys import PublicKeyXOnly as _CCXOnly
    BACKEND = "libsecp256k1"
except ImportError:          # pragma: no cover
    _CCPriv = _CCXOnly = None
    BACKEND = "python"

HARDENED = BACKEND == "libsecp256k1"


def pubkey_from_seckey(seckey: bytes) -> bytes:
    if HARDENED:
        return _CCPriv(seckey).public_key_xonly.format()
    return _py_pubkey(seckey)


def schnorr_sign(msg: bytes, seckey: bytes, aux: bytes = b"\x00" * 32) -> bytes:
    if HARDENED:
        sig = _CCPriv(seckey).sign_schnorr(msg, aux)
        if not schnorr_verify(msg, pubkey_from_seckey(seckey), sig):
            raise RuntimeError("self-verification failed")
        return sig
    return _py_sign(msg, seckey, aux)


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64 or len(msg) != 32:
        return False
    if HARDENED:
        try:
            return bool(_CCXOnly(pubkey).verify(sig, msg))
        except (ValueError, TypeError):
            return False
    return _py_verify(msg, pubkey, sig)


# ------------------------------------------- Lamport one-time signatures
# The post-quantum recovery path. Security rests only on SHA-256 preimage
# resistance, which Grover's algorithm weakens to ~128 bits, not breaks.

LAMPORT_PUB_LEN = 256 * 2 * 32   # 16 KiB
LAMPORT_SIG_LEN = 256 * 32       # 8 KiB


def lamport_keygen(seed: bytes):
    sk = [[tagged_hash("Kairos/lamport/sk", seed + bytes([bit]) + i.to_bytes(2, "big"))
           for bit in (0, 1)] for i in range(256)]
    pub = b"".join(sha256(sk[i][0]) + sha256(sk[i][1]) for i in range(256))
    return sk, pub


def _bits(msg32: bytes):
    v = _i(msg32)
    return [(v >> (255 - i)) & 1 for i in range(256)]


def lamport_sign(msg: bytes, sk) -> bytes:
    h = tagged_hash("Kairos/lamport/msg", msg)
    return b"".join(sk[i][bit] for i, bit in enumerate(_bits(h)))


def lamport_verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    if len(pub) != LAMPORT_PUB_LEN or len(sig) != LAMPORT_SIG_LEN:
        return False
    h = tagged_hash("Kairos/lamport/msg", msg)
    for i, bit in enumerate(_bits(h)):
        want = pub[(2 * i + bit) * 32:(2 * i + bit + 1) * 32]
        if sha256(sig[i * 32:(i + 1) * 32]) != want:
            return False
    return True


def pq_root(lamport_pub: bytes) -> bytes:
    return tagged_hash("Kairos/pqroot", lamport_pub)


# ------------------------------------------------------ MuHash3072 (UTXO)
# Incremental multiset hash (Bellare & Micciancio 1997; as used in Bitcoin
# Core's coinstatsindex). Insert = multiply, remove = multiply the
# denominator; order-independent, O(1) per update.

MUHASH_P = 2 ** 3072 - 1103717


def muhash_element(data: bytes) -> int:
    v = int.from_bytes(hashlib.shake_256(b"Kairos/muhash" + data).digest(384), "little")
    return (v % MUHASH_P) or 1


class MuHash:
    def __init__(self, value: int = 1):
        self.num = value
        self.den = 1

    def insert(self, data: bytes):
        self.num = self.num * muhash_element(data) % MUHASH_P

    def remove(self, data: bytes):
        self.den = self.den * muhash_element(data) % MUHASH_P

    def value(self) -> int:
        v = self.num * pow(self.den, -1, MUHASH_P) % MUHASH_P
        self.num, self.den = v, 1
        return v

    def digest(self) -> bytes:
        return tagged_hash("Kairos/utxoset", self.value().to_bytes(384, "little"))


# ----------------------------------------------------------- Merkle trees
# Leaves and inner nodes use different tags, and an odd node is promoted
# rather than duplicated. Together these remove Bitcoin's CVE-2012-2459
# ambiguity and the 64-byte-transaction / inner-node confusion.

def merkle_root(leaves):
    if not leaves:
        return b"\x00" * 32
    level = [tagged_hash("Kairos/leaf", x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(tagged_hash("Kairos/node", level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def merkle_proof(leaves, index):
    """Returns list of (sibling_hash, sibling_is_right). Promoted nodes add no step."""
    level = [tagged_hash("Kairos/leaf", x) for x in leaves]
    proof = []
    while len(level) > 1:
        sib = index ^ 1
        if sib < len(level):
            proof.append((level[sib], sib > index))
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(tagged_hash("Kairos/node", level[i] + level[i + 1])
                       if i + 1 < len(level) else level[i])
        level, index = nxt, index // 2
    return proof


def merkle_verify(leaf, proof, root) -> bool:
    h = tagged_hash("Kairos/leaf", leaf)
    for sib, is_right in proof:
        h = tagged_hash("Kairos/node", h + sib if is_right else sib + h)
    return h == root


# -------------------------------------------------------- bech32m address

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frm, to, pad=True):
    acc = bits = 0
    out = []
    maxv = (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to - bits)) & maxv)
    elif not pad and (bits >= frm or ((acc << (to - bits)) & maxv)):
        raise ValueError("invalid padding")
    return out


def bech32m_encode(hrp: str, payload: bytes) -> str:
    data = _convertbits(payload, 8, 5)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ _BECH32M
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + chk)


def bech32m_decode(hrp: str, s: str) -> bytes:
    s = s.lower()
    pos = s.rfind("1")
    if s[:pos] != hrp or pos + 7 > len(s):
        raise ValueError("wrong network prefix")
    data = [_CHARSET.index(c) for c in s[pos + 1:]]
    if _polymod(_hrp_expand(hrp) + data) != _BECH32M:
        raise ValueError("bad checksum")
    return bytes(_convertbits(data[:-6], 5, 8, pad=False))
