"""
SLH-DSA-SHA2-128s (FIPS 205), the stateless hash-based signature scheme that
backs every address on rules-2 networks (testnet 3, mainnet).

Why this scheme: it depends only on SHA-256, it keeps no state (a key can sign
up to 2^64 messages, so one key can serve a whole wallet), and it is a NIST
standard. Signatures are 7,856 bytes, public keys 32 bytes.

Pure Python, written to follow FIPS 205 section by section. Keys and addresses
(ADRS) are plain integers; the 22-byte compressed address of the SHA2
instantiation (section 11.2) is packed directly. The SHA-256 state after the
64-byte block PK.seed || 0^48 is computed once per key and copied for every
call, which is the standard optimisation and changes no output.

Signing costs about 2 million hash calls (a few seconds); verifying about
2 thousand (a few milliseconds). Only `verify` is consensus code.
"""
import hashlib
import hmac
import struct

# Parameter set SLH-DSA-SHA2-128s (FIPS 205, table 2)
N = 16          # security parameter, bytes
H = 63          # total tree height
D = 7           # layers
HP = 9          # height of each XMSS tree (h')
A = 12          # FORS tree height
K = 14          # FORS trees
LG_W = 4
W = 16
M = 30          # message digest bytes
LEN1 = 32
LEN2 = 3
LEN = LEN1 + LEN2
PK_BYTES = 2 * N
SK_BYTES = 4 * N
SIG_BYTES = (1 + K * (1 + A) + H + D * LEN) * N      # 7,856

# ADRS types (FIPS 205 section 4.2)
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)

_MD_BYTES = (K * A + 7) // 8                       # 21
_TREE_BYTES = (H - H // D + 7) // 8                # 7
_LEAF_BYTES = (H // D + 7) // 8                    # 2
_ADRS = struct.Struct(">BQBIII")                   # compressed ADRS: layer, tree, type, 3 words


class _Ctx:
    """Tweakable hash functions for one PK.seed (FIPS 205 section 11.2.1)."""
    __slots__ = ("base",)

    def __init__(self, pk_seed: bytes):
        self.base = hashlib.sha256(pk_seed + b"\x00" * (64 - N))

    def h(self, adrs: bytes, data: bytes) -> bytes:
        """F, H, T_l and PRF all have this form for category 1."""
        s = self.base.copy()
        s.update(adrs)
        s.update(data)
        return s.digest()[:N]


def _base_2b(x: bytes, b: int, out_len: int):
    """Algorithm 4."""
    out, total, bits, i = [], 0, 0, 0
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) | x[i]
            i += 1
            bits += 8
        bits -= b
        out.append((total >> bits) & ((1 << b) - 1))
    return out


def _wots_digits(msg: bytes):
    """Message digits plus checksum digits (Algorithms 7 and 8)."""
    d = _base_2b(msg, LG_W, LEN1)
    csum = sum(W - 1 - x for x in d) << ((8 - (LEN2 * LG_W) % 8) % 8)
    return d + _base_2b(csum.to_bytes((LEN2 * LG_W + 7) // 8, "big"), LG_W, LEN2)


def _chain(c: _Ctx, x: bytes, start: int, steps: int, layer, tree, kp, i) -> bytes:
    """Algorithm 5."""
    for j in range(start, start + steps):
        x = c.h(_ADRS.pack(layer, tree, WOTS_HASH, kp, i, j), x)
    return x


def _wots_pk(c: _Ctx, sk_seed: bytes, layer: int, tree: int, kp: int) -> bytes:
    """Algorithm 6."""
    tops = []
    for i in range(LEN):
        sk = c.h(_ADRS.pack(layer, tree, WOTS_PRF, kp, i, 0), sk_seed)
        tops.append(_chain(c, sk, 0, W - 1, layer, tree, kp, i))
    return c.h(_ADRS.pack(layer, tree, WOTS_PK, kp, 0, 0), b"".join(tops))


def _wots_sign(c: _Ctx, msg: bytes, sk_seed: bytes, layer, tree, kp) -> bytes:
    """Algorithm 7."""
    out = []
    for i, d in enumerate(_wots_digits(msg)):
        sk = c.h(_ADRS.pack(layer, tree, WOTS_PRF, kp, i, 0), sk_seed)
        out.append(_chain(c, sk, 0, d, layer, tree, kp, i))
    return b"".join(out)


def _wots_pk_from_sig(c: _Ctx, sig: bytes, msg: bytes, layer, tree, kp) -> bytes:
    """Algorithm 8."""
    tops = []
    for i, d in enumerate(_wots_digits(msg)):
        tops.append(_chain(c, sig[i * N:(i + 1) * N], d, W - 1 - d, layer, tree, kp, i))
    return c.h(_ADRS.pack(layer, tree, WOTS_PK, kp, 0, 0), b"".join(tops))


def _xmss_tree(c: _Ctx, sk_seed: bytes, layer: int, tree: int):
    """All levels of one XMSS tree, leaves first (Algorithm 9 for every node)."""
    level = [_wots_pk(c, sk_seed, layer, tree, i) for i in range(1 << HP)]
    levels = [level]
    for z in range(1, HP + 1):
        level = [c.h(_ADRS.pack(layer, tree, TREE, 0, z, i), level[2 * i] + level[2 * i + 1])
                 for i in range(len(level) // 2)]
        levels.append(level)
    return levels


def _auth(levels, idx: int, height: int) -> bytes:
    return b"".join(levels[j][(idx >> j) ^ 1] for j in range(height))


def _xmss_root_from_sig(c: _Ctx, idx: int, sig: bytes, msg: bytes, layer: int, tree: int) -> bytes:
    """Algorithm 11."""
    node = _wots_pk_from_sig(c, sig[:LEN * N], msg, layer, tree, idx)
    auth = sig[LEN * N:]
    ti = idx
    for k in range(HP):
        a = auth[k * N:(k + 1) * N]
        if (idx >> k) & 1 == 0:
            ti //= 2
            node = c.h(_ADRS.pack(layer, tree, TREE, 0, k + 1, ti), node + a)
        else:
            ti = (ti - 1) // 2
            node = c.h(_ADRS.pack(layer, tree, TREE, 0, k + 1, ti), a + node)
    return node


def _fors_indices(md: bytes):
    return _base_2b(md, A, K)


def _fors_sign(c: _Ctx, md: bytes, sk_seed: bytes, tree: int, kp: int) -> bytes:
    """Algorithm 16, building each FORS tree once."""
    out = []
    for i, x in enumerate(_fors_indices(md)):
        base = i << A
        leaves = []
        for j in range(1 << A):
            sk = c.h(_ADRS.pack(0, tree, FORS_PRF, kp, 0, base + j), sk_seed)
            if j == x:
                out.append(sk)
            leaves.append(c.h(_ADRS.pack(0, tree, FORS_TREE, kp, 0, base + j), sk))
        levels = [leaves]
        for z in range(1, A):
            prev = levels[-1]
            off = i << (A - z)
            levels.append([c.h(_ADRS.pack(0, tree, FORS_TREE, kp, z, off + t), prev[2 * t] + prev[2 * t + 1])
                           for t in range(len(prev) // 2)])
        out.append(_auth(levels, x, A))
    return b"".join(out)


def _fors_pk_from_sig(c: _Ctx, sig: bytes, md: bytes, tree: int, kp: int) -> bytes:
    """Algorithm 17."""
    roots = []
    step = (A + 1) * N
    for i, x in enumerate(_fors_indices(md)):
        part = sig[i * step:(i + 1) * step]
        ti = (i << A) + x
        node = c.h(_ADRS.pack(0, tree, FORS_TREE, kp, 0, ti), part[:N])
        for j in range(A):
            a = part[(j + 1) * N:(j + 2) * N]
            if (x >> j) & 1 == 0:
                ti //= 2
                node = c.h(_ADRS.pack(0, tree, FORS_TREE, kp, j + 1, ti), node + a)
            else:
                ti = (ti - 1) // 2
                node = c.h(_ADRS.pack(0, tree, FORS_TREE, kp, j + 1, ti), a + node)
        roots.append(node)
    return c.h(_ADRS.pack(0, tree, FORS_ROOTS, kp, 0, 0), b"".join(roots))


def _mgf1(seed: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]


def _h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    return _mgf1(r + pk_seed + hashlib.sha256(r + pk_seed + pk_root + msg).digest(), M)


def _split_digest(digest: bytes):
    md = digest[:_MD_BYTES]
    idx_tree = int.from_bytes(digest[_MD_BYTES:_MD_BYTES + _TREE_BYTES], "big") % (1 << (H - H // D))
    idx_leaf = int.from_bytes(digest[_MD_BYTES + _TREE_BYTES:_MD_BYTES + _TREE_BYTES + _LEAF_BYTES],
                              "big") % (1 << (H // D))
    return md, idx_tree, idx_leaf


# ------------------------------------------------------------ internal API

def keygen_internal(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes):
    """Algorithm 18. Returns (secret key, public key) as byte strings."""
    assert len(sk_seed) == len(sk_prf) == len(pk_seed) == N
    c = _Ctx(pk_seed)
    root = _xmss_tree(c, sk_seed, D - 1, 0)[HP][0]
    return sk_seed + sk_prf + pk_seed + root, pk_seed + root


def sign_internal(msg: bytes, sk: bytes, addrnd: bytes = None) -> bytes:
    """Algorithm 19. `addrnd` None gives the deterministic variant (opt_rand = PK.seed)."""
    sk_seed, sk_prf, pk_seed, pk_root = sk[:N], sk[N:2 * N], sk[2 * N:3 * N], sk[3 * N:]
    c = _Ctx(pk_seed)
    opt = pk_seed if addrnd is None else addrnd
    r = hmac.new(sk_prf, opt + msg, hashlib.sha256).digest()[:N]
    md, idx_tree, idx_leaf = _split_digest(_h_msg(r, pk_seed, pk_root, msg))
    sig_fors = _fors_sign(c, md, sk_seed, idx_tree, idx_leaf)
    node = _fors_pk_from_sig(c, sig_fors, md, idx_tree, idx_leaf)
    out = [r, sig_fors]
    tree, leaf = idx_tree, idx_leaf
    for layer in range(D):                       # Algorithm 12, with whole trees
        levels = _xmss_tree(c, sk_seed, layer, tree)
        out.append(_wots_sign(c, node, sk_seed, layer, tree, leaf))
        out.append(_auth(levels, leaf, HP))
        node = levels[HP][0]
        leaf, tree = tree & ((1 << HP) - 1), tree >> HP
    return b"".join(out)


def verify_internal(msg: bytes, sig: bytes, pk: bytes) -> bool:
    """Algorithm 20."""
    if len(sig) != SIG_BYTES or len(pk) != PK_BYTES:
        return False
    pk_seed, pk_root = pk[:N], pk[N:]
    c = _Ctx(pk_seed)
    r = sig[:N]
    fors_len = K * (A + 1) * N
    md, idx_tree, idx_leaf = _split_digest(_h_msg(r, pk_seed, pk_root, msg))
    node = _fors_pk_from_sig(c, sig[N:N + fors_len], md, idx_tree, idx_leaf)
    ht = sig[N + fors_len:]
    xl = (LEN + HP) * N
    tree, leaf = idx_tree, idx_leaf
    for layer in range(D):                       # Algorithm 13
        node = _xmss_root_from_sig(c, leaf, ht[layer * xl:(layer + 1) * xl], node, layer, tree)
        leaf, tree = tree & ((1 << HP) - 1), tree >> HP
    return node == pk_root


# ------------------------------------------------------------ pure SLH-DSA (Algorithms 22, 24)

def _wrap(msg: bytes, ctx: bytes) -> bytes:
    if len(ctx) > 255:
        raise ValueError("context too long")
    return bytes([0, len(ctx)]) + ctx + msg


def keygen(seed: bytes):
    """Deterministic key pair from a 48-byte seed (SK.seed || SK.prf || PK.seed)."""
    if len(seed) != 3 * N:
        raise ValueError("seed must be 48 bytes")
    return keygen_internal(seed[:N], seed[N:2 * N], seed[2 * N:])


def sign(msg: bytes, sk: bytes, ctx: bytes = b"", addrnd: bytes = None) -> bytes:
    return sign_internal(_wrap(msg, ctx), sk, addrnd)


def verify(msg: bytes, sig: bytes, pk: bytes, ctx: bytes = b"") -> bool:
    if len(ctx) > 255:
        return False
    return verify_internal(_wrap(msg, ctx), sig, pk)
