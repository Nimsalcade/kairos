"""
MuSig2 multi-signatures (BIP327) for Kairos.

Several signers produce ONE BIP340 Schnorr signature for an aggregate key.
A MuSig2 output is an ordinary Kairos address whose Schnorr key is the
aggregate key, so on chain it looks and verifies exactly like a single-key
spend: no consensus change. It follows BIP327 to the letter and passes all
of its official test vectors (tests/test_musig.py).

    keys = key_sort([individual_pubkey(sk) for sk in secret_keys])
    ctx  = key_agg(keys)
    address = make_address(get_xonly_pubkey(ctx), pq_root)          # see below
    # round 1: every signer
    secnonce, pubnonce = nonce_gen(sk, pk, get_xonly_pubkey(ctx), msg)
    # round 2: every signer, once all pubnonces are known
    session = SessionContext(nonce_agg(pubnonces), keys, [], [], msg)
    psig = sign(secnonce, sk, session)
    # anyone
    sig = partial_sig_agg(psigs, session)       # a BIP340 signature for the aggregate key

THE POST-QUANTUM PATH. Every Kairos address also commits to a post-quantum
root. There is no way to aggregate hash-based keys, so a MuSig2 address
cannot have an n-of-n post-quantum fallback. Under the testnet 2 rule (only
Lamport spends after the quantum switch), such an output is spendable after
activation only by whoever holds the Lamport key its address commits to. The
parties must choose, and say so explicitly (`musig_address`):

  * an unspendable root: the coins freeze if the switch ever activates;
  * one party's Lamport root: that party alone can move the coins after activation.

The commit-delay-reveal rule recommended for testnet 3 (docs/pq-scaling.md)
removes the dilemma: a never-revealed aggregate key stays spendable by
Schnorr after activation, with a prior commitment.

This is the readable reference. Its arithmetic is not constant time: a
production wallet must use libsecp256k1's MuSig2 module.
"""
import os
from typing import List, Optional, Sequence, Tuple

from .crypto import G, N, P, point_add, point_mul, tagged_hash, lift_x

Point = Optional[Tuple[int, int]]          # None is the point at infinity


class InvalidContributionError(ValueError):
    """Raised with the index of the signer whose input is invalid (BIP327 'blame')."""

    def __init__(self, signer: Optional[int], contrib: str):
        super().__init__(f"invalid {contrib} from signer {signer}")
        self.signer, self.contrib = signer, contrib


# ------------------------------------------------------------ encodings
def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _bytes32(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _xbytes(pt) -> bytes:
    return _bytes32(pt[0])


def _has_even_y(pt) -> bool:
    return pt[1] % 2 == 0


def _cbytes(pt) -> bytes:
    return (b"\x02" if _has_even_y(pt) else b"\x03") + _xbytes(pt)


def _cbytes_ext(pt) -> bytes:
    return b"\x00" * 33 if pt is None else _cbytes(pt)


def _neg(pt):
    return None if pt is None else (pt[0], P - pt[1])


def _mul(pt, k):
    if pt is None or k % N == 0:
        return None
    return point_mul(pt, k % N)


def _cpoint(b: bytes):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("bad compressed point")
    pt = lift_x(_int(b[1:]))
    if pt is None:
        raise ValueError("x is not on the curve")
    return pt if b[0] == 2 else _neg(pt)


def _cpoint_ext(b: bytes):
    return None if b == b"\x00" * 33 else _cpoint(b)


# ------------------------------------------------------------ keys
def individual_pubkey(sk: bytes) -> bytes:
    d = _int(sk)
    if not 0 < d < N:
        raise ValueError("The secret key must be an integer in the range 1..n-1.")
    return _cbytes(point_mul(G, d))


def key_sort(pubkeys: Sequence[bytes]) -> List[bytes]:
    return sorted(pubkeys)


class KeyAggContext:
    def __init__(self, Q, gacc: int, tacc: int):
        self.Q, self.gacc, self.tacc = Q, gacc, tacc


def get_xonly_pubkey(ctx: KeyAggContext) -> bytes:
    return _xbytes(ctx.Q)


def get_plain_pubkey(ctx: KeyAggContext) -> bytes:
    return _cbytes(ctx.Q)


def _hash_keys(pubkeys) -> bytes:
    return tagged_hash("KeyAgg list", b"".join(pubkeys))


def _second_key(pubkeys) -> bytes:
    for pk in pubkeys:
        if pk != pubkeys[0]:
            return pk
    return b"\x00" * 33


def _key_agg_coeff_internal(pubkeys, pk, pk2) -> int:
    if pk == pk2:
        return 1
    return _int(tagged_hash("KeyAgg coefficient", _hash_keys(pubkeys) + pk)) % N


def key_agg_coeff(pubkeys, pk) -> int:
    return _key_agg_coeff_internal(pubkeys, pk, _second_key(pubkeys))


def key_agg(pubkeys: Sequence[bytes]) -> KeyAggContext:
    pubkeys = list(pubkeys)
    pk2 = _second_key(pubkeys)
    Q = None
    for i, pk in enumerate(pubkeys):
        try:
            Pi = _cpoint(pk)
        except ValueError:
            raise InvalidContributionError(i, "pubkey")
        Q = point_add(Q, _mul(Pi, _key_agg_coeff_internal(pubkeys, pk, pk2)))
    if Q is None:
        raise ValueError("The aggregate public key is infinite.")
    return KeyAggContext(Q, 1, 0)


def apply_tweak(ctx: KeyAggContext, tweak: bytes, is_xonly: bool) -> KeyAggContext:
    if len(tweak) != 32:
        raise ValueError("The tweak must be a 32-byte array.")
    g = N - 1 if is_xonly and not _has_even_y(ctx.Q) else 1
    t = _int(tweak)
    if t >= N:
        raise ValueError("The tweak must be less than n.")
    Q = point_add(_mul(ctx.Q, g), _mul(G, t))
    if Q is None:
        raise ValueError("The result of tweaking cannot be infinity.")
    return KeyAggContext(Q, g * ctx.gacc % N, (t + g * ctx.tacc) % N)


# ------------------------------------------------------------ nonces
def _nonce_hash(rand, pk, aggpk, i, m_prefixed, extra_in) -> int:
    buf = (rand + bytes([len(pk)]) + pk + bytes([len(aggpk)]) + aggpk + m_prefixed
           + len(extra_in).to_bytes(4, "big") + extra_in + bytes([i]))
    return _int(tagged_hash("MuSig/nonce", buf))


def nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pk: bytes, aggpk: Optional[bytes],
                       msg: Optional[bytes], extra_in: Optional[bytes]):
    if sk is not None:
        rand = bytes(a ^ b for a, b in zip(sk, tagged_hash("MuSig/aux", rand_)))
    else:
        rand = rand_
    aggpk = aggpk or b""
    m_prefixed = b"\x00" if msg is None else b"\x01" + len(msg).to_bytes(8, "big") + msg
    extra_in = extra_in or b""
    k1 = _nonce_hash(rand, pk, aggpk, 0, m_prefixed, extra_in) % N
    k2 = _nonce_hash(rand, pk, aggpk, 1, m_prefixed, extra_in) % N
    if k1 == 0 or k2 == 0:
        raise ValueError("nonce is zero")
    pubnonce = _cbytes(point_mul(G, k1)) + _cbytes(point_mul(G, k2))
    return bytearray(_bytes32(k1) + _bytes32(k2) + pk), pubnonce


def nonce_gen(sk: Optional[bytes], pk: bytes, aggpk: Optional[bytes] = None, msg: Optional[bytes] = None,
              extra_in: Optional[bytes] = None):
    """(secnonce, pubnonce). The secnonce is a bytearray that sign() wipes, so it
    can never sign twice: reusing a MuSig2 nonce reveals the secret key."""
    if len(pk) != 33:
        raise ValueError("The pubkey must be a 33-byte array.")
    return nonce_gen_internal(os.urandom(32), sk, pk, aggpk, msg, extra_in)


def nonce_agg(pubnonces: Sequence[bytes]) -> bytes:
    out = b""
    for j in range(2):
        R = None
        for i, pn in enumerate(pubnonces):
            try:
                Rij = _cpoint(pn[j * 33:(j + 1) * 33])
            except ValueError:
                raise InvalidContributionError(i, "pubnonce")
            R = point_add(R, Rij)
        out += _cbytes_ext(R)
    return out


# ------------------------------------------------------------ signing session
class SessionContext:
    def __init__(self, aggnonce: bytes, pubkeys: Sequence[bytes], tweaks: Sequence[bytes],
                 is_xonly: Sequence[bool], msg: bytes):
        self.aggnonce, self.pubkeys = aggnonce, list(pubkeys)
        self.tweaks, self.is_xonly, self.msg = list(tweaks), list(is_xonly), msg


def _session_values(s: SessionContext):
    ctx = key_agg(s.pubkeys)
    for t, x in zip(s.tweaks, s.is_xonly):
        ctx = apply_tweak(ctx, t, x)
    b = _int(tagged_hash("MuSig/noncecoef", s.aggnonce + _xbytes(ctx.Q) + s.msg)) % N
    try:
        R1 = _cpoint_ext(s.aggnonce[0:33])
        R2 = _cpoint_ext(s.aggnonce[33:66])
    except ValueError:
        raise InvalidContributionError(None, "aggnonce")
    R = point_add(R1, _mul(R2, b)) or G
    e = _int(tagged_hash("BIP0340/challenge", _xbytes(R) + _xbytes(ctx.Q) + s.msg)) % N
    return ctx.Q, ctx.gacc, ctx.tacc, b, R, e


def _session_key_agg_coeff(s: SessionContext, Pt) -> int:
    pk = _cbytes(Pt)
    if pk not in s.pubkeys:
        raise ValueError("The signer's pubkey must be included in the list of pubkeys.")
    return key_agg_coeff(s.pubkeys, pk)


def sign(secnonce: bytearray, sk: bytes, session: SessionContext) -> bytes:
    Q, gacc, _, b, R, e = _session_values(session)
    k1_, k2_ = _int(bytes(secnonce[0:32])), _int(bytes(secnonce[32:64]))
    secnonce[:64] = bytes(64)                          # never again
    if not 0 < k1_ < N or not 0 < k2_ < N:
        raise ValueError("first secnonce value is out of range." if not 0 < k1_ < N
                         else "second secnonce value is out of range.")
    k1, k2 = (k1_, k2_) if _has_even_y(R) else (N - k1_, N - k2_)
    d_ = _int(sk)
    if not 0 < d_ < N:
        raise ValueError("secret key value is out of range.")
    Pt = point_mul(G, d_)
    pk = _cbytes(Pt)
    if pk != bytes(secnonce[64:97]):
        raise ValueError("Public key does not match nonce_gen argument")
    a = _session_key_agg_coeff(session, Pt)
    g = 1 if _has_even_y(Q) else N - 1
    d = g * gacc * d_ % N
    s = (k1 + b * k2 + e * a * d) % N
    psig = _bytes32(s)
    pubnonce = _cbytes(point_mul(G, k1_)) + _cbytes(point_mul(G, k2_))
    if not _partial_sig_verify_internal(psig, pubnonce, pk, session):
        raise RuntimeError("partial signature does not verify")
    return psig


def deterministic_sign(sk: bytes, aggothernonce: bytes, pubkeys: Sequence[bytes], tweaks: Sequence[bytes],
                       is_xonly: Sequence[bool], msg: bytes, rand: Optional[bytes] = None):
    """BIP327 stateless signing for the last signer: (pubnonce, psig)."""
    sk_ = bytes(a ^ b for a, b in zip(sk, tagged_hash("MuSig/aux", rand))) if rand is not None else sk
    ctx = key_agg(pubkeys)
    for t, x in zip(tweaks, is_xonly):
        ctx = apply_tweak(ctx, t, x)
    aggpk = get_xonly_pubkey(ctx)
    ks = []
    for i in range(2):
        ks.append(_int(tagged_hash("MuSig/deterministic/nonce", sk_ + aggothernonce + aggpk
                                   + len(msg).to_bytes(8, "big") + msg + bytes([i]))) % N)
    if 0 in ks:
        raise ValueError("nonce is zero")
    pubnonce = _cbytes(point_mul(G, ks[0])) + _cbytes(point_mul(G, ks[1]))
    d = _int(sk)
    if not 0 < d < N:
        raise ValueError("secret key value is out of range.")
    pk = _cbytes(point_mul(G, d))
    secnonce = bytearray(_bytes32(ks[0]) + _bytes32(ks[1]) + pk)
    try:
        aggnonce = nonce_agg([pubnonce, aggothernonce])
    except InvalidContributionError:
        raise InvalidContributionError(None, "aggothernonce")
    return pubnonce, sign(secnonce, sk, SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg))


def _partial_sig_verify_internal(psig: bytes, pubnonce: bytes, pk: bytes, session: SessionContext) -> bool:
    Q, gacc, _, b, R, e = _session_values(session)
    s = _int(psig)
    if s >= N:
        return False
    R1, R2 = _cpoint(pubnonce[0:33]), _cpoint(pubnonce[33:66])
    Re = point_add(R1, _mul(R2, b))
    if not _has_even_y(R):
        Re = _neg(Re)
    Pt = _cpoint(pk)
    a = _session_key_agg_coeff(session, Pt)
    g = 1 if _has_even_y(Q) else N - 1
    g_ = g * gacc % N
    return _mul(G, s) == point_add(Re, _mul(Pt, e * a * g_ % N))


def partial_sig_verify(psig: bytes, pubnonces: Sequence[bytes], pubkeys: Sequence[bytes],
                       tweaks: Sequence[bytes], is_xonly: Sequence[bool], msg: bytes, i: int) -> bool:
    aggnonce = nonce_agg(pubnonces)
    session = SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    try:
        return _partial_sig_verify_internal(psig, pubnonces[i], pubkeys[i], session)
    except InvalidContributionError:
        raise
    except ValueError:
        raise InvalidContributionError(i, "pubnonce" if len(pubnonces[i]) else "pubkey")


def partial_sig_agg(psigs: Sequence[bytes], session: SessionContext) -> bytes:
    Q, _, tacc, _, R, e = _session_values(session)
    s = 0
    for i, ps in enumerate(psigs):
        si = _int(ps)
        if si >= N:
            raise InvalidContributionError(i, "psig")
        s = (s + si) % N
    g = 1 if _has_even_y(Q) else N - 1
    s = (s + e * g * tacc) % N
    return _xbytes(R) + _bytes32(s)


# ------------------------------------------------------------ Kairos addresses
UNSPENDABLE_PQ_ROOT = tagged_hash("Kairos/musig/no-pq-path", b"")   # nobody knows a Lamport key for it


def musig_address(pubkeys: Sequence[bytes], pq_root: bytes) -> Tuple[bytes, bytes]:
    """(address, aggregate x-only key) for a MuSig2 output. `pq_root` must be
    chosen explicitly: UNSPENDABLE_PQ_ROOT, or one party's Lamport root (see
    the module docstring for what each means after the quantum switch)."""
    from .tx import make_address
    if len(pq_root) != 32:
        raise ValueError("pq_root must be 32 bytes")
    agg = get_xonly_pubkey(key_agg(key_sort(pubkeys)))
    return make_address(agg, pq_root), agg
