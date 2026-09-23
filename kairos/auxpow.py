"""
Merge-mining (auxiliary proof-of-work).

A new SHA-256d chain is tiny next to Bitcoin, so anyone renting a sliver of
Bitcoin's hash power could rewrite it. Merge-mining turns that around: a
Bitcoin miner commits a Kairos block hash inside its Bitcoin coinbase and the
same work secures both chains at no extra cost.

Format follows the structure established by Namecoin (2011) so existing
merge-mining pool software can be adapted with minimal changes:

    coinbase_tx        Bitcoin coinbase, non-witness serialization
    parent_hash        32 bytes, unused (kept for format compatibility)
    coinbase_branch    Merkle branch coinbase -> Bitcoin merkle root (index 0)
    coinbase_index     must be 0
    chain_branch       Merkle branch Kairos hash -> aux-chain tree root
    chain_index        slot of Kairos in the aux-chain tree
    parent_header      80-byte Bitcoin header

The coinbase scriptSig must contain, exactly once:
    fabe6d6d | reversed(aux tree root) | tree size u32 LE | nonce u32 LE

NOTE: byte-for-byte compatibility with specific pool software must be
confirmed on testnet against that software before mainnet.
"""
import io
import struct
from dataclasses import dataclass, field
from typing import List

from .crypto import sha256d

MM_MAGIC = bytes.fromhex("fabe6d6d")
MAX_BRANCH = 30


def _varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def _read_varint(f):
    b = f.read(1)
    if not b:
        raise ValueError("truncated auxpow")
    b = b[0]
    if b < 0xFD:
        return b
    n = {0xFD: 2, 0xFE: 4, 0xFF: 8}[b]
    d = f.read(n)
    if len(d) != n:
        raise ValueError("truncated auxpow")
    return int.from_bytes(d, "little")


def _read(f, n):
    d = f.read(n)
    if len(d) != n:
        raise ValueError("truncated auxpow")
    return d


def parse_btc_tx(f) -> bytes:
    """Consume one non-witness Bitcoin transaction from f and return its raw bytes.
    Also returns nothing about semantics: we only need exact bytes and scriptSig."""
    start = f.tell()
    _read(f, 4)
    n_in = _read_varint(f)
    if n_in == 0:
        raise ValueError("witness-serialized or empty coinbase not accepted")
    for _ in range(n_in):
        _read(f, 36)
        _read(f, _read_varint(f))
        _read(f, 4)
    for _ in range(_read_varint(f)):
        _read(f, 8)
        _read(f, _read_varint(f))
    _read(f, 4)
    end = f.tell()
    f.seek(start)
    return _read(f, end - start)


def coinbase_script(tx: bytes) -> bytes:
    f = io.BytesIO(tx)
    _read(f, 4)
    if _read_varint(f) != 1:
        raise ValueError("parent coinbase must have one input")
    prev = _read(f, 36)
    if prev != b"\x00" * 32 + b"\xff\xff\xff\xff":
        raise ValueError("parent tx is not a coinbase")
    return _read(f, _read_varint(f))


def fold_branch(h: bytes, branch: List[bytes], index: int) -> bytes:
    """Bitcoin-style Merkle path evaluation (internal byte order)."""
    for sib in branch:
        h = sha256d(sib + h) if index & 1 else sha256d(h + sib)
        index >>= 1
    return h


def expected_index(nonce: int, chain_id: int, height: int) -> int:
    """Deterministic slot so one miner cannot put two Kairos blocks in one tree."""
    m = 0xFFFFFFFF
    r = (nonce * 1103515245 + 12345) & m
    r = (r + chain_id) & m
    r = (r * 1103515245 + 12345) & m
    return r % (1 << height)


@dataclass
class AuxPow:
    coinbase_tx: bytes
    coinbase_branch: List[bytes] = field(default_factory=list)
    chain_branch: List[bytes] = field(default_factory=list)
    chain_index: int = 0
    parent_header: bytes = b""
    parent_hash: bytes = b"\x00" * 32
    coinbase_index: int = 0

    def serialize(self) -> bytes:
        out = [self.coinbase_tx, self.parent_hash, _varint(len(self.coinbase_branch))]
        out += self.coinbase_branch
        out.append(struct.pack("<i", self.coinbase_index))
        out.append(_varint(len(self.chain_branch)))
        out += self.chain_branch
        out.append(struct.pack("<i", self.chain_index))
        out.append(self.parent_header)
        return b"".join(out)

    @classmethod
    def deserialize(cls, f) -> "AuxPow":
        if isinstance(f, (bytes, bytearray)):
            f = io.BytesIO(f)
        cb = parse_btc_tx(f)
        if len(cb) > 100_000:
            raise ValueError("parent coinbase too large")
        ph = _read(f, 32)
        n = _read_varint(f)
        if n > MAX_BRANCH:
            raise ValueError("coinbase branch too long")
        cbb = [_read(f, 32) for _ in range(n)]
        cbi = struct.unpack("<i", _read(f, 4))[0]
        n = _read_varint(f)
        if n > MAX_BRANCH:
            raise ValueError("chain branch too long")
        chb = [_read(f, 32) for _ in range(n)]
        chi = struct.unpack("<i", _read(f, 4))[0]
        hdr = _read(f, 80)
        return cls(cb, cbb, chb, chi, hdr, ph, cbi)

    @property
    def parent_pow_hash(self) -> int:
        # Bitcoin compares hashes as little-endian 256-bit integers.
        return int.from_bytes(sha256d(self.parent_header), "little")

    def check(self, aux_hash: bytes, chain_id: int, target: int):
        """Raises ValueError unless this proves `target`-level work for `aux_hash`."""
        if len(self.parent_header) != 80:
            raise ValueError("bad parent header")
        if self.coinbase_index != 0:
            raise ValueError("coinbase must be the first parent transaction")
        if len(self.coinbase_tx) <= 64:
            # a 64-byte "transaction" could be an inner Merkle node in disguise
            raise ValueError("parent coinbase too short")
        if len(self.chain_branch) > MAX_BRANCH:
            raise ValueError("chain branch too long")
        if self.parent_pow_hash > target:
            raise ValueError("parent proof-of-work too weak")
        root = fold_branch(sha256d(self.coinbase_tx), self.coinbase_branch, 0)
        if root != self.parent_header[36:68]:
            raise ValueError("coinbase not in parent merkle root")
        chain_root = fold_branch(aux_hash, self.chain_branch, self.chain_index)
        script = coinbase_script(self.coinbase_tx)
        if script.count(MM_MAGIC) != 1:
            raise ValueError("merge-mining header must appear exactly once")
        pos = script.index(MM_MAGIC) + 4
        if script[pos:pos + 32] != chain_root[::-1]:
            raise ValueError("aux chain root not committed after magic")
        tail = script[pos + 32:pos + 40]
        if len(tail) != 8:
            raise ValueError("missing tree size / nonce")
        size, nonce = struct.unpack("<II", tail)
        if size != 1 << len(self.chain_branch):
            raise ValueError("tree size mismatch")
        if self.chain_index != expected_index(nonce, chain_id, len(self.chain_branch)):
            raise ValueError("wrong slot in aux chain tree")


def build_commitment(aux_hash: bytes, nonce: int = 0) -> bytes:
    """Coinbase scriptSig fragment for a pool merge-mining Kairos alone."""
    return MM_MAGIC + aux_hash[::-1] + struct.pack("<II", 1, nonce)
