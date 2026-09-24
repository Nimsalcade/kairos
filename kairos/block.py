"""
Kairos blocks.

Header (124 bytes):
    version u32 | height u32 | prev_hash 32 | tx_root 32 | utxo_root 32 |
    time u64 | bits u32 | nonce u64

 * version: bits 0..7 must be 1; bit 8 = merge-mined (auxpow follows the
   header); bits 16..28 = soft-fork signalling (params.Deployment). Other bits
   are ignored by consensus so that future signals never split old nodes.

 * height is in the header: light clients know where they are without trust.
 * tx_root commits to wtxids, so witnesses are committed directly. Clean slate
   means no need for Bitcoin's witness-commitment-in-coinbase workaround.
 * utxo_root is the MuHash3072 digest of the full UTXO set AFTER this block.
   Any node can bootstrap from a recent snapshot and verify it against
   proof-of-work instead of replaying all history.
 * time is 64-bit: no year-2106 problem.
"""
import io
import struct
from dataclasses import dataclass, field
from typing import List

from typing import Optional

from .auxpow import AuxPow
from .crypto import sha256d, merkle_root
from .params import ChainParams, bits_to_target
from .tx import Transaction, TxOut, make_coinbase, read_varint, write_varint, NULL_HASH

VERSION_BASE = 1
VERSION_AUXPOW = 0x100          # header flag: work is proven by a merge-mined parent

HEADER_FMT = "<II32s32s32sQIQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
GENESIS_MESSAGE = (b"22/Sep/2026 Kairos genesis: money should outlive "
                   b"the machines that mint it")


@dataclass
class BlockHeader:
    version: int
    height: int
    prev_hash: bytes
    tx_root: bytes
    utxo_root: bytes
    time: int
    bits: int
    nonce: int

    def serialize(self) -> bytes:
        return struct.pack(HEADER_FMT, self.version, self.height, self.prev_hash,
                           self.tx_root, self.utxo_root, self.time, self.bits, self.nonce)

    @classmethod
    def deserialize(cls, b: bytes) -> "BlockHeader":
        return cls(*struct.unpack(HEADER_FMT, b))

    @property
    def hash(self) -> bytes:
        return sha256d(self.serialize())

    def check_pow(self) -> bool:
        return int.from_bytes(self.hash, "big") <= bits_to_target(self.bits)


@dataclass
class Block:
    header: BlockHeader
    txs: List[Transaction] = field(default_factory=list)
    auxpow: Optional[AuxPow] = None

    def check_pow(self, params: ChainParams) -> bool:
        h = self.header
        target = bits_to_target(h.bits)
        if h.version & VERSION_AUXPOW:
            if self.auxpow is None or h.height < params.auxpow_start_height:
                return False
            try:
                self.auxpow.check(h.hash, params.mm_chain_id, target)
            except ValueError:
                return False
            return True
        return self.auxpow is None and h.check_pow()

    @property
    def hash(self) -> bytes:
        return self.header.hash

    def compute_tx_root(self) -> bytes:
        return merkle_root([t.wtxid for t in self.txs])

    def _aux_bytes(self) -> bytes:
        return self.auxpow.serialize() if self.header.version & VERSION_AUXPOW and self.auxpow else b""

    def serialize(self) -> bytes:
        return (self.header.serialize() + self._aux_bytes() + write_varint(len(self.txs))
                + b"".join(t.serialize() for t in self.txs))

    @classmethod
    def deserialize(cls, b: bytes) -> "Block":
        if len(b) < HEADER_SIZE:
            raise ValueError("block too short")
        f = io.BytesIO(b)
        header = BlockHeader.deserialize(f.read(HEADER_SIZE))
        aux = AuxPow.deserialize(f) if header.version & VERSION_AUXPOW else None
        n = read_varint(f)
        if n > 100_000:
            raise ValueError("too many transactions")
        txs = [Transaction.deserialize(f) for _ in range(n)]
        if f.read(1):
            raise ValueError("trailing data")
        return cls(header, txs, aux)

    @property
    def size(self) -> int:
        """Consensus size: excludes the auxpow proof, which is not block content."""
        return HEADER_SIZE + len(write_varint(len(self.txs))) + sum(t.size for t in self.txs)


def mine(header: BlockHeader, max_tries: int = 1 << 62, should_stop=None) -> bool:
    """Grind the nonce. Returns True when a valid proof-of-work is found."""
    target = bits_to_target(header.bits)
    prefix = header.serialize()[:-8]
    for n in range(header.nonce, header.nonce + max_tries):
        if int.from_bytes(sha256d(prefix + struct.pack("<Q", n)), "big") <= target:
            header.nonce = n
            return True
        if should_stop is not None and n & 0x3FF == 0 and should_stop():
            header.nonce = n
            return False
    return False


def genesis_block(params: ChainParams) -> Block:
    # The genesis output pays to the all-zero address: nobody can spend it.
    cb = make_coinbase(0, [TxOut(0, NULL_HASH)], GENESIS_MESSAGE)
    from .crypto import MuHash
    hdr = BlockHeader(VERSION_BASE, 0, NULL_HASH, b"", MuHash().digest(), params.genesis_time,
                      params.genesis_bits, params.genesis_nonce)
    blk = Block(hdr, [cb])
    hdr.tx_root = blk.compute_tx_root()
    return blk
