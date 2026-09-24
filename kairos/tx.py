"""
Kairos transactions.

 * UTXO model, like Bitcoin.
 * txid covers only the body (no witness): malleability is impossible by design.
 * Every output pays to a 32-byte *dual-key commitment*:
       address = H("Kairos/address", schnorr_pubkey || pq_root)
   The owner can spend with a 64-byte Schnorr signature today, or with a
   hash-based Lamport signature if elliptic-curve cryptography ever falls.
 * The signature hash commits to the chain id (cross-chain replay protection),
   to the whole transaction (SIGHASH_ALL only) and to the value and address of
   every coin being spent. A signer therefore knows exactly what it pays and
   what fee it leaves, without needing the previous transactions (the problem
   Bitcoin fixed with BIP143 for hardware wallets).
 * Optional expiry height: stuck transactions die instead of haunting mempools.
"""
import io
import struct
from dataclasses import dataclass, field
from typing import List

from .crypto import (tagged_hash, schnorr_verify, lamport_verify, pq_root,
                     LAMPORT_PUB_LEN, LAMPORT_SIG_LEN)

NULL_HASH = b"\x00" * 32
COINBASE_INDEX = 0xFFFFFFFF

WIT_SCHNORR = 0x01
WIT_LAMPORT = 0x02


# ------------------------------------------------------------ serialization

def write_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_varint(f) -> int:
    b = f.read(1)
    if not b:
        raise ValueError("unexpected end of data")
    b = b[0]
    if b < 0xFD:
        return b
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[b]
    return int.from_bytes(read_exact(f, size), "little")


def read_exact(f, n: int) -> bytes:
    d = f.read(n)
    if len(d) != n:
        raise ValueError("unexpected end of data")
    return d


def write_bytes(b: bytes) -> bytes:
    return write_varint(len(b)) + b


def read_bytes(f, limit=1 << 20) -> bytes:
    n = read_varint(f)
    if n > limit:
        raise ValueError("field too large")
    return read_exact(f, n)


# ---------------------------------------------------------------- addresses

def make_address(schnorr_pubkey: bytes, pqroot: bytes) -> bytes:
    return tagged_hash("Kairos/address", schnorr_pubkey + pqroot)


# ---------------------------------------------------------------- structures

@dataclass(frozen=True)
class OutPoint:
    txid: bytes
    index: int

    def serialize(self) -> bytes:
        return self.txid + struct.pack("<I", self.index)


@dataclass
class TxIn:
    prev: OutPoint
    witness: bytes = b""


@dataclass
class TxOut:
    value: int
    address: bytes


@dataclass
class Transaction:
    inputs: List[TxIn]
    outputs: List[TxOut]
    expiry: int = 0             # last block height this tx may be mined in; 0 = never expires
    version: int = 1
    _cache: dict = field(default_factory=dict, repr=False, compare=False)

    # -- encoding
    def body(self) -> bytes:
        out = [struct.pack("<I", self.version), write_varint(len(self.inputs))]
        out += [i.prev.serialize() for i in self.inputs]
        out.append(write_varint(len(self.outputs)))
        out += [struct.pack("<Q", o.value) + o.address for o in self.outputs]
        out.append(struct.pack("<I", self.expiry))
        return b"".join(out)

    def serialize(self) -> bytes:
        return self.body() + b"".join(write_bytes(i.witness) for i in self.inputs)

    @classmethod
    def deserialize(cls, f) -> "Transaction":
        if isinstance(f, (bytes, bytearray)):
            f = io.BytesIO(f)
        version = struct.unpack("<I", read_exact(f, 4))[0]
        n_in = read_varint(f)
        if n_in > 10_000:
            raise ValueError("too many inputs")
        ins = []
        for _ in range(n_in):
            txid = read_exact(f, 32)
            idx = struct.unpack("<I", read_exact(f, 4))[0]
            ins.append(TxIn(OutPoint(txid, idx)))
        n_out = read_varint(f)
        if n_out > 10_000:
            raise ValueError("too many outputs")
        outs = [TxOut(struct.unpack("<Q", read_exact(f, 8))[0], read_exact(f, 32))
                for _ in range(n_out)]
        expiry = struct.unpack("<I", read_exact(f, 4))[0]
        for i in ins:
            i.witness = read_bytes(f, 64 * 1024)
        return cls(ins, outs, expiry, version)

    # -- identities
    def invalidate(self):
        self._cache.clear()

    @property
    def txid(self) -> bytes:
        if "txid" not in self._cache:
            self._cache["txid"] = tagged_hash("Kairos/txid", self.body())
        return self._cache["txid"]

    @property
    def wtxid(self) -> bytes:
        if "wtxid" not in self._cache:
            self._cache["wtxid"] = tagged_hash("Kairos/wtxid", self.serialize())
        return self._cache["wtxid"]

    def sighash(self, chain_id: bytes, spent) -> bytes:
        """`spent` is the (value, address) of each input's coin, in input order."""
        commit = b"".join(struct.pack("<Q", v) + a for v, a in spent)
        return tagged_hash("Kairos/sighash", chain_id + self.body()
                           + tagged_hash("Kairos/spent", commit))

    @property
    def size(self) -> int:
        if "size" not in self._cache:
            self._cache["size"] = len(self.serialize())
        return self._cache["size"]

    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1 and self.inputs[0].prev.txid == NULL_HASH
                and self.inputs[0].prev.index == COINBASE_INDEX)

    def coinbase_height(self) -> int:
        return struct.unpack("<I", self.inputs[0].witness[:4])[0]


def make_coinbase(height: int, outputs: List[TxOut], extra: bytes = b"") -> Transaction:
    # Height is committed in the coinbase, so no two coinbases can share a txid
    # (Bitcoin needed BIP30/BIP34 to patch this after the fact).
    wit = struct.pack("<I", height) + extra[:96]
    return Transaction([TxIn(OutPoint(NULL_HASH, COINBASE_INDEX), wit)], outputs)


# ---------------------------------------------------------------- witnesses

def schnorr_witness(pubkey: bytes, pqroot: bytes, sig: bytes) -> bytes:
    return bytes([WIT_SCHNORR]) + pubkey + pqroot + sig


def lamport_witness(pubkey: bytes, lamport_pub: bytes, sig: bytes) -> bytes:
    return bytes([WIT_LAMPORT]) + pubkey + lamport_pub + sig


def verify_witness(witness: bytes, address: bytes, sighash: bytes, pq_only: bool = False) -> bool:
    if not witness:
        return False
    kind = witness[0]
    if kind == WIT_SCHNORR:
        if len(witness) != 1 + 32 + 32 + 64:
            return False
        if pq_only:
            return False   # elliptic-curve spends disabled: quantum emergency is active
        pk, pqr, sig = witness[1:33], witness[33:65], witness[65:]
        return make_address(pk, pqr) == address and schnorr_verify(sighash, pk, sig)
    if kind == WIT_LAMPORT:
        if len(witness) != 1 + 32 + LAMPORT_PUB_LEN + LAMPORT_SIG_LEN:
            return False
        pk = witness[1:33]
        lpub = witness[33:33 + LAMPORT_PUB_LEN]
        sig = witness[33 + LAMPORT_PUB_LEN:]
        return (make_address(pk, pq_root(lpub)) == address
                and lamport_verify(sighash, lpub, sig))
    return False
