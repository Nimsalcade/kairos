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

Rules 2 (testnet 3, mainnet; transaction version 2) change the outputs and the
post-quantum key, see docs/rules-v2.md:
 * An output script is 33 bytes: a version byte and a 32-byte program.
   Version 0 pays to H("Kairos/address2", schnorr_pubkey || slh_leaf), where
   slh_leaf = H("Kairos/slh-leaf", slhdsa_pubkey || salt). Version 0x80 is a
   spend commitment (value 0, never a coin). Versions 1..0x7F are reserved for
   future soft forks and are spendable with any witness; 0x81..0xFF are invalid.
 * The post-quantum key is SLH-DSA-SHA2-128s (FIPS 205). It is stateless, so a
   wallet can use one key for all its addresses; the per-address salt keeps
   the addresses unlinkable until an SLH-DSA spend reveals the key.
"""
import io
import struct
from dataclasses import dataclass, field
from typing import List

from .crypto import (tagged_hash, schnorr_verify, lamport_verify, pq_root,
                     LAMPORT_PUB_LEN, LAMPORT_SIG_LEN)
from . import slhdsa

NULL_HASH = b"\x00" * 32
COINBASE_INDEX = 0xFFFFFFFF

WIT_SCHNORR = 0x01
WIT_LAMPORT = 0x02              # rules 1 only
WIT_SLHDSA = 0x03               # rules 2 only

TX_VERSION_V1 = 1
TX_VERSION_V2 = 2               # rules 2: outputs carry a version byte

OUT_KEY = 0x00                  # rules 2 output versions
OUT_COMMIT = 0x80
OUT_FUTURE_MAX = 0x7F           # 1..0x7F: reserved for soft forks, anyone can spend

SCHNORR_WITNESS_LEN = 1 + 32 + 32 + 64
SLHDSA_WITNESS_LEN = 1 + 32 + slhdsa.PK_BYTES + 32 + slhdsa.SIG_BYTES     # 7,953


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


def slh_leaf(slh_pubkey: bytes, salt: bytes) -> bytes:
    return tagged_hash("Kairos/slh-leaf", slh_pubkey + salt)


def make_script(schnorr_pubkey: bytes, leaf: bytes) -> bytes:
    """Rules 2: the 33-byte script of a version-0 (key) output."""
    return bytes([OUT_KEY]) + tagged_hash("Kairos/address2", schnorr_pubkey + leaf)


def commit_script(commitment: bytes) -> bytes:
    return bytes([OUT_COMMIT]) + commitment


def spend_commitment(txid: bytes, schnorr_pubkeys) -> bytes:
    """What must be on chain `reveal_delay` blocks before a Schnorr spend once the
    quantum switch is active: the transaction's id and every Schnorr key it will
    reveal, in input order. Without the keys an attacker could not compute it,
    so it cannot be made in advance by anyone but the owner."""
    return tagged_hash("Kairos/commit", txid + b"".join(schnorr_pubkeys))


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
    def deserialize(cls, f, rules: int = 1) -> "Transaction":
        """`rules` is the network's rule set: it fixes the output script length
        (32 bytes under rules 1, 33 under rules 2), so a rules-1 node parses every
        transaction exactly as 0.4 did, whatever its version field says."""
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
        script_len = 33 if rules >= 2 else 32
        outs = [TxOut(struct.unpack("<Q", read_exact(f, 8))[0], read_exact(f, script_len))
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


def make_coinbase(height: int, outputs: List[TxOut], extra: bytes = b"", version: int = TX_VERSION_V1) -> Transaction:
    # Height is committed in the coinbase, so no two coinbases can share a txid
    # (Bitcoin needed BIP30/BIP34 to patch this after the fact).
    wit = struct.pack("<I", height) + extra[:96]
    return Transaction([TxIn(OutPoint(NULL_HASH, COINBASE_INDEX), wit)], outputs, 0, version)


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


# ------------------------------------------------------ rules 2 witnesses

def schnorr_witness2(pubkey: bytes, leaf: bytes, sig: bytes) -> bytes:
    return bytes([WIT_SCHNORR]) + pubkey + leaf + sig


def slhdsa_witness(pubkey: bytes, slh_pubkey: bytes, salt: bytes, sig: bytes) -> bytes:
    return bytes([WIT_SLHDSA]) + pubkey + slh_pubkey + salt + sig


def verify_witness2(witness: bytes, script: bytes, sighash: bytes):
    """Check a witness against a rules-2 version-0 script. Returns the revealed
    Schnorr key for a valid Schnorr spend, b"" for a valid SLH-DSA spend and
    None if invalid. (The commit-delay-reveal rule is checked by the chain.)"""
    if not witness or len(script) != 33 or script[0] != OUT_KEY:
        return None
    kind = witness[0]
    if kind == WIT_SCHNORR and len(witness) == SCHNORR_WITNESS_LEN:
        pk, leaf, sig = witness[1:33], witness[33:65], witness[65:]
        if make_script(pk, leaf) == script and schnorr_verify(sighash, pk, sig):
            return pk
        return None
    if kind == WIT_SLHDSA and len(witness) == SLHDSA_WITNESS_LEN:
        pk = witness[1:33]
        spk = witness[33:33 + slhdsa.PK_BYTES]
        salt = witness[33 + slhdsa.PK_BYTES:65 + slhdsa.PK_BYTES]
        sig = witness[65 + slhdsa.PK_BYTES:]
        if make_script(pk, slh_leaf(spk, salt)) == script and slhdsa.verify(sighash, sig, spk):
            return b""
        return None
    return None
