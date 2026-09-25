"""
Post-quantum spending measurements.

Two questions matter once the quantum switch is active:

 * What does the Lamport path actually cost on a real chain? (`measure`)
   Transaction sizes, inputs per transaction and block fill, read from blocks.
 * How long would it take to move N coins? (`sweep_plan`)
   Computed from the exact serialized size of Lamport transactions under the
   consensus block limit and the wallet's per-transaction cap, not from
   rounded constants, so the figures change automatically if the witness
   format or the limits do.

Both are exposed as the `getpqstats` RPC.
"""
import math
from statistics import median

from .block import HEADER_SIZE
from .crypto import LAMPORT_PUB_LEN, LAMPORT_SIG_LEN
from .tx import (OutPoint, Transaction, TxIn, TxOut, WIT_LAMPORT, WIT_SCHNORR,
                 make_coinbase, write_varint)

LAMPORT_WITNESS = 1 + 32 + LAMPORT_PUB_LEN + LAMPORT_SIG_LEN     # 24,609 bytes
SCHNORR_WITNESS = 1 + 32 + 32 + 64                               # 129 bytes
MAX_TX_BYTES = 950_000          # the wallet's cap per transaction (wallet.Wallet.MAX_TX_BYTES)
MAX_RANGE = 20_000              # blocks per call, so the RPC never holds the chain lock for long


def tx_size(n_inputs: int, n_outputs: int, witness_len: int, expiry: bool = False) -> int:
    """Exact serialized size of a transaction with these counts."""
    return Transaction([TxIn(OutPoint(b"\x00" * 32, i), b"\x00" * witness_len) for i in range(n_inputs)],
                       [TxOut(1, b"\x00" * 32)] * n_outputs, 1 if expiry else 0).size


def input_bytes(witness_len: int) -> int:
    """What one more input adds to a transaction."""
    return tx_size(2, 1, witness_len) - tx_size(1, 1, witness_len)


def max_inputs(limit: int, n_outputs: int, witness_len: int) -> int:
    """The most inputs that fit in `limit` bytes."""
    base, per = tx_size(1, n_outputs, witness_len), input_bytes(witness_len)
    if base > limit:
        return 0
    n = 1 + (limit - base) // per
    while n > 1 and tx_size(n, n_outputs, witness_len) > limit:   # varint boundaries
        n -= 1
    return n


def block_room(params) -> int:
    """Bytes a block has for non-coinbase transactions (a typical 1-output coinbase
    with an 8-byte tag, and a 3-byte transaction count)."""
    cb = make_coinbase(1, [TxOut(1, b"\x00" * 32)], b"\x00" * 8).size
    return params.max_block_size - HEADER_SIZE - len(write_varint(0xFFFF)) - cb


def sweep_plan(params, n_coins: int, share: float = 1.0, witness_len: int = LAMPORT_WITNESS,
               base_fee: int = None) -> dict:
    """How long moving `n_coins` coins takes if the sweeps get `share` of every
    block. Each sweep is a transaction of as many inputs as fit under the wallet
    cap, paying to one output. Every input carries its own witness: a Lamport
    signature is never shared between inputs, even from the same address."""
    if n_coins <= 0 or not 0 < share <= 1:
        raise ValueError("n_coins must be positive and share in (0, 1]")
    per_tx = max_inputs(MAX_TX_BYTES, 1, witness_len)
    room = int(block_room(params) * share)
    full = tx_size(per_tx, 1, witness_len)
    k = room // full
    rest = max_inputs(room - k * full, 1, witness_len) if room - k * full > 0 else 0
    per_block = k * per_tx + rest
    if per_block == 0:
        raise ValueError("no input fits in the block share")
    blocks = math.ceil(n_coins / per_block)
    txs = math.ceil(n_coins / per_tx)
    total = (n_coins // per_tx) * full + (tx_size(n_coins % per_tx, 1, witness_len) if n_coins % per_tx else 0)
    fee_rate = params.min_base_fee if base_fee is None else base_fee
    seconds = blocks * params.target_spacing
    return {"coins": n_coins, "share": share, "witness_bytes": witness_len,
            "bytes_per_input": input_bytes(witness_len), "inputs_per_tx": per_tx,
            "inputs_per_block": per_block, "transactions": txs, "blocks": blocks,
            "total_bytes": total, "seconds": seconds, "days": round(seconds / 86400, 2),
            "min_fee_krs": round(total * fee_rate / 1e8, 8)}


def _summary(values) -> dict:
    if not values:
        return {"count": 0}
    return {"count": len(values), "min": min(values), "median": median(values),
            "mean": round(sum(values) / len(values), 2), "max": max(values)}


def measure(chain, start: int, end: int) -> dict:
    """Read blocks start..end of the active chain and report how the Lamport
    path is actually used."""
    if not 0 <= start <= end <= chain.height:
        raise ValueError("block range out of bounds")
    if end - start + 1 > MAX_RANGE:
        raise ValueError(f"at most {MAX_RANGE} blocks per call")
    limit = chain.params.max_block_size
    fills, pq_sizes, pq_inputs, sch_sizes, busy = [], [], [], [], []
    missing = lamport_in = schnorr_in = mixed = 0
    for h in range(start, end + 1):
        blk = chain.blocks.get(chain.active[h].hash)
        if blk is None:            # below a fast-sync snapshot: header only
            missing += 1
            continue
        fills.append(blk.size / limit)
        n_pq = 0
        for tx in blk.txs[1:]:
            kinds = {i.witness[:1] for i in tx.inputs}
            lam = sum(1 for i in tx.inputs if i.witness[:1] == bytes([WIT_LAMPORT]))
            lamport_in += lam
            schnorr_in += sum(1 for i in tx.inputs if i.witness[:1] == bytes([WIT_SCHNORR]))
            if kinds == {bytes([WIT_LAMPORT])}:
                pq_sizes.append(tx.size)
                pq_inputs.append(len(tx.inputs))
                n_pq += 1
            elif lam:
                mixed += 1
            else:
                sch_sizes.append(tx.size)
        if n_pq:
            busy.append({"height": h, "size": blk.size, "fill": round(blk.size / limit, 4),
                         "pq_txs": n_pq, "txs": len(blk.txs) - 1})
    per_input = (round(sum(pq_sizes) / sum(pq_inputs), 1) if pq_inputs else None)
    fs = _summary(fills)
    for k in ("min", "median", "mean", "max"):
        if k in fs:
            fs[k] = round(fs[k], 6)
    return {"start": start, "end": end, "blocks": end - start + 1, "missing_bodies": missing,
            "pq_active_at_end": chain.pq_active(chain.active[end]),
            "pq_txs": _summary(pq_sizes), "pq_inputs_per_tx": _summary(pq_inputs),
            "observed_bytes_per_pq_input": per_input,
            "model_bytes_per_pq_input": input_bytes(LAMPORT_WITNESS),
            "schnorr_txs": _summary(sch_sizes), "mixed_txs": mixed,
            "inputs": {"lamport": lamport_in, "schnorr": schnorr_in},
            "block_fill": fs, "blocks_with_pq_txs": busy[:500]}
