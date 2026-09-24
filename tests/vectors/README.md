# Kairos consensus conformance vectors

These files are the contract a second implementation of Kairos, in C++, Rust
or anything else, must meet. They are produced by the Python reference node
and describe, block by block, what it accepts and rejects and what state it
reaches. An implementation that disagrees on any step would split the chain.

```
python3 tests/vectors/run.py                         # the reference passes
python3 tests/vectors/run.py --external ./my-node-replay   # check another node
python3 tests/vectors/generate.py                    # regenerate (deterministic)
```

`tests/test_vectors.py` runs on every CI build. It checks that the reference
passes, that the committed files are byte for byte what the generator
produces, and that seven deliberately injected consensus bugs are each caught.

## Files

| File | What it covers |
|---|---|
| `chains/core.json` | Every transaction rule, block structure, coinbase rules, timestamps, a parent-invalid child, an orphan, a reorganisation with a double spend, malformed encodings, and accepted boundary cases |
| `chains/limits.json` | Block and transaction size limits; the base fee rising (including the +1 floor), falling, and the burn |
| `chains/asert.json` | ASERT difficulty rising under fast blocks, falling under slow ones, clamped at the proof-of-work limit |
| `chains/softfork.json` | Version-bits states: started, locked in, active, failed at timeout, lock-in exactly at timeout; Lamport valid before and after activation, Schnorr invalid after |
| `chains/flagday.json` | `pq_emergency_height` activation without signalling |
| `chains/auxpow.json` | Merge-mined blocks, the start height, and four broken proofs |
| `chains/checkpoints.json` | A checkpoint mismatch and a fork below the last checkpoint |
| `functions.json` | The pure functions, for porting one piece at a time (below) |

## Chain vector format

```json
{
  "format": 1,
  "name": "core",
  "description": "...",
  "params": { "name": "regtest", "chain_id": "4b525401", "pow_limit": "0fff...", "deployments": [...], ... },
  "genesis": "<hash of the genesis block built from params>",
  "steps": [
    {
      "note": "Schnorr signature with one bit flipped",
      "now": 1790035262,
      "block": "<serialized block, hex>",
      "expect": "invalid: invalid signature",
      "tip": "<hex>", "height": 5, "utxo_root": "<hex>", "next_base_fee": 1,
      "deployments": {"pq": "started"}
    }
  ]
}
```

- `params` holds every consensus field of `ChainParams` (`kairos/params.py`).
  Bytes are hex; `pow_limit` is a 64-digit hex number.
- Build the genesis block from `params` and check its hash against `genesis`.
  Then submit each step's block in order to one chain. Before each step, set
  the node's clock to `now`, which is used by the future-timestamp rule.
- `expect` is the result of submitting the block:
  - `accepted`: the block is valid and all its ancestors are known. It may
    or may not become the tip.
  - `invalid: <reason>`: the block breaks a rule (reasons below).
  - `orphan`: the parent is unknown. A node may hold the block until the
    parent arrives; the vectors rely on that once.
  - `duplicate`: the block was already fully known.
  - `malformed`: the bytes do not decode as a block.
- `tip`, `height`, `utxo_root`, `next_base_fee` and `deployments` describe
  the chain after the step: the active tip, its height, its UTXO commitment,
  the base fee the next block must use, and each deployment's state for the
  next block.

Each invalid block is a valid block with exactly one rule broken. So its
reason does not depend on the order in which an implementation checks rules.
An implementation may use its own error names; run it with
`--accept-any-reason`, but it must still reject the same block at the same
step.

### External implementations

`run.py --external CMD` runs `CMD <vector.json>` once per chain vector. The
command replays the steps on a fresh chain and prints a JSON array with one
object per step. `status` is required; the other fields are compared when
present:

```json
[{"status": "accepted", "tip": "...", "height": 1, "utxo_root": "...", "next_base_fee": 1,
  "deployments": {"pq": "started"}}, ...]
```

## Rejection reasons and where they are tested

| Reason | Rule | Vectors |
|---|---|---|
| `unknown block version` | the header version's low byte must be 1 | core |
| `target above proof-of-work limit` | bits may not encode a target above `pow_limit` | core |
| `proof-of-work too weak` | header hash, or merge-mining proof, meets the target; auxpow only from `auxpow_start_height` | core, auxpow |
| `first transaction must be coinbase` | | core |
| `multiple coinbases` | | core |
| `block too large` | consensus size, excluding the auxpow proof, at most `max_block_size` | limits |
| `tx_root mismatch` | tagged Merkle root over wtxids | core |
| `bad coinbase witness size` | 4 to `coinbase_witness_max` bytes | core |
| `coinbase height mismatch` | the coinbase witness starts with the height | core |
| `bad height` | parent height + 1 | core |
| `checkpoint mismatch` / `fork below last checkpoint` | `params.checkpoints` | checkpoints |
| `bad difficulty bits` | ASERT from the genesis anchor | core, asert |
| `timestamp too early` | above the median of the last 11 blocks | core |
| `timestamp too far in future` | at most `now + max_future_drift` | core |
| `parent invalid` | | core |
| `unknown tx version` | version 1 only | core |
| `transaction expired` | expiry 0, or at least the block height | core |
| `transaction too large` | at most half the block limit | limits |
| `empty inputs or outputs` | | core |
| `duplicate input` | | core |
| `bad output` / `output total overflow` | 0 < value ≤ MAX_MONEY, sum ≤ MAX_MONEY | core |
| `missing or spent input` | includes a double spend inside one block | core |
| `immature coinbase spend` | `coinbase_maturity` blocks | core |
| `invalid signature` | witness kind, lengths, address commitment, sighash (chain id, amounts), and Schnorr disabled once `pq` is active | core, softfork, flagday |
| `outputs exceed inputs` | | core |
| `fee N below base fee burn M` | fee ≥ base fee × size | core, limits |
| `bad coinbase fields` | coinbase version 1, expiry 0 | core |
| `bad coinbase output` | 0 ≤ value ≤ MAX_MONEY | core |
| `coinbase pays too much` | at most subsidy + fees − burns | core |
| `utxo_root mismatch` | MuHash3072 of the UTXO set after the block | core |
| `base fee mismatch` | header `fee` = next base fee | core |

Not covered, on purpose:

- `unexpected coinbase` and `output already exists` cannot be reached
  through a block. A coinbase after the first position fails as `multiple
  coinbases` first, and txids cannot repeat.
- `fork below the UTXO snapshot this node started from` depends on how a node
  was bootstrapped, not on the chain.
- Mempool policy (`conflicts`, `mempool full`) is not consensus.

## Function vectors (`functions.json`)

Each key is a list of cases with inputs and the expected output:

| Key | Function |
|---|---|
| `tagged_hash` | BIP340-style tagged SHA-256 |
| `bits` | compact bits ↔ target, including the round trip |
| `subsidy`, `generated_at` | emission from the amount issued, and at a height |
| `asert` | `asert_target` for a grid of anchors, drifts and heights |
| `next_base_fee` | the base-fee controller |
| `merkle_root` | tagged Merkle root, 1 to 9 leaves |
| `muhash` | MuHash3072 digests after inserts and removals |
| `coin_bytes` | the serialization MuHash commits to |
| `address` | address from the Schnorr key and `pq_root`, and its bech32m forms |
| `sighash` | txid and signature hash for three chain ids, with and without an amount change |
| `witness` | `verify_witness` for Schnorr and Lamport witnesses, valid and broken, with `pq_only` on and off |
| `lamport` | `pq_root` from a key seed |
| `auxpow` | the merge-mining proof check, with the exact error for each broken proof |
| `aux_slot` | the merge-mining tree slot |
| `genesis` | the regtest genesis block and its hash |
