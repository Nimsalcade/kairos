# Quantum-switch rehearsal on testnet 2

Status: **activated and measured.** The `pq` deployment activated at block
6048 as scheduled. Lamport-signed payments were sent, mined and received,
including a payment that needed 61 coins and was split into two
transactions. Every measured size matched the model to the byte, and the
largest block reached all three seeds within the same second.

This is the rehearsal required by LAUNCH.md, Gate 3: activate the quantum
emergency on a public network by miner signalling, then move coins with
Lamport signatures and measure what it costs.

## 1. What is being tested

Kairos addresses commit to two keys: a Schnorr key used today, and a
Lamport (hash-based) key held in reserve. The `pq` deployment is a soft fork
on version bit 16. Once active, Schnorr witnesses are invalid and every
spend must reveal its Lamport key. The switch has no timeout
(`timeout_height = 0`): once armed it can only activate, which is what an
emergency needs and why activation on testnet 2 is irreversible.

Parameters on testnet 2:

| Parameter | Value |
|---|---|
| Version bit | 16 |
| Start height | 0 |
| Timeout | none |
| Window | 2016 blocks |
| Threshold | 1916 signalling blocks (95 %) |

## 2. Timeline

Heights come from the chain. To add wall-clock times, run
`kairos --testnet rpc getblockheader $(kairos --testnet rpc getblockhash H)`
and read `time`.

| Height | Event |
|---|---|
| 0 | Testnet 2 genesis, 2026-09-24 00:00 UTC. Nodes run 0.4.0. |
| 805 | All three seeds upgraded to 0.4.1 (seeds agree on block 800). |
| 806 | The maintainer's miner starts with `--signal pq`. |
| 1691–1870 | An outside miner mines blocks with version 1, without the signal. Confirmed at 1691, 1800 and 1859 with `getblockheader`. |
| 2016 | First window closes short of the threshold (blocks 0–805 and the outside miner's blocks did not signal). State stays `started`. |
| 2016–4031 | Second window: every block signals. 1720 of 1720 at height 3735; the threshold was crossed at block 3931. |
| 4032 | State `locked_in` (confirmed at height 4569, `since: 4032`). From here activation cannot be stopped. |
| 4184 | The outside miner returns, still without the signal, taking about half the blocks. No effect after lock-in. |
| 6048 | State `active`. Schnorr spends become invalid (confirmed at height 6051, `since: 6048`). |
| 6054 | First Lamport spend mined: 5 KRS from the console `send`, received by a seed's wallet. |
| 6055 | Second Lamport spend: 3 KRS from RPC `sendtoaddress`. |
| 6082 | A 600 KRS payment, split by the wallet into two transactions with 61 Lamport inputs, mined in one 1.50 MB block. |

## 3. Findings before activation

**Sends failed after activation (fixed in 0.4.1).** A regtest rehearsal before
signalling showed that the console `send` and RPC `sendtoaddress` still
signed with Schnorr once the switch was active, so every payment was rejected
as "invalid signature". 0.4.1 makes the wallet take the Lamport path by
itself, splits payments that need more than about 38 inputs into several
transactions, and refuses to sweep an address holding more coins than fit in
one transaction, because a Lamport key may sign only once. On regtest the
switch activated at height 16 and both send paths delivered exact amounts.
This is why signalling on testnet 2 waited for 0.4.1.

**A miner that does not signal can cost a whole window.** The first window
could not succeed in any case, because blocks 0–805 predate signalling. But
the outside miner's roughly 73 unsignalled blocks alone used up almost three
quarters of what a window tolerates (100 non-signalling blocks). A slightly
larger share of non-upgraded hash power would have pushed lock-in back by
2016 blocks. On mainnet, the miners who do not upgrade decide the timing of
an emergency. See the recommendations in section 6.

**Peer drops on one home connection.** The maintainer's node lost all three
seeds at once five times between heights 4836 and 5097, and reconnected
each time within a block or two. The seeds logged only "lost peer", with no
stall or ban reason, and the node logged no "stalled; dropping". The cause is
the local network, not the node.

**Duplicate "new tip" lines (fixed in 0.4.2).** During sync one height was
logged up to three times with the same hash. Peer threads compared the tip
against the one they saw before their own submit, so a thread also reported
tips that another thread had produced. Logging only; consensus was never
affected.

## 4. Measurements after activation

All figures come from the maintainer's node (0.4.1 for the sends, then
main at 91ef97e for `getpqstats`) over blocks 6048–6085:

```
kairos --testnet rpc getdeploymentinfo
kairos --testnet rpc getpqstats 6048 6085
```

### 4.1 Activation

- `getdeploymentinfo` at height 6051: `"state": "active", "since": 6048`.
- First block with a Lamport spend: **6054**.
- Schnorr spends after 6048: none mined. `getpqstats` counts 0 Schnorr and
  0 mixed transactions, and 63 Lamport inputs to 0 Schnorr inputs. Rejection
  of a Schnorr spend in the first active block is covered by the
  `softfork.json` conformance vector ("invalid signature"); no one tried one
  on testnet 2.

### 4.2 Sends

All three paid addresses of a seed's wallet. Its balance showed 5 KRS once
the first payment was mined.

| Path | Amount | Transactions | Inputs / outputs | Size | Mined in |
|---|---|---|---|---|---|
| Console `send` | 5 KRS | 1 (`cf1e446f…`) | 1 / 2 | 24,738 B | 6054 |
| RPC `sendtoaddress` | 3 KRS | 1 (`597ef997…`) | 1 / 2 | 24,738 B | 6055 |
| RPC `sendtoaddress`, split | 600 KRS | 2 (`2b77ed73…`, `0162251a…`) | 38 / 1 and 23 / 2 | 936,674 B and 566,994 B | 6082 |

The console `send` printed "(post-quantum: Lamport signatures)". The RPC
call returned a single txid for the small payment and a list of two for the
600 KRS one. The wallet filled the first transaction to its 38-input cap and
put the remaining 23 coins and the change in the second.

The model gives 24,738 bytes for a 1-input, 2-output Lamport transaction,
and the mempool reported exactly that. Block 6082's two transactions total
1,503,668 bytes. Of all splits of 1 to 38 inputs and 1 to 2 outputs, only
61 inputs with 3 outputs over two transactions produce that number.

**Finding: a transaction sent during a block waited one extra block.** The
3 KRS payment reached the mempool while block 6054 was being mined, and the
miner kept working on the block it had already built, so the payment was
mined in 6055. Fixed in 0.4.2: the miner rebuilds its block 10 seconds after
new transactions arrive.

### 4.3 Transaction and block figures

From `getpqstats 6048 6085` (38 blocks, all bodies present):

| Measure | Value |
|---|---|
| Post-quantum transactions | 4 |
| Size: min / median / max | 24,738 / 295,866 / 936,674 B |
| Inputs per transaction: min / median / max | 1 / 12 / 38 |
| Lamport inputs, total | 63 |
| Bytes per Lamport input, observed | 24,653.1 (includes per-transaction overhead) |
| Bytes per Lamport input, model | 24,648 |
| Block fill: mean / max | 2.0 % / 75.2 % (block 6082) |

### 4.4 Sweep capacity

The model below is computed by `getpqstats` from exact transaction sizes,
assuming sweeps get the whole of every block.

| Coins to move | Transactions | Blocks | Days at 120 s | Minimum fee |
|---|---|---|---|---|
| 100 | 3 | 2 | 0.003 | 0.025 KRS |
| 10,000 | 264 | 124 | 0.17 | 2.46 KRS |
| 1,000,000 | 26,316 | 12,346 | 17.1 | 246 KRS |
| 100,000,000 | 2,631,579 | 1,234,568 | 1,715 | 24,649 KRS |

Observed: the busiest block, 6082, carried 61 Lamport inputs in 1,503,892
bytes (75.2 % of the limit), which is 24,654 bytes per input including the
block's header and coinbase. The model allows 81 inputs per block. The chain
confirms the per-input cost the table is built on, so the table stands:
Lamport can move thousands of coins in hours, but not a real UTXO set.

### 4.5 Node behaviour under full Lamport blocks

- **Validation time.** Measured offline, not on testnet 2: a regtest block of
  1,873,572 bytes with 76 Lamport inputs in two transactions validates in
  26 ms on a node that has not seen its transactions, on both crypto
  backends (Lamport verification is hashing only). Validation is not the
  bottleneck; size is.
- **Relay and propagation time.** All three seeds logged block 6082 in the
  same second, 15:32:23 UTC, and block 6081 at 15:32:15–16. None logged a
  stall or misbehaviour line that day. So the 1.50 MB block reached every
  seed within 8 seconds of 6081, mining time included, and the seeds
  received it within one second of each other (the log's resolution).
  Between 0.4.1 nodes a block travels as hex inside JSON, so block 6082 was
  about 3 MB on each link; the binary frames in 0.4.2 halve that.
- **Mempool.** The miner's node accepted two transactions of 937 KB and
  567 KB at once and mined both in the next block (the mempool holds 64 MB).

## 5. Conclusions

1. **The emergency mechanism works end to end on a public network.** Miner
   signalling locked the switch in at 4032 despite a non-signalling outside
   miner, activation followed at 6048 without intervention, and both wallet
   send paths moved coins with Lamport signatures from the first eligible
   block.
2. **The size model is exact.** Every transaction and block size observed
   matched the calculation to the byte, so the capacity figures in
   `docs/pq-scaling.md` can be relied on.
3. **Lamport cannot move a real UTXO set.** About 81 coins per block means
   17 days for a million coins with every block given to sweeps. This
   confirms the recommendation to replace it before mainnet with
   commit-delay-reveal backed by SLH-DSA (testnet 3, a hard fork).
4. **Timing depends on miners who do not upgrade.** One outside miner came
   close to delaying lock-in by a full window.
5. **Two operational bugs were found, both fixed:** payments failing after
   activation (0.4.1, found on regtest before signalling) and a transaction
   waiting a block if it arrived mid-block (0.4.2).

## 6. Recommendations so far

- The Lamport path works as an emergency brake but cannot move a real UTXO
  set quickly: about 81 inputs per 2 MB block. See `docs/pq-scaling.md` for
  the options and the recommended replacement.
- Wallets should consolidate coins with Schnorr while it is still safe, so
  an emergency has fewer coins to move.
- Mainnet needs a way to activate an emergency without waiting for miners
  who do not upgrade, for example a flag-day height announced in a release
  (`pq_emergency_height` already exists for this).
