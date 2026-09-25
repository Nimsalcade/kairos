# Quantum-switch rehearsal on testnet 2

Status: **in progress.** The `pq` deployment is locked in and activates at
block 6048. Sections marked *to fill* are completed after activation from
the commands given in each section.

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
| 6048 | State `active`. Schnorr spends become invalid. *To confirm.* |

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

## 4. Measurements after activation (*to fill*)

Run on any 0.4.2 node after block 6048:

```
kairos --testnet rpc getdeploymentinfo
kairos --testnet rpc getpqstats 6048 <tip> '[100, 10000, 1000000, 100000000]'
```

### 4.1 Activation

- `getdeploymentinfo` at 6048: *to fill*
- First block with a Lamport spend: *to fill*
- Any Schnorr spend rejected after 6048 (expected: none mined): *to fill*

### 4.2 Sends

| Path | Amount | Transactions | Size | Confirmed at |
|---|---|---|---|---|
| Console `send` | *to fill* | | | |
| RPC `sendtoaddress` | *to fill* | | | |
| Split sweep (more than 38 coins) | *to fill* | | | |

### 4.3 Transaction and block figures

From `getpqstats`:

| Measure | Value |
|---|---|
| Post-quantum transactions | *to fill* |
| Size: median / max | *to fill* |
| Inputs per transaction: median / max | *to fill* |
| Bytes per Lamport input, observed | *to fill* |
| Bytes per Lamport input, model | 24,648 |
| Block fill: mean / max | *to fill* |

### 4.4 Sweep capacity

The model below is computed by `getpqstats` from exact transaction sizes,
assuming sweeps get the whole of every block. It is the figure the observed
blocks should confirm.

| Coins to move | Blocks | Days at 120 s |
|---|---|---|
| 100 | 2 | 0.003 |
| 10,000 | 124 | 0.17 |
| 1,000,000 | 12,346 | 17.1 |
| 100,000,000 | 1,234,568 | 1,715 |

Observed: *to fill* (how many inputs the busiest block carried, and whether
propagation or validation time grew with block size).

### 4.5 Node behaviour under full Lamport blocks

- Block validation time for a full block: *to fill*
- Propagation time seed to seed: *to fill*
- Mempool behaviour with several 950 KB transactions: *to fill*

## 5. Conclusions (*to fill*)

## 6. Recommendations so far

- The Lamport path works as an emergency brake but cannot move a real UTXO
  set quickly: about 81 inputs per 2 MB block. See `docs/pq-scaling.md` for
  the options and the recommended replacement.
- Wallets should consolidate coins with Schnorr while it is still safe, so
  an emergency has fewer coins to move.
- Mainnet needs a way to activate an emergency without waiting for miners
  who do not upgrade, for example a flag-day height announced in a release
  (`pq_emergency_height` already exists for this).
