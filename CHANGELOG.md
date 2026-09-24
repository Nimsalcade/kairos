# Changelog

## 0.4.0 — testnet 2: consensus v2, headers-first, fast sync

**The public testnet was reset.** 0.4.0 changes the signature hash and the
block header, so it is a new chain ("testnet 2") with its own chain id, magic
and genesis. Testnet coins never had value; wallets keep working (same seed,
same addresses) with a zero balance. Data directories from 0.3 are ignored
(`blocks-v2.dat` is left untouched; the new files are `blocks-v3.dat`,
`chainstate.dat`, `headers.dat`). The whitepaper is revised (revision 4,
`docs/kairos-whitepaper.md`) to describe these rules; revision 3 is kept as
`docs/kairos-whitepaper-r3-0.3.0.pdf`.

Consensus (hard fork)
- The signature hash commits to the value and address of every coin being
  spent, so a signer always knows what it pays and what fee it leaves without
  the previous transactions (the problem BIP143 fixed for hardware wallets).
- Soft-fork activation by miner signalling in header version bits 16..28
  (BIP8-style, height based; 95 % of a 2016-block window on mainnet and
  testnet). The post-quantum emergency switch is the first deployment and
  never times out; once ACTIVE, Schnorr spends are invalid and only Lamport
  spends are accepted. `pq_emergency_height` remains as a flag-day override.
- The header gains `fee`, the base fee for the next block (132 bytes). With
  `utxo_root` the header now commits to everything a node needs to continue
  from a snapshot, and light clients read the fee level from headers.
- Context-free block checks reject targets above the proof-of-work limit.

Network (protocol 4; 0.3 nodes are disconnected politely, never banned)
- Headers-first sync: a peer's whole chain of headers (with merge-mining
  proofs) is validated for work, schedule and timestamps before any body is
  requested; bodies are then fetched in order along the most-work header
  chain from every peer that has them, 16 in flight per peer, and stalled
  requests move to another peer after 60 s. Nobody can make a node download
  a chain that does not carry the most work. `getblocks` is gone.
- Every exception while handling a message counts as misbehaviour. 0.3.0 let
  deeply nested JSON (RecursionError) and `"height": 1e999` (OverflowError)
  kill the reader thread and leave zombie connections holding slots.
- JSON numbers used as integers are validated (no floats, bools, negatives).
- The orphan pool is bounded in bytes and age, and an orphan must claim at
  least 1/64 of the tip's per-block work: trivially mined junk is not stored.

Node and storage
- Fast sync: `kairos utxo export FILE` on any synced node, `kairos utxo
  import FILE` on a new one. The snapshot is adopted only if its MuHash
  digest equals the `utxo_root` of a header the node has verified
  proof-of-work for; history below it is never downloaded and cannot be
  reorganised.
- Fast restart: clean shutdown (and every 2000 blocks) writes
  `chainstate.dat`; startup rebuilds the index from the block file without
  re-validating snapshot-covered blocks. `--reindex` forces a full replay.
- Blocks are read back from disk through a small cache instead of being held
  in memory forever. Best-chain selection is incremental (sync was quadratic).
- Reorganisations recover ancestors' UTXO commitments arithmetically from the
  child's, so only the tip's MuHash value is kept.

Wallet
- Lamport one-time keys are recorded as spent on disk *before* a signature
  exists: a crash mid-signing can never lead to a second signature.
- A fresh address for every mined block and every change output, so a Schnorr
  public key is revealed at most once. Restore rescans the chain with a gap
  limit of 20 and finds every address.
- The scrypt key is derived once per session rather than on every save.

RPC/CLI: `getblockchaininfo` shows `headers`, `assumed_height`, `pq_only` and
`softforks`; new `getdeploymentinfo`, `setsignal`, `rescanwallet`,
`dumputxoset`, `loadutxoset`; `node --signal pq`, `node --reindex`; the
console `info` command shows soft-fork state.

Tests: 78 (23 new), run with both signature backends.

## 0.3.0 — the network heals and finds itself

Networking (protocol 3; interoperates with 0.2.x)
- Automatic reconnection: `--connect` peers are kept connected forever and
  redialled with backoff whenever a connection drops or a peer restarts.
- Peer discovery: address manager (`peers.json`) fed by seed nodes, `getaddr`
  / `addr` gossip and inbound peers' advertised ports; nodes keep up to 8
  outbound connections. Public networks accept only globally routable IPv4.
- Testnet seed nodes built in: `python -m kairos --testnet node` joins the
  network with no IP addresses at all.
- Address gossip is only sent to protocol-3 peers, and unknown message types
  are now ignored instead of penalised, so future versions stay compatible.
- RPC: `addnode`, `getnodeaddresses`; `getpeerinfo` shows protocol/manual.

Robustness fixes found by rehearsing the live rollout
- Per-peer send queue with a dedicated writer thread. Previously two nodes
  sending large amounts to each other at once could deadlock, which froze a
  miner. Peers that stop reading for 64 MB are dropped.
- Requested blocks/transactions no longer count toward the flood limit; a new
  node downloading a long chain used to ban the seed it was syncing from.
- A connection that closes mid-message (peer restarting) is no longer
  mistaken for an oversized-message attack and banned for 24 hours.
- Tip announcements and sync requests are rate-limited, so catching up on
  hundreds of blocks no longer looks like a flood to other peers.
- Peers chosen by the operator (`--connect`, `addnode`) are disconnected and
  retried on misbehaviour, never IP-banned.
- The listening socket is released properly on shutdown.

Tests: 55 (12 new: address manager, discovery, reconnection, seed bootstrap,
self-connection, persistence, 0.2.2 compatibility). Rollout rehearsed with
real processes on separate IPs: 0.2.2 seeds upgraded one by one under a
0.3 miner, at realistic pace and at >100 blocks/s, with zero bans.

## 0.2.2 — handshake ordering fix

- Fix: a node could send a message before its own version when the peer's
  version arrived instantly (a race introduced by the 0.2.1 tip announcement).
  The peer then correctly banned it for "message before handshake". Seen on
  the live testnet when a miner reconnected to all seed nodes. Version is now
  written before the reader thread starts, so it is always first on the wire.
- Regression test: 200 immediate-version connections must each see version first.

## 0.2.1 — relay fixes found on the live testnet

- Fix: blocks mined while a peer handshake was in progress were never announced
  to that peer. Nodes now announce their tip when a handshake completes.
- Fix: blocks connected from the orphan pool were never relayed onward, which
  could leave a node one block behind until the next block. Nodes now announce
  the resulting tip as well as the block received.
- Regression test reproducing both races with deliberately slow handshakes.
  Found because the Singapore seed node's setup refused to go live when the
  three-node network test timed out on its slower VM.

## 0.2.0 — hardening release (testnet candidate)

Consensus
- Merge-mining (AuxPoW) with Bitcoin in Namecoin-style format, multi-chain
  tree with deterministic slot, rejects parent coinbases <= 64 bytes.
- Header version: low byte must be 1; upper bits reserved for soft-fork signalling.
- Coinbase witness limited to 4..100 bytes.
- Checkpoint support, including rejection of forks below the last checkpoint.
- Public testnet with its own genesis, chain id, magic, ports and address prefix (tkrs1).

Cryptography
- Constant-time libsecp256k1 backend (via coincurve) with pure-Python fallback.
- Differential test proving both backends agree on valid and malformed signatures.
- Mainnet wallets refuse to sign without the hardened backend.

Networking (protocol 2, incompatible with 0.1.x)
- Version handshake bound to genesis hash; self-connection detection.
- Announce-then-request relay (inv/getdata) replaces pushing full data.
- Misbehaviour scoring with 24 h bans; rate limiting; message size cap;
  inbound peer cap; handshake and idle timeouts; pings.

Node
- Bounded mempool with fee-rate eviction; bounded signature cache and orphans.
- Crash-safe block storage (magic, length, checksum; torn tails truncated).
  New file name `blocks-v2.dat`; 0.1.x regtest data is not migrated.
- Authenticated JSON-RPC modelled on Bitcoin Core, including
  createauxblock / submitauxblock / getauxblock for pools.
- Daemon mode; CLI options accepted before or after the command.

Wallet
- Encrypted seed at rest; atomic, fsynced writes; mode 0600.
- bech32m backup codes (krsseed1...) with typo detection; restore command.
- Tracks revealed one-time keys; never mines or sends change to them.

Tests: 41 (23 core + 18 hardening), including fuzzing, merge-mining attacks,
peer attacks, crash recovery and RPC-driven merge-mining.

## 0.1.0 — initial release
