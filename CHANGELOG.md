# Changelog

## Unreleased

No consensus change.

- Fix: a transaction that arrived while a block was being mined waited for
  the next block, because the miner kept the block it had built (seen on
  testnet 2 at 6054–6055). The miner now rebuilds its block 10 seconds after
  new transactions arrive. Not consensus.
- Fix: `kairos rpc ... | head` printed a BrokenPipeError traceback when the
  reader stopped early.
- `docs/rehearsal-testnet2.md` filled in: activation at 6048, Lamport sends
  mined from 6054, a 600 KRS payment split into two transactions (61 inputs,
  1.50 MB block), `getpqstats` over 6048–6085, and conclusions. Every observed
  size matched the model to the byte. LAUNCH.md's rehearsal item is done.
- Fix: a node syncing from several peers logged the same "new tip" up to
  once per peer. Peer threads compared the tip against the one they saw
  before their own submit, so a thread also reported tips another thread had
  produced. The node now reports each tip once. Logging only.
- Binary P2P (protocol 5, `kairos/wire.py`): after the JSON version
  handshake, two 0.4.2 nodes switch to binary frames (magic, command,
  length, payload). Blocks, transactions and headers travel as raw bytes
  instead of hex, which halves block traffic, and each frame's length is
  checked against a per-command limit before its payload is read. With a
  0.4.0 or 0.4.1 node the conversation stays JSON; interoperation was
  checked in both directions against the released 0.4.1 code. Frames decode
  into the same messages as JSON, so validation is one code path. Hostile
  frames (bad magic, oversized lengths, garbage) earn a ban and never crash
  the node. Encrypted transport (BIP324) is left to the production node.
- MuSig2 (BIP327) in `kairos/musig.py`: key aggregation, tweaks, nonce
  generation and aggregation, partial signing and verification, signature
  aggregation, deterministic signing. It passes every official BIP327 test
  vector. A MuSig2 output is an ordinary Kairos address whose Schnorr key is
  the aggregate key, spent with one 64-byte signature; a test pays and spends
  a 3-of-3 output on chain. No consensus change. Hash-based keys cannot be
  aggregated, so a MuSig2 address must name its post-quantum root
  explicitly: an unspendable root, which freezes the coins if the quantum
  switch activates, or one party's Lamport root, which lets that party alone
  move them after activation. The commit-delay-reveal rule proposed for
  testnet 3 removes this trade-off. A secret nonce is wiped when it signs,
  so it can never sign twice.
- HD wallets: new wallets derive keys by BIP32 from BIP39 words at
  `m/44'/coin'/0'/0/i` (coin 19282' on mainnet, pending SLIP-44
  registration; 1' on test networks). A hardware wallet holding the same
  words derives the same Schnorr keys: each Kairos key is the x-coordinate of
  the standard BIP32 key at that path. Every address's post-quantum key is
  derived from its private key, so an xpub alone cannot produce Kairos
  addresses; watch-only software needs the addresses from the signer.
  `wallet backup` shows the 24 words; `wallet restore "words..."` and
  `wallet xpub` are new. Existing wallets keep their derivation unchanged.
  Verified against all official BIP32 (17 derivations, 16 invalid keys) and
  BIP39 (24) test vectors; RIPEMD-160 has a pure-Python fallback for Python
  builds without it.
- HD wallet files use format 3, which 0.4.0 and 0.4.1 refuse to open. Their
  secrets live under new field names, so an older version raises an error
  instead of deriving legacy keys from the BIP39 seed and showing addresses
  the HD wallet never scans. The encryption MAC also covers the key scheme
  and account. Legacy wallets keep format 2, field for field, and still open
  in 0.4.1 after 0.4.2 saves them. An HD file written by a pre-release build
  in format 2 is rewritten as format 3 the first time it is opened. A test
  runs the released 0.4.1 wallet module, frozen and checked against its git
  blob, against every case.
- Eclipse resistance: the address manager now follows Bitcoin Core's design.
  NEW and TRIED tables are split into buckets placed by a keyed hash with a
  secret per-node key. An address heard from a peer is placed by that peer's
  /16 as well as its own, so one source reaches at most 16 of 256 NEW buckets:
  in a test, 20,000 addresses flooded from one IP kept 490 slots and
  displaced none of 285 honest ones. An address that worked in the last week
  keeps its TRIED slot against newcomers. Outbound connections go to at most
  one peer per /16. `peers.json` gains the key and table (0.4 files still
  load). `getnetworkinfo` reports table sizes.
- New RPC `getpqstats [start end coins share]`: for a block range (default
  the last 2016), post-quantum transaction sizes, inputs per transaction,
  block fill and bytes per Lamport input as observed on chain; and for each
  coin count, how many transactions, blocks and days a sweep takes, computed
  from exact serialized sizes. Example:
  `kairos --testnet rpc getpqstats 6048 6300 '[1000, 1000000]'`.
- `docs/pq-scaling.md`: post-quantum scaling options compared with sizes
  measured by `tools/pq_sizes.py` (real signatures for Lamport, compressed
  Lamport, WOTS+, XMSS-style trees, SLH-DSA and ML-DSA; standard formulas
  checked against FIPS 204/205 tables). Recommends commit-delay-reveal as the
  rule the quantum switch enables, SLH-DSA-SHA2-128s as the fallback key, and
  versioned outputs, all for testnet 3.
- Consensus conformance vectors in `tests/vectors/`: 180 block-by-block
  steps over 7 chains (every reachable rejection reason, reorg, orphan,
  malformed data, ASERT, base fee, version-bits states, the quantum switch by
  signalling and by flag day, merge-mining, checkpoints) and 228 function
  cases (sighash, witnesses, MuHash, ASERT, base fee, auxpow and more).
  `run.py --external CMD` checks another implementation step by step. CI
  verifies the files are exactly what the generator produces and that seven
  injected consensus bugs are each caught.
- `docs/production-node-plan.md`: Bitcoin Core fork against Rust from
  scratch, a component-by-component map of Kairos rules onto Core code, an
  effort estimate (35–53 person-months for the fork), risks, and three
  consensus changes to make on testnet 3 before the port freezes the rules.
- `docs/rehearsal-testnet2.md`: report skeleton for the quantum-switch
  rehearsal on testnet 2, with the timeline to lock-in at 4032 and the
  measurement sections to fill after activation at 6048.

## 0.4.1 — post-quantum sends

No consensus change: 0.4.1 runs on testnet 2 alongside 0.4.0 nodes.

- Fix: after the quantum switch activates, the console `send` and RPC
  `sendtoaddress` signed with Schnorr and every payment was rejected as
  "invalid signature". The wallet now takes the Lamport path by itself once
  `pq` is active (`post_quantum` remains as an explicit override).
- A post-quantum payment that needs more inputs than fit in one transaction
  (about 38 at 24.6 KB per Lamport witness, under a 950 KB wallet cap) is
  split into several transactions; every coin at an address stays in the same
  transaction so a one-time key never signs twice. `sendtoaddress` returns a
  list of txids in that case; the console prints them all.
- An address holding more coins than fit in one transaction cannot be swept
  safely after activation; the wallet refuses with a clear message. Since
  0.4.0 every reward and change output gets a fresh address, so this only
  affects addresses that were reused on purpose. Consolidate such coins with
  ordinary Schnorr spends while the switch is inactive.
- Change below 1,000 motes is left to the miner instead of creating dust.
- Tests: 82 (4 new): automatic Lamport mode, split sweeps under the cap, the
  refusal, and the console and RPC send paths after activation on regtest.

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
