# Production node plan

Status: proposal. This covers LAUNCH.md Gate 2: a production implementation
beside the Python reference, which stays the readable specification and the
source of the conformance vectors in `tests/vectors/`.

## 1. Recommendation

**Fork Bitcoin Core.** Keep the Python node as the second implementation that
checks it: every release must pass the conformance vectors, and the two must
agree under differential fuzzing.

The deciding argument is not consensus code. Kairos's consensus rules are a
few thousand lines in any language. What takes years is everything around
them that keeps a node alive on a hostile network: peer management and
eviction, anti-DoS accounting, eclipse resistance, compact block relay,
encrypted transport, a UTXO database with crash safety, pruning, snapshot
sync, fuzzing harnesses, reproducible builds and a release process. Bitcoin
Core has had all of this attacked in production for fifteen years. A new
Rust node would start that clock at zero.

There are precedents for a Core fork with a different transaction format.
Elements (Liquid) is a Core fork with confidential transactions and its own
transaction serialization. Namecoin Core is a Core fork carrying the
merge-mining proof Kairos copies. Both track upstream Core releases.

## 2. How Kairos maps onto Bitcoin Core

| Kairos rule or component | In Bitcoin Core | Work |
|---|---|---|
| SHA-256d proof of work, chain work, headers-first sync, header anti-DoS (`HeadersSyncState`) | Reused | Small: new header layout, 132 bytes with height, UTXO root, base fee, 64-bit time and nonce |
| BIP340 Schnorr | libsecp256k1 | None |
| Tagged hashes | `HashWriter` / `TaggedHash` | None |
| bech32m | `bech32.cpp` | None |
| Tagged Merkle tree with node promotion | New, replaces `ComputeMerkleRoot` | Small |
| MuHash3072 UTXO commitment | `MuHash3072` and `Num3072` (used by coinstatsindex) | Medium. The arithmetic and prime are the same. Kairos maps elements with SHAKE256 where Core uses ChaCha20 over SHA-256, and hashes the result with a Kairos tag. The commitment must also be kept per block in the connect path, with undo, rather than in a background index |
| UTXO set, `CCoinsViewCache`, LevelDB chainstate, undo data | Reused | Small. A Kairos output `(value, 32-byte address)` fits `CTxOut` with a fixed witness-program-style script |
| Transaction format: no script, no sequence, no locktime; expiry; one witness blob per input; tagged txid and wtxid | `CTransaction` is used everywhere | **Large.** This is the most invasive change: serialization, mempool, relay, RPC, wallet and the functional tests all touch it |
| Witness verification: Schnorr or Lamport against the address commitment, `pq_only` | Replaces `VerifyScript` and the interpreter | Medium. Simpler than script, but policy code assumes script |
| Signature hash committing to chain id, body and all spent amounts and addresses | Like BIP341's `SigMsg` | Small |
| Lamport verification | New | Small |
| ASERT per-block difficulty | Bitcoin Cash Node's `aserti3-2d` in `pow.cpp` (MIT, same code base) | Small |
| Smooth emission with tail | `GetBlockSubsidy` | Small |
| Base fee: EIP-1559 controller, burn, header field | New in validation, `BlockAssembler`, mempool accounting, fee estimation | Medium |
| Coinbase height, maturity, witness size | BIP34-style, reused | Small |
| Version bits, height-based, no timeout for `pq` | `versionbits.cpp` is BIP9 with start and timeout times | Medium: convert to heights (BIP8-style) |
| Merge-mining proof, `createauxblock` / `submitauxblock` | Namecoin Core's `auxpow.cpp` and RPCs | Small to medium: new header |
| UTXO snapshots verified against the header commitment | assumeutxo (`loadtxoutset`) | Medium, and it gets simpler: Kairos can check a snapshot against the header's UTXO root instead of a hard-coded hash |
| P2P: binary, BIP324 encrypted transport, compact blocks, addrman bucketing, eviction, DNS seeds | Reused | Small: network magic, message changes for the new header and transaction format |
| Wallet: HD keys, dual-key addresses, one-time Lamport keys | Descriptor wallet | **Large.** A new descriptor type for Kairos addresses; post-quantum key handling; PSBT equivalent |
| RPC | Reused framework, Bitcoin-compatible names already used by Kairos | Medium |
| Tests | Unit tests, fuzzers, functional test framework | **Large.** The functional tests build Bitcoin transactions; the framework's transaction code must be ported first |

## 3. Effort

These are estimates for a team that already knows the Bitcoin Core code base.
A team learning it should add half again.

| Work package | Person-months |
|---|---:|
| Header, block format, proof of work, ASERT, subsidy, merkle, chain params | 3–4 |
| Transaction format and serialization through validation, mempool, relay | 8–12 |
| Witness verification replacing script; sighash; Lamport; policy | 3–5 |
| UTXO commitment in the connect path, undo, snapshot verification | 3–4 |
| Base fee: validation, block assembly, mempool, fee estimation | 3–4 |
| Height-based version bits, the `pq` deployment | 1–2 |
| Merge-mining port from Namecoin | 1–2 |
| Wallet: HD keys, Kairos descriptors, post-quantum keys, signing | 6–9 |
| RPC and functional test framework port | 5–8 |
| Conformance vectors, differential fuzzing against the Python node | 2–3 |
| **Total** | **35–53** |

That is about a year for four experienced engineers to reach a testnet-ready
node. Hardening, the external audits in Gate 1, and six months of public
testnet (Gate 3) come after it and run partly in parallel.

**Rust from scratch, for comparison.** The consensus code would be quicker to
write and clearer, because Kairos has no script. Crates exist for most
primitives: `secp256k1` (libsecp256k1 bindings), `bitcoin_hashes`, a RocksDB
binding, `tokio`. But the P2P layer, mempool, anti-DoS, storage and wallet
must all be built and then survive attack. A realistic estimate is 60–100
person-months to reach the robustness the Core fork starts with. The record
of alternative Bitcoin implementations is sobering. btcd, a mature Go
implementation, split from Bitcoin Core in 2022 over a witness-size limit. The
Rust node parity-bitcoin was abandoned.

## 4. Risks of the Core fork, and how to contain them

- **Upstream drift.** Every Core release has to be merged. Keep Kairos
  changes as a patch series on a tagged Core release, as Elements does. Keep
  the transaction-format change behind the serialization layer as far as
  possible.
- **The transaction-format change is invasive.** It touches more code than
  everything else together. Do it first, alone, and gate it with the
  conformance vectors and differential fuzzing against the Python node before
  building anything on top.
- **C++ expertise.** The team must be able to review Core-level C++. This is
  a hiring constraint, not a technical one.
- **Licensing.** Core, Bitcoin Cash Node and Namecoin are MIT licensed, which
  is compatible with Kairos's MIT licence.

## 5. Consensus changes to make before the port freezes the rules

Porting is the moment the rules become expensive to change. These are the
changes worth making on testnet 3 first. Together they form one hard fork,
which means a new chain:

1. **Versioned outputs**, with unknown versions valid to spend, so later
   post-quantum schemes can arrive as soft forks. See `docs/pq-scaling.md`.
2. **Commit-delay-reveal as the rule the `pq` deployment switches on,** and
   an SLH-DSA key in new addresses. See `docs/pq-scaling.md`.
3. **Use Bitcoin Core's exact MuHash3072 element mapping** (ChaCha20 over
   SHA-256), with a Kairos domain prefix in the hashed data. Then Core's
   audited class can be used unchanged, and auditors review one less custom
   primitive.

## 6. Order of work

1. Fork a tagged Core release. Replace the chain parameters, header and proof
   of work, with the Python node producing the expected hashes.
2. Port the transaction format end to end until the `core` and `limits`
   vectors pass.
3. Add witness verification, sighash and Lamport until the `softfork` and
   `flagday` vectors pass.
4. Add the UTXO commitment, ASERT, base fee and merge-mining until every
   vector passes.
5. Run differential fuzzing: random and mutated blocks fed to both nodes,
   which must agree on every accept and reject.
6. Build the wallet and RPC, run the functional tests, and join testnet next
   to the Python nodes.
