# Kairos mainnet launch gate

Kairos 0.4.0 is **release-candidate software for a public testnet.** It is not yet
fit to hold real value. This file is the checklist that decides when it is.
Every item must be complete, with evidence published, before a mainnet
genesis is announced. None of them can be skipped by a single author, however
capable, because each one exists to catch mistakes its author cannot see.

## Gate 1 — Independent review (cannot be done by the authors)

- [ ] **Consensus audit** by at least two independent firms with blockchain
      consensus experience. Scope: `params.py`, `tx.py`, `block.py`,
      `auxpow.py`, `chain.py`. All high/critical findings fixed and re-reviewed.
- [ ] **Cryptography review** of the dual-key address scheme, the Lamport
      emergency path, the MuHash commitment, and the wallet encryption format.
- [ ] **Economic review** of emission, tail, base-fee burn and fee-sniping
      incentives by someone who did not design them.
- [ ] **Public bug bounty** running for the whole testnet period, with a
      consensus-bug tier large enough to beat what an attacker could earn.

## Gate 2 — A second implementation

- [ ] **Port to a production codebase** (recommended: a fork of Bitcoin Core,
      which already contains BIP340, bech32m, MuHash3072 and witness-free
      txids). The Python client stays as the readable reference.
- [ ] **Cross-implementation consensus testing**: both clients run the same
      chain, replay the same fuzzed blocks, and agree on every accept/reject.
      Two implementations that disagree is a chain split waiting to happen.
- [ ] Replace JSON-over-TCP with a binary protocol; add compact block relay
      and DNS seeds, and a UTXO database (the reference node keeps the UTXO
      set in memory; blocks are already on disk).
- [x] Headers-first sync and peer discovery (addr gossip): 0.3.0 / 0.4.0.

## Gate 3 — Public testnet (minimum 6 months)

- [ ] Testnet (`--testnet`) running continuously with independent operators
      on at least three continents.
- [ ] **Merge-mining verified with real pool software** against the
      `createauxblock` / `submitauxblock` interface. The auxpow format follows
      Namecoin's layout, but byte-level compatibility is only proven by a
      pool actually mining blocks.
- [ ] Deliberate adversarial exercises: a reorg of 10+ blocks, a 51% attack
      by the organisers, mempool flooding, eclipse attempts, malformed-message
      floods, clock-skewed miners. Results published.
- [ ] A rehearsal of the **quantum emergency**: activate the `pq` deployment
      on testnet by miner signalling (`--signal pq`) and sweep coins with
      Lamport signatures at scale. (Mechanism built in 0.4.0; rehearsal pending.)
- [ ] No consensus-affecting bug found in the final 90 days.

## Gate 4 — Still to design and build

- [x] Soft-fork activation mechanism (BIP8-style version bits, 0.4.0). The
      quantum switch is its first deployment.
- [ ] Standard HD wallet derivation (BIP32-style) so hardware wallets and
      other software can hold Kairos keys.
- [ ] MuSig2 key aggregation for multi-party outputs.
- [x] UTXO snapshot export/import verified against the header commitment
      (0.4.0). Still to do: publish snapshots and their hashes with releases.
- [ ] Final replacement of the Lamport path with a compact hash-based scheme
      (e.g. SPHINCS+) if reviewers recommend it.

## Gate 5 — Launch hygiene

- [ ] Reproducible builds; releases signed by several maintainers.
- [ ] Mainnet genesis re-mined with a **fresh timestamp and message chosen at
      launch**, published with the checkpoint in the release notes. The
      current mainnet genesis in `params.py` is a placeholder.
- [ ] Legal review in the jurisdictions of whoever launches it. A new
      currency with a public launch has securities, tax and money-transmission
      implications that vary by country.
- [ ] A written incident-response plan: who can publish an emergency release,
      how nodes are told, how a consensus bug is handled.

## What 0.4.0 already provides

See `CHANGELOG.md`. In short: merge-mining with Bitcoin, a constant-time
signing backend with mainnet refusal to sign without it, differential tests
proving both crypto backends agree, amount-committing signatures, soft-fork
activation by signalling, headers-first sync with multi-peer download, a
hardened P2P layer, bounded memory pools and caches, crash-safe storage with
fast restart, fast sync from verified UTXO snapshots, checkpoints, encrypted
wallets with address rotation and checksummed backups, an authenticated
Bitcoin-style JSON-RPC, a testnet, and 78 tests including fuzzing and
live-network attack scenarios.
