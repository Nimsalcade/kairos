# Kairos

**A peer-to-peer electronic cash system built to last.**

Kairos keeps what Bitcoin got right (SHA-256d proof-of-work, UTXOs, the chain
with the most work wins) and redesigns what seventeen years of operation have
exposed. Read the [whitepaper](docs/kairos-whitepaper.pdf).

> [!WARNING]
> **Kairos is an experimental, unaudited public testnet.** Testnet coins have
> **no value and never will**. There is **no mainnet, no token sale, no
> pre-sale and no airdrop**. Anyone offering to sell you Kairos is scamming you.
> The path to a real network is written down in [LAUNCH.md](LAUNCH.md).

> [!NOTE]
> **0.4.0 starts testnet 2.** The consensus rules changed (see
> [CHANGELOG.md](CHANGELOG.md)), so the 0.3 chain was retired. Your wallet
> and backup code keep working; balances start again from zero.

## What is different

| Problem in Bitcoin                          | Kairos, from block 0                                      |
|---------------------------------------------|-----------------------------------------------------------|
| Security budget shrinks toward zero         | Smooth emission that settles into a small permanent reward |
| Fee auctions are volatile                   | Predictable base fee (EIP-1559 style), which is burned    |
| Quantum computers could break today's keys  | Every address also commits to a hash-based backup key     |
| New nodes must replay all history           | Every block commits to the unspent coins and the next base fee; new nodes start from a verified snapshot |
| Hardware wallets cannot see what they pay   | Signatures commit to the amounts being spent              |
| Soft forks need ad-hoc coordination         | Version-bit signalling built in; the quantum switch is the first deployment |
| Difficulty adjusts only every two weeks     | Difficulty adjusts every block (ASERT)                    |
| Small SHA-256 chains are easy to attack     | Merge-mining with Bitcoin supported                       |
| Malleability, Merkle and replay quirks      | Excluded by design                                        |

## Join the testnet

You need Python 3.9 or newer. Tested on Linux (Python 3.9 to 3.13) and macOS.
Windows should work but hasn't been tested yet; reports are welcome.

**1. Get the code.** Click the green **Code** button above, choose **Download
ZIP**, and unzip it. Or, with git: `git clone` this repository.

**2. Install and start a node.** Open a terminal in the unzipped folder:

macOS / Linux:
```
python3 -m venv .venv
.venv/bin/pip install coincurve
.venv/bin/python -m kairos --testnet node --mine
```

Windows (PowerShell):
```
py -m venv .venv
.venv\Scripts\pip install coincurve
.venv\Scripts\python -m kairos --testnet node --mine
```

The first start creates an **encrypted wallet**. Choose a passphrase, then write
down the backup code it prints (`krsseed1...`). Your node finds the network by
itself through the built-in seed nodes. Leave out `--mine` if you only want to
run a node.

**3. Use it.** Type commands at the `>` prompt:

| Command | What it does |
|---|---|
| `info` | Chain height, supply, fees and soft-fork state |
| `balance` | Your coins (mining rewards unlock after 20 blocks) |
| `address` | Your address, to receive coins |
| `send <address> <amount>` | Pay someone, e.g. `send tkrs1... 2.5` |
| `peers` | Who you're connected to |
| `backup` | Show your backup code again |
| `quit` | Stop the node |

Several commands can go on one line, separated by `;`.

### Seed nodes

These are built in, so you don't need to type them:

| Location | Address |
|---|---|
| Frankfurt | `95.179.255.186:19333` |
| Singapore | `45.76.176.39:19333` |
| Miami | `207.246.114.19:19333` |

## Run it your way

- **Always-on server:** [`deploy/setup-seed.sh`](deploy/setup-seed.sh) turns a
  fresh Ubuntu 24.04 server into a hardened, auto-restarting node (unprivileged
  service user, firewall, encrypted wallet, test suite run before going live).
- **Scripting:** the node serves a Bitcoin Core-style JSON-RPC on localhost with
  cookie authentication:
  ```
  python -m kairos --testnet rpc getblockchaininfo
  python -m kairos --testnet rpc sendtoaddress tkrs1... 1.5
  python -m kairos --testnet rpc getpeerinfo
  ```
- **Private experiments:** `--regtest` gives you a private chain with instant
  blocks; `python -m kairos demo` runs a three-node network on your machine.
- **Wallet tools:** `python -m kairos --testnet wallet show | backup | restore <code>`
- **Fast sync:** on a synced node, `python -m kairos --testnet utxo export kairos.snap`;
  on a new node that has been running for a minute (so it has the headers),
  `python -m kairos --testnet utxo import kairos.snap`. The snapshot is only
  accepted if it matches the UTXO commitment in a header whose proof-of-work
  the node has verified. The node then downloads only newer blocks.
- **Soft forks:** miners signal readiness with `--mine --signal pq`; everyone
  can watch the count with `rpc getdeploymentinfo`.
- **Recovery:** `node --reindex` replays every block from disk if
  `chainstate.dat` is ever in doubt.

## Run the tests

```
python -m unittest discover -s tests
```

There are 78 tests, covering consensus rules, soft-fork activation, attacks on
the network layer, headers-first sync, merge-mining proofs, wallet encryption,
crash recovery, fast restart, fast sync, peer discovery and fuzzing. They run
with both signature backends, libsecp256k1 and the pure-Python reference
(`KAIROS_FORCE_PY_CRYPTO=1`).

## Project layout

| Path | Contents |
|---|---|
| `kairos/crypto.py` | Schnorr (libsecp256k1 or reference), Lamport, MuHash3072, Merkle trees, bech32m |
| `kairos/params.py` | Consensus constants, emission, difficulty, base fee, soft-fork deployments, networks |
| `kairos/tx.py`, `block.py` | Transactions, dual-key addresses, blocks, proof-of-work |
| `kairos/auxpow.py` | Merge-mining proofs |
| `kairos/chain.py` | Validation, soft-fork state, UTXO set, reorganisations, mempool, block store, snapshots, fast sync |
| `kairos/wallet.py` | Encrypted deterministic wallet with address rotation and rescan |
| `kairos/node.py`, `addrman.py` | Peer-to-peer network, headers-first sync, discovery, DoS protection |
| `kairos/rpc.py` | JSON-RPC server and client |
| `docs/` | Whitepaper |
| `deploy/` | Server setup script |

## Get involved

- **Announcement and discussion:** [Bitcointalk thread](https://bitcointalk.org/index.php?topic=5594931.0), posted by the maintainer of this repository as CreatorofKairos.
- **Found a bug?** [Open an issue](../../issues/new/choose) using the bug report form.
- **Found a security problem?** Please **don't** open a public issue. See
  [SECURITY.md](SECURITY.md) for private reporting.
- **Want to contribute code?** Read [CONTRIBUTING.md](CONTRIBUTING.md).
- **The most useful thing right now:** run a node, keep it running, and try to
  break the network. That's what a testnet is for.

## Status and history

See [CHANGELOG.md](CHANGELOG.md). Version 0.4.0 starts testnet 2.
Mainnet requires independent audits, a second implementation and at least six
months of public testing; see [LAUNCH.md](LAUNCH.md).

## Credits and license

The design and reference implementation were drafted with the help of Claude,
an AI model made by Anthropic. Kairos is an independent project and is not
affiliated with or endorsed by Anthropic.

Released under the [MIT License](LICENSE).
