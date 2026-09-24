# Security policy

## Reporting a vulnerability

**Please do not report security problems in public issues.** Use GitHub's
private reporting instead: open the **Security** tab of this repository and
click **Report a vulnerability**. Only the maintainers can see the report.

Especially important to report privately:
- anything that lets a block or transaction break the consensus rules (creating
  coins, double spending, spending without a valid signature);
- anything that makes two nodes disagree about which chain is valid;
- anything that crashes, freezes or disconnects nodes remotely;
- weaknesses in wallet encryption, key derivation or signing.

Please include the Kairos version (`python -m kairos --testnet rpc getnetworkinfo`),
steps to reproduce, and what you expected to happen. You'll get an
acknowledgement, and fixes will be released before details are made public.

Kairos is an unaudited testnet whose coins have no value, so there is no paid
bounty yet. Reporters are credited in the changelog unless they prefer not to be.

## What the system is designed to resist

| Threat | Defence |
|---|---|
| Rented SHA-256 hash power rewriting a young chain | Merge-mining with Bitcoin (`auxpow.py`); effective only once a large share of Bitcoin hash power participates |
| Transaction malleability | txid excludes witnesses; sighash covers the whole body |
| Cross-fork / cross-network replay | chain id inside every signature hash |
| Merkle tree ambiguity (CVE-2012-2459, 64-byte txs) | tagged leaf/node hashes, no duplication; auxpow rejects parent coinbases of 64 bytes or less |
| Duplicate coinbase txids | height committed in header and coinbase |
| Timestamp and difficulty manipulation | per-block ASERT, median-time-past, 2 h future limit |
| Quantum break of secp256k1 | pre-committed Lamport key per address; the `pq` soft fork, activated by miner signalling (or a flag day), disables curve spends |
| A signer misled about what it spends | signature hash commits to every input's value and address |
| Being fed a long chain that carries little work | headers-first: work, schedule and timestamps of the whole header chain are checked before a body is fetched |
| A fake state snapshot | a snapshot is adopted only if its MuHash equals the `utxo_root` of a header with verified proof-of-work; issued supply is recomputed from the schedule |
| Side-channel key leakage when signing | libsecp256k1 backend; wallets refuse to sign on mainnet without it |
| Backend disagreement causing a chain split | differential test across both Schnorr implementations |
| Peer sending garbage, floods, huge messages | ban score, 24 h IP ban, token-bucket rate limit, 5 MB line cap; any exception while handling a message is a ban |
| Filling memory with unknown-parent blocks | orphan pool bounded in bytes and age; an orphan must claim 1/64 of the tip's work |
| A peer that never delivers what it announced | per-peer in-flight limit; stalled requests re-issued to another peer after 60 s |
| Unsolicited bandwidth attacks | inv/getdata relay: data is only sent when requested |
| Connecting to another network | handshake requires matching genesis and magic |
| Memory exhaustion | capped mempool with fee-rate eviction, capped orphans and signature cache; blocks live on disk, not in memory |
| Poisoning a valid block with a corrupted proof | PoW/structure failures are never cached as "invalid block" |
| Crash during write | checksummed block records; torn tail detected and truncated on startup; a damaged `chainstate.dat` means a full replay, never wrong state |
| Crash while signing with a one-time key | the key is marked spent on disk before the signature is produced |
| Wallet theft from disk | seed encrypted (scrypt N=2^17 + HMAC-CTR + HMAC tag), file mode 0600, atomic writes |
| RPC abuse | localhost-only by default, random cookie, constant-time compare, 4 MB body cap |

## Known limitations (0.4.0)

- **Unaudited.** No independent review has taken place. See `LAUNCH.md`.
- **Single implementation, in Python.** The UTXO set and undo data are held
  in memory (blocks are on disk). Adequate for testnet, not for years of
  mainnet history.
- **Fast sync trusts proof-of-work only.** A node that imports a snapshot
  never validates the history below it; an attacker with a majority of the
  hash rate for the depth of that history could feed it a false state, as they
  could rewrite any chain. Prefer snapshots well below the tip.
- **Pure-Python fallback crypto is not constant-time.** It is kept as the
  readable reference and for verification; mainnet signing requires coincurve.
- **Merge-mining pool compatibility is unproven** against real pool software.
- **Merge-mining cuts both ways:** a large Bitcoin pool can also attack a
  merge-mined chain at near-zero marginal cost. Security depends on many
  independent pools participating.
- **P2P gaps:** no compact blocks, no Tor/I2P, JSON wire format (hex doubles
  block size on the wire).
- **Eclipse attacks:** the address manager is deliberately simple (no
  bucketing by network group, unlike Bitcoin Core). An attacker who fills a
  node's address table and connection slots can control its view of the
  chain. Seed nodes and `--connect` peers reduce but do not remove this risk.
- **Wallet:** decrypted seed is held in memory while the node runs; no
  hardware-wallet or BIP32 interoperability; a Lamport key reused on two
  messages is broken (the wallet prevents this, consensus cannot).
- **Clock:** nodes trust their local clock. Run NTP.
