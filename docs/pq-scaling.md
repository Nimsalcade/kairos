# Post-quantum scaling

Status: design proposal for testnet 3. Nothing here changes testnet 2.

Every figure in this document is produced by `tools/pq_sizes.py`. For each
scheme, the tool either signs and verifies with a real implementation and
measures the result, or computes the size from the standard's parameter
formula and checks it against the standard's own table. Capacity comes from
the node's sweep model (`kairos/pqstats.py`, also behind the `getpqstats`
RPC), which uses exact serialized transaction sizes under the 2 MB block
limit and the wallet's 950 KB per-transaction cap. To reproduce:

```
pip install slh-dsa dilithium-py     # optional: real SLH-DSA and ML-DSA signatures
python3 tools/pq_sizes.py
```

## 1. The problem

The quantum switch deployed on testnet 2 makes every spend reveal a Lamport
key: 24,609 bytes of witness per input. A 2 MB block then holds 81 inputs,
against about 12,000 Schnorr inputs today. That is a 148-fold loss of
spending capacity.

| Coins that must move | Blocks of Lamport spends | Time at 120 s blocks |
|---|---:|---:|
| 1,000,000 | 12,346 | 17 days |
| 100,000,000 | 1,234,568 | 4.7 years |

## 2. What an emergency actually has to protect

Getting the threat right changes which option wins.

- **A Kairos address hides both keys.** It is `H(schnorr_pk || pq_root)`. A
  quantum attacker needs a Schnorr public key before it can compute the
  private key, and a public key appears only when a coin at that address is
  spent. Since 0.4.0 the wallet uses a fresh address for every reward and
  every change output, and it spends all coins of an address in one
  transaction.
- **Before activation**, three kinds of coin are exposed: coins at an address
  whose key was already revealed (address reuse), coins in a transaction
  waiting in the mempool, and nothing else.
- **After activation**, no coin can be stolen with an elliptic-curve break,
  because Schnorr witnesses are invalid. Coins are safe where they sit. What is
  lost is spending capacity: every payment now carries a hash-based signature.

So "migrating the UTXO set" is not a race against thieves after activation.
The two real costs are the window between the threat becoming credible and
activation, and a chain that can only process 81 inputs per block afterwards.
A good design shrinks both.

## 3. Options

### 3.1 Signature schemes

| Scheme | PQ key in witness | Signature | Witness | Bytes per input | Inputs per 2 MB block | 1M coins (days) | 100M coins (days) | Source |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Lamport (deployed) | 16,384 | 8,192 | 24,609 | 24,648 | 81 | 17.15 | 1,714.68 | measured |
| Lamport, compressed | 0 | 16,384 | 16,417 | 16,456 | 121 | 11.48 | 1,147.84 | measured |
| WOTS+ n=32 w=4 | 32 | 4,256 | 4,321 | 4,360 | 458 | 3.03 | 303.25 | measured |
| WOTS+ n=32 w=16 | 32 | 2,144 | 2,209 | 2,248 | 889 | 1.56 | 156.23 | measured |
| WOTS+ n=32 w=256 | 32 | 1,088 | 1,153 | 1,192 | 1,677 | 0.83 | 82.82 | measured |
| WOTS+ n=16 w=16 | 16 | 560 | 609 | 648 | 3,085 | 0.45 | 45.02 | measured |
| WOTS+ tree h=4 (XMSS-style) | 32 | 2,276 | 2,341 | 2,380 | 840 | 1.65 | 165.34 | measured |
| WOTS+ tree h=10 (XMSS-style) | 32 | 2,468 | 2,533 | 2,572 | 777 | 1.79 | 178.75 | measured |
| SLH-DSA-SHA2-128s | 32 | 7,856 | 7,921 | 7,960 | 251 | 5.53 | 553.34 | measured (slh-dsa library) |
| SLH-DSA-SHA2-128f | 32 | 17,088 | 17,153 | 17,192 | 116 | 11.97 | 1,197.32 | measured (slh-dsa library) |
| SLH-DSA-SHA2-192s | 48 | 16,224 | 16,305 | 16,344 | 122 | 11.38 | 1,138.43 | formula = FIPS 205 table |
| SLH-DSA-SHA2-192f | 48 | 35,664 | 35,745 | 35,784 | 55 | 25.25 | 2,525.25 | formula = FIPS 205 table |
| SLH-DSA-SHA2-256s | 64 | 29,792 | 29,889 | 29,928 | 66 | 21.04 | 2,104.38 | measured (slh-dsa library) |
| SLH-DSA-SHA2-256f | 64 | 49,856 | 49,953 | 49,992 | 39 | 35.61 | 3,561.25 | formula = FIPS 205 table |
| ML-DSA-44 | 1,312 | 2,420 | 3,765 | 3,804 | 525 | 2.65 | 264.55 | measured (dilithium-py) |
| ML-DSA-65 | 1,952 | 3,309 | 5,294 | 5,333 | 374 | 3.71 | 371.36 | measured (dilithium-py) |
| ML-DSA-87 | 2,592 | 4,627 | 7,252 | 7,291 | 274 | 5.07 | 506.89 | measured (dilithium-py) |
| FN-DSA-512 (Falcon) | 897 | 666 | 1,596 | 1,635 | 1,223 | 1.14 | 113.57 | published sizes |
| XMSS-SHA2_10_256 | 64 | 2,500 | 2,597 | 2,636 | 758 | 1.83 | 183.23 | formula (RFC 8391) |
| XMSS-SHA2_20_256 | 64 | 2,820 | 2,917 | 2,956 | 676 | 2.06 | 205.46 | formula (RFC 8391) |
| XMSSMT-SHA2_20/2_256 | 64 | 4,963 | 5,060 | 5,099 | 392 | 3.54 | 354.31 | formula (RFC 8391) |
| XMSSMT-SHA2_60/3_256 | 64 | 8,392 | 8,489 | 8,528 | 234 | 5.94 | 593.54 | formula (RFC 8391) |

Notes from the tool:
- Lamport (deployed): one-time; existing addresses
- Lamport, compressed: one-time; verifies against existing addresses
- WOTS+ n=32 w=4: one-time; 256-bit hash; verify ≤ 399 hashes
- WOTS+ n=32 w=16: one-time; 256-bit hash; verify ≤ 1005 hashes
- WOTS+ n=32 w=256: one-time; 256-bit hash; verify ≤ 8670 hashes
- WOTS+ n=16 w=16: one-time; 128-bit level; verify ≤ 525 hashes
- WOTS+ tree h=4 (XMSS-style): 16 signatures per key; stateful
- WOTS+ tree h=10 (XMSS-style): 1024 signatures per key; stateful
- SLH-DSA-SHA2-128s: stateless; verify ≤ 3,928 hashes; sign 4.0 s, verify 4 ms here
- SLH-DSA-SHA2-128f: stateless; verify ≤ 11,870 hashes; sign 0.2 s, verify 11 ms here
- SLH-DSA-SHA2-192s: stateless; verify ≤ 5,681 hashes
- SLH-DSA-SHA2-192f: stateless; verify ≤ 17,216 hashes
- SLH-DSA-SHA2-256s: stateless; verify ≤ 8,443 hashes; sign 5.9 s, verify 14 ms here
- SLH-DSA-SHA2-256f: stateless; verify ≤ 17,521 hashes
- ML-DSA-44: lattice; stateless
- ML-DSA-65: lattice; stateless
- ML-DSA-87: lattice; stateless
- FN-DSA-512 (Falcon): lattice; floating-point signing
- XMSS-SHA2_10_256: 2^10 signatures; stateful
- XMSS-SHA2_20_256: 2^20 signatures; stateful
- XMSSMT-SHA2_20/2_256: 2^20 signatures; stateful
- XMSSMT-SHA2_60/3_256: 2^60 signatures; stateful

The deployed Lamport witness carries the full 16 KiB public key. Compressed
Lamport reveals, for each message bit, the chosen preimage and the hash of
the other one. The verifier rebuilds the full key and checks it against the
`pq_root` the address already commits to. It is the only option that works
for coins at existing addresses. The tool proves this against a real wallet
key. It saves a third and nothing more.

Hash-based schemes rest only on the hash function. The lattice schemes, ML-DSA
and Falcon, add new mathematical assumptions and are much younger. They are
listed for comparison only.

### 3.2 Stateful against stateless

WOTS+ and XMSS are three to twenty times smaller than Lamport. But a WOTS+
key that signs two different messages leaks enough for a forgery, and XMSS
must never reuse a leaf. In a wallet this state fails silently, and the
failure is total. It fails in the ordinary ways: a backup restored while a
spend is still unconfirmed, the same seed on two devices, a fee bump, or a
hardware wallet that lost its counter. Part of the state can be recovered
from the chain, because a confirmed spend shows the key was used. What cannot
be recovered is a signature that was only broadcast.

Lamport, as deployed today, has exactly this risk. 0.4.1 contains it by never
letting an address sign twice, and by refusing to sweep an address that holds
more coins than fit in one transaction.

SLH-DSA has no state at all, is standardised (FIPS 205), and depends only on
the hash function. The 128s set costs 7,921 bytes of witness, which is
3.1 times smaller than today's Lamport witness. Signing is slow: 3.7 s here
with a compiled library, and far slower on a hardware wallet. Verification is
fast: 4 ms here, and at most 3,928 hash calls.

### 3.3 Non-signature approaches

**Consolidate while Schnorr is safe.** Fewer coins means fewer inputs to move
later. This needs no fork: it is wallet behaviour and user guidance. It
shrinks the problem in proportion but does not change its shape.

**Commit-delay-reveal, which also covers migration intents made before an
emergency.** A coin whose Schnorr key has never been revealed can be spent
safely even after an elliptic-curve break, provided the owner first commits to
the exact spending transaction. The rule after activation becomes:

1. The owner publishes `C = H("Kairos/commit", txid)` on chain. `C` reveals
   nothing about the key or the coin.
2. After `D` blocks, the owner broadcasts the transaction with an ordinary
   Schnorr witness.
3. Nodes accept a Schnorr witness only if its commitment was mined at least `D`
   blocks earlier, and only if no coin at that address was spent before the
   commitment. That second condition excludes keys that were already public.

An attacker who reads the public key from the revealed transaction can compute
the private key. But it cannot produce a commitment that is `D` blocks old for
a transaction it did not know about. Its only route is to reorganise `D`
blocks. Commitments made before an emergency serve as pre-committed migration
intents: they are already old enough on the day of activation.

The commitment has to be paid for. The simplest answer needs no new
transaction type. The owner moves one coin by the hash-based path, and that
transaction carries a Merkle root over the commitments for all their other
coins. Each later reveal then includes a Merkle path. So one expensive spend
per wallet unlocks cheap spends for everything else.

| Non-signature option | Bytes per coin | Coins per 2 MB block | 1M coins (days) | 100M coins (days) |
|---|---:|---:|---:|---:|
| commit-delay-reveal, 1 commitment per coin | 198 | 10,099 | 0.14 | 13.75 |
| commit-delay-reveal, 1 commitment per 32 coins | 167 | 11,974 | 0.12 | 11.6 |

The first row assumes one 32-byte commitment per coin. The second assumes one
commitment per 32 coins.

## 4. Capacity for 1M and 100M coins

The tables above assume sweeps get the whole of every block. The rows that
matter:

| Approach | Inputs per block | 1M coins | 100M coins |
|---|---:|---:|---:|
| Lamport, deployed | 81 | 17 days | 4.7 years |
| Lamport, compressed | 121 | 11.5 days | 3.1 years |
| SLH-DSA-SHA2-128s | 251 | 5.5 days | 1.5 years |
| WOTS+ n=32 w=16 | 889 | 1.6 days | 156 days |
| WOTS+ n=16 w=16 (128-bit level) | 3,085 | 0.45 days | 45 days |
| Commit-delay-reveal | about 10,000 | 3.4 hours | 14 days |

No signature scheme with conservative security moves 100M coins in weeks.
Only commit-delay-reveal keeps the chain close to its normal capacity, because
most spends remain 166-byte Schnorr inputs.

## 5. Recommendation

For testnet 3, and for any mainnet after it:

1. **Make commit-delay-reveal the rule the `pq` deployment switches on.** After
   activation, a Schnorr spend needs a commitment mined at least `D` blocks
   earlier, and its key must not have been revealed before that commitment.
   A starting point for review is `D = 100` blocks, about 3.3 hours. It trades
   payment latency against the depth of reorganisation an attacker would
   need. Relative to the rules before activation this is a tightening, so it
   stays a soft fork activated by signalling.
2. **Give new addresses an SLH-DSA-SHA2-128s key in place of Lamport**, for
   coins whose Schnorr key is already public, and as the permanent fallback.
   It has no state, it is standardised, it depends only on the hash, and it
   is 3.1 times smaller than today's witness. Size matters less once
   commit-delay-reveal carries most spends, so statelessness should decide.
   Reviewers may want to weigh a two-leaf key in addition: WOTS+ for the
   first signature and SLH-DSA whenever the wallet is unsure. It would make
   the typical spend 2.2 KB, but it reintroduces state.
3. **Version the outputs.** An output should carry a version next to its
   32-byte program, and unknown versions should be valid to spend, as with
   segwit versions. Then a later scheme, such as a lattice scheme or a
   smaller SLH-DSA parameter set, can arrive as a soft fork. Today any new
   witness kind is a hard fork.
4. **Tell users now to consolidate and never reuse addresses.** This needs no
   fork.
5. **Add a flag day as a backstop.** The testnet 2 rehearsal showed that a
   single miner who does not upgrade can delay signalling by a whole window.
   A release that sets `pq_emergency_height` must stay possible.

### Does it need a hard fork?

| Change | On testnet 2 | On a new chain |
|---|---|---|
| Commit-delay-reveal as the `pq` rule | Hard fork: it relaxes the rule already locked in, which bans Schnorr outright | Soft fork deployment, since it only tightens the rules before activation |
| SLH-DSA key in new addresses | Hard fork: new witness kind and address derivation | Part of the genesis rules |
| Compressed Lamport witness | Hard fork: new witness kind | Not needed; addresses are new |
| Versioned outputs | Hard fork: new output format | Part of the genesis rules |
| Consolidation guidance | None | None |

**Yes: the recommendation needs a new chain, which is testnet 3.** Testnet 2
keeps its Lamport rule and finishes the rehearsal as it is. None of this
should be retrofitted onto testnet 2.

## 6. Open questions for review

- The value of `D`, and whether commitments expire (for example after a
  year), which bounds what nodes must store: 36 bytes per commitment.
- The exact rule for "key not revealed before the commitment". Nodes need an
  index from address to the height of its first spend.
- Whether a smaller, non-standard SLH-DSA parameter set with fewer signatures
  per key is worth its departure from FIPS 205.
- Lost coins at addresses with revealed keys can no longer be stolen after
  activation, but they can be stolen during the window before it. How short
  that window can be made is a question of governance, not code.
