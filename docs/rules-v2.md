# Kairos consensus rules, version 2

Rules 2 are the rules of **testnet 3** and of **mainnet**, from Kairos 0.5.0.
Testnet 2 keeps rules 1 unchanged: a 0.5.0 node started with `--testnet2`
validates, parses and relays exactly as 0.4.1 does.

Rules 2 put into consensus what `docs/pq-scaling.md` and
`docs/production-node-plan.md` recommended before the rules freeze. There are
four changes:

1. **Versioned outputs**, so that later signature schemes can arrive as soft
   forks.
2. **SLH-DSA-SHA2-128s** (FIPS 205) as the post-quantum key in every
   address, in place of Lamport.
3. **Commit-delay-reveal** as the rule the `pq` switch turns on. Schnorr
   spends stay about 130 bytes per input after an emergency, instead of being
   banned.
4. **Bitcoin Core's MuHash3072** for the UTXO commitment, so a port can use
   Core's audited class unchanged.

Everything else is exactly as in rules 1: proof-of-work, ASERT, emission, the
burned base fee, merge mining, headers, version bits, the block limit, the
sighash construction and the chain-id replay protection.

The reference implementation is `kairos/chain.py` (`check_tx`,
`_check_witnesses2`, `_check_commitment`, `apply_tx`), `kairos/tx.py` and
`kairos/slhdsa.py`. The conformance vectors `tests/vectors/chains/rules2.json`
and the `rules2` section of `tests/vectors/functions.json` pin them down.

## 1. Transactions and outputs

Every transaction, the coinbase included, has `version = 2`. Any other version
is invalid (`unknown tx version`).

An output is `value (u64) | script (33 bytes)`, where
`script = version (1 byte) || program (32 bytes)`. The script length follows
from the network's rules, not from the transaction: a rules-1 node reads
32-byte outputs whatever the version field says.

| Version | Meaning | Value | Spending rule |
|---|---|---|---|
| `0x00` | Key output (address) | 1 to MAX_MONEY | Schnorr or SLH-DSA witness, see 2 and 3 |
| `0x01`–`0x7F` | Reserved for soft forks | 1 to MAX_MONEY | None: **any** witness spends it |
| `0x80` | Spend commitment | exactly 0 | Never a coin; creates a commitment record |
| `0x81`–`0xFF` | Invalid | | Invalid (`unknown output version`) |

Versions `0x01`–`0x7F` are anyone-can-spend by consensus, as segwit versions
are in Bitcoin, so a future scheme (a lattice signature, a smaller SLH-DSA set)
can later give one of them rules as a soft fork. Relay policy refuses to
create or spend them, so nobody loses coins to a version whose rules are not
yet defined.

A coinbase may pay only version-0 outputs.

## 2. Addresses and witnesses

```
slh_leaf = H("Kairos/slh-leaf", slh_pubkey || salt)                 slh_pubkey: 32 bytes, salt: 32 bytes
program  = H("Kairos/address2", schnorr_pubkey || slh_leaf)          H = BIP340 tagged SHA-256
script   = 0x00 || program
address  = bech32m(hrp, script)          hrp: krs (mainnet), tkr3 (testnet 3), krr (regtest)
```

SLH-DSA is stateless: one key can sign up to 2^64 messages. So a wallet uses
one SLH-DSA key for all its addresses, and a different salt for each address.
Addresses stay unlinkable until an SLH-DSA spend reveals the key. Revealing a
leaf in a Schnorr spend reveals nothing about the key. The reference wallet
derives the SLH-DSA key from the seed (for HD wallets, from the hardened
account key) and the salt from each address's private key, so an xpub cannot
derive addresses.

Witnesses of a version-0 input:

| Kind | Layout | Size | Valid if |
|---|---|---|---|
| `0x01` Schnorr | kind, schnorr_pk (32), slh_leaf (32), BIP340 sig (64) | 129 | the script matches and the signature verifies; after activation, also section 3 |
| `0x03` SLH-DSA | kind, schnorr_pk (32), slh_pk (32), salt (32), SLH-DSA sig (7,856) | 7,953 | the script matches and the signature verifies (pure SLH-DSA-SHA2-128s, FIPS 205 Algorithm 24, empty context) |

Anything else is invalid, including the rules-1 Lamport kind `0x02`. Both
kinds sign the same sighash as rules 1 (BIP340 tagged hash over chain id, body
and spent coins). Every SLH-DSA input of a transaction signs the same message,
so the wallet signs once and repeats the signature in each input.

## 3. Commit-delay-reveal

A spend commitment for transaction `T` is

```
C = H("Kairos/commit", txid(T) || schnorr_pk_1 || ... || schnorr_pk_k)
```

over the Schnorr keys that `T`'s Schnorr inputs reveal, in input order. It is
published as an output `TxOut(0, 0x80 || C)` of any transaction. Nobody but
the owner can compute `C` before the keys are public, because the address
commits to them only through a hash.

Once the `pq` deployment is **active** (or the flag day
`pq_emergency_height` is reached), a transaction with at least one Schnorr
input, mined at height `h`, is valid only if both of these hold:

1. A commitment record for its `C` exists at height `h_c` with
   `h - h_c >= reveal_delay`. Otherwise it is invalid with
   `Schnorr spend without a commitment` or `commitment younger than D blocks`.
2. For every Schnorr input's address, either no reveal record exists, or its
   height is greater than `h_c`: no coin at that address was spent before the
   commitment was mined. Otherwise it is invalid with
   `key was revealed before its commitment`.

SLH-DSA spends need no commitment, before or after activation. Before
activation Schnorr spends need none either. Commitments made before activation
still count afterwards, so pre-committed migration intents are old enough on
the day of an emergency.

`reveal_delay` is 100 blocks (about 3.3 hours) on mainnet and testnet 3, and 5
on regtest.

**Why it is safe.** An attacker who can compute a private key from a public key
learns the key only when the owner's transaction reveals it. To spend the coin
the attacker then needs its own commitment that is `reveal_delay` blocks old.
It could not make one earlier without the key, and making one now means
outracing the owner's already broadcast transaction for 100 blocks, or
reorganising 100 blocks. Rule 2 closes the remaining gap: coins at an address
whose key was already revealed, for example through address reuse, can move
only by SLH-DSA.

**Why it scales.** A revealed payment is a normal 129-byte-per-input Schnorr
transaction, and one commitment of 41 bytes covers a transaction of any size.
Moving a million coins takes hours, not the 17 days of Lamport sweeps
(`docs/pq-scaling.md`).

**The price.** A payment made through commit-delay-reveal after an emergency
waits `reveal_delay` blocks, and its fee is fixed when it is committed. The
reference wallet pays 4 times the current base fee. If the base fee overtakes
that, the owner signs a new reveal and commits again, which is allowed as long
as the key is still unrevealed.

## 4. Records

Rules 2 keep two kinds of records in the same map as the coins. They use
outpoint indexes that no transaction output can have (a transaction has at
most 10,000 outputs), and every record has value 0 and a script of 33 zero
bytes:

| Record | Outpoint | Height | Created by |
|---|---|---|---|
| commitment | `(C, 0xFFFFFFFE)` | block that mined the commitment | an output of version `0x80`; a second commitment with the same `C` (in the chain or in the same transaction) is invalid |
| reveal | `(program, 0xFFFFFFFD)` | block that first spent from the address | the first spend of any version-0 coin with that program, by either witness kind |

No input may name an outpoint with index `>= 0xFFFFFF00` (`missing or spent
input`). Records are part of the UTXO commitment, so they are persisted,
undone on reorganisation and carried by UTXO snapshots exactly like coins. A
node that starts from a snapshot therefore enforces commit-delay-reveal from
its first block. Records never expire. Whether commitments should expire, for
example after a year, is still an open question (`docs/pq-scaling.md`).

## 5. UTXO commitment

`utxo_root` is Bitcoin Core's MuHash3072 (`src/crypto/muhash.cpp`) over one
element per entry of the map:

```
element = "Kairos/utxo2\0" || txid (32) || index (u32 LE) || value (u64 LE) || script (33) || height (u32 LE) || coinbase (1)
```

Each element is mapped to a number by taking SHA-256 of the element as a
ChaCha20 key and reading 384 bytes of keystream (nonce 0, counter 0) as a
little-endian number. The numbers are multiplied modulo `2^3072 - 1103717`, and
the digest is SHA-256 of the 384-byte little-endian product. Only the prefix
in the data separates Kairos elements from other uses; the construction is
Core's, so its class can be used unchanged.

## 6. Networks

| Network | Rules | Chain id | Magic | P2P / RPC port | Genesis |
|---|---|---|---|---|---|
| mainnet (placeholder) | 2 | `KRS\x02` | `f94b5253` | 9333 / 9332 | `000007dcd7…1146d` (re-mined at launch) |
| testnet 3 | 2 | `KRS\x04` | `0d4b5253` | 19335 / 19334 | `00000d3a41…7beee`, 2026-09-28 00:00 UTC |
| testnet 2 | 1 | `KRS\x03` | `0c4b5253` | 19333 / 19332 | unchanged |
| regtest | 2 | `KRT\x02` | `fa4b5255` | 29335 / 29334 | |
| regtest (rules 1) | 1 | `KRT\x01` | `fa4b5254` | 29333 / 29332 | unchanged |

The command line uses `--testnet` for testnet 3, `--testnet2` for testnet 2,
`--regtest` for rules-2 regtest and `--regtest1` for rules-1 regtest.
