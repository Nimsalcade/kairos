# Kairos: A Peer-to-Peer Electronic Cash System Built to Last

**The Kairos developers**
Drafted with Claude, an AI model made by Anthropic
Reference implementation: kairos-0.4.0 (revision 4)
September 24, 2026

**Abstract.** Bitcoin solved double-spending without a trusted party, and
seventeen years of operation have confirmed that the core design is sound. The
same years have also exposed where it strains: a security budget that is
scheduled to shrink toward zero, fee markets that swing violently, public keys
that a large quantum computer could break, a full-history download that grows
without bound, signatures that do not tell a signer what it is paying, and
consensus quirks that had to be patched after launch. Kairos keeps what worked
unchanged, including proof-of-work over SHA-256d, the UTXO model, and
most-accumulated-work consensus, and redesigns the parts that time revealed.
Issuance decays smoothly into a small perpetual tail, and a burned base fee
lets usage offset it. Every block header commits to the entire UTXO set with an
incremental multiset hash and to the fee level of the next block, so a new node
can start from a recent state verified by proof-of-work instead of replaying
history. Every address commits to both an elliptic-curve key and a hash-based
one-time key, and the rules include a signalling mechanism by which the network
can switch to the hash-based key if elliptic-curve cryptography falls, so coins
move rather than being stolen or frozen. Difficulty adjusts every block, nodes
validate a chain's headers before downloading its blocks, and Bitcoin miners can
secure the chain through merge-mining from its first day. Malleability, Merkle
ambiguity, duplicate coinbases, blind signing and cross-chain replay are
excluded by construction.

## 1. Introduction

The 2008 design asked participants to trust only mathematics and the honest
majority of CPU power. That promise has held. What a successor must address is
not whether the system works but whether it keeps working as conditions change
over decades: as block subsidies approach zero, as the chain grows past what
ordinary machines can replay, and as the cryptographic assumptions underneath
age.

We take a conservative position. A component is changed only when operating
experience has shown a concrete failure mode and a well-understood remedy
exists. Every mechanism in Kairos has either been deployed elsewhere or analysed
in the literature; the contribution is in choosing them together, fixing them
into consensus from the first block, and showing that they compose. A new
system can do what an existing one cannot: adopt all of these at genesis
without the compromises that backward compatibility forces on soft forks. Where
the rules must still be able to change later, the mechanism for changing them
is itself part of consensus from the start (section 9).

This revision describes the rules of kairos-0.4.0. It differs from revision 3
in three consensus rules: the signature hash commits to the coins being spent,
the header carries the base fee of the next block, and soft forks are activated
by miner signalling. The public test network was restarted for it.

## 2. Transactions

As in Bitcoin, a coin is a chain of signatures, and a transaction spends
previous outputs and creates new ones. Kairos changes what an output pays to
and what a signature signs.

**Dual-key addresses.** An output pays to a 32-byte commitment to two public
keys: a BIP340 Schnorr key [2] used for everyday spending, and the root hash of
a Lamport one-time key [6] held in reserve. Neither key is revealed until the
output is spent. Schnorr signatures are 64 bytes, provably secure in the
random-oracle model, and support key aggregation, so a multi-party output can
be indistinguishable from a single-party one.

```
   Schnorr public key            Lamport public key
   32 bytes, BIP340              16 KiB, hash-based
          |                              |
          |                    pq_root = H(Lamport key)
          |                              |
          +--------------+---------------+
                         |
              address = H(Schnorr key || pq_root)

   today:      64-byte Schnorr signature
   emergency:  Lamport signature (section 10)
```
*Figure 1. A Kairos address commits to a classical and a post-quantum key.*

**Witnesses outside the identifier.** A transaction's identifier is the hash of
its body only: inputs, outputs, version and expiry. Signatures travel in a
separate witness section, so no third party can change a transaction's
identifier by re-encoding a signature. Bitcoin reached this property in 2017
through BIP141 [8]; Kairos starts with it.

**What is signed.** The signature hash covers the chain identifier, the whole
transaction body, and, for every input, the value and address of the coin it
spends. A transaction signed for one network is invalid on any fork or test
network that uses a different identifier, which removes cross-chain replay
without special-case rules. Committing to the spent values means a signer knows
exactly what it pays and what fee it leaves without needing the previous
transactions, which is what a hardware wallet or any other offline signer
requires; Bitcoin added this property in BIP143 [12] after signers had been
misled about fees. Because the coin an input names is fixed by its outpoint,
the signature check depends only on the transaction bytes and the UTXO set,
and a node can cache it safely.

**Expiry.** A transaction may name a last height at which it can be mined.
Payments that fail to confirm in time become permanently invalid instead of
lingering, which gives wallets a clean answer to the question of whether an
unconfirmed payment can still happen.

## 3. Timestamp Server and Proof-of-Work

The proof-of-work function is unchanged: a block is valid when the double
SHA-256 hash of its header is at most a target. Sharing Bitcoin's algorithm
puts Kairos beside the largest pool of SHA-256 hardware in existence, and
anyone who rents a small fraction of it can outpace a new network. Several
small SHA-256 chains have been rewritten this way.

Kairos therefore accepts two forms of work. A block may carry its own proof, or
an auxiliary proof-of-work: a Bitcoin block header whose coinbase transaction
commits to the Kairos block hash, together with the Merkle branch linking that
coinbase to the header [11]. The same hashing secures both chains, so Bitcoin
miners can protect Kairos at almost no extra cost, and the commitment sits in a
Merkle tree of chain slots so one pool can merge-mine several chains at once. A
deterministic slot rule stops a miner from placing two Kairos blocks in one
tree, and parent coinbases of 64 bytes or less are rejected so that an inner
Merkle node cannot pose as a transaction. Merge-mining is not a complete
defence: a pool that merge-mines can also attack at near-zero marginal cost, so
security grows with the number of independent pools that take part.

The header is 132 bytes and carries four additions to Bitcoin's 80. The block
height is explicit, so light clients know their position without trusting
anyone and no two coinbase transactions can ever share an identifier. The
transaction root commits to full witness-inclusive hashes, so signatures are
covered directly by proof-of-work. The UTXO root commits to the entire set of
unspent outputs after the block, and the fee field commits to the base fee that
applies to the next block (sections 6 and 7). Timestamps are 64-bit.

```
   version  u32   bits 0..7 = 1; bit 8 = merge-mined; bits 16..28 = signals
   height   u32
   prev     32    hash of the parent header
   tx_root  32    Merkle root of witness-inclusive transaction hashes
   utxo_root 32   MuHash of the UTXO set after this block
   time     u64
   bits     u32   compact target
   fee      u64   base fee (motes per byte) for the next block
   nonce    u64
```
*Figure 2. The 132-byte header. Each header commits to its parent, its
transactions, and the complete state that results.*

The version field is structured. Its low byte must be 1. Bit 8 says the block's
work is proven by a merge-mined parent. Bits 16 to 28 are reserved for
signalling readiness for rule changes (section 9). All other bits are ignored
by consensus, so that a future signal never causes older nodes to reject
blocks.

## 4. Difficulty

Bitcoin retargets once every 2016 blocks, which produces oscillation when hash
power moves quickly and has enabled timestamp-manipulation attacks at window
boundaries. Kairos recomputes the target at every block using an absolutely
scheduled exponential rule (ASERT) [3]. With genesis as the anchor, a block's
target depends only on how far its parent is ahead of or behind the ideal
schedule:

    target = anchor_target · 2^((t_parent − t_anchor − T · h_parent) / τ)

where T is the 120-second target spacing and τ is a two-day half-life. Being
two days behind schedule doubles the target; two days ahead halves it. The
computation uses integer fixed-point arithmetic with a cubic approximation of
2^x, so every implementation agrees to the bit. Timestamps must exceed the
median of the previous eleven blocks and may not run more than two hours into
the future. On the main network the first block after genesis starts at
Bitcoin's 2009 minimum difficulty, so the earliest coins cost real work rather
than being claimable in a burst.

Because the schedule is absolute, a chain that has run ahead of it (as a young
test network with few miners does) carries that lead as a higher target, and a
pause eats into the lead because the schedule keeps moving while the chain does
not. That is exactly what eases the target: a factor of two per two days of
drift, so about 12% after an eight-hour pause. The first block after a pause is
mined at the target its parent implies; the easing applies from the second
block on.

## 5. Network

The network runs the same steps as the original design. New transactions are
broadcast to all nodes; each node collects them into a block and works on a
proof-of-work; when a node finds one it broadcasts the block; nodes accept it
only if every transaction in it is valid and not already spent; and they
express acceptance by building on its hash. Nodes always consider the chain
with the most accumulated work to be correct, and on a tie keep the first they
received.

Data is announced, never pushed: a node learns of a block or transaction by its
hash and requests it only if it lacks it. Synchronisation is headers-first. A
node asks a peer for headers, up to 2000 at a time, and validates each one for
proof-of-work (including any merge-mining proof, which travels with the
header), difficulty schedule and timestamps before it asks for a single block
body. Bodies are then fetched in order along the header chain with the most
work, from every peer that has them, sixteen in flight per peer, and a request
that stalls for a minute is re-issued elsewhere. No peer can make a node
download a chain that does not carry the most work, and a block whose parent
is unknown is held only briefly, in bounded memory, and only if it claims a
credible amount of work.

When a heavier branch appears, a node disconnects blocks back to the fork point
using stored undo data, connects the new branch, and returns any transactions
from abandoned blocks to its memory pool. A block is validated entirely against
a copy-on-write view of the UTXO set before any state changes, so an invalid
block can never leave a node half-updated.

## 6. Incentive

**Emission without cliffs.** Instead of halving every four years, each block's
subsidy is a fixed fraction of the coins not yet issued from a 21 million main
curve, with a floor:

    subsidy = max( 0.6 KRS , (21,000,000 KRS − issued) / 2^21 )

The first block pays 10.01 KRS, which at one block per two minutes is 300 coins
per hour, the same hourly issuance as Bitcoin in 2009. Half of the main curve
is issued after about 5.5 years. There are no sudden drops in miner revenue, so
there is no scheduled moment when a large share of hash power becomes
unprofitable at once. After about 22.5 years the curve reaches the floor and
the chain pays 0.6 KRS per block forever: about 157,800 KRS per year, 0.8% of
supply at that point and a shrinking fraction thereafter.

| Years since genesis | Kairos, cumulative KRS | Bitcoin, cumulative BTC |
|---:|---:|---:|
| 1 | 2,475,000 | 2,630,000 |
| 2 | 4,658,000 | 5,260,000 |
| 4 | 8,283,000 | 10,510,000 |
| 8 | 13,299,000 | 15,760,000 |
| 16 | 18,176,000 | 19,692,000 |
| 22 | 19,669,000 | 20,511,000 |
| 32 | 21,249,000 | 20,919,000 |
| 40 | 22,511,000 | 20,980,000 |

*Table 1. Gross issuance at two-minute and ten-minute blocks respectively,
computed block by block from the consensus rules with 365.25-day years, before
Kairos's fee burn. The Kairos curve passes 21 million around year 30 and then
grows by the tail alone.*

**Why a tail.** A proof-of-work chain is only as secure as what it pays for
work. If that payment must eventually come entirely from fees, security becomes
as volatile as fee demand, and an empty mempool invites miners to rewrite recent
blocks to steal the fees in them. Budish [10] shows the cost of attack is
bounded by the flow payment to miners; a permanent floor keeps that bound from
collapsing. Monero has operated with a tail emission since 2022 [9].

**Burned base fee.** Every transaction pays at least a per-byte base fee, which
is destroyed, plus an optional tip to the miner. The base fee rises by up to
12.5% after a block larger than the 1 MB target and falls after a smaller one,
as in EIP-1559 [4]; it never falls below one mote per byte. Users face a
predictable price instead of a blind auction. Because miners cannot collect the
base fee, they gain nothing by padding blocks with their own transactions to
manipulate it. The fee in force for the next block is written into every header,
so a light client reads the price level from headers alone and a node resuming
from a snapshot knows it without the previous block's size. The burn also closes
the monetary loop: net supply growth is the tail minus the burn, and it reaches
zero when the average block burns 0.6 KRS, for example full-target blocks at a
base fee of 60 motes per byte. Heavy use makes the currency scarcer; light use
leaves a small, predictable inflation that pays for security.

## 7. Committed State and Fast Synchronization

A new Bitcoin node must download and replay every transaction since 2009 to
learn the current set of unspent outputs, which is the only state it needs.
Kairos commits that state in every header. The commitment is a MuHash over the
multiset of unspent outputs [5]: each output is hashed to an element of the
multiplicative group modulo the prime 2^3072 − 1103717, the set's hash is the
product of its elements, adding an output multiplies it in and spending one
divides it out. Updates cost constant time per output and are independent of
order, so any node can maintain the commitment as it validates, and because the
group has inverses a node can recover an ancestor's commitment from a
descendant's when it reorganises.

A new node therefore downloads headers, chooses a block buried under enough
work, fetches a snapshot of the UTXO set from any untrusted source, and checks
it. The rule is strict: the snapshot is adopted only if its MuHash equals the
UTXO root of a header the node has already verified proof-of-work for, on the
node's own header chain and ahead of its current tip. Nothing else in the
snapshot is trusted. Total issuance to that height is recomputed from the
emission schedule, which is a pure function of height; burned supply follows by
conservation from the coins in the set; the base fee is read from the header.
The history below the snapshot is then assumed valid: its headers are kept,
its blocks are never downloaded, and no fork below it is accepted.

A false snapshot can only be accepted if a majority of hash power has
repeatedly committed to a false UTXO root, which every honest validating node
rejects, so this is the same assumption the system already rests on. The
deeper the chosen block, the more work an attacker would have to redo. The
reference implementation does not yet validate the assumed history in the
background; a node that wants full assurance replays from genesis instead.

## 8. Simplified Payment Verification

As in the original design, a light client keeps only headers and checks that a
transaction is included by its Merkle branch. Kairos uses different hash tags
for leaves and inner nodes and promotes an odd node instead of duplicating it.
This removes two known Bitcoin weaknesses: the duplicated-leaf ambiguity that
allowed CVE-2012-2459 [7], and the possibility of a 64-byte transaction being
mistaken for an inner node in a Merkle proof. Light clients read the current
fee level from the header directly, and can check balances against the
committed UTXO root once proofs of set membership are added.

## 9. Upgrading the Rules

A currency that must last has to be able to tighten its rules without a
central party and without a race. Kairos includes an activation mechanism in
consensus from genesis, modelled on Bitcoin's version bits [13] but keyed to
block heights rather than clock time.

A deployment names a header version bit, a start height, an optional timeout
height, a window length and a threshold. Blocks in the same window share a
state, and a window's state is decided by the signalling in the window before
it:

    DEFINED  -> STARTED    once the window starts at or after start_height
    STARTED  -> LOCKED_IN  if at least threshold blocks in the previous
                           window set the deployment's bit
             -> FAILED     if the window starts at or after timeout_height
    LOCKED_IN -> ACTIVE    one window later, unconditionally

On the main and test networks a window is 2016 blocks (about 2.8 days) and the
threshold is 1916 blocks, or 95%. A miner signals by setting the bit in blocks
it mines while the deployment is STARTED or LOCKED_IN; the reference node
exposes this as a command-line flag and reports the running count. Nodes that
do not know a deployment ignore its bit, so signalling never splits them from
the network; only the new rule, once ACTIVE, can do that, and only for blocks
that break it. Deployments are the vehicle for every later tightening
mentioned in this paper, including the quantum switch below and any future
replacement of the Lamport scheme.

## 10. Surviving a Quantum Adversary

A sufficiently large quantum computer running Shor's algorithm would recover
the private key for any exposed elliptic-curve public key. Hash functions are
only weakened by Grover's algorithm, to roughly 128-bit security for SHA-256.
Kairos prepares for this at genesis instead of at a moment of crisis.

Every address already commits to a Lamport key whose security rests only on
SHA-256. The first deployment defined in the rules is the post-quantum
emergency switch. It has a start height of zero and no timeout, so it is armed
for the life of the chain and can be activated in any window by 95% of miners.
Once ACTIVE, Schnorr spends are invalid and every output can still be spent
with its Lamport key. Nobody's coins are frozen and none are stolen: an
attacker who derives a Schnorr private key gains nothing, because that key no
longer authorises anything. For the case where miners themselves cannot be
trusted to signal in time, an emergency release can also fix the switch at a
flag-day height.

A Lamport key must sign only one message. The signature hash covers the whole
transaction, so every input from one address signs the identical message; the
reference wallet therefore sweeps every coin at an address in a single
transaction, sends change to a fresh, never-revealed key, and records the key
as spent on disk before it produces the signature, so that a crash while
signing can never lead to a second signature. Lamport witnesses are 24,609
bytes, so emergency transactions are large and expensive. That is the right
trade: this is an escape path, and more compact hash-based schemes such as
SPHINCS+ can replace it by soft fork later, since only the committed root is
fixed. Because a Schnorr public key is revealed on the wire only when its coins
are spent, the wallet also gives every block reward and every change output a
fresh address, so a key is exposed at most once, at the moment its coins move.

## 11. Calculations

The probability that an attacker with fraction q of the hash power ever
catches up from z blocks behind follows the gambler's-ruin analysis of the
original paper [1] and is unchanged, since it depends on blocks rather than
seconds. What changes is wall-clock time. The table gives the confirmations
needed to bring the attacker's success probability below 0.1%.

| q | blocks z | Kairos (2 min) | 10-minute blocks |
|---:|---:|---:|---:|
| 0.10 | 5 | 10 min | 50 min |
| 0.15 | 8 | 16 min | 80 min |
| 0.20 | 11 | 22 min | 110 min |
| 0.25 | 15 | 30 min | 150 min |
| 0.30 | 24 | 48 min | 240 min |
| 0.35 | 41 | 82 min | 410 min |
| 0.40 | 89 | 178 min | 890 min |

Shorter blocks are not free. With a block propagation time of a few seconds,
roughly 2 to 3% of blocks at a two-minute spacing will be orphaned, against a
fraction of a percent at ten minutes, which gives a small advantage to
well-connected miners. We judge a five-fold improvement in settlement time to be
worth this, but compact block relay is a prerequisite for a production network.

## 12. Reference Implementation and Limitations

The accompanying kairos-0.4.0 implements everything above in about 4,300 lines
of Python: BIP340 Schnorr with a constant-time libsecp256k1 backend and a
readable reference fallback, Lamport signatures, MuHash3072, domain-separated
Merkle trees, bech32m addresses, merge-mining proofs, full consensus validation
with chain reorganisation, version-bit deployments, a bounded memory pool,
crash-safe block storage with a chainstate snapshot for fast restart, UTXO
snapshot export and import, an encrypted deterministic wallet with address
rotation and gap-limit recovery, a peer-to-peer protocol with headers-first
synchronisation, misbehaviour scoring, rate limits and bans, automatic
reconnection and peer discovery, and a Bitcoin-style JSON-RPC including the
calls merge-mining pools use. Its 78 tests include a differential test showing
that the two signature backends agree on valid and malformed inputs, fuzzing of
blocks and transactions, attacks by misbehaving peers, the full life cycle of a
deployment, tampered and mismatched snapshots, reorganisations across a restart,
and a block merge-mined end to end through the RPC interface.

It is a public-testnet candidate, not a system for real value. It has not been
independently audited; it keeps the UTXO set and undo data in memory; it does
not validate assumed history after a fast sync; compact block relay, MuSig2 and
a binary wire format remain to be built; and compatibility with real
merge-mining pool software has yet to be demonstrated. The conditions for a
mainnet launch, including independent audits, a second implementation and at
least six months of public testnet, are set out in the release's LAUNCH
document. None of the remaining work requires changing the consensus rules
described here.

## 13. Conclusion

We have proposed a system for electronic transactions without relying on trust
that keeps the proof-of-work foundation of the original and changes only what
long operation has shown to need changing. Its security budget has a floor, and
usage can offset the inflation that floor creates. Its fees are predictable and
readable from headers. Its state is committed so that joining the network does
not require replaying history. Its signatures say what they spend. Its coins
have a pre-committed path through the failure of elliptic-curve cryptography,
and the network has a pre-committed way to take it. Its consensus rules exclude
by construction the malleability, Merkle, coinbase and replay problems that
Bitcoin had to patch. The network remains robust in its unstructured
simplicity: nodes work all at once with little coordination, need not be
identified, and vote with their CPU power on the valid chain.

## References

[1] S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.
[2] P. Wuille, J. Nick, T. Ruffing, "BIP340: Schnorr Signatures for secp256k1," 2020.
[3] M. Lundeberg, J. Toomim et al., "ASERT difficulty adjustment algorithm (aserti3-2d)," Bitcoin Cash upgrade specification, 2020.
[4] V. Buterin, E. Conner, R. Dudley, M. Slipper, I. Norden, A. Bakhta, "EIP-1559: Fee market change for ETH 1.0 chain," 2019.
[5] M. Bellare, D. Micciancio, "A New Paradigm for Collision-free Hashing: Incrementality at Reduced Cost," EUROCRYPT 1997.
[6] L. Lamport, "Constructing Digital Signatures from a One Way Function," SRI International, 1979.
[7] CVE-2012-2459, Bitcoin Merkle tree duplicate-transaction vulnerability, 2012.
[8] E. Lombrozo, J. Lau, P. Wuille, "BIP141: Segregated Witness (Consensus layer)," 2015.
[9] Monero Project, tail emission, active since May 2022.
[10] E. Budish, "The Economic Limits of Bitcoin and the Blockchain," NBER Working Paper 24717, 2018.
[11] Namecoin project, merged mining specification (auxiliary proof-of-work), 2011.
[12] J. Lau, P. Wuille, "BIP143: Transaction Signature Verification for Version 0 Witness Program," 2016.
[13] P. Wuille, P. Todd, G. Maxwell, R. Russell, "BIP9: Version bits with timeout and delay," 2015.
