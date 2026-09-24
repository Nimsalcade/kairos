"""
Kairos consensus parameters and the pure functions derived from them:
monetary emission, per-block ASERT difficulty, and the base-fee rule.
"""
from dataclasses import dataclass, replace
from typing import Optional

COIN = 100_000_000                 # 1 KRS = 10^8 motes
MAX_MONEY = 2 ** 63 - 1


@dataclass(frozen=True)
class Deployment:
    """A soft fork activated by miner signalling in header version bits
    (BIP8-style, height based). States, decided once per window from the
    signalling in the previous window:

        DEFINED -> STARTED (from start_height) -> LOCKED_IN (threshold reached)
        -> ACTIVE one window later. STARTED -> FAILED if timeout_height passes
        (timeout 0 = the switch stays armed forever, as an emergency must)."""
    name: str
    bit: int                       # header version bit, 16..28
    start_height: int = 0
    timeout_height: int = 0
    window: int = 2016             # ~2.8 days at 120 s blocks
    threshold: int = 1916          # 95 %


@dataclass(frozen=True)
class ChainParams:
    name: str
    hrp: str                        # bech32m address prefix
    chain_id: bytes                 # committed in every signature hash (replay protection)
    magic: bytes                    # P2P network magic
    pow_limit: int
    genesis_bits: int
    genesis_time: int
    genesis_nonce: int
    target_spacing: int = 120       # seconds per block
    asert_halflife: int = 2 * 86400 # difficulty doubles/halves per 2 days of drift
    no_retarget: bool = False
    coinbase_maturity: int = 100
    max_block_size: int = 2_000_000
    target_block_size: int = 1_000_000
    emission_supply: int = 21_000_000 * COIN
    emission_speed: int = 21        # remaining supply decays by 1/2^21 per block
    tail_reward: int = 60_000_000   # 0.6 KRS per block, forever
    min_base_fee: int = 1           # motes per byte
    base_fee_change_denom: int = 8  # max +/-12.5% base-fee move per block
    max_future_drift: int = 2 * 3600
    mtp_window: int = 11
    pq_emergency_height: Optional[int] = None  # flag-day override; normally activated by the "pq" deployment
    deployments: tuple = ()                    # (Deployment, ...) soft forks this release knows
    asert_anchor_bits: Optional[int] = None    # starting difficulty for block 1 (fair launch)
    mm_chain_id: int = 0x4B52                   # merge-mining slot id ("KR")
    auxpow_start_height: int = 1                # merge-mining allowed from block 1
    checkpoints: tuple = ()                     # ((height, hash_hex), ...) hard-coded by releases
    coinbase_witness_max: int = 100
    seeds: tuple = ()                           # "ip:port" nodes asked for peers on first start


def subsidy(params: ChainParams, generated: int) -> int:
    """Smooth exponential emission with a perpetual tail.
    No halving cliffs: the reward is a fixed fraction of what remains."""
    return max(params.tail_reward, (params.emission_supply - generated) >> params.emission_speed)


# ------------------------------------------------ compact target encoding

def bits_to_target(bits: int) -> int:
    exp, mant = bits >> 24, bits & 0x7FFFFF
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def target_to_bits(t: int) -> int:
    size = (t.bit_length() + 7) // 8
    mant = t << (8 * (3 - size)) if size <= 3 else t >> (8 * (size - 3))
    if mant & 0x800000:
        mant >>= 8
        size += 1
    return (size << 24) | mant


def block_work(bits: int) -> int:
    return (1 << 256) // (bits_to_target(bits) + 1)


# ------------------------------------------------ ASERT difficulty (per block)

def asert_target(params: ChainParams, anchor_bits: int, anchor_time: int,
                 parent_time: int, parent_height: int) -> int:
    """Absolutely Scheduled Exponentially Rising Targets (aserti3-2d style),
    anchored at genesis. Target scales by 2^((actual - ideal)/halflife) using
    integer-only fixed-point arithmetic, so every node computes identical bits."""
    anchor_target = bits_to_target(anchor_bits)
    time_diff = parent_time - anchor_time
    exponent = ((time_diff - params.target_spacing * parent_height) * 65536) // params.asert_halflife
    shifts = exponent >> 16           # arithmetic (floor) shift, also for negatives
    frac = exponent & 0xFFFF
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac * frac
                       + 5127 * frac * frac * frac + (1 << 47)) >> 48)
    nxt = anchor_target * factor
    nxt = nxt << shifts if shifts >= 0 else nxt >> -shifts
    nxt >>= 16
    return max(1, min(nxt, params.pow_limit))


def next_base_fee(params: ChainParams, base_fee: int, block_size: int) -> int:
    """EIP-1559-style controller on block size. The base fee is burned."""
    t = params.target_block_size
    delta = base_fee * (block_size - t) // (t * params.base_fee_change_denom)
    if block_size > t and delta == 0:
        delta = 1
    return max(params.min_base_fee, base_fee + delta)


# ------------------------------------------------------------- networks

# The post-quantum emergency switch. Once ACTIVE, elliptic-curve (Schnorr)
# spends are invalid and only hash-based Lamport spends are accepted.
PQ_DEPLOYMENT = Deployment("pq", bit=16, start_height=0, timeout_height=0)

MAINNET = ChainParams(
    name="main", hrp="krs", chain_id=b"KRS\x01", magic=b"\xf9\x4b\x52\x53",
    pow_limit=(1 << 236) - 1,
    genesis_bits=0x1E0FFFFF,
    genesis_time=1790035200,          # placeholder: re-mined with a fresh message at launch (LAUNCH.md)
    genesis_nonce=338424,
    asert_anchor_bits=0x1D00FFFF,     # block 1 starts at Bitcoin's 2009 "difficulty 1"
    deployments=(PQ_DEPLOYMENT,),
)

# Testnet 2 (0.4.0). The 0.3 testnet was reset because the signature hash and
# the activation rules changed; testnet coins never had value.
TESTNET = replace(
    MAINNET, name="test", hrp="tkrs", chain_id=b"KRS\x03", magic=b"\x0c\x4b\x52\x53",
    genesis_time=1790208000,          # 2026-09-24T00:00:00Z
    genesis_nonce=705116,
    coinbase_maturity=20,
    asert_anchor_bits=0x1E03FFFF,     # CPU-friendly start; ASERT raises it as miners join
    seeds=("95.179.255.186:19333", "45.76.176.39:19333", "207.246.114.19:19333"),
)

REGTEST = replace(
    MAINNET, name="regtest", hrp="krt", chain_id=b"KRT\x01", magic=b"\xfa\x4b\x52\x54",
    pow_limit=(1 << 252) - 1, genesis_bits=0x200FFFFF, no_retarget=True,
    coinbase_maturity=2, genesis_nonce=14, asert_anchor_bits=None,
    deployments=(replace(PQ_DEPLOYMENT, window=8, threshold=6),),
)

NETWORKS = {"main": MAINNET, "test": TESTNET, "regtest": REGTEST}
DEFAULT_PORTS = {"main": (9333, 9332), "test": (19333, 19332), "regtest": (29333, 29332)}
