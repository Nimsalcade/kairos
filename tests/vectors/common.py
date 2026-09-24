"""Shared by the vector generator and the runner: chain parameters as JSON and
the replay of a chain vector against the reference implementation."""
import os
import sys
from dataclasses import fields, replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from kairos.block import Block, genesis_block
from kairos.chain import Chain
from kairos.params import ChainParams, Deployment

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("KAIROS_VECTORS_DIR", HERE)      # the generator can write elsewhere (tests)
CHAINS = os.path.join(OUT, "chains")
FUNCTIONS = os.path.join(OUT, "functions.json")
FORMAT = 1


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def params_to_json(p: ChainParams) -> dict:
    out = {}
    for f in fields(p):
        v = getattr(p, f.name)
        if f.name == "deployments":
            v = [{"name": d.name, "bit": d.bit, "start_height": d.start_height,
                  "timeout_height": d.timeout_height, "window": d.window, "threshold": d.threshold} for d in v]
        elif f.name == "checkpoints":
            v = [[h, x] for h, x in v]
        elif f.name == "seeds":
            continue                               # networking only
        elif isinstance(v, bytes):
            v = v.hex()
        elif f.name == "pow_limit":
            v = f"{v:064x}"
        out[f.name] = v
    return out


def params_from_json(d: dict) -> ChainParams:
    kw = dict(d)
    for k in ("chain_id", "magic"):
        kw[k] = bytes.fromhex(kw[k])
    kw["pow_limit"] = int(kw["pow_limit"], 16)
    kw["deployments"] = tuple(Deployment(**x) for x in kw["deployments"])
    kw["checkpoints"] = tuple((h, x) for h, x in kw["checkpoints"])
    known = {f.name for f in fields(ChainParams)}
    unknown = set(kw) - known
    if unknown:
        raise ValueError(f"unknown parameters {sorted(unknown)}")
    return ChainParams(**kw)


def observe(chain: Chain) -> dict:
    """What every implementation must agree on after a step."""
    t = chain.tip
    return {"tip": t.hash.hex(), "height": t.height, "utxo_root": t.header.utxo_root.hex(),
            "next_base_fee": t.next_base_fee,
            "deployments": {k: v["state"] for k, v in chain.deployment_info(t).items()}}


def submit(chain: Chain, block_hex: str) -> str:
    try:
        blk = Block.deserialize(bytes.fromhex(block_hex))
    except (ValueError, IndexError, KeyError) as e:        # noqa: F841 - any decoding failure
        return "malformed"
    except Exception:                                        # struct.error and friends
        return "malformed"
    return chain.submit_block(blk)


def replay(vector: dict):
    """Run a chain vector against the reference node. Yields (index, step,
    status, observed) for every step."""
    params = params_from_json(vector["params"])
    if genesis_block(params).hash.hex() != vector["genesis"]:
        raise AssertionError("genesis does not match the parameters")
    clock = Clock(vector["steps"][0]["now"] if vector["steps"] else params.genesis_time)
    chain = Chain(params, now=clock)
    for i, step in enumerate(vector["steps"]):
        clock.t = step["now"]
        status = submit(chain, step["block"])
        yield i, step, status, observe(chain)
