"""
Kairos JSON-RPC, modelled on Bitcoin Core's interface so existing tooling
(explorers, monitors, exchange integrations, pool software) needs minimal change.

Security:
  * binds to 127.0.0.1 by default; exposing it requires an explicit --rpcbind
  * HTTP Basic auth with a random cookie written to <datadir>/.cookie (mode 0600),
    compared in constant time
  * request bodies capped at 4 MB; every handler error is caught and reported

Hash convention: Kairos RPC shows hashes in natural byte order. The merge-mining
calls (createauxblock/submitauxblock/getauxblock) additionally use Bitcoin's
reversed order for `hash`, because that is what merge-mining pool software expects.
"""
import base64
import hmac
import json
import os
import secrets
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .auxpow import AuxPow
from .chain import ValidationError
from .crypto import BACKEND
from .params import COIN, bits_to_target, subsidy
from .tx import Transaction

MAX_BODY = 4 * 1024 * 1024


class RPCError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def _amount(v) -> int:
    try:
        motes = round(float(v) * COIN)
    except (TypeError, ValueError):
        raise RPCError(-3, "invalid amount")
    if motes <= 0:
        raise RPCError(-3, "amount must be positive")
    return motes


def _hash_arg(h, reverse=False) -> bytes:
    try:
        b = bytes.fromhex(h)
    except (TypeError, ValueError):
        raise RPCError(-8, "hash must be hex")
    if len(b) != 32:
        raise RPCError(-8, "hash must be 32 bytes")
    return b[::-1] if reverse else b


class RPCServer:
    def __init__(self, node, datadir, host="127.0.0.1", port=0, password=None):
        self.node, self.chain, self.wallet = node, node.chain, node.wallet
        self.aux_templates = {}
        self.lock = threading.Lock()
        self.password = password or secrets.token_hex(32)
        self.cookie_path = os.path.join(datadir, ".cookie")
        fd = os.open(self.cookie_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"__cookie__:{self.password}")
        self._auth = "Basic " + base64.b64encode(f"__cookie__:{self.password}".encode()).decode()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                if not hmac.compare_digest(self.headers.get("Authorization", ""), server._auth):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="kairos"')
                    self.end_headers()
                    return
                n = int(self.headers.get("Content-Length", 0))
                if n > MAX_BODY:
                    self.send_response(413)
                    self.end_headers()
                    return
                try:
                    req = json.loads(self.rfile.read(n))
                    resp = ([server.dispatch(r) for r in req[:100]] if isinstance(req, list)
                            else server.dispatch(req))
                    code = 200
                except ValueError:
                    resp, code = {"result": None, "error": {"code": -32700, "message": "parse error"},
                                  "id": None}, 500
                body = json.dumps(resp).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        try:
            os.remove(self.cookie_path)
        except OSError:
            pass

    # ------------------------------------------------------------ dispatch
    def dispatch(self, req):
        rid = req.get("id") if isinstance(req, dict) else None
        try:
            if not isinstance(req, dict) or not isinstance(req.get("method"), str):
                raise RPCError(-32600, "invalid request")
            fn = getattr(self, "rpc_" + req["method"], None)
            if fn is None:
                raise RPCError(-32601, "method not found")
            params = req.get("params") or []
            if not isinstance(params, list):
                raise RPCError(-32602, "params must be a list")
            with self.chain.lock:
                result = fn(*params)
            return {"result": result, "error": None, "id": rid}
        except RPCError as e:
            return {"result": None, "error": {"code": e.code, "message": e.message}, "id": rid}
        except TypeError:
            return {"result": None, "error": {"code": -1, "message": "wrong number of parameters"}, "id": rid}
        except (ValidationError, ValueError, RuntimeError, PermissionError) as e:
            return {"result": None, "error": {"code": -1, "message": str(e)}, "id": rid}

    # ------------------------------------------------------------ chain
    def _difficulty(self, bits):
        return round(bits_to_target(0x1D00FFFF) / bits_to_target(bits), 8)

    def rpc_getblockcount(self):
        return self.chain.height

    def rpc_getbestblockhash(self):
        return self.chain.tip.hash.hex()

    def rpc_getblockhash(self, height):
        if not isinstance(height, int) or not 0 <= height <= self.chain.height:
            raise RPCError(-8, "block height out of range")
        return self.chain.active[height].hash.hex()

    def rpc_getblockchaininfo(self):
        t = self.chain.tip
        s = self.chain.supply()
        return {"chain": self.chain.params.name, "blocks": t.height, "headers": t.height,
                "bestblockhash": t.hash.hex(), "difficulty": self._difficulty(t.header.bits),
                "time": t.header.time, "mediantime": self.chain.median_time_past(t),
                "chainwork": f"{t.chainwork:064x}", "utxo_root": t.header.utxo_root.hex(),
                "generated": s["generated"] / COIN, "burned": s["burned"] / COIN,
                "circulating": s["circulating"] / COIN, "next_base_fee": s["next_base_fee"],
                "pq_only": self.chain.pq_active(t), "softforks": self.chain.deployment_info(t),
                "crypto_backend": BACKEND}

    def rpc_getdeploymentinfo(self):
        return {"hash": self.chain.tip.hash.hex(), "height": self.chain.height,
                "deployments": self.chain.deployment_info(self.chain.tip)}

    def rpc_setsignal(self, name, enable=True):
        if self.chain.deployment(str(name)) is None:
            raise RPCError(-8, "unknown deployment")
        (self.chain.signal.add if enable else self.chain.signal.discard)(str(name))
        return sorted(self.chain.signal)

    def _index(self, h):
        idx = self.chain.index.get(_hash_arg(h))
        if idx is None:
            raise RPCError(-5, "block not found")
        return idx

    def rpc_getblockheader(self, h):
        idx = self._index(h)
        hd = idx.header
        nxt = (self.chain.active[idx.height + 1].hash.hex()
               if self.chain.on_active_chain(idx) and idx.height < self.chain.height else None)
        return {"hash": idx.hash.hex(), "height": idx.height, "version": hd.version,
                "confirmations": (self.chain.height - idx.height + 1) if self.chain.on_active_chain(idx) else -1,
                "previousblockhash": hd.prev_hash.hex(), "nextblockhash": nxt,
                "tx_root": hd.tx_root.hex(), "utxo_root": hd.utxo_root.hex(), "time": hd.time,
                "bits": f"{hd.bits:08x}", "nonce": hd.nonce, "difficulty": self._difficulty(hd.bits),
                "chainwork": f"{idx.chainwork:064x}"}

    def rpc_getblock(self, h, verbosity=1):
        idx = self._index(h)
        blk = self.chain.blocks[idx.hash]
        if verbosity == 0:
            return blk.serialize().hex()
        out = self.rpc_getblockheader(h)
        out.update(size=blk.size, auxpow=blk.auxpow is not None, tx=[t.txid.hex() for t in blk.txs])
        return out

    def rpc_gettxoutsetinfo(self):
        t = self.chain.tip
        return {"height": t.height, "bestblock": t.hash.hex(), "txouts": len(self.chain.utxos),
                "total_amount": sum(c.value for c in self.chain.utxos.values()) / COIN,
                "muhash": t.header.utxo_root.hex()}

    # ------------------------------------------------------------ mempool / tx
    def rpc_getrawmempool(self):
        return [t.hex() for t in self.chain.mempool]

    def rpc_getmempoolinfo(self):
        return {"size": len(self.chain.mempool), "bytes": self.chain.mempool_bytes,
                "maxmempool": self.chain.max_mempool_bytes,
                "base_fee": self.chain.tip.next_base_fee}

    def rpc_sendrawtransaction(self, hexstr):
        try:
            tx = Transaction.deserialize(bytes.fromhex(hexstr))
        except ValueError:
            raise RPCError(-22, "TX decode failed")
        try:
            self.node.submit_tx(tx)
        except ValidationError as e:
            raise RPCError(-26, str(e))
        return tx.txid.hex()

    # ------------------------------------------------------------ network
    def rpc_getconnectioncount(self):
        return len(self.node.peers)

    def rpc_getpeerinfo(self):
        return [{"addr": p.key or f"{p.addr[0]}:{p.addr[1]}", "inbound": not p.outbound, "ready": p.ready,
                 "manual": p.manual, "proto": p.proto, "height": p.height, "banscore": p.score}
                for p in list(self.node.peers)]

    def rpc_addnode(self, addr, command="add"):
        if command == "add":
            try:
                self.node.add_manual(str(addr))
            except ValueError:
                raise RPCError(-8, "address must be ip:port")
        elif command == "remove":
            self.node.manual.discard(str(addr))
        elif command == "onetry":
            self.node._start_dial(str(addr))
        else:
            raise RPCError(-8, "command must be add, remove or onetry")
        return None

    def rpc_getnodeaddresses(self, count=10):
        return [{"address": k, "time": int(t)} for k, t in self.node.addrman.sample(int(count))]

    def rpc_getnetworkinfo(self):
        from .node import PROTOCOL_VERSION, AGENT
        return {"version": __version__, "subversion": AGENT, "protocolversion": PROTOCOL_VERSION,
                "connections": len(self.node.peers), "port": self.node.port,
                "banned": len([b for b in self.node.banned if self.node.is_banned(b)]),
                "known_addresses": len(self.node.addrman)}

    def rpc_getmininginfo(self):
        t = self.chain.tip
        return {"blocks": t.height, "difficulty": self._difficulty(self.chain.expected_bits(t)),
                "next_subsidy": subsidy(self.chain.params, t.generated) / COIN,
                "pooledtx": len(self.chain.mempool), "chain": self.chain.params.name,
                "merge_mining_chain_id": self.chain.params.mm_chain_id,
                "signalling": sorted(self.chain.signal)}

    # ------------------------------------------------------------ wallet
    def _w(self):
        if self.wallet is None:
            raise RPCError(-18, "no wallet loaded")
        return self.wallet

    def rpc_validateaddress(self, addr):
        from .crypto import bech32m_decode
        try:
            raw = bech32m_decode(self.chain.params.hrp, str(addr))
            ok = len(raw) == 32
        except (ValueError, IndexError):
            raw, ok = b"", False
        return {"isvalid": ok, "address": addr if ok else None,
                "ismine": bool(ok and self.wallet and raw in self.wallet.by_addr)}

    def rpc_getnewaddress(self, label=""):
        return self._w().new_address()

    def rpc_rescanwallet(self):
        w = self._w()
        w.rescan(self.chain)
        return {"keys": len(w.keys), "used": len(w.used)}

    def rpc_getbalance(self):
        return self._w().balance(self.chain)["spendable"] / COIN

    def rpc_getbalances(self):
        b = self._w().balance(self.chain)
        return {"mine": {"trusted": b["spendable"] / COIN, "immature": b["immature"] / COIN}}

    def rpc_listunspent(self):
        w = self._w()
        tipn = self.chain.height
        return [{"txid": op.txid.hex(), "vout": op.index, "address": w.encode(c.address),
                 "amount": c.value / COIN, "confirmations": tipn - c.height + 1}
                for op, c in w.coins(self.chain).items()]

    def rpc_sendtoaddress(self, addr, amount):
        w = self._w()
        try:
            to = w.decode(addr)
        except ValueError:
            raise RPCError(-5, "invalid address")
        try:
            tx = w.create_tx(self.chain, to, _amount(amount))
        except ValueError as e:
            raise RPCError(-6, str(e))
        self.node.submit_tx(tx)
        return tx.txid.hex()

    # ------------------------------------------------------------ merge mining
    def rpc_createauxblock(self, address):
        try:
            payout = self._w().decode(address) if self.wallet else None
        except ValueError:
            raise RPCError(-5, "invalid address")
        if payout is None:
            from .crypto import bech32m_decode
            payout = bech32m_decode(self.chain.params.hrp, address)
        blk = self.chain.create_block(payout, b"/merge-mined/", auxpow=True)
        h = blk.hash
        with self.lock:
            if len(self.aux_templates) > 64:
                self.aux_templates.clear()
            self.aux_templates[h] = blk
        target = bits_to_target(blk.header.bits)
        return {"hash": h[::-1].hex(), "kairoshash": h.hex(), "chainid": self.chain.params.mm_chain_id,
                "previousblockhash": blk.header.prev_hash.hex(), "coinbasevalue": blk.txs[0].outputs[0].value,
                "bits": f"{blk.header.bits:08x}", "height": blk.header.height,
                "_target": target.to_bytes(32, "little").hex()}

    def rpc_submitauxblock(self, hash_hex, auxpow_hex):
        h = _hash_arg(hash_hex, reverse=True)
        with self.lock:
            blk = self.aux_templates.get(h)
        if blk is None:
            raise RPCError(-8, "block hash unknown or stale")
        try:
            blk.auxpow = AuxPow.deserialize(bytes.fromhex(auxpow_hex))
        except ValueError as e:
            raise RPCError(-1, f"auxpow decode failed: {e}")
        status = self.chain.submit_block(blk)
        if status == "accepted":
            self.node.announce_block(blk)
            return True
        return False

    def rpc_getauxblock(self, hash_hex=None, auxpow_hex=None):
        if hash_hex is None:
            return self.rpc_createauxblock(self._w().encode(self._w().mining_address))
        return self.rpc_submitauxblock(hash_hex, auxpow_hex)

    def rpc_help(self):
        return sorted(m[4:] for m in dir(self) if m.startswith("rpc_"))

    def rpc_stop(self):
        threading.Thread(target=self.node.stop, daemon=True).start()
        return "Kairos server stopping"


def call(datadir, port, method, params, host="127.0.0.1"):
    with open(os.path.join(datadir, ".cookie")) as f:
        cred = f.read().strip()
    req = urllib.request.Request(
        f"http://{host}:{port}/", data=json.dumps({"id": 1, "method": method, "params": params}).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(cred.encode()).decode(),
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b'{"error":{"message":"http error"}}')
