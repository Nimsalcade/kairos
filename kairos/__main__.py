"""
kairos - command line

  python -m kairos [--testnet|--regtest] info
  python -m kairos demo
  python -m kairos [net] node [--connect host:port] [--mine] [--rpcport N]
  python -m kairos [net] rpc <method> [params...]
  python -m kairos [net] wallet show|backup|encrypt|restore <code>
  python -m kairos [net] utxo export|import <file>     (node must be running)
"""
import argparse
import getpass
import json
import os
import sys
import threading
import time

from . import __version__
from . import crypto
from .chain import Chain, ValidationError
from .node import Node
from .params import NETWORKS, DEFAULT_PORTS, REGTEST, COIN, subsidy
from .wallet import Wallet, fmt

_plock = threading.Lock()
_console = False


def say(*a):
    """Log from network threads without mangling the interactive prompt."""
    with _plock:
        if _console:
            print("\r\033[K" + " ".join(map(str, a)) + "\n> ", end="", flush=True)
        else:
            print(*a, flush=True)


def net(args):
    return NETWORKS["regtest" if args.regtest else "test" if args.testnet else "main"]


def datadir_for(args, p):
    return os.path.expanduser(args.datadir or f"~/.kairos/{p.name}")


def wallet_path(args, p):
    return args.wallet or os.path.join(datadir_for(args, p), "wallet.json")


def ask_passphrase(new=False):
    env = os.environ.get("KAIROS_WALLET_PASSPHRASE")
    if env:
        return env
    if not sys.stdin.isatty():
        raise SystemExit("wallet passphrase needed: set KAIROS_WALLET_PASSPHRASE or run interactively")
    if not new:
        return getpass.getpass("wallet passphrase: ")
    while True:
        a = getpass.getpass("choose a wallet passphrase (10+ chars): ")
        if len(a) < 10:
            print("too short")
            continue
        if a == getpass.getpass("repeat passphrase: "):
            return a
        print("passphrases differ")


def open_wallet(args, p):
    path = wallet_path(args, p)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if os.path.exists(path):
        with open(path) as f:
            enc = json.load(f).get("encrypted")
        return Wallet.load(p, path, ask_passphrase() if enc else None)
    if p.name == "regtest":
        return Wallet.load_or_create(p, path)
    print("creating a new wallet (it will be encrypted)")
    w = Wallet.load_or_create(p, path, ask_passphrase(new=True))
    print(f"\nBACKUP CODE - write it down, it restores all your coins:\n  {w.backup_code()}\n")
    return w


def safety_banner(p):
    if p.name == "regtest":
        return
    print("=" * 72)
    print(" Kairos 0.3.x has NOT been independently audited. See LAUNCH.md.")
    if not crypto.HARDENED:
        print(" libsecp256k1 not found: signing is disabled on this network.")
        print(" Install it with:  pip install coincurve")
    print("=" * 72)


# ---------------------------------------------------------------- commands
def cmd_info(args):
    p = net(args)
    c = Chain(p)
    g = c.blocks[c.genesis.hash]
    print(f"Kairos v{__version__}  network={p.name}  crypto={crypto.BACKEND}")
    print(f"genesis hash     {c.genesis.hash.hex()}")
    print(f"genesis time     {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(g.header.time))}")
    print(f"genesis message  {g.txs[0].inputs[0].witness[4:].decode()}")
    print(f"block spacing    {p.target_spacing}s, ASERT half-life {p.asert_halflife // 3600}h")
    print(f"initial subsidy  {fmt(subsidy(p, 0))}  (smooth decay, no halvings)")
    print(f"tail subsidy     {fmt(p.tail_reward)} per block, forever")
    print(f"base fee         EIP-1559 style, burned; target {p.target_block_size:,} B, max {p.max_block_size:,} B")
    print(f"merge mining     chain id 0x{p.mm_chain_id:04x}, from height {p.auxpow_start_height}")
    print(f"address prefix   {p.hrp}1...  (bech32m, dual-key Schnorr + Lamport)")
    print(f"default ports    p2p {DEFAULT_PORTS[p.name][0]}, rpc {DEFAULT_PORTS[p.name][1]}")


def cmd_demo(args):
    p = REGTEST
    print("== Kairos demo: three independent nodes on localhost ==\n")
    names = ["alice", "bob", "carol"]
    chains = [Chain(p) for _ in names]
    wallets = [Wallet(p) for _ in names]
    nodes = [Node(c, wallet=w, name=n, log=say) for c, w, n in zip(chains, wallets, names)]
    nodes[0].connect("127.0.0.1", nodes[1].port)
    nodes[1].connect("127.0.0.1", nodes[2].port)
    time.sleep(0.5)
    print(f"topology: alice:{nodes[0].port} <-> bob:{nodes[1].port} <-> carol:{nodes[2].port}\n")

    def settle(h):
        end = time.time() + 20
        while time.time() < end and not all(c.height == h for c in chains):
            time.sleep(0.05)
        time.sleep(0.2)

    print("-- alice mines 4 blocks (bob and carol learn of them only via gossip)")
    for _ in range(4):
        nodes[0].mine_one()
    settle(4)
    carol_addr = wallets[2].encode(wallets[2].mining_address)
    print(f"\n-- alice pays carol 12.5 KRS  ->  {carol_addr}")
    tx = wallets[0].create_tx(chains[0], wallets[2].decode(carol_addr), int(12.5 * COIN), tip_per_byte=10)
    nodes[0].submit_tx(tx)
    time.sleep(0.5)
    print(f"   txid {tx.txid.hex()}  size {tx.size} B")
    print("\n-- bob mines the next block, including alice's transaction")
    nodes[1].mine_one()
    settle(5)
    print("\n-- final state, as seen independently by each node")
    for n, c in zip(names, chains):
        a = sum(x.value for x in wallets[0].coins(c, True).values())
        cc = sum(x.value for x in wallets[2].coins(c, True).values())
        print(f"   {n:5s}: height {c.height}  tip {c.tip.hash.hex()[:16]}  alice={fmt(a)}  carol={fmt(cc)}")
    s = chains[2].supply()
    print(f"\n   supply: generated {fmt(s['generated'])}, burned {fmt(s['burned'])}, "
          f"circulating {fmt(s['circulating'])}")
    agree = len({c.tip.hash for c in chains}) == 1
    print(f"\n   consensus: {'ALL NODES AGREE' if agree else 'DIVERGED'}")
    for n in nodes:
        n.stop()
    return 0 if agree else 1


HELP = ("commands (one per line, or separate with ';'):\n"
        "  info | balance | address | newaddress | send <addr> <KRS> | mine [n] | peers | backup | quit")


def run_command(line, chain, wallet, node):
    if not line:
        return
    cmd, rest = line[0].lower(), line[1:]
    try:
        if cmd == "quit":
            return "quit"
        elif cmd == "help":
            print(HELP)
        elif cmd == "info":
            s = chain.supply()
            print(f"height {s['height']} tip {chain.tip.hash.hex()}\n"
                  f"circulating {fmt(s['circulating'])} burned {fmt(s['burned'])} "
                  f"base fee {s['next_base_fee']} motes/B mempool {len(chain.mempool)} peers {len(node.peers)}")
            for name, d in chain.deployment_info().items():
                extra = f" ({d['signalled']}/{d['elapsed']} signalling)" if d["state"] == "started" else ""
                print(f"soft fork {name}: {d['state']}{extra}")
        elif cmd == "balance":
            b = wallet.balance(chain)
            print(f"spendable {fmt(b['spendable'])}  immature {fmt(b['immature'])}  "
                  f"(receive address: {wallet.encode(wallet.mining_address)})")
        elif cmd == "address":
            print(wallet.encode(wallet.mining_address))
        elif cmd == "newaddress":
            print(wallet.new_address())
        elif cmd == "backup":
            print(wallet.backup_code())
        elif cmd == "send":
            if len(rest) != 2:
                raise ValueError("usage: send <addr> <KRS>")
            to = wallet.decode(rest[0])
            try:
                tx = wallet.create_tx(chain, to, int(round(float(rest[1]) * COIN)))
            except ValueError as e:
                if "insufficient" not in str(e):
                    raise
                b = wallet.balance(chain)
                hint = ""
                if b["spendable"] == 0 and b["immature"] == 0:
                    hint = " This node's wallet has never received coins: mine or get paid first."
                elif b["spendable"] == 0:
                    hint = (f" Mining rewards need {chain.params.coinbase_maturity} confirmations "
                            f"before they can be spent.")
                raise ValueError(f"insufficient funds: spendable {fmt(b['spendable'])}, "
                                 f"immature {fmt(b['immature'])}.{hint}")
            node.submit_tx(tx)
            note = "  (note: that address belongs to this same wallet)" if to in wallet.by_addr else ""
            print(f"sent {tx.txid.hex()}{note}\n  it confirms when a block is mined")
        elif cmd == "mine":
            for _ in range(int(rest[0]) if rest else 1):
                node.mine_one()
        elif cmd == "peers":
            if not node.peers:
                print("no peers")
            for pr in node.peers:
                print(f"{pr.key or pr.addr[0]:24s} {'outbound' if pr.outbound else 'inbound ':8s} "
                      f"{'ready' if pr.ready else 'handshaking':11s} height {pr.height}"
                      f"{'  (manual)' if pr.manual else ''}")
            print(f"{len(node.addrman)} known addresses")
        else:
            print(f"unknown command '{cmd}' (type 'help')")
    except (ValueError, ValidationError, IndexError, RuntimeError) as e:
        print(f"error: {e}")


def cmd_node(args):
    global _console
    p = net(args)
    safety_banner(p)
    datadir = datadir_for(args, p)
    os.makedirs(datadir, mode=0o700, exist_ok=True)
    wallet = open_wallet(args, p)
    print(f"loading chain from {datadir} ...")
    chain = Chain(p, datadir=datadir, reindex=args.reindex)
    chain.log = say
    chain.signal.update(args.signal or [])
    for name in chain.signal:
        if chain.deployment(name) is None:
            raise SystemExit(f"unknown deployment {name!r}; known: "
                             f"{', '.join(d.name for d in p.deployments) or 'none'}")
    wallet.attach(chain)
    p2p, rpcp = DEFAULT_PORTS[p.name]
    node = Node(chain, host=args.bind, port=args.port or p2p, wallet=wallet, log=say,
                name="node", max_inbound=args.maxinbound, max_outbound=args.maxoutbound)
    print(f"Kairos v{__version__} [{p.name}] p2p {args.bind}:{node.port}  height {chain.height}  "
          f"crypto {crypto.BACKEND}")
    rpc = None
    if not args.norpc:
        from .rpc import RPCServer
        rpc = RPCServer(node, datadir, host=args.rpcbind, port=args.rpcport or rpcp)
        print(f"rpc on {args.rpcbind}:{rpc.port} (cookie auth: {rpc.cookie_path})")
    for peer in args.connect or []:
        try:
            node.add_manual(peer)
            print(f"will keep connected to {peer}")
        except ValueError:
            print(f"ignoring bad address {peer!r} (use ip:port)")
    if not args.connect:
        if p.seeds:
            print(f"finding peers automatically ({len(p.seeds)} seed nodes known)")
        else:
            print("no --connect peers and no seed nodes for this network: running alone")
    if args.mine:
        node.start_mining()
        print("mining started" + (f", signalling {sorted(chain.signal)}" if chain.signal else ""))
    if args.daemon or not sys.stdin.isatty():
        print("running (Ctrl-C to stop)")
        try:
            while node.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        _console = True
        print(HELP)
        while node.running:
            try:
                raw = input("> ")
            except (EOFError, KeyboardInterrupt):
                break
            if any(run_command(part.strip().split(), chain, wallet, node) == "quit"
                   for part in raw.split(";")):
                break
    _console = False
    print("shutting down")
    node.stop()
    if rpc:
        rpc.stop()
    chain.close()


def cmd_rpc(args):
    from .rpc import call
    p = net(args)
    params = []
    for x in args.params:
        try:
            params.append(json.loads(x))
        except ValueError:
            params.append(x)
    try:
        r = call(datadir_for(args, p), args.rpcport or DEFAULT_PORTS[p.name][1], args.method, params)
    except OSError as e:
        raise SystemExit(f"cannot reach node: {e}")
    if r.get("error"):
        raise SystemExit(f"error {r['error'].get('code')}: {r['error'].get('message')}")
    res = r["result"]
    print(json.dumps(res, indent=2) if isinstance(res, (dict, list)) else res)


def cmd_utxo(args):
    from .rpc import call
    p = net(args)
    path = os.path.abspath(args.file)
    method = "dumputxoset" if args.action == "export" else "loadutxoset"
    try:
        r = call(datadir_for(args, p), args.rpcport or DEFAULT_PORTS[p.name][1], method, [path])
    except OSError as e:
        raise SystemExit(f"cannot reach node (it must be running): {e}")
    if r.get("error"):
        raise SystemExit(f"error: {r['error'].get('message')}")
    res = r["result"]
    if args.action == "export":
        print(f"wrote {path}: {res['coins']:,} coins at height {res['height']} "
              f"({res['bytes']:,} bytes), utxo_root {res['utxo_root']}")
    else:
        print(f"adopted snapshot at height {res['height']} ({res['coins']:,} coins); "
              f"the node now downloads only newer blocks")


def cmd_wallet(args):
    p = net(args)
    path = wallet_path(args, p)
    if args.action == "restore":
        if os.path.exists(path):
            raise SystemExit(f"{path} exists; move it away first")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        pw = None if p.name == "regtest" else ask_passphrase(new=True)
        w = Wallet.restore(p, args.code, path, passphrase=pw)
        print(f"restored {len(w.keys)} addresses into {path}")
        return
    w = open_wallet(args, p)
    if args.action == "show":
        print(f"wallet {path} ({'encrypted' if w.passphrase else 'NOT encrypted'})")
        for i, k in enumerate(w.keys):
            print(f"  [{i}] {w.encode(k.address)}")
    elif args.action == "backup":
        print(w.backup_code())
    elif args.action == "encrypt":
        w.encrypt(ask_passphrase(new=True))
        print("wallet encrypted")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kairos", description=f"Kairos v{__version__}")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--testnet", action="store_true")
    g.add_argument("--regtest", action="store_true")
    ap.add_argument("--datadir")
    ap.add_argument("--wallet")
    ap.add_argument("--rpcport", type=int)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)   # same options also accepted after the command
    common.add_argument("--testnet", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--regtest", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--datadir", default=argparse.SUPPRESS)
    common.add_argument("--wallet", default=argparse.SUPPRESS)
    common.add_argument("--rpcport", type=int, default=argparse.SUPPRESS)
    sub.add_parser("info", parents=[common])
    sub.add_parser("demo", parents=[common])
    n = sub.add_parser("node", parents=[common])
    n.add_argument("--port", type=int)
    n.add_argument("--bind", default="0.0.0.0")
    n.add_argument("--connect", action="append")
    n.add_argument("--mine", action="store_true")
    n.add_argument("--norpc", action="store_true")
    n.add_argument("--rpcbind", default="127.0.0.1")
    n.add_argument("--maxinbound", type=int, default=32)
    n.add_argument("--maxoutbound", type=int, default=8)
    n.add_argument("--daemon", action="store_true", help="no console")
    n.add_argument("--signal", action="append", metavar="NAME",
                   help="signal readiness for a soft fork in mined blocks (e.g. pq)")
    n.add_argument("--reindex", action="store_true", help="ignore chainstate.dat and replay all blocks")
    r = sub.add_parser("rpc", parents=[common])
    r.add_argument("method")
    r.add_argument("params", nargs="*")
    wl = sub.add_parser("wallet", parents=[common])
    wl.add_argument("action", choices=["show", "backup", "encrypt", "restore"])
    wl.add_argument("code", nargs="?")
    ux = sub.add_parser("utxo", parents=[common])
    ux.add_argument("action", choices=["export", "import"])
    ux.add_argument("file")
    args = ap.parse_args(argv)
    if args.testnet and args.regtest:
        ap.error("choose one of --testnet / --regtest")
    fn = {"info": cmd_info, "demo": cmd_demo, "node": cmd_node, "rpc": cmd_rpc, "wallet": cmd_wallet,
          "utxo": cmd_utxo}
    return fn[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
