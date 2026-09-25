"""
Binary P2P framing (protocol 5).

The handshake stays one line of JSON in each direction, so 0.4 nodes, which
speak only JSON, keep working. If both `version` messages carry
"binary": 1, every later message in both directions is a binary frame:

    magic (4) | command (12, ASCII, zero-padded) | length (4, little endian) | payload

This is safe to switch without a race. Each side's first message is its
version, and a node sends nothing else until it has received the peer's
version. So both sides know, before the first frame, that the other one
switches too.

Payloads (varint as in transactions, hashes as 32 raw bytes):

    inv, getdata   varint n, n block hashes, varint m, m txids
    getheaders     varint n, n locator hashes
    headers        varint n, then n x (varint len, header with merge-mining proof)
    block, tx      the serialized block or transaction
    ping, pong     u64 nonce
    getaddr        empty
    addr           varint n, then n x (IPv4 4 bytes, port u16 big endian, seen u64)

Blocks, transactions and headers travel as raw bytes instead of hex inside
JSON, which halves their size, and a frame's length is checked against a
per-command limit before its payload is read. Frames decode into the same
dictionaries the JSON protocol produces, so message handling, and all its
validation, is one code path.

The frames carry no checksum (TCP already has one) and no encryption.
Encrypted transport (BIP324) belongs to the production node
(docs/production-node-plan.md).
"""
import io
import ipaddress
import struct

from .tx import read_varint, write_varint

HEADER = struct.Struct("<4s12sI")
HEADER_SIZE = HEADER.size                      # 20 bytes
MAX_ITEMS = 50_000                             # any list in a frame

# largest payload accepted per command, checked before reading it
LIMITS = {"block": 5 * 1024 * 1024, "tx": 1024 * 1024, "headers": 5 * 1024 * 1024,
          "inv": 64 * 1024 + 16, "getdata": 64 * 1024 + 16, "getheaders": 64 * 32 + 8,
          "addr": 1000 * 14 + 8, "getaddr": 0, "ping": 8, "pong": 8}
DEFAULT_LIMIT = 64 * 1024                      # commands this version does not know


class FrameError(ValueError):
    pass


def _hashes(f, limit=MAX_ITEMS):
    n = read_varint(f)
    if n > limit:
        raise FrameError("too many items")
    out = []
    for _ in range(n):
        h = f.read(32)
        if len(h) != 32:
            raise FrameError("truncated hash")
        out.append(h.hex())
    return out


def _put_hashes(hs):
    return write_varint(len(hs)) + b"".join(bytes.fromhex(h) for h in hs)


def encode_payload(msg: dict) -> bytes:
    t = msg["type"]
    if t in ("inv", "getdata"):
        return _put_hashes(msg.get("blocks", [])) + _put_hashes(msg.get("txs", []))
    if t == "getheaders":
        return _put_hashes(msg.get("locator", []))
    if t == "headers":
        items = [bytes.fromhex(x) for x in msg.get("data", [])]
        return write_varint(len(items)) + b"".join(write_varint(len(x)) + x for x in items)
    if t in ("block", "tx"):
        return bytes.fromhex(msg["data"])
    if t in ("ping", "pong"):
        return struct.pack("<Q", msg.get("n", 0))
    if t == "getaddr":
        return b""
    if t == "addr":
        out = []
        for key, seen in msg.get("addrs", []):
            host, _, port = key.rpartition(":")
            try:
                ip = ipaddress.IPv4Address(host)
            except ValueError:
                continue                        # only IPv4 is relayed
            out.append(ip.packed + struct.pack(">HQ", int(port), int(seen)))
        return write_varint(len(out)) + b"".join(out)
    raise FrameError(f"no binary encoding for {t}")


def decode_payload(command: str, payload: bytes) -> dict:
    f = io.BytesIO(payload)
    msg = {"type": command}
    if command in ("inv", "getdata"):
        msg["blocks"], msg["txs"] = _hashes(f), _hashes(f)
    elif command == "getheaders":
        msg["locator"] = _hashes(f, 64)
    elif command == "headers":
        n = read_varint(f)
        if n > 2000:
            raise FrameError("too many headers")
        items = []
        for _ in range(n):
            ln = read_varint(f)
            if ln > 64 * 1024:
                raise FrameError("header too large")
            x = f.read(ln)
            if len(x) != ln:
                raise FrameError("truncated header")
            items.append(x.hex())
        msg["data"] = items
    elif command in ("block", "tx"):
        msg["data"] = payload.hex()
        return msg
    elif command in ("ping", "pong"):
        if len(payload) != 8:
            raise FrameError("bad ping")
        msg["n"] = struct.unpack("<Q", payload)[0]
        return msg
    elif command == "getaddr":
        pass
    elif command == "addr":
        n = read_varint(f)
        if n > 1000:
            raise FrameError("too many addresses")
        addrs = []
        for _ in range(n):
            x = f.read(14)
            if len(x) != 14:
                raise FrameError("truncated address")
            port, seen = struct.unpack(">HQ", x[4:])
            addrs.append([f"{ipaddress.IPv4Address(x[:4])}:{port}", seen])
        msg["addrs"] = addrs
    else:
        return msg                              # unknown command: its payload is ignored
    if f.read(1):
        raise FrameError("trailing bytes")
    return msg


def encode(magic: bytes, msg: dict) -> bytes:
    t = msg["type"]
    if len(t) > 12 or not t.isascii():
        raise FrameError("bad command")
    payload = encode_payload(msg)
    return HEADER.pack(magic, t.encode().ljust(12, b"\x00"), len(payload)) + payload


def read_frame(f, magic: bytes):
    """Read one frame from a binary file object. Returns (command, payload), or
    None at a clean end of stream. Raises FrameError for anything malformed."""
    head = f.read(HEADER_SIZE)
    if not head:
        return None
    if len(head) != HEADER_SIZE:
        raise EOFError("connection closed mid-frame")
    m, cmd, length = HEADER.unpack(head)
    if m != magic:
        raise FrameError("bad magic")
    name = cmd.rstrip(b"\x00")
    if b"\x00" in name or not name or not all(0x61 <= c <= 0x7A for c in name):
        raise FrameError("bad command")
    command = name.decode()
    if length > LIMITS.get(command, DEFAULT_LIMIT):
        raise FrameError(f"{command} frame too large")
    payload = f.read(length)
    if len(payload) != length:
        raise EOFError("connection closed mid-frame")
    return command, payload
