# small builders for server-side tls bytes and a fake socket to feed the parser
import os
import struct

from hollowlock.tls import HRR_RANDOM


def u16(v):
    return struct.pack("!H", v)


def ext(t, body):
    return u16(t) + u16(len(body)) + body


def server_hello(group=None, hrr=False, version=0x0304, cipher=0x1301, key_len=32, extra=b""):
    exts = b""
    if version == 0x0304:
        exts += ext(0x002B, u16(0x0304))
        if group is not None:
            exts += ext(0x0033, u16(group) if hrr else u16(group) + u16(key_len) + os.urandom(key_len))
    exts += extra
    body = (u16(0x0303) + (HRR_RANDOM if hrr else os.urandom(32)) + bytes([32]) + os.urandom(32)
            + u16(cipher) + b"\x00" + (u16(len(exts)) + exts if exts else b""))
    return b"\x02" + struct.pack("!I", len(body))[1:] + body


def record(ctype, payload):
    return bytes([ctype]) + b"\x03\x03" + u16(len(payload)) + payload


def alert(desc):
    return record(0x15, bytes([2, desc]))


class FakeSock:
    """recv() hands back the given chunks one at a time, b'' at the end (a FIN)."""

    def __init__(self, *chunks):
        self.chunks = [c for c in chunks if c]

    def recv(self, n):
        if not self.chunks:
            return b""
        head = self.chunks[0]
        out, rest = head[:n], head[n:]
        if rest:
            self.chunks[0] = rest
        else:
            self.chunks.pop(0)
        return out


def parse_client_hello(data):
    # just enough parsing to check what we built
    assert data[0] == 0x16 and data[5] == 0x01
    body = data[9:]
    i = 2 + 32
    i += 1 + body[i]
    n = struct.unpack("!H", body[i:i + 2])[0]
    suites = [struct.unpack("!H", body[i + 2 + k:i + 4 + k])[0] for k in range(0, n, 2)]
    i += 2 + n
    i += 1 + body[i]
    elen = struct.unpack("!H", body[i:i + 2])[0]
    exts, j, end = {}, i + 2, i + 2 + elen
    while j < end:
        t, ln = struct.unpack("!HH", body[j:j + 4])
        exts[t] = body[j + 4:j + 4 + ln]
        j += 4 + ln
    return suites, exts


def rec(outcome="group", group=None, hrr=False, alert_name=None, error_class=None, version="TLSv1.3"):
    # a probe record the way tls.probe returns it
    return {"outcome": outcome, "group": group, "hrr": hrr, "alert": alert_name,
            "error_class": error_class, "error": error_class, "version": version if outcome != "error" else None,
            "group_name": None, "cipher": None, "attempts": 1, "elapsed_ms": 1}
