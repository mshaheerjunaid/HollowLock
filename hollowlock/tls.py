import os
import socket
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .security import MAX_TLS_RECORD, PROBE_TIMEOUT

# sha-256 of "HelloRetryRequest", the fixed marker for an HRR
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

TLS13 = 0x0304
CIPHER_SUITES = [0x1301, 0x1302, 0x1303]
SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0807, 0x0808]

ALERT_NAMES = {
    40: "handshake_failure", 47: "illegal_parameter", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 109: "missing_extension",
}


def _u16(v):
    return struct.pack("!H", v)


def _block(n, body):
    if n == 1:
        return bytes([len(body)]) + body
    if n == 2:
        return _u16(len(body)) + body
    if n == 3:
        return struct.pack("!I", len(body))[1:] + body
    raise ValueError(n)


def _ext(t, body):
    return _u16(t) + _block(2, body)


def _x25519_pub():
    # throwaway key, we never finish the handshake
    k = X25519PrivateKey.generate()
    return k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def build_client_hello(hostname, groups, send_x25519_share):
    host = hostname.encode()
    sni = _block(2, b"\x00" + _block(2, host))
    sg = _block(2, b"".join(_u16(g) for g in groups))
    sa = _block(2, b"".join(_u16(a) for a in SIG_ALGS))
    sv = _block(1, _u16(TLS13))
    pskm = _block(1, b"\x01")

    if send_x25519_share:
        ks = _block(2, _u16(0x001D) + _block(2, _x25519_pub()))
    else:
        ks = _block(2, b"")  # empty -> forces the server to pick and retry

    exts = (_ext(0x0000, sni) + _ext(0x000A, sg) + _ext(0x000D, sa)
            + _ext(0x002B, sv) + _ext(0x002D, pskm) + _ext(0x0033, ks))

    body = (_u16(0x0303) + os.urandom(32) + _block(1, os.urandom(32))
            + _block(2, b"".join(_u16(c) for c in CIPHER_SUITES))
            + _block(1, b"\x00") + _block(2, exts))

    handshake = b"\x01" + _block(3, body)
    return b"\x16\x03\x01" + _block(2, handshake)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf if len(buf) == n else None


def _read_record(sock):
    header = _recv_exact(sock, 5)
    if not header:
        return None, None
    length = struct.unpack("!H", header[3:5])[0]
    if length == 0 or length > MAX_TLS_RECORD:   # never trust a hostile length
        return None, None
    return header[0], _recv_exact(sock, length)


def _parse_extensions(data):
    out, i = {}, 0
    while i + 4 <= len(data):
        etype = struct.unpack("!H", data[i:i + 2])[0]
        elen = struct.unpack("!H", data[i + 2:i + 4])[0]
        if i + 4 + elen > len(data):             # truncated / lying length
            break
        out[etype] = data[i + 4:i + 4 + elen]
        i += 4 + elen
    return out


def _read_response(sock):
    ctype, frag = _read_record(sock)
    if not frag:
        return ("closed", None, None)
    if ctype == 0x15:  # alert
        desc = frag[1] if len(frag) >= 2 else None
        return ("alert", ALERT_NAMES.get(desc, f"alert_{desc}"), desc)
    if ctype != 0x16 or len(frag) < 38 or frag[0] != 0x02:
        return ("closed", None, None)

    sh = frag[4:]
    is_hrr = sh[2:34] == HRR_RANDOM
    i = 34
    i += 1 + sh[i]   # session id
    i += 3           # cipher suite + compression
    if i + 2 > len(sh):
        return ("closed", None, None)
    ext_len = struct.unpack("!H", sh[i:i + 2])[0]
    i += 2
    exts = _parse_extensions(sh[i:i + ext_len])

    ks = exts.get(0x0033)  # key_share -> the chosen group
    if ks and len(ks) >= 2:
        return ("group", struct.unpack("!H", ks[0:2])[0], is_hrr)
    return ("closed", None, None)


def probe(hostname, ip, groups, send_x25519_share, timeout=PROBE_TIMEOUT):
    # send one hello, read one answer
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall(build_client_hello(hostname, groups, send_x25519_share))
            return _read_response(sock)
        finally:
            sock.close()
    except Exception as e:
        return ("error", f"{type(e).__name__}: {e}", None)
