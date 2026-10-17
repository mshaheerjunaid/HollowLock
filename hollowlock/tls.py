import ipaddress
import os
import socket
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

from .groups import name_of
from .security import MAX_READ, MAX_TLS_RECORD, PROBE_TIMEOUT

# sha-256 of "HelloRetryRequest", the fixed marker for an HRR
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

TLS13, TLS12 = 0x0304, 0x0303
VERSION_NAMES = {0x0304: "TLSv1.3", 0x0303: "TLSv1.2", 0x0302: "TLSv1.1", 0x0301: "TLSv1.0"}

TLS13_SUITES = [0x1301, 0x1302, 0x1303]
# chrome's tls 1.2 suites, only sent by the browser-like probe
TLS12_SUITES = [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
            0x0806, 0x0601, 0x0807, 0x0808, 0x0603]

ALERT_NAMES = {
    10: "unexpected_message", 40: "handshake_failure", 47: "illegal_parameter",
    50: "decode_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 109: "missing_extension", 112: "unrecognized_name",
    120: "no_application_protocol",
}


class ProbeError(Exception):
    # carries the error class used for INCONCLUSIVE reasons
    def __init__(self, kind, msg):
        super().__init__(msg)
        self.kind = kind


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


def _x25519():
    k = X25519PrivateKey.generate()   # throwaway, we never finish the handshake
    return k.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)


def _ec_point(curve):
    k = ec.generate_private_key(curve)
    return k.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint)


def share_for(group):
    # client key_share body per group. hybrid layouts follow
    # draft-ietf-tls-ecdhe-mlkem: x25519 hybrid puts ml-kem first,
    # the nist-curve hybrids put the ecdh point first.
    if group == 0x001D:
        return _x25519()
    if group == 0x0017:
        return _ec_point(ec.SECP256R1())
    if group == 0x0018:
        return _ec_point(ec.SECP384R1())
    if group == 0x11EC:
        ek, _ = ML_KEM_768.keygen()
        return ek + _x25519()                       # 1184 + 32 = 1216
    if group == 0x11EB:
        ek, _ = ML_KEM_768.keygen()
        return _ec_point(ec.SECP256R1()) + ek       # 65 + 1184 = 1249
    if group == 0x11ED:
        ek, _ = ML_KEM_1024.keygen()
        return _ec_point(ec.SECP384R1()) + ek       # 97 + 1568 = 1665
    raise ValueError(f"no share builder for {name_of(group)}")


def build_client_hello(hostname, groups, shares=(), alpn=None, tls12=False):
    """groups is supported_groups in order, shares the groups we send a key for
    (empty means an empty key_share, which forces an HRR). tls12 adds the
    1.2 fallback a browser offers."""
    sg = _block(2, b"".join(_u16(g) for g in groups))
    sa = _block(2, b"".join(_u16(a) for a in SIG_ALGS))
    sv = _block(1, _u16(TLS13) + (_u16(TLS12) if tls12 else b""))
    pskm = _block(1, b"\x01")
    ks = _block(2, b"".join(_u16(g) + _block(2, share_for(g)) for g in shares))

    exts = b"" if _is_ip(hostname) else _ext(0x0000, _block(2, b"\x00" + _block(2, hostname.encode("idna"))))
    if tls12:
        exts += _ext(0x0017, b"") + _ext(0xFF01, b"\x00")   # ems, renegotiation_info
    exts += _ext(0x000A, sg)
    if tls12:
        exts += _ext(0x000B, b"\x01\x00")                    # ec_point_formats
    if alpn:
        exts += _ext(0x0010, _block(2, b"".join(_block(1, p.encode()) for p in alpn)))
    exts += (_ext(0x000D, sa) + _ext(0x002B, sv) + _ext(0x002D, pskm)
             + _ext(0x0033, ks))

    suites = TLS13_SUITES + (TLS12_SUITES if tls12 else [])
    body = (_u16(TLS12) + os.urandom(32) + _block(1, os.urandom(32))
            + _block(2, b"".join(_u16(c) for c in suites))
            + _block(1, b"\x00") + _block(2, exts))
    return b"\x16\x03\x01" + _block(2, b"\x01" + _block(3, body))


def _is_ip(host):
    # sni must not carry an ip literal (rfc 6066), so a bare address goes without it
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_server_hello(sock):
    """Read records until one whole ServerHello or HRR is assembled. Skips a
    ChangeCipherSpec, handles a message split across records, and never
    reads more than MAX_READ bytes."""
    hs, total = b"", 0
    while True:
        header = _recv_exact(sock, 5)
        if not header:
            if hs or total:
                raise ProbeError("unparseable", "connection closed mid-message")
            return {"outcome": "refused", "alert": None, "detail": "closed after hello"}
        if len(header) < 5:
            raise ProbeError("unparseable", "truncated record header")
        ctype, length = header[0], struct.unpack("!H", header[3:5])[0]
        if length == 0 or length > MAX_TLS_RECORD:      # never trust a hostile length
            raise ProbeError("unparseable", f"bad record length {length}")
        total += 5 + length
        if total > MAX_READ:
            raise ProbeError("unparseable", "server hello too large")
        frag = _recv_exact(sock, length)
        if len(frag) < length:
            raise ProbeError("unparseable", "truncated record")

        if ctype == 0x14:                    # change_cipher_spec, ignore
            continue
        if ctype == 0x15:
            if hs or len(frag) < 2:
                raise ProbeError("unparseable", "alert mid-message")
            return {"outcome": "refused", "alert": ALERT_NAMES.get(frag[1], f"alert_{frag[1]}"),
                    "detail": None}
        if ctype != 0x16:
            raise ProbeError("unparseable", f"unexpected record type {ctype}")

        hs += frag
        if len(hs) >= 4:
            if hs[0] != 0x02:
                raise ProbeError("unparseable", f"first handshake message is type {hs[0]}")
            mlen = int.from_bytes(hs[1:4], "big")
            if mlen > MAX_READ:
                raise ProbeError("unparseable", "server hello too large")
            if len(hs) >= 4 + mlen:
                return parse_server_hello(hs[4:4 + mlen])


def _parse_extensions(data):
    out, i = {}, 0
    while i < len(data):
        if i + 4 > len(data):
            raise ProbeError("unparseable", "truncated extension header")
        etype, elen = struct.unpack("!HH", data[i:i + 4])
        if i + 4 + elen > len(data):          # lying length
            raise ProbeError("unparseable", "truncated extension")
        out[etype] = data[i + 4:i + 4 + elen]
        i += 4 + elen
    return out


def parse_server_hello(sh):
    if len(sh) < 38:
        raise ProbeError("unparseable", "server hello too short")
    legacy = struct.unpack("!H", sh[0:2])[0]
    is_hrr = sh[2:34] == HRR_RANDOM
    i = 35 + sh[34]                          # skip session id
    if i + 3 > len(sh):
        raise ProbeError("unparseable", "server hello too short")
    cipher = struct.unpack("!H", sh[i:i + 2])[0]
    i += 3
    exts = {}
    if i < len(sh):
        if i + 2 > len(sh):
            raise ProbeError("unparseable", "truncated extensions")
        elen = struct.unpack("!H", sh[i:i + 2])[0]
        if i + 2 + elen > len(sh):
            raise ProbeError("unparseable", "truncated extensions")
        exts = _parse_extensions(sh[i + 2:i + 2 + elen])

    sv = exts.get(0x002B)
    if sv is not None and len(sv) != 2:
        raise ProbeError("unparseable", "bad supported_versions")
    version = struct.unpack("!H", sv)[0] if sv else legacy
    vname = VERSION_NAMES.get(version, f"0x{version:04x}")

    if version != TLS13:
        if version <= TLS12:
            return {"outcome": "tls12", "version": vname, "cipher": cipher, "hrr": False}
        raise ProbeError("unparseable", f"unknown version {vname}")

    ks = exts.get(0x0033)
    if not ks or len(ks) < 2:
        raise ProbeError("unparseable", "tls 1.3 hello without key_share")
    group = struct.unpack("!H", ks[0:2])[0]
    if not is_hrr:
        # group(2) + len(2) + key, check the length the server claims
        if len(ks) < 4 or struct.unpack("!H", ks[2:4])[0] != len(ks) - 4:
            raise ProbeError("unparseable", "bad key_share length")
    elif len(ks) != 2:
        raise ProbeError("unparseable", "bad hrr key_share")
    return {"outcome": "group", "group": group, "hrr": is_hrr,
            "version": vname, "cipher": cipher}


def probe(hostname, ip, groups, shares=(), alpn=None, tls12=False,
          timeout=PROBE_TIMEOUT, port=443):
    """One hello to the pinned ip, one answer back. Returns a dict with
    outcome group / refused / tls12 / error, never raises."""
    base = {"outcome": None, "group": None, "group_name": None, "hrr": False,
            "version": None, "cipher": None, "alert": None, "error": None,
            "error_class": None}
    try:
        hello = build_client_hello(hostname, groups, shares, alpn, tls12)
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
        except socket.timeout:
            raise ProbeError("timeout", "connect timed out")
        except OSError as e:
            raise ProbeError("connect_error", f"{type(e).__name__}: {e}")
        try:
            sock.settimeout(timeout)
            sock.sendall(hello)
            got = read_server_hello(sock)
        finally:
            sock.close()
    except ProbeError as e:
        got = {"outcome": "error", "error_class": e.kind, "error": str(e)}
    except socket.timeout:
        got = {"outcome": "error", "error_class": "timeout", "error": "read timed out"}
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        got = {"outcome": "error", "error_class": "reset", "error": type(e).__name__}
    except OSError as e:
        got = {"outcome": "error", "error_class": "reset", "error": f"{type(e).__name__}: {e}"}

    base.update(got)
    base.pop("detail", None)
    base["group_name"] = name_of(base["group"])
    return base
