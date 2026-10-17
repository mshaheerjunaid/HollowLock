import struct

import pytest
from kyber_py.ml_kem import ML_KEM_768

from hollowlock import tls
from hollowlock.engine import PROBES
from hollowlock.tls import ProbeError, read_server_hello

from helpers import FakeSock, alert, ext, parse_client_hello, record, server_hello, u16


def _shares(exts):
    ks = exts[0x0033]
    total = struct.unpack("!H", ks[:2])[0]
    out, i = [], 2
    while i < 2 + total:
        g, n = struct.unpack("!HH", ks[i:i + 4])
        out.append((g, ks[i + 4:i + 4 + n]))
        i += 4 + n
    return out


def test_browser_like_hello():
    b = PROBES["B"]
    hello = tls.build_client_hello("example.com", b["groups"], b["shares"], b["alpn"], b["tls12"])
    suites, exts = parse_client_hello(hello)

    groups = exts[0x000A][2:]
    assert [struct.unpack("!H", groups[k:k + 2])[0] for k in range(0, len(groups), 2)] == \
        [0x11EC, 0x001D, 0x0017, 0x0018]
    shares = _shares(exts)
    assert [g for g, _ in shares] == [0x11EC, 0x001D]
    hybrid = shares[0][1]
    assert len(hybrid) == 1216
    # the first 1184 bytes must be a real ml-kem-768 key, encaps validates it
    ML_KEM_768.encaps(hybrid[:1184])
    assert len(shares[1][1]) == 32
    assert b"example.com" in exts[0x0000]
    assert b"h2" in exts[0x0010] and b"http/1.1" in exts[0x0010]
    # browser-like also offers the tls 1.2 fallback
    assert exts[0x002B] == b"\x04\x03\x04\x03\x03"
    assert 0xC02F in suites and 0x1301 in suites


def test_no_sni_for_ip_literal():
    _, exts = parse_client_hello(tls.build_client_hello("203.0.113.7", [0x001D]))
    assert 0x0000 not in exts
    _, exts = parse_client_hello(tls.build_client_hello("example.com", [0x001D]))
    assert 0x0000 in exts


def test_hybrid_share_layouts():
    assert len(tls.share_for(0x11EC)) == 1184 + 32
    p256 = tls.share_for(0x11EB)
    assert len(p256) == 65 + 1184 and p256[0] == 0x04          # point first
    p384 = tls.share_for(0x11ED)
    assert len(p384) == 97 + 1568 and p384[0] == 0x04


def test_empty_key_share_and_tls13_only():
    hello = tls.build_client_hello("example.com", PROBES["A"]["groups"])
    suites, exts = parse_client_hello(hello)
    assert exts[0x0033] == b"\x00\x00"
    assert exts[0x002B] == b"\x02\x03\x04"
    assert suites == tls.TLS13_SUITES
    assert 0x0010 not in exts


def test_server_hello():
    r = read_server_hello(FakeSock(record(0x16, server_hello(0x11EC, key_len=1120))))
    assert r["outcome"] == "group" and r["group"] == 0x11EC and not r["hrr"] and r["version"] == "TLSv1.3"


def test_hrr():
    r = read_server_hello(FakeSock(record(0x16, server_hello(0x001D, hrr=True))))
    assert r["outcome"] == "group" and r["group"] == 0x001D and r["hrr"]


def test_tls12_server_hello():
    r = read_server_hello(FakeSock(record(0x16, server_hello(version=0x0303, cipher=0xC02F))))
    assert r["outcome"] == "tls12" and r["version"] == "TLSv1.2" and r["cipher"] == 0xC02F


def test_split_across_records_and_byte_by_byte():
    sh = server_hello(0x11EC, key_len=1120)
    r = read_server_hello(FakeSock(record(0x16, sh[:20]), record(0x16, sh[20:300]), record(0x16, sh[300:])))
    assert r["outcome"] == "group" and r["group"] == 0x11EC
    data = record(0x16, sh)
    r = read_server_hello(FakeSock(*[data[k:k + 1] for k in range(len(data))]))
    assert r["group"] == 0x11EC


def test_change_cipher_spec_first():
    r = read_server_hello(FakeSock(record(0x14, b"\x01"), record(0x16, server_hello(0x001D))))
    assert r["outcome"] == "group" and r["group"] == 0x001D


def test_alert_is_refused():
    r = read_server_hello(FakeSock(alert(40)))
    assert r == {"outcome": "refused", "alert": "handshake_failure", "detail": None}
    assert read_server_hello(FakeSock(alert(70)))["alert"] == "protocol_version"


def test_clean_close_is_refused():
    assert read_server_hello(FakeSock())["outcome"] == "refused"


@pytest.mark.parametrize("data", [
    record(0x16, server_hello(0x001D))[:20],                  # truncated record
    b"\x16\x03\x03",                                          # truncated header
    b"\x16\x03\x03\xff\xff" + b"\x00" * 10,                   # oversized length
    b"\x16\x03\x03\x00\x00",                                  # zero length
    record(0x17, b"hello"),                                   # wrong record type
    record(0x16, b"\x0b\x00\x00\x01\x00"),                    # not a server hello
    b"HTTP/1.1 400 Bad Request\r\n\r\n",                      # not tls at all
])
def test_bad_input_is_unparseable(data):
    with pytest.raises(ProbeError) as e:
        read_server_hello(FakeSock(data))
    assert e.value.kind == "unparseable"


def test_lying_extension_length():
    sh = bytearray(server_hello(0x001D))
    body_ext = sh.find(u16(0x002B))
    sh[body_ext + 2:body_ext + 4] = u16(500)                  # claims more than is there
    with pytest.raises(ProbeError):
        read_server_hello(FakeSock(record(0x16, bytes(sh))))


def test_hello_size_cap():
    # a server hello claiming more than MAX_READ is dropped before we read it
    huge = b"\x02" + (80000).to_bytes(3, "big") + b"\x00" * 100
    with pytest.raises(ProbeError):
        read_server_hello(FakeSock(record(0x16, huge)))
    # and so is a stream of filler records that never ends in a hello
    filler = [record(0x14, b"\x01" * 16000) for _ in range(5)]
    with pytest.raises(ProbeError):
        read_server_hello(FakeSock(*filler))


def test_probe_connect_error():
    # nothing listens on port 9 of loopback in the test environment
    r = tls.probe("example.com", "127.0.0.1", [0x001D], timeout=2, port=9)
    assert r["outcome"] == "error" and r["error_class"] in ("connect_error", "timeout")
