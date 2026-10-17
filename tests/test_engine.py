import socket

import pytest

from hollowlock import engine, provenance, security
from hollowlock.security import BlockedTarget, InvalidDomain


@pytest.mark.parametrize("target", ["127.0.0.1", "https://127.0.0.1/", "10.0.0.5", "192.168.1.1",
                                    "[::1]", "169.254.169.254"])
def test_public_scan_refuses_private_addresses(target):
    with pytest.raises(BlockedTarget):
        engine.scan(target)


@pytest.mark.parametrize("target", ["", "localhost", "exa mple.com", "a" * 300, "bad_label.com"])
def test_invalid_domains(target):
    with pytest.raises(InvalidDomain):
        engine.scan(target)


def test_dns_failure_is_signed_inconclusive(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    r = engine.scan("does-not-exist.example")
    assert r["verdict"] == "INCONCLUSIVE" and r["verdict_reason"] == "dns_error"
    assert r["score"] is None and r["signature"]["algorithm"] == "ML-DSA-65"
    assert r["cbom"]["components"][0]["algorithm"] == "undetermined"


def test_ipv4_preferred(monkeypatch):
    def fake(host, port, proto=0):
        return [(socket.AF_INET6, 1, 6, "", ("2606:4700::1", 443, 0, 0)),
                (socket.AF_INET, 1, 6, "", ("104.16.0.1", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    ip, fam, every = security.resolve_public_ip("example.com")
    assert (ip, fam) == ("104.16.0.1", "ipv4") and every == ["104.16.0.1", "2606:4700::1"]


def test_ipv6_fallback_and_private_dropped(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, 1, 6, "", ("10.1.1.1", 443)),
        (socket.AF_INET6, 1, 6, "", ("2606:4700::1", 443, 0, 0))])
    assert security.resolve_public_ip("example.com")[:2] == ("2606:4700::1", "ipv6")


def test_bad_mode():
    with pytest.raises(ValueError):
        engine.scan("example.com", mode="slow")


def test_provenance_fields():
    p = provenance.collect("paced", "karachi", 1.0, 6, 1, ip="1.2.3.4", family="ipv4")
    for k in ("tool_version", "git_commit", "python", "os", "platform", "openssl", "kyber_py",
              "dilithium_py", "cryptography", "mode", "vantage", "probe_gap", "timeout", "retries",
              "ip", "family"):
        assert k in p
    assert p["tool_version"] == "2.0.0" and p["vantage"] == "karachi"


def test_source_commit_fallback(tmp_path):
    assert provenance.git_commit(tmp_path) == "release"
    (tmp_path / "SOURCE_COMMIT.txt").write_text("a" * 40 + "\n")
    assert provenance.git_commit(tmp_path) == "a" * 40
