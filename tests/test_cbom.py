from hollowlock import cbom


def report(verdict="ENFORCED", group="X25519MLKEM768", pq=True, cipher="TLS_AES_128_GCM_SHA256",
           tls12=True, cert=None):
    return {"domain": "example.com", "scanned_at": "2026-10-17T00:00:00+00:00", "verdict": verdict,
            "key_exchange": {"default_group": group, "default_is_pq": pq},
            "protocol": {"negotiated": "TLSv1.3", "cipher": cipher, "tls1_2": tls12},
            "certificate": cert if cert is not None else
            {"sig_alg": "ecdsa-with-SHA256", "is_pq": False, "key_type": "EC secp256r1",
             "key_bits": 256, "key_is_pq": False}}


def comp(b, asset):
    return next(c for c in b["components"] if c["asset"] == asset)


def test_aes128_is_acceptable():
    c = comp(cbom.build(report()), "Symmetric cipher")
    assert c["status"] == "acceptable" and "AES-256 is preferred" in c["action"]
    assert comp(cbom.build(report(cipher="TLS_AES_256_GCM_SHA384")), "Symmetric cipher")["status"] == "safe"


def test_tls12_is_a_finding():
    b = cbom.build(report())
    c = comp(b, "TLS 1.2 support")
    assert c["status"] == "finding" and c["action"] == "Plan to retire TLS 1.2 once legacy clients allow"
    assert comp(b, "Protocol")["status"] == "acceptable"
    assert "tls 1.2" not in b["summary"].lower()


def test_key_exchange_follows_probe_b():
    assert comp(cbom.build(report()), "Key exchange")["status"] == "safe"
    c = comp(cbom.build(report("PARTIAL", "X25519", False)), "Key exchange")
    assert c["status"] == "vulnerable" and c["algorithm"] == "X25519"
    c = comp(cbom.build(report("INCONCLUSIVE", "undetermined", False)), "Key exchange")
    assert c["status"] == "undetermined" and c["algorithm"] == "undetermined"


def test_certificate_key_respects_is_pq():
    pq_cert = {"sig_alg": "ML-DSA-65", "is_pq": True, "key_type": "ML-DSA-65", "key_bits": None,
               "key_is_pq": True}
    b = cbom.build(report(cert=pq_cert))
    assert comp(b, "Certificate key")["status"] == "safe"
    assert comp(b, "Certificate signature")["status"] == "safe"


def test_summary_has_no_semicolons_or_colons():
    for v in ("ENFORCED", "PARTIAL", "INCONCLUSIVE"):
        s = cbom.build(report(v, "X25519", v == "ENFORCED"))["summary"]
        assert ";" not in s and ":" not in s
