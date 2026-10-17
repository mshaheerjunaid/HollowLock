from hollowlock.report import (ENFORCED, HOLLOW, INCONCLUSIVE, LEGACY_HYBRID, PARTIAL, STRICT,
                               TLS12_ONLY, decide, hrr_needed_for_pq, score_for)
from hollowlock.security import AGILITY_GROUPS

from helpers import rec


def agility(accepted=(), errors=()):
    out = {}
    for g in AGILITY_GROUPS:
        if g in accepted:
            out[g] = rec("group", g, hrr=True)
        elif g in errors:
            out[g] = rec("error", error_class="reset")
        else:
            out[g] = rec("refused", alert_name="handshake_failure")
    return out


REFUSED = rec("refused", alert_name="handshake_failure")


def test_inconclusive_when_b_fails():
    for cls in ("timeout", "reset", "connect_error", "unparseable"):
        v = decide(REFUSED, rec("error", error_class=cls), REFUSED, agility())
        assert v == (INCONCLUSIVE, cls)
    assert decide(REFUSED, REFUSED, REFUSED, agility()) == (INCONCLUSIVE, "default_refused")


def test_inconclusive_when_pq_probe_errors():
    v = decide(rec("error", error_class="reset"), rec("group", 0x001D), rec("group", 0x001D, hrr=True),
               agility(accepted=(0x001D,)))
    assert v == (INCONCLUSIVE, "pq_probe_error")
    # an agility hybrid hit still decides it
    v = decide(rec("error", error_class="reset"), rec("group", 0x001D), rec("group", 0x001D, hrr=True),
               agility(accepted=(0x001D, 0x11EC)))
    assert v == (PARTIAL, None)


def test_tls12_only():
    assert decide(REFUSED, rec("tls12", version="TLSv1.2"), REFUSED, agility()) == (TLS12_ONLY, None)


def test_strict_and_enforced():
    b = rec("group", 0x11EC)
    assert decide(rec("group", 0x11EC, hrr=True), b, REFUSED, agility((0x11EC,))) == (STRICT, None)
    assert decide(rec("group", 0x11EC, hrr=True), b, rec("group", 0x001D, hrr=True),
                  agility((0x11EC, 0x001D))) == (ENFORCED, None)
    assert decide(rec("group", 0x11EC, hrr=True), b, rec("error", error_class="timeout"),
                  agility((0x11EC,))) == (INCONCLUSIVE, "classical_probe_error")


def test_partial():
    v = decide(rec("group", 0x11EC, hrr=True), rec("group", 0x001D), rec("group", 0x001D, hrr=True),
               agility((0x001D, 0x11EC)))
    assert v == (PARTIAL, None)
    # pure ml-kem reachable also counts
    v = decide(REFUSED, rec("group", 0x001D), rec("group", 0x001D, hrr=True), agility((0x001D, 0x0201)))
    assert v == (PARTIAL, None)


def test_legacy_hybrid():
    v = decide(rec("group", 0x6399, hrr=True), rec("group", 0x001D), rec("group", 0x001D, hrr=True),
               agility((0x001D, 0x6399)))
    assert v == (LEGACY_HYBRID, None)


def test_hollow():
    v = decide(REFUSED, rec("group", 0x001D), rec("group", 0x001D, hrr=True), agility((0x001D, 0x0017)))
    assert v == (HOLLOW, None)
    # a fin-close counts as a refusal too
    fin = rec("refused")
    assert decide(fin, rec("group", 0x0017), fin, agility((0x0017,)))[0] == HOLLOW


def test_hollow_needs_every_pq_probe_refused():
    v = decide(REFUSED, rec("group", 0x001D), rec("group", 0x001D, hrr=True),
               agility((0x001D,), errors=(0x11EB,)))
    assert v == (INCONCLUSIVE, "pq_probe_error")


def test_hrr_needed_for_pq():
    a = rec("group", 0x11EC, hrr=True)
    assert hrr_needed_for_pq(a, rec("group", 0x001D)) is True
    assert hrr_needed_for_pq(a, rec("group", 0x11EC)) is False
    assert hrr_needed_for_pq(a, rec("group", 0x11EB, hrr=True)) is True
    assert hrr_needed_for_pq(REFUSED, rec("group", 0x001D)) is False


def test_scores():
    sig = {"cipher": "TLS_AES_128_GCM_SHA256", "tls1_2": False, "default_group": "X25519MLKEM768",
           "supported": [], "cert": {"key_type": "EC secp256r1", "key_bits": 256}}
    assert score_for(INCONCLUSIVE, sig) is None and score_for(TLS12_ONLY, sig) is None
    # aes-128 is not penalised against aes-256
    assert score_for(ENFORCED, sig) == score_for(ENFORCED, dict(sig, cipher="TLS_AES_256_GCM_SHA384"))
    assert score_for(STRICT, sig) > score_for(ENFORCED, sig) > score_for(PARTIAL, sig) > score_for(HOLLOW, sig)
