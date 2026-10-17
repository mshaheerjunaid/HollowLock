# verdicts and the dashboard score. kept apart from the network code so the
# meaning of a result is easy to read and change in one place.
from .groups import (is_legacy_draft, is_pq, is_pure_mlkem, is_standard_hybrid)

INCONCLUSIVE = "INCONCLUSIVE"
TLS12_ONLY = "TLS12_ONLY"
STRICT = "STRICT"
ENFORCED = "ENFORCED"
PARTIAL = "PARTIAL"
LEGACY_HYBRID = "LEGACY_HYBRID"
HOLLOW = "HOLLOW"

VERDICTS = [STRICT, ENFORCED, PARTIAL, LEGACY_HYBRID, HOLLOW, TLS12_ONLY, INCONCLUSIVE]

LABEL = {STRICT: "Strict", ENFORCED: "Enforced", PARTIAL: "Partial",
         LEGACY_HYBRID: "Legacy Hybrid", HOLLOW: "Hollow",
         TLS12_ONLY: "TLS 1.2 Only", INCONCLUSIVE: "Inconclusive"}

EXPLAIN = {
    STRICT: "Post-quantum by default, and clients that offer only classical groups are turned away.",
    ENFORCED: "Post-quantum by default, while clients that offer only classical groups are still served.",
    PARTIAL: "The server can negotiate post-quantum but hands an ordinary browser classical key exchange.",
    LEGACY_HYBRID: "The only post-quantum groups it accepts are pre-standard Kyber drafts.",
    HOLLOW: "No post-quantum key exchange is accepted at all, every session is classical.",
    TLS12_ONLY: "The server only speaks TLS 1.2, which has no way to carry these hybrid groups.",
    INCONCLUSIVE: "The probes could not reach a clear answer, so no verdict is given.",
}

REASONS = {
    "dns_error": "The name did not resolve.",
    "timeout": "The browser-like probe timed out.",
    "reset": "The connection was reset during the browser-like probe.",
    "connect_error": "The TCP connection could not be opened.",
    "unparseable": "The server answered with bytes that are not a valid server hello.",
    "default_refused": "The server refused the browser-like probe outright.",
    "pq_probe_error": "The post-quantum probes failed, so Partial and Hollow cannot be told apart.",
    "classical_probe_error": "The classical-only probe failed, so Strict and Enforced cannot be told apart.",
    "undetermined": "The probe results do not match any verdict rule.",
}


def _picked(r):
    return r is not None and r["outcome"] == "group"


def decide(a, b, c, agility, baseline_version=None):
    """Apply the verdict rules in order. a, b, c are probe records, agility maps
    group code to its probe record. Probe D never feeds the verdict.
    Returns (verdict, reason), reason is None unless INCONCLUSIVE."""
    tls13_records = [a, b, c] + list(agility.values())

    # 1. inconclusive when the browser-like probe got no usable answer
    if b["outcome"] not in ("group", "tls12"):
        if b["outcome"] == "error":
            return INCONCLUSIVE, b["error_class"] or "unparseable"
        return INCONCLUSIVE, "default_refused"
    b_hybrid = _picked(b) and is_standard_hybrid(b["group"])
    b_classical = _picked(b) and not is_pq(b["group"])
    hybrid_agility_hit = any(_picked(r) and is_standard_hybrid(g) for g, r in agility.items())
    if b_classical and a["outcome"] == "error" and not hybrid_agility_hit:
        return INCONCLUSIVE, "pq_probe_error"

    # 2. tls 1.2 only
    if b["outcome"] == "tls12":
        return TLS12_ONLY, None
    if baseline_version == "TLSv1.2" and all(
            r["outcome"] == "tls12" or (r["outcome"] == "refused" and r["alert"] == "protocol_version")
            for r in tls13_records):
        return TLS12_ONLY, None

    # 3 and 4. hybrid by default, split on how classical-only clients are treated
    if b_hybrid:
        if c["outcome"] == "refused":
            return STRICT, None
        if c["outcome"] == "group":
            return ENFORCED, None
        return INCONCLUSIVE, "classical_probe_error"

    # 5. classical by default but a real pq group is reachable
    pq_reach = [a] + list(agility.values())
    if b_classical and any(_picked(r) and (is_standard_hybrid(r["group"]) or is_pure_mlkem(r["group"]))
                           for r in pq_reach):
        return PARTIAL, None

    # 6. only the kyber drafts
    accepted_pq = [r["group"] for r in [a, b] + list(agility.values()) if _picked(r) and is_pq(r["group"])]
    if accepted_pq and all(is_legacy_draft(g) for g in accepted_pq):
        return LEGACY_HYBRID, None

    # 7. nothing post-quantum anywhere
    pq_agility = [r for g, r in agility.items() if is_pq(g)]
    if b_classical and a["outcome"] == "refused" and all(r["outcome"] == "refused" for r in pq_agility):
        return HOLLOW, None

    if b_classical and any(r["outcome"] == "error" for r in pq_agility):
        return INCONCLUSIVE, "pq_probe_error"
    return INCONCLUSIVE, "undetermined"


def hrr_needed_for_pq(a, b):
    # pq was only reached through a retry: probe a got a hybrid via hrr and the
    # browser-like probe didn't get a pq group in its first server hello
    a_hybrid = _picked(a) and a["hrr"] and is_standard_hybrid(a["group"])
    b_direct = _picked(b) and is_pq(b["group"]) and not b["hrr"]
    return bool(a_hybrid and not b_direct)


def score_for(verdict, sig):
    # a dashboard convenience with chosen weights. study tables never use it.
    if verdict in (INCONCLUSIVE, TLS12_ONLY):
        return None
    cipher = sig.get("cipher") or ""
    aead = cipher.startswith("TLS_") or "GCM" in cipher or "CHACHA20" in cipher
    bonus = (2 if aead else 0) + _key_bonus(sig.get("cert") or {})
    bonus -= 4 if sig.get("tls1_2") else 0          # old protocol still on
    supported = sig.get("supported") or []
    hybrids = sum(1 for g in supported if g.get("kind") == "standard hybrid")
    x25519mlkem = sig.get("default_group") == "X25519MLKEM768"

    if verdict == STRICT:
        return _clamp(90 + (4 if x25519mlkem else 0) + (2 if hybrids >= 2 else 0) + bonus, 86, 98)
    if verdict == ENFORCED:
        return _clamp(82 + (4 if x25519mlkem else 0) + (2 if hybrids >= 2 else 0) + bonus, 78, 94)
    if verdict == PARTIAL:
        mlkem_ok = any(g.get("name") == "X25519MLKEM768" for g in supported)
        return _clamp(52 + (4 if mlkem_ok else 0) + bonus, 42, 70)
    if verdict == LEGACY_HYBRID:
        return _clamp(36 + bonus, 28, 46)
    return _clamp(24 + bonus, 8, 36)


def _key_bonus(cert):
    kt, kb = cert.get("key_type") or "", cert.get("key_bits") or 0
    if kt.startswith("EC"):
        return 2
    if kt == "RSA":
        return 2 if kb >= 3072 else (0 if kb >= 2048 else -6)
    return 0


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))
