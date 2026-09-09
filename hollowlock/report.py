# verdict, score and the migration story. kept apart from the network code so
# the meaning of a result is easy to read and change in one place.

HEADLINE = {
    "enforced": "The post-quantum lock holds.",
    "partial": "Post-quantum is present but not doing the work.",
    "hollow": "The quantum-safe label is empty.",
}


def decide(supports_pq, default_is_pq):
    if not supports_pq:
        return "hollow"
    return "enforced" if default_is_pq else "partial"


def score_for(verdict, sig):
    # score inside the verdict band from what we actually measured
    cipher = sig.get("cipher") or ""
    strong_cipher = ("AES_256" in cipher) or ("CHACHA20" in cipher)
    tls12_pen = -4 if sig.get("tls1_2") else 0          # old protocol still on
    tls13 = bool(sig.get("tls1_3"))
    default_group = sig.get("default_group") or ""
    supported = sig.get("supported") or []
    pq_count = sum(1 for g in supported if g.get("pq"))
    key_bonus = _key_bonus(sig.get("cert") or {})

    if verdict == "enforced":
        s = 84
        s += 5 if default_group == "X25519MLKEM768" else 0   # standard, not a draft
        s += 2 if pq_count >= 2 else 0                        # more than one pq option
        s += 2 if strong_cipher else 0
        return _clamp(s + key_bonus + tls12_pen, 80, 98)

    if verdict == "partial":
        s = 52
        s += 4 if any(g["name"] == "X25519MLKEM768" for g in supported) else 0
        s += 2 if strong_cipher else 0
        return _clamp(s + key_bonus + tls12_pen, 42, 70)

    # hollow
    s = 26 + (2 if strong_cipher else 0) + (0 if tls13 else -6)
    return _clamp(s + key_bonus + tls12_pen, 8, 38)


def migration_note(verdict):
    if verdict == "enforced":
        return ("Migrated at the edge. Sessions to this host resist "
                "harvest-now-decrypt-later capture today.")
    if verdict == "partial":
        return ("Half migrated. The capability is deployed but not preferred, "
                "so ordinary clients still get classical key exchange. The fix "
                "is server-side group ordering, not new software.")
    return ("Not started at this edge. Every session is quantum-vulnerable, "
            "and anything recorded now can be decrypted once a quantum "
            "computer exists.")


def _key_bonus(cert):
    kt, kb = cert.get("key_type", ""), cert.get("key_bits") or 0
    if kt.startswith("EC"):
        return 2
    if kt == "RSA":
        return 2 if kb >= 3072 else (0 if kb >= 2048 else -6)
    return 0


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))
