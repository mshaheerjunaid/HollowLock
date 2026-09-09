from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import baseline, cbom, crypto
from .groups import PQ_GROUPS, name_of, is_pq
from .report import decide, score_for
from .security import clean_domain, resolve_public_ip, AGILITY_GROUPS, PROBE_TIMEOUT
from .tls import probe

PQ = list(PQ_GROUPS.keys())
CLASSICAL = [0x001D, 0x0017]     # x25519, secp256r1


def scan(domain, timeout=PROBE_TIMEOUT):
    host = clean_domain(domain)
    ip, ips = resolve_public_ip(host)      # ssrf-checked, pinned

    # everything is a separate connection, so run them together
    with ThreadPoolExecutor(max_workers=8) as pool:
        fa = pool.submit(probe, host, ip, PQ, False, timeout)              # pq only
        fb = pool.submit(probe, host, ip, PQ + CLASSICAL, True, timeout)   # default pick
        fc = pool.submit(probe, host, ip, CLASSICAL, False, timeout)       # classical
        fbase = pool.submit(baseline.gather, host, ip, timeout)
        fg = {g: pool.submit(probe, host, ip, [g], False, timeout) for g in AGILITY_GROUPS}
        a, b, c = fa.result(), fb.result(), fc.result()
        base = fbase.result()
        supported = [g for g, f in fg.items() if f.result()[0] == "group"]

    supports_pq = _pq(a) or _pq(b) or any(is_pq(g) for g in supported)
    pq_group = (name_of(a[1]) if _pq(a) else name_of(b[1]) if _pq(b)
                else next((name_of(g) for g in supported if is_pq(g)), None))
    default_group = name_of(b[1]) if b[0] == "group" else "unknown"
    default_is_pq = _pq(b)
    verdict = decide(supports_pq, default_is_pq)
    tls13 = bool(base.get("tls1_3"))
    sup = [{"name": name_of(g), "pq": is_pq(g)} for g in supported]
    cert = base.get("cert")

    rep = {
        "domain": host, "ip": ip, "ips": ips,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verdict": verdict,
        "score": score_for(verdict, {"tls1_2": base.get("tls1_2"), "tls1_3": tls13,
                                     "cipher": base.get("cipher"),
                                     "default_group": default_group,
                                     "supported": sup, "cert": cert}),
        "key_exchange": {"supports_pq": supports_pq, "pq_group": pq_group,
                         "default_group": default_group, "default_is_pq": default_is_pq,
                         "supported": sup},
        "protocol": {"negotiated": base.get("tls_version"), "cipher": base.get("cipher"),
                     "tls1_3": tls13, "tls1_2": bool(base.get("tls1_2")),
                     "alpn": base.get("alpn"), "http3": bool(base.get("http3")),
                     "hsts": base.get("hsts")},
        "certificate": cert,
        "server": {"banner": base.get("server"), "latency_ms": base.get("latency_ms")},
        "probes": _matrix(a, b, c),
        "findings": _findings(verdict, supports_pq, pq_group, default_is_pq, base),
        "migration": {"stage": verdict, "note": ""},
    }
    rep["cbom"] = cbom.build(rep)
    rep["migration"]["note"] = rep["cbom"]["summary"]
    rep["signature"] = crypto.sign_report(rep)   # ml-dsa over the whole report
    return rep


def _pq(r):
    return r[0] == "group" and is_pq(r[1])


def _text(r):
    if r[0] == "group":
        return f"server chose {name_of(r[1])}" + (" (via retry)" if r[2] else "")
    if r[0] == "alert":
        return f"{r[1]} (no shared group)"
    if r[0] == "error":
        return f"connection error: {r[1]}"
    return "connection closed"


def _matrix(a, b, c):
    return [
        {"off": "Post-Quantum Only", "res": _text(a), "s": "good" if _pq(a) else "bad"},
        {"off": "Post-Quantum + Classical", "res": _text(b), "s": "good" if _pq(b) else "bad"},
        {"off": "Classical Only", "res": _text(c), "s": "neutral"},
    ]


def _findings(verdict, supports_pq, pq_group, default_is_pq, base):
    f = []
    if supports_pq:
        f.append({"k": "Post-Quantum Key Exchange", "v": f"Available ({pq_group})",
                  "n": "The server will negotiate a hybrid post-quantum group.",
                  "s": "good" if default_is_pq else "warn"})
    else:
        f.append({"k": "Post-Quantum Key Exchange", "v": "Not offered",
                  "n": "The server rejects every post-quantum group.", "s": "bad"})

    dp = {"enforced": ("Post-quantum by default", "A normal client gets the hybrid group.", "good"),
          "partial": ("Classical by default", "It can do post-quantum but reaches for classical first.", "bad"),
          "hollow": ("Classical only", "Every session uses quantum-vulnerable key exchange.", "bad")}[verdict]
    f.append({"k": "Default Protection", "v": dp[0], "n": dp[1], "s": dp[2]})

    cert = base.get("cert") or {}
    f.append({"k": "Certificate Signature", "v": cert.get("sig_alg", "unknown"),
              "n": "Classical. Public CAs don't issue post-quantum certificates yet.",
              "s": "good" if cert.get("is_pq") else "neutral"})
    return f
