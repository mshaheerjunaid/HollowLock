import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import baseline, cbom, crypto, provenance
from .groups import is_pq, kind_of, name_of
from .report import (EXPLAIN, INCONCLUSIVE, LABEL, REASONS, decide,
                     hrr_needed_for_pq, score_for)
from .security import (AGILITY_GROUPS, PROBE_TIMEOUT, DnsError, clean_domain,
                       resolve_public_ip)
from .tls import probe

# the four fixed probes. only a, b and c (plus agility) feed the verdict.
PROBES = {
    "A": {"label": "Post-quantum only",
          "groups": [0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202, 0x6399, 0x639A],
          "shares": (), "alpn": None, "tls12": False},
    "B": {"label": "Browser-like",
          "groups": [0x11EC, 0x001D, 0x0017, 0x0018],
          "shares": (0x11EC, 0x001D), "alpn": ["h2", "http/1.1"], "tls12": True},
    "C": {"label": "Classical only",
          "groups": [0x001D, 0x0017, 0x0018],
          "shares": (), "alpn": None, "tls12": False},
    # v1's default probe, kept to show how older or embedded clients are treated
    "D": {"label": "Classical-share client",
          "groups": [0x11EC, 0x11EB, 0x11ED, 0x6399, 0x639A, 0x001D, 0x0017],
          "shares": (0x001D,), "alpn": None, "tls12": False},
}
FAST_WORKERS = 4


def scan(domain, *, mode="fast", probe_gap=1.0, retries=1, timeout=PROBE_TIMEOUT, vantage=None):
    """Public entry point. Validates the name and runs the ssrf guard, so it
    refuses loopback and private addresses. InvalidDomain and BlockedTarget
    propagate; a name that doesn't resolve comes back as a signed
    INCONCLUSIVE report."""
    if mode not in ("fast", "paced"):
        raise ValueError("mode must be fast or paced")
    host = clean_domain(domain)
    opts = {"mode": mode, "probe_gap": probe_gap, "retries": retries,
            "timeout": timeout, "vantage": vantage}
    try:
        ip, family, ips = resolve_public_ip(host)
    except DnsError as e:
        return _dns_report(host, str(e), opts)
    return _scan_at(host, ip, family, ips, port=443, **opts)


def _scan_at(host, ip, family, ips, *, port, mode, probe_gap, retries, timeout, vantage):
    # takes an already chosen address and skips the ssrf guard. only scan() and
    # the validation harness call this, the cli and dashboard never do.
    def run_probe(spec):
        attempt, rec = 0, None
        while True:
            attempt += 1
            t0 = time.perf_counter()
            rec = probe(host, ip, spec["groups"], spec["shares"], spec["alpn"],
                        spec["tls12"], timeout=timeout, port=port)
            rec["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
            # retry only real failures, a refusal is an answer
            if rec["outcome"] != "error" or attempt > retries:
                break
            time.sleep(min(4.0, 1.0 * attempt))
        rec["attempts"] = attempt
        return rec

    tasks = [(pid, lambda s=spec: run_probe(s)) for pid, spec in PROBES.items()]
    for g in AGILITY_GROUPS:
        spec = {"groups": [g], "shares": (), "alpn": None, "tls12": False}
        tasks.append((g, lambda s=spec: run_probe(s)))
    tasks.append(("baseline", lambda: baseline.gather(host, ip, timeout, port)))
    tasks.append(("tls12", lambda: baseline.supports_12(host, ip, timeout, port)))

    results = {}
    if mode == "fast":
        with ThreadPoolExecutor(max_workers=FAST_WORKERS) as pool:
            futs = [(k, pool.submit(fn)) for k, fn in tasks]
            results = {k: f.result() for k, f in futs}
    else:
        for n, (k, fn) in enumerate(tasks):
            if n:
                time.sleep(probe_gap)      # one connection at a time, spaced out
            results[k] = fn()

    a, b, c, d = (results[k] for k in "ABCD")
    agility = {g: results[g] for g in AGILITY_GROUPS}
    base = results["baseline"]
    base["tls1_2"] = results["tls12"]
    return _assemble(host, ip, family, ips, a, b, c, d, agility, base,
                     dict(mode=mode, probe_gap=probe_gap, retries=retries,
                          timeout=timeout, vantage=vantage))


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _assemble(host, ip, family, ips, a, b, c, d, agility, base, opts):
    verdict, reason = decide(a, b, c, agility, base.get("tls_version"))
    reach = [a, b] + list(agility.values())
    pq_hits = [r["group"] for r in reach if r["outcome"] == "group" and is_pq(r["group"])]
    supported = [{"name": name_of(g), "code": f"0x{g:04x}", "pq": is_pq(g), "kind": kind_of(g)}
                 for g, r in agility.items() if r["outcome"] == "group"]
    b_group = name_of(b["group"]) if b["outcome"] == "group" else (
        "TLS 1.2" if b["outcome"] == "tls12" else "undetermined")
    cert = base.get("cert")

    rep = {
        "domain": host, "ip": ip, "family": family, "ips": ips,
        "scanned_at": _now(),
        "verdict": verdict, "verdict_label": LABEL[verdict],
        "verdict_reason": reason, "reason_text": REASONS.get(reason),
        "explanation": EXPLAIN[verdict],
        "hrr_needed_for_pq": hrr_needed_for_pq(a, b),
        "key_exchange": {
            "supports_pq": bool(pq_hits),
            "pq_group": name_of(pq_hits[0]) if pq_hits else None,
            "default_group": b_group,
            "default_is_pq": b["outcome"] == "group" and is_pq(b["group"]),
            "supported": supported,
            "agility": [{"name": name_of(g), "code": f"0x{g:04x}", "kind": kind_of(g),
                         "outcome": r["outcome"], "hrr": r["hrr"], "alert": r["alert"],
                         "error_class": r["error_class"], "attempts": r["attempts"],
                         "elapsed_ms": r["elapsed_ms"]} for g, r in agility.items()],
        },
        "protocol": {"negotiated": base.get("tls_version"), "cipher": base.get("cipher"),
                     "tls1_3": bool(base.get("tls1_3")), "tls1_2": base.get("tls1_2"),
                     "alpn": base.get("alpn"), "http3": bool(base.get("http3")),
                     "hsts": base.get("hsts"), "default_probe_version": b.get("version")},
        "certificate": cert,
        "server": {"banner": base.get("server"), "latency_ms": base.get("latency_ms"),
                   "baseline_error": base.get("error")},
        "probes": [_probe_row(pid, r) for pid, r in zip("ABCD", (a, b, c, d))],
    }
    rep["score"] = score_for(verdict, {"tls1_2": base.get("tls1_2"), "cipher": base.get("cipher"),
                                       "default_group": b_group, "supported": supported,
                                       "cert": cert})
    rep["cbom"] = cbom.build(rep)
    rep["migration"] = {"stage": verdict, "note": rep["cbom"]["summary"]}
    rep["provenance"] = provenance.collect(ip=ip, family=family, **opts)
    rep["signature"] = crypto.sign(rep)          # ml-dsa over everything above
    return rep


def _probe_row(pid, r):
    spec = PROBES[pid]
    if r["outcome"] == "group":
        res = f"server chose {r['group_name']}" + (" (via HelloRetryRequest)" if r["hrr"] else "")
        state = "good" if is_pq(r["group"]) else "bad"
    elif r["outcome"] == "tls12":
        res, state = f"server answered with {r['version']}", "bad"
    elif r["outcome"] == "refused":
        res, state = (f"refused, {r['alert']}" if r["alert"] else "refused, connection closed"), "neutral"
    else:
        res, state = f"error, {r['error_class']} ({r['error']})", "warn"
    if pid in "CD" and r["outcome"] == "group" and not is_pq(r["group"]):
        state = "neutral"         # c and d show treatment of older clients, not a fault
    return {"id": pid, "label": spec["label"], "off": spec["label"],
            "groups": [name_of(g) for g in spec["groups"]],
            "shares": [name_of(g) for g in spec["shares"]],
            "outcome": r["outcome"], "group": r["group_name"], "hrr": r["hrr"],
            "version": r["version"], "alert": r["alert"], "error": r["error"],
            "error_class": r["error_class"], "attempts": r["attempts"],
            "elapsed_ms": r["elapsed_ms"], "used_for_verdict": pid != "D",
            "res": res, "s": state}


def _dns_report(host, err, opts):
    rep = {
        "domain": host, "ip": None, "family": None, "ips": [], "scanned_at": _now(),
        "verdict": INCONCLUSIVE, "verdict_label": LABEL[INCONCLUSIVE],
        "verdict_reason": "dns_error", "reason_text": REASONS["dns_error"] + f" ({err})",
        "explanation": EXPLAIN[INCONCLUSIVE], "hrr_needed_for_pq": False,
        "key_exchange": {"supports_pq": False, "pq_group": None, "default_group": "undetermined",
                         "default_is_pq": False, "supported": [], "agility": []},
        "protocol": {"negotiated": None, "cipher": None, "tls1_3": False, "tls1_2": False,
                     "alpn": None, "http3": False, "hsts": None, "default_probe_version": None},
        "certificate": None,
        "server": {"banner": None, "latency_ms": None, "baseline_error": None},
        "probes": [], "score": None,
    }
    rep["cbom"] = cbom.build(rep)
    rep["migration"] = {"stage": INCONCLUSIVE, "note": rep["cbom"]["summary"]}
    rep["provenance"] = provenance.collect(**opts)
    rep["signature"] = crypto.sign(rep)
    return rep
