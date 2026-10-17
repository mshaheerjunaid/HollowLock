# build a cryptographic bill of materials from a scan. every line comes from
# what we actually saw on the wire, so it's specific to this host.
# status is one of safe, acceptable, finding, vulnerable, undetermined.
from .report import INCONCLUSIVE, LEGACY_HYBRID, PARTIAL, TLS12_ONLY

LABELS = {"safe": "Quantum-safe", "acceptable": "Acceptable", "finding": "Finding",
          "vulnerable": "Vulnerable", "undetermined": "Undetermined"}


def build(rep):
    kx, proto = rep["key_exchange"], rep["protocol"]
    cert = rep.get("certificate") or {}
    verdict = rep["verdict"]
    comps = [_key_exchange(verdict, kx)]

    if cert:
        comps.append(_c("Certificate signature", cert.get("sig_alg"),
                        "safe" if cert.get("is_pq") else "vulnerable",
                        None if cert.get("is_pq") else
                        "No public CA issues post-quantum certificates yet, so this one waits on the ML-DSA rollout"))
        comps.append(_c("Certificate key", _keyname(cert),
                        "safe" if cert.get("key_is_pq") else "vulnerable",
                        None if cert.get("key_is_pq") else
                        "Classical, and it migrates once post-quantum certificates ship"))

    neg = proto.get("negotiated")
    if neg == "TLSv1.3":
        comps.append(_c("Protocol", neg, "acceptable", None))
        if proto.get("tls1_2"):
            comps.append(_c("TLS 1.2 support", "TLSv1.2 still accepted", "finding",
                            "Plan to retire TLS 1.2 once legacy clients allow"))
    elif neg:
        comps.append(_c("Protocol", neg, "vulnerable", "Enable TLS 1.3, which hybrid key exchange needs"))
    else:
        comps.append(_c("Protocol", None, "undetermined", None))

    comps.append(_cipher(proto.get("cipher") or ""))

    todo = [c for c in comps if c["status"] == "vulnerable" and c["action"]]
    return {"target": rep["domain"], "generated_at": rep["scanned_at"],
            "components": comps, "to_migrate": len(todo),
            "summary": _summary(todo, verdict)}


def _key_exchange(verdict, kx):
    if verdict == INCONCLUSIVE:
        return _c("Key exchange", "undetermined", "undetermined", None)
    if verdict == TLS12_ONLY:
        return _c("Key exchange", "TLS 1.2 key exchange", "vulnerable",
                  "Move to TLS 1.3 and enable a hybrid group such as X25519MLKEM768")
    if kx["default_is_pq"]:
        return _c("Key exchange", kx["default_group"], "safe", None)
    action = {PARTIAL: "Put X25519MLKEM768 ahead of the classical groups in the server's preference order",
              LEGACY_HYBRID: "Replace the Kyber draft with X25519MLKEM768 and prefer it"}.get(
        verdict, "Enable and prefer a hybrid group such as X25519MLKEM768")
    return _c("Key exchange", kx["default_group"], "vulnerable", action)


def _cipher(cipher):
    if not cipher:
        return _c("Symmetric cipher", None, "undetermined", None)
    if "AES_256" in cipher or "AES256" in cipher or "CHACHA20" in cipher:
        return _c("Symmetric cipher", cipher, "safe", None)
    if "AES_128" in cipher or "AES128" in cipher:
        # grover isn't a practical threat to aes-128, nist still accepts it
        return _c("Symmetric cipher", cipher, "acceptable",
                  "AES-256 is preferred for long-lived secrets")
    return _c("Symmetric cipher", cipher, "vulnerable", "Move to AES-256-GCM or ChaCha20-Poly1305")


def _c(asset, algo, status, action):
    return {"asset": asset, "algorithm": algo or "unknown", "status": status,
            "label": LABELS[status], "quantum_safe": status == "safe", "action": action}


def _keyname(cert):
    kt, kb = cert.get("key_type") or "", cert.get("key_bits")
    return f"{kt} {kb}-bit" if kb else (kt or "unknown")


def _summary(todo, verdict):
    if verdict == INCONCLUSIVE:
        return "The key exchange could not be determined, so this bill of materials is incomplete."
    if not todo:
        return "Nothing to change at the edge. Certificates move once CAs issue post-quantum signatures."
    word = "thing" if len(todo) == 1 else "things"
    return f"{len(todo)} {word} to change, " + ", ".join(t["asset"].lower() for t in todo) + "."
