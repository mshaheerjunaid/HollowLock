# build a cryptographic bill of materials from a scan. every line comes from
# what we actually saw on the wire, so it's specific to this host.

def build(rep):
    kx = rep["key_exchange"]
    proto = rep["protocol"]
    cert = rep.get("certificate") or {}
    comps = []

    comps.append(_c("Key exchange", kx["default_group"], "key-agreement",
                    kx["default_is_pq"],
                    None if kx["default_is_pq"]
                    else "Enable and prefer a hybrid group such as X25519MLKEM768"))

    if cert:
        comps.append(_c("Certificate signature", cert.get("sig_alg"), "signature",
                        cert.get("is_pq", False),
                        None if cert.get("is_pq")
                        else "No public CA issues post-quantum certificates yet, so this one waits on the ML-DSA rollout"))
        comps.append(_c("Certificate key", _keyname(cert), "public-key", False,
                        "Classical, and it migrates once post-quantum certificates ship"))

    comps.append(_c("Protocol", proto.get("negotiated"), "protocol",
                    proto.get("tls1_3", False),
                    "Turn off TLS 1.2" if proto.get("tls1_2") else None))

    cipher = proto.get("cipher") or ""
    strong = "AES_256" in cipher or "CHACHA20" in cipher
    comps.append(_c("Symmetric cipher", cipher, "cipher", strong,
                    None if strong
                    else "Prefer AES-256-GCM or ChaCha20, since Grover halves the effective key length"))

    todo = [c for c in comps if not c["quantum_safe"] and c["action"]]
    return {"target": rep["domain"], "generated_at": rep["scanned_at"],
            "components": comps, "to_migrate": len(todo),
            "summary": _summary(todo)}


def _c(asset, algo, typ, safe, action):
    return {"asset": asset, "algorithm": algo or "unknown", "type": typ,
            "quantum_safe": bool(safe), "action": action}


def _keyname(cert):
    kt, kb = cert.get("key_type", ""), cert.get("key_bits")
    return f"{kt} {kb}-bit" if kb else (kt or "unknown")


def _summary(todo):
    if not todo:
        return "Nothing to change at the edge. Certificates move once CAs issue post-quantum signatures."
    n = len(todo)
    word = "thing" if n == 1 else "things"
    return f"{n} {word} to change, " + ", ".join(t["asset"].lower() for t in todo) + "."
