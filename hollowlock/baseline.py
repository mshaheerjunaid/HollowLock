import socket
import ssl
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .security import PROBE_TIMEOUT

PQ_CERT_HINTS = ("ml-dsa", "dilithium", "slh-dsa", "sphincs", "falcon")


def gather(hostname, ip, timeout=PROBE_TIMEOUT):
    # one normal handshake for the stuff the pq probe skips
    out = {"tls_version": None, "cipher": None, "server": None, "alpn": None,
           "latency_ms": None, "hsts": None, "http3": False,
           "tls1_2": False, "tls1_3": False, "cert": None}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False           # inspecting, not trusting
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    try:
        t0 = time.perf_counter()
        raw = socket.create_connection((ip, 443), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=hostname) as s:
            out["latency_ms"] = int((time.perf_counter() - t0) * 1000)
            out["tls_version"] = s.version()
            out["tls1_3"] = s.version() == "TLSv1.3"
            c = s.cipher()
            out["cipher"] = c[0] if c else None
            out["alpn"] = s.selected_alpn_protocol()
            der = s.getpeercert(binary_form=True)
            if der:
                out["cert"] = _read_cert(der)
            _http_head(s, hostname, out)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"

    out["tls1_2"] = _supports_12(hostname, ip, timeout)
    return out


def _read_cert(der):
    cert = x509.load_der_x509_certificate(der)
    sig = (cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        ktype, kbits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        ktype, kbits = f"EC {key.curve.name}", key.curve.key_size
    else:
        ktype, kbits = type(key).__name__, None
    try:
        sans = len(cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value)
    except Exception:
        sans = 0
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days
    return {"sig_alg": sig, "is_pq": any(h in sig.lower() for h in PQ_CERT_HINTS),
            "key_type": ktype, "key_bits": kbits,
            "issuer": _name(cert.issuer), "subject": _name(cert.subject),
            "not_before": cert.not_valid_before_utc.date().isoformat(),
            "not_after": not_after.date().isoformat(),
            "days_left": days_left, "san_count": sans}


def _name(n):
    for oid in (x509.NameOID.ORGANIZATION_NAME, x509.NameOID.COMMON_NAME):
        vals = n.get_attributes_for_oid(oid)
        if vals:
            return vals[0].value
    return None


def _http_head(s, hostname, out):
    # HEAD once, pull banner / hsts / h3
    try:
        s.sendall((f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\n"
                   f"User-Agent: HollowLock\r\nConnection: close\r\n\r\n").encode())
        data = s.recv(4096).decode("latin-1", "ignore")
        for line in data.split("\r\n"):
            low = line.lower()
            if low.startswith("server:"):
                out["server"] = line.split(":", 1)[1].strip()[:80]
            elif low.startswith("strict-transport-security:"):
                out["hsts"] = line.split(":", 1)[1].strip()[:80]
            elif low.startswith("alt-svc:") and "h3" in low:
                out["http3"] = True
    except Exception:
        pass


def _supports_12(hostname, ip, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        return False
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=hostname) as s:
            return s.version() == "TLSv1.2"
    except Exception:
        return False
