# hollowlock's own crypto: one long-term ML-DSA-65 key per machine that signs
# every report. verification always needs a trusted public key handed in from
# outside, never the copy embedded in the report. the algorithm lives in this
# file only, so swapping it is a single edit.
import hashlib
import json
import os
import threading
import time
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

ALG = "ML-DSA-65"            # FIPS 204
PRIV_NAME = "hollowlock_mldsa65.key"
PUB_NAME = "hollowlock_mldsa65.pub"
PK_LEN = 1952

_lock = threading.Lock()
_cache = None


def key_dir():
    # HOLLOWLOCK_KEY_DIR overrides, mainly for tests
    if os.environ.get("HOLLOWLOCK_KEY_DIR"):
        return Path(os.environ["HOLLOWLOCK_KEY_DIR"])
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "HollowLock"
    return Path.home() / ".config" / "hollowlock"


def fingerprint(pk):
    return hashlib.sha256(pk).hexdigest()


def canonical(obj):
    body = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def _write_private(path, data):
    # create-only, owner read/write. windows ignores the mode bits.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _create(d):
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    pk, sk = ML_DSA_65.keygen()
    _write_private(d / PRIV_NAME, sk)
    (d / PUB_NAME).write_text(pk.hex() + "\n", encoding="ascii")
    return pk, sk


def load_or_create():
    global _cache
    with _lock:
        if _cache is None:
            d = key_dir()
            priv, pub = d / PRIV_NAME, d / PUB_NAME
            if priv.is_file() and pub.is_file():
                _cache = (bytes.fromhex(pub.read_text(encoding="ascii").strip()), priv.read_bytes())
            else:
                _cache = _create(d)
        return _cache


def rotate():
    # keep the old public key under its fingerprint so old reports stay checkable,
    # the old private key is deleted
    global _cache
    with _lock:
        d = key_dir()
        pub = d / PUB_NAME
        if pub.is_file():
            old = bytes.fromhex(pub.read_text(encoding="ascii").strip())
            pub.replace(d / f"hollowlock_mldsa65.{fingerprint(old)[:16]}.{int(time.time())}.pub")
            (d / PRIV_NAME).unlink(missing_ok=True)
        _cache = _create(d)
        return _cache


def public_key():
    return load_or_create()[0]


def sign(obj):
    pk, sk = load_or_create()
    return {"algorithm": ALG, "public_key": pk.hex(), "fingerprint": fingerprint(pk),
            "signature": ML_DSA_65.sign(sk, canonical(obj)).hex()}


def check(obj, trusted_pk):
    """(ok, reason). the trusted key must be supplied, the embedded one is only
    compared against it, never used on its own."""
    if not trusted_pk or len(trusted_pk) != PK_LEN:
        return False, "no valid trusted public key supplied"
    sig = obj.get("signature") if isinstance(obj, dict) else None
    if not isinstance(sig, dict) or sig.get("algorithm") != ALG:
        return False, "not signed with " + ALG
    if sig.get("fingerprint") != fingerprint(trusted_pk):
        return False, "signer fingerprint does not match the trusted key"
    if sig.get("public_key") != trusted_pk.hex():
        return False, "embedded public key does not match the trusted key"
    try:
        ok = ML_DSA_65.verify(trusted_pk, canonical(obj), bytes.fromhex(sig["signature"]))
    except (KeyError, ValueError, TypeError):
        return False, "malformed signature"
    return (True, "ok") if ok else (False, "signature does not match the content")


def verify(obj, trusted_pk):
    return check(obj, trusted_pk)[0]


def load_public_key_file(path):
    # hex text (what we export) or the raw 1952 bytes
    data = Path(path).read_bytes()
    if len(data) == PK_LEN:
        return data
    return bytes.fromhex(data.decode("ascii").strip())


def export_public_key(path):
    pk = public_key()
    Path(path).write_text(pk.hex() + "\n", encoding="ascii")
    return pk
