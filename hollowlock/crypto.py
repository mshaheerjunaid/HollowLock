# hollowlock's own crypto. it lives on loopback so there's no channel to
# encrypt, but we still sign every report so a saved one can't be edited
# without it showing. the signature is post-quantum, and the algorithm sits
# in one place so swapping it later is a single edit.
import json

from dilithium_py.ml_dsa import ML_DSA_65

ALG = "ML-DSA-65"          # FIPS 204
_pk, _sk = ML_DSA_65.keygen()   # fresh keypair per run


def _canonical(rep):
    body = {k: v for k, v in rep.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_report(rep):
    return {"algorithm": ALG, "public_key": _pk.hex(),
            "signature": ML_DSA_65.sign(_sk, _canonical(rep)).hex()}


def verify(rep):
    sig = rep.get("signature") or {}
    try:
        return ML_DSA_65.verify(bytes.fromhex(sig["public_key"]),
                                _canonical(rep), bytes.fromhex(sig["signature"]))
    except Exception:
        return False
