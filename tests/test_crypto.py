import json
import os

import pytest

from hollowlock import crypto


def test_sign_and_verify_roundtrip():
    rep = {"domain": "example.com", "verdict": "ENFORCED", "probe_gap": 1.0}
    rep["signature"] = crypto.sign(rep)
    pk = crypto.public_key()
    assert crypto.verify(rep, pk)
    # a json round trip (what a saved file goes through) still verifies
    assert crypto.verify(json.loads(json.dumps(rep, indent=2)), pk)
    assert rep["signature"]["fingerprint"] == crypto.fingerprint(pk)


def test_edited_report_fails():
    rep = {"domain": "example.com", "verdict": "HOLLOW"}
    rep["signature"] = crypto.sign(rep)
    rep["verdict"] = "STRICT"
    ok, why = crypto.check(rep, crypto.public_key())
    assert not ok and "content" in why


def test_other_key_fails(tmp_path, monkeypatch):
    rep = {"domain": "example.com"}
    rep["signature"] = crypto.sign(rep)
    mine = crypto.public_key()
    # someone else signs an edited copy with their own key and embeds it
    monkeypatch.setenv("HOLLOWLOCK_KEY_DIR", str(tmp_path / "attacker"))
    monkeypatch.setattr(crypto, "_cache", None)
    forged = {"domain": "example.com", "verdict": "STRICT"}
    forged["signature"] = crypto.sign(forged)
    theirs = crypto.public_key()
    assert crypto.verify(forged, theirs)            # valid under the attacker's own key
    assert not crypto.verify(forged, mine)          # but not under the trusted one
    assert not crypto.verify(rep, theirs)


def test_no_trusted_key_means_no_pass():
    rep = {"a": 1}
    rep["signature"] = crypto.sign(rep)
    assert not crypto.verify(rep, b"")
    assert not crypto.verify(rep, None)


def test_key_persists_and_rotates(key_dir):
    pk1 = crypto.public_key()
    crypto._cache = None
    assert crypto.public_key() == pk1                # loaded from disk, not regenerated
    if os.name != "nt":
        assert (key_dir / crypto.PRIV_NAME).stat().st_mode & 0o777 == 0o600
    crypto.rotate()
    pk2 = crypto.public_key()
    assert pk2 != pk1
    kept = [p.name for p in key_dir.glob("hollowlock_mldsa65.*.pub")]
    assert any(crypto.fingerprint(pk1)[:16] in n for n in kept)


def test_public_key_file_formats(tmp_path):
    pk = crypto.export_public_key(tmp_path / "pub.txt")
    assert crypto.load_public_key_file(tmp_path / "pub.txt") == pk
    (tmp_path / "pub.bin").write_bytes(pk)
    assert crypto.load_public_key_file(tmp_path / "pub.bin") == pk
    with pytest.raises(ValueError):
        (tmp_path / "bad.txt").write_text("zz")
        crypto.load_public_key_file(tmp_path / "bad.txt")
