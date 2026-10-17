import json

from hollowlock import crypto
from hollowlock.__main__ import main


def test_key_and_verify(tmp_path, capsys):
    assert main(["key", "--export", str(tmp_path / "pub.txt")]) == 0
    assert crypto.fingerprint(crypto.public_key()) in capsys.readouterr().out

    good = {"domain": "example.com", "verdict": "HOLLOW"}
    good["signature"] = crypto.sign(good)
    (tmp_path / "r.json").write_text(json.dumps(good, indent=2))
    assert main(["verify", str(tmp_path / "r.json"), "--pubkey", str(tmp_path / "pub.txt")]) == 0

    bad = dict(good, verdict="STRICT")
    line = {"row": {"host": "example.com"}, "report": bad}
    line["signature"] = crypto.sign(line)
    other = {"row": {"host": "example.org"}, "report": good}
    other["signature"] = crypto.sign(other)
    (tmp_path / "r.jsonl").write_text(json.dumps(other) + "\n" + json.dumps(line) + "\n")
    assert main(["verify", str(tmp_path / "r.jsonl"), "--pubkey", str(tmp_path / "pub.txt")]) == 1
    out = capsys.readouterr().out
    assert "PASS  r.jsonl:1" in out and "FAIL  r.jsonl:2" in out and "embedded report" in out


def test_rotate_needs_confirmation(monkeypatch, capsys):
    pk = crypto.public_key()
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    assert main(["key", "--new"]) == 1
    assert crypto.public_key() == pk
    assert main(["key", "--new", "--yes"]) == 0
    assert crypto.public_key() != pk
