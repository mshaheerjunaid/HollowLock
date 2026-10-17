import pytest

from hollowlock import crypto


@pytest.fixture(autouse=True)
def key_dir(tmp_path, monkeypatch):
    # every test gets its own throwaway signing key
    monkeypatch.setenv("HOLLOWLOCK_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(crypto, "_cache", None)
    yield tmp_path / "keys"
    crypto._cache = None
