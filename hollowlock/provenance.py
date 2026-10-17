# where a report came from: tool version, source commit, environment, settings
import platform
import re
import ssl
from importlib import metadata
from pathlib import Path

TOOL_VERSION = "2.0.0"
ROOT = Path(__file__).resolve().parent.parent
_HEX40 = re.compile(r"\b[0-9a-f]{40}\b")


def git_commit(root=ROOT):
    # live git hash first (read from .git, no subprocess), then SOURCE_COMMIT.txt, then "release"
    try:
        git = root / ".git"
        if git.is_file():                      # worktree pointer
            git = (root / git.read_text().split(":", 1)[1].strip()).resolve()
        head = (git / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head if _HEX40.fullmatch(head) else "release"
        ref = head.split(":", 1)[1].strip()
        loose = git / ref
        if loose.is_file():
            return loose.read_text().strip()
        for line in (git / "packed-refs").read_text().splitlines():
            if line.endswith(" " + ref):
                return line.split()[0]
    except (OSError, IndexError):
        pass
    try:
        m = _HEX40.search((root / "SOURCE_COMMIT.txt").read_text())
        if m:
            return m.group(0)
    except OSError:
        pass
    return "release"


def _ver(dist):
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return None


def collect(mode, vantage, probe_gap, timeout, retries, ip=None, family=None):
    return {
        "tool_version": TOOL_VERSION,
        "git_commit": git_commit(),
        "python": platform.python_version(),
        "os": platform.system(),
        "platform": platform.platform(),
        "openssl": ssl.OPENSSL_VERSION,
        "kyber_py": _ver("kyber-py"),
        "dilithium_py": _ver("dilithium-py"),
        "cryptography": _ver("cryptography"),
        "mode": mode, "vantage": vantage, "probe_gap": probe_gap,
        "timeout": timeout, "retries": retries,
        "ip": ip, "family": family,
    }
