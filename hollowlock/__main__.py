import argparse
import json
import sys
import threading
import webbrowser
from pathlib import Path

from . import crypto
from .provenance import TOOL_VERSION


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "key":
        return key_cmd(argv[1:])
    if argv and argv[0] == "verify":
        return verify_cmd(argv[1:])
    return dashboard(argv)


def dashboard(argv):
    p = argparse.ArgumentParser(prog="hollowlock",
                                description="Post-quantum TLS posture scanner (local dashboard). "
                                            "Subcommands: key, verify.")
    p.add_argument("--port", type=int, default=8721)
    p.add_argument("--no-browser", action="store_true", help="don't open a browser")
    p.add_argument("--version", action="version", version=f"hollowlock {TOOL_VERSION}")
    args = p.parse_args(argv)

    from .server import make_server          # keep key/verify free of the server import
    try:
        httpd = make_server(args.port)
    except OSError as e:
        print(f"could not start on port {args.port}: {e}", file=sys.stderr)
        return 2
    crypto.load_or_create()                  # make sure the signing key exists before the first scan

    url = f"http://127.0.0.1:{args.port}/"
    print(f"HollowLock {TOOL_VERSION} is running at {url}")
    print(f"signing key fingerprint {crypto.fingerprint(crypto.public_key())}")
    print("nothing leaves your machine except the scans you ask for. ctrl-c to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye.")
        httpd.shutdown()
    return 0


def key_cmd(argv):
    p = argparse.ArgumentParser(prog="hollowlock key",
                                description="Create or show the ML-DSA-65 signing key and export its public half.")
    p.add_argument("--export", metavar="PATH", help="write the public key (hex) to this file")
    p.add_argument("--new", action="store_true", help="rotate to a fresh keypair")
    p.add_argument("--yes", action="store_true", help="confirm --new without the prompt")
    args = p.parse_args(argv)

    if args.new:
        if not args.yes:
            ans = input("Rotating replaces the signing key. Old reports stay checkable only with the old "
                        "public key, which is kept beside the new one. Type ROTATE to continue: ")
            if ans.strip() != "ROTATE":
                print("not rotated.")
                return 1
        crypto.rotate()
        print("rotated.")
    pk = crypto.public_key()
    print(f"algorithm    {crypto.ALG}")
    print(f"key folder   {crypto.key_dir()}")
    print(f"fingerprint  {crypto.fingerprint(pk)}")
    if args.export:
        crypto.export_public_key(args.export)
        print(f"public key   written to {args.export}")
    return 0


def verify_cmd(argv):
    p = argparse.ArgumentParser(prog="hollowlock verify",
                                description="Verify a signed report (.json) or every line of a .jsonl file "
                                            "against a trusted public key.")
    p.add_argument("file")
    p.add_argument("--pubkey", required=True, help="trusted public key file from 'hollowlock key --export'")
    args = p.parse_args(argv)

    try:
        pk = crypto.load_public_key_file(args.pubkey)
    except (OSError, ValueError) as e:
        print(f"cannot read public key: {e}", file=sys.stderr)
        return 2
    print(f"trusted key {crypto.fingerprint(pk)}")

    path = Path(args.file)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        return 2

    if path.suffix.lower() == ".jsonl":
        items = [(n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    else:
        items = [(1, text)]

    failed = 0
    for n, raw in items:
        ok, why = verify_record(raw, pk)
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {path.name}:{n}  {why}")
    print(f"{len(items) - failed} passed, {failed} failed")
    return 1 if failed or not items else 0


def verify_record(raw, pk):
    # a batch line is signed itself and may carry a signed report inside, both must hold
    try:
        obj = json.loads(raw)
    except ValueError as e:
        return False, f"not json ({e})"
    ok, why = crypto.check(obj, pk)
    if not ok:
        return False, why
    inner = obj.get("report")
    if isinstance(inner, dict) and "signature" in inner:
        ok, why = crypto.check(inner, pk)
        if not ok:
            return False, "embedded report: " + why
    return True, "ok"


if __name__ == "__main__":
    raise SystemExit(main())
