import argparse
import sys
import threading
import webbrowser

from .server import make_server


def main(argv=None):
    p = argparse.ArgumentParser(prog="hollowlock",
                                description="Post-quantum posture scanner (local app).")
    p.add_argument("--port", type=int, default=8721)
    p.add_argument("--no-browser", action="store_true", help="don't open a browser")
    args = p.parse_args(argv)

    try:
        httpd = make_server(args.port)
    except OSError as e:
        print(f"could not start on port {args.port}: {e}", file=sys.stderr)
        return 2

    url = f"http://127.0.0.1:{args.port}/"
    print(f"HollowLock is running at {url}")
    print("nothing leaves your machine except the scans you ask for. ctrl-c to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye.")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
