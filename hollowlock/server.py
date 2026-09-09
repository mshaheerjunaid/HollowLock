import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import engine, pdf_report
from .security import (BlockedTarget, InvalidDomain, MAX_BODY, MAX_REPORT,
                       RATE_MIN_INTERVAL, new_token)

WEB = Path(__file__).parent / "web"
TOKEN = new_token()      # ui echoes this back so nothing else can drive us

HEADERS = {
    "Content-Security-Policy":
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), usb=()",
    "Cache-Control": "no-store",
}

TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8", ".woff2": "font/woff2",
         ".jpg": "image/jpeg", ".png": "image/png"}


class _Gate:
    # rate limit + single flight, so nothing hammers the network
    def __init__(self):
        self._lock = threading.Lock()
        self._last = 0.0

    def allow(self):
        with self._lock:
            now = time.monotonic()
            if now - self._last < RATE_MIN_INTERVAL:
                return False
            self._last = now
            return True


_gate = _Gate()


class Handler(BaseHTTPRequestHandler):
    server_version = "HollowLock"
    sys_version = ""     # don't leak the python version

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _local_only(self):
        host = self.headers.get("Host", "")
        if not (host.startswith("127.0.0.1:") or host.startswith("localhost:")):
            return False
        origin = self.headers.get("Origin")
        if origin and not (origin.startswith("http://127.0.0.1:")
                           or origin.startswith("http://localhost:")):
            return False
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            html = (WEB / "index.html").read_text(encoding="utf-8").replace("__HL_TOKEN__", TOKEN)
            return self._send(200, html.encode(), TYPES[".html"])
        if path == "/favicon.ico":
            return self._send(204, b"", "text/plain")
        return self._static(path)

    def _static(self, path):
        name = path.lstrip("/")
        # flat files only, no traversal
        if "/" in name or ".." in name or Path(name).suffix not in TYPES:
            return self._send(404, b"not found", "text/plain")
        f = WEB / name
        if not f.is_file():
            return self._send(404, b"not found", "text/plain")
        self._send(200, f.read_bytes(), TYPES[Path(name).suffix])

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/api/scan", "/api/report.pdf"):
            return self._send(404, b'{"error":"not found"}')
        if not self._local_only():
            return self._send(403, b'{"error":"forbidden origin"}')
        if self.headers.get("X-HollowLock-Token") != TOKEN:
            return self._send(403, b'{"error":"bad token"}')
        if path == "/api/report.pdf":
            return self._pdf()
        if not _gate.allow():
            return self._send(429, b'{"error":"slow down"}')

        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(400, b'{"error":"bad request"}')
        try:
            domain = str(json.loads(self.rfile.read(n)).get("domain", ""))
        except Exception:
            return self._send(400, b'{"error":"bad json"}')

        try:
            rep = engine.scan(domain)
        except InvalidDomain as e:
            return self._send(400, json.dumps({"error": "Invalid Domain"}).encode())
        except BlockedTarget as e:
            return self._send(400, json.dumps({"error": f"blocked: {e}"}).encode())
        except Exception as e:
            return self._send(500, json.dumps({"error": f"scan failed: {e}"}).encode())
        self._send(200, json.dumps(rep).encode())


    def _pdf(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0 or n > MAX_REPORT:
            return self._send(400, b'{"error":"bad request"}')
        try:
            report = json.loads(self.rfile.read(n))
            pdf = pdf_report.build(report, str(WEB / "logo-dark.png"))
        except Exception as e:
            return self._send(500, json.dumps({"error": f"pdf failed: {e}"}).encode())
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", "attachment; filename=hollowlock.pdf")
        self.send_header("Content-Length", str(len(pdf)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(pdf)


def make_server(port=8721):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)   # loopback only
