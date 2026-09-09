import ipaddress
import secrets
import socket
from urllib.parse import urlsplit

# resource caps. these bound what a hostile server can make us do.
PROBE_TIMEOUT = 6           # seconds per connection
MAX_TLS_RECORD = 16384      # a tls record can't legally exceed this
MAX_BODY = 1024             # request body from the ui is tiny (a domain)
MAX_REPORT = 300000         # the report we render to pdf is bigger
RATE_MIN_INTERVAL = 0.8     # min gap between scans, stops accidental hammering

# groups we enumerate to describe a server's crypto agility
AGILITY_GROUPS = [0x001D, 0x0017, 0x0018, 0x0019, 0x11EC, 0x11EB, 0x6399]


class InvalidDomain(Exception):
    pass


class BlockedTarget(Exception):
    pass


def clean_domain(raw):
    # urlsplit strips scheme, path, port and userinfo for us
    if not raw or len(raw) > 255:
        raise InvalidDomain("empty or too long")
    parts = urlsplit(raw if "://" in raw else "//" + raw.strip())
    host = (parts.hostname or "").strip(".")
    if not host or len(host) > 253:
        raise InvalidDomain("no hostname")
    # ip literal? let it through here, the ssrf guard checks the address itself
    if _looks_like_ip(host):
        return host
    # otherwise it has to look like a real dns name
    labels = host.split(".")
    if len(labels) < 2:
        raise InvalidDomain("not a fully qualified domain")
    for lab in labels:
        if not lab or len(lab) > 63:
            raise InvalidDomain("bad label")
        if not all(c.isalnum() or c == "-" for c in lab):
            raise InvalidDomain("illegal character")
    return host


def resolve_public_ip(host):
    # ssrf guard: resolve once, drop anything on our own network, pin the ip
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BlockedTarget(f"dns lookup failed: {e}")

    ips = []
    for _, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if _is_public(ip) and ip not in ips:
            ips.append(ip)
    if not ips:
        raise BlockedTarget("resolves only to private or reserved addresses")
    return ips[0], ips


def new_token():
    # per-process secret the ui must echo back, keeps other local apps out
    return secrets.token_urlsafe(32)


def _looks_like_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_public(ip):
    a = ipaddress.ip_address(ip)
    bad = (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
           or a.is_reserved or a.is_unspecified)
    return not bad
