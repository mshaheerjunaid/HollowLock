import ipaddress
import secrets
import socket
from urllib.parse import urlsplit

# resource caps. these bound what a hostile server can make us do.
PROBE_TIMEOUT = 6           # seconds per connection
MAX_TLS_RECORD = 16384      # a tls plaintext record can't legally exceed this
MAX_READ = 65536            # total bytes we'll read hunting for one server hello
MAX_BODY = 1024             # request body from the ui is tiny (a domain)
MAX_REPORT = 300000         # the signed report we render to pdf is bigger
RATE_MIN_INTERVAL = 0.8     # min gap between scans, stops accidental hammering

# groups probed one at a time to map what the server accepts
AGILITY_GROUPS = [
    0x001D, 0x0017, 0x0018, 0x0019,     # classical
    0x11EC, 0x11EB, 0x11ED,             # standard hybrids
    0x0201, 0x0202,                     # pure ml-kem
    0x6399, 0x639A,                     # kyber drafts
]


class InvalidDomain(Exception):
    pass


class BlockedTarget(Exception):
    pass


class DnsError(Exception):
    # name didn't resolve at all. not a security refusal, a scan can still report it
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
    # ssrf guard: resolve once, drop anything on our own network, pin one ip.
    # ipv4 first, ipv6 only when there's no public v4 address.
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as e:
        raise DnsError(str(e))

    v4, v6 = [], []
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if not _is_public(ip):
            continue
        bucket = v4 if fam == socket.AF_INET else v6
        if ip not in bucket:
            bucket.append(ip)
    every = v4 + v6
    if not every:
        raise BlockedTarget("resolves only to private or reserved addresses")
    ip = every[0]
    return ip, ("ipv4" if ip in v4 else "ipv6"), every


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
    a = ipaddress.ip_address(ip.split("%", 1)[0])
    bad = (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
           or a.is_reserved or a.is_unspecified)
    return not bad
