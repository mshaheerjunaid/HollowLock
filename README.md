<p align="center">
  <img src="assets/HollowLock_Logo.jpg" alt="HollowLock" width="380">
</p>

<h1 align="center">HollowLock</h1>

<p align="center">
  See whether a site's post-quantum encryption is actually in force, or just a label.
</p>

---

Turning post-quantum TLS on and enforcing it are different things. A server can
advertise a hybrid post-quantum key exchange and still hand every real
connection classical crypto, with nothing to warn anyone. Traffic recorded today
is then readable later by whoever kept it and waits for a quantum computer,
whatever the config file claims.

HollowLock is a local app. You dial in a domain, it runs the actual TLS
handshakes, and it shows the key exchange the server really negotiates. The name
is the point: a lock that looks solid and is empty inside.

## What it shows

Type a domain and you get its public TLS edge, read live:

- Verdict and score: Enforced, Partial, or Hollow.
- The three handshake probes, and the group the server picked in each.
- Crypto agility: every key-exchange group the server actually accepts.
- Protocol: version, TLS 1.2 fallback, cipher, ALPN, HTTP/3, HSTS.
- Certificate: signature, key type and size, issuer, validity, days left.
- Edge: server banner, resolved IPs, handshake latency.
- A cryptographic bill of materials, with the change each asset needs.

The verdicts:

- **Enforced**: post-quantum is offered and used by default.
- **Partial**: post-quantum is available but classical is used by default, so
  ordinary clients stay unprotected.
- **Hollow**: no post-quantum key exchange at all.

## Run it

```bash
git clone https://github.com/mshaheerjunaid/hollowlock
cd hollowlock
pip install .
hollowlock
```

It serves a dashboard on `127.0.0.1` and opens it. Nothing leaves your machine
except the scans you ask for.

## How it works

HollowLock writes its own TLS 1.3 ClientHello and reads the ServerHello, so it
does not need your system OpenSSL to support post-quantum, which most builds
still don't. It sends three probes and reads which group the server selects, a
HelloRetryRequest included:

| Client offered | Hollow site | Enforced site |
| --- | --- | --- |
| post-quantum only | refuses | retries and picks the hybrid group |
| post-quantum + classical | picks classical | picks the hybrid group |
| classical only | picks classical | picks classical |

The rest is read from one ordinary handshake alongside those. One caveat worth
knowing: run it from behind a corporate proxy or some VPNs and everything reads
classical, because you are measuring the proxy, not the site.

## Its own cryptography

HollowLock runs on loopback, so there is no network channel to encrypt. Where it
does use crypto it is post-quantum, and it is kept in one module so the algorithm
is a single edit to change. Every report is signed with ML-DSA-65 (FIPS 204) and
the signature travels with it, so a saved report that was edited later fails
verification. The signing library is pure Python, which keeps the supply chain
small.

## Cryptographic bill of materials

After a scan HollowLock builds a CBOM from what it saw: key exchange, certificate
signature and key, protocol, and cipher. Each is marked quantum-safe or not and
carries the concrete migration step. It is built from the host's real
configuration, not a template, and you can download the whole thing as a signed PDF.

## Security

The tool connects to servers you name and parses bytes they send back, so it is
hardened on purpose: an SSRF guard, a loopback-only server behind a per-run
token, a strict content security policy, XSS-safe rendering, and a bounded
parser. Details are in [SECURITY.md](SECURITY.md).

## Scope

It reads the public TLS edge. It cannot see a site's internal systems, so it
grades what faces the internet, not a whole migration program. Only scan hosts
you are allowed to test.

## License

MIT. See [LICENSE](LICENSE).
