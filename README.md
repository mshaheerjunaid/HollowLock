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
is the point, a lock that looks solid from outside and is empty inside.

This is version 2.0.0.

## Editions

Version 2 comes in two editions built on the same core package, and the
`hollowlock/` folder is byte for byte identical in both. The standard edition is
the dashboard plus the `hollowlock key` and `hollowlock verify` commands. The
study edition adds bulk scanning of a target list, batch verification, summary
tables and the validation material behind the measurement method. Any single
scan gives the same answer in either edition, because the probes, verdicts and
signing all live in the shared core.

## What It Shows

Type a domain and you get its public TLS edge, read live:

- A verdict out of seven, a one-line explanation, and a score where one applies.
- The four handshake probes in a table, with the group each one got, whether a
  HelloRetryRequest was needed, the TLS version and the time taken.
- Every group from a fixed test list (listed below) and whether the server
  accepted it when it was offered on its own.
- Protocol details such as the negotiated version, TLS 1.2 fallback, cipher,
  ALPN, HTTP/3 and HSTS.
- The certificate's signature algorithm, key type and size, issuer and validity.
- The edge itself, meaning the server banner, the address scanned with its
  family, every resolved address and the handshake latency.
- A cryptographic bill of materials with the change each asset needs.
- The signer fingerprint, whether the signature verified, and the provenance of
  the scan.

You can download the result as a signed JSON file, which is the verifiable
record, or as a PDF rendering of it.

## The Seven Verdicts

The rules are applied in this order, and the first one that matches decides.
Probe D never takes part.

1. **INCONCLUSIVE.** Probe B did not end in `group` or `tls12`. Also INCONCLUSIVE when Probe B selected a classical group, Probe A ended in `error`, and no agility probe for a standard hybrid group ended in `group`, because Partial and Hollow then cannot be told apart. Store a machine-readable reason, for example `dns_error`, `timeout`, `reset`, `unparseable` or `pq_probe_error`.
2. **TLS12_ONLY.** Probe B ended in `tls12`, or the baseline handshake negotiated TLS 1.2 and every TLS 1.3 probe ended in `tls12` or a `protocol_version` alert.
3. **STRICT.** Probe B selected a standard hybrid group (0x11EC, 0x11EB or 0x11ED) and Probe C ended in `refused`.
4. **ENFORCED.** Probe B selected a standard hybrid group and Probe C was accepted. In plain terms, "post-quantum by default; classical-only clients are still served".
5. **PARTIAL.** Probe B selected a classical group, but Probe A or any agility probe selected a standard hybrid or pure ML-KEM group.
6. **LEGACY_HYBRID.** The only post-quantum groups accepted anywhere are the pre-standard Kyber drafts (0x6399, 0x639A).
7. **HOLLOW.** Probe B selected a classical group, Probe A ended in `refused`, and every post-quantum agility probe ended in `refused`.

A few cases fall outside those seven lines, and the tool marks them
INCONCLUSIVE rather than guessing. When Probe B gets a hybrid group but Probe C
errors, the reason is `classical_probe_error`, since Strict and Enforced can't be
separated. When Probe B gets a classical group, Probe A is refused and one of the
post-quantum agility probes errors instead of being refused, the reason is
`pq_probe_error`. Anything else that matches no rule is `undetermined`. The
other reasons you can see are `connect_error` when the TCP connection never
opened and `default_refused` when the server turned down the browser-like probe
outright. "Accepted anywhere" in rule 6 means Probe A, Probe B or an agility
probe.

Every report also carries `hrr_needed_for_pq`. It is true when Probe A reached a
standard hybrid group through a HelloRetryRequest and Probe B, which already
sent a hybrid key share, did not get a post-quantum group in its first
ServerHello. Put simply, post-quantum was only reachable after a retry.

## How It Works

HollowLock writes its own TLS 1.3 ClientHello and reads the server's answer, so
it does not need your system OpenSSL to support post-quantum, which most builds
still don't. Each scan sends the four probes below, then offers every group from
a fixed test list on its own, and finishes with two ordinary handshakes through
Python's `ssl` module, one normal and one capped at TLS 1.2.

| Probe | Groups offered | Key shares sent | Decides the verdict |
| --- | --- | --- | --- |
| A, post-quantum only | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM768, MLKEM1024, X25519Kyber768Draft00, SecP256r1Kyber768Draft00 | none, which forces a HelloRetryRequest | yes |
| B, browser-like | X25519MLKEM768, X25519, secp256r1, secp384r1 in Chrome's order | X25519MLKEM768 and X25519 | yes |
| C, classical only | X25519, secp256r1, secp384r1 | none | yes |
| D, classical-share client | the v1 list, the three standard hybrids, both Kyber drafts, X25519, secp256r1 | X25519 only | no |

Probe B is built to look like a current browser. Its X25519MLKEM768 share is a
real ML-KEM-768 encapsulation key followed by an X25519 public key, 1216 bytes
in total, and it also sends ALPN for `h2` and `http/1.1`. It offers TLS 1.2 as a
fallback the way a browser does, so a server that only speaks TLS 1.2 answers
with a TLS 1.2 ServerHello instead of an error. The other probes offer TLS 1.3
only. Probe D is the probe version 1 used by default. Many servers pick a group
the client already sent a share for, which avoids a HelloRetryRequest, so a
server can give D classical crypto while every real browser gets the hybrid.
That is why D is reported but never decides anything.

The fixed test list is X25519, secp256r1, secp384r1, secp521r1, X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM768, MLKEM1024,
X25519Kyber768Draft00 and SecP256r1Kyber768Draft00. Each one is offered alone
with an empty key share, and every group is labelled as a standard hybrid, pure
ML-KEM, legacy draft or classical.

Every probe ends in exactly one of four outcomes. `group` means a ServerHello or
HelloRetryRequest with a key share was parsed, and `tls12` means the server
answered with TLS 1.2. `refused` means an alert or a clean close after our hello,
and `error` covers a failed connection, a timeout, a reset or bytes that don't
parse. A refusal is an answer, so only errors are retried, once, after a short
pause.

In the dashboard probes run four at a time. The study edition runs them one
after another with a pause between connections. A full scan opens 17
connections when nothing has to be retried.

## The Score

The dashboard shows a score out of 100 inside each verdict's band. It is a
convenience with weights I chose, nothing more, and the study tables never use
it, they use the verdict and the raw fields. INCONCLUSIVE and TLS12_ONLY get no
score at all. AES-128 is not penalised, since NIST still treats it as acceptable.

## Signing and Verification

Every report is signed with ML-DSA-65 (FIPS 204) by a long-term key that lives
on your machine. On Windows the key sits in `%APPDATA%\HollowLock\`, and
elsewhere it is in `~/.config/hollowlock/`. It is created the first time you run
the tool, and the private half never leaves that folder.

```bash
hollowlock key                     # create the key if needed, print its fingerprint
hollowlock key --export pub.txt    # write the public key so others can check your reports
hollowlock key --new               # rotate after confirming, the old public key is kept
hollowlock verify report.json --pubkey pub.txt
hollowlock verify results.jsonl --pubkey pub.txt
```

Verification always needs a trusted public key handed in from outside. The copy
embedded in a report is only compared against it, and a report signed by any
other key fails. `verify` checks one JSON report, or every line of a JSONL file,
prints pass or fail per line, and exits non-zero if anything fails.

## Run It

```bash
pip install git+https://github.com/mshaheerjunaid/HollowLock
hollowlock
```

Or clone the repository and run `pip install .` inside it. HollowLock serves a
dashboard on `127.0.0.1` and opens it in your browser. Nothing leaves your
machine except the scans you ask for.

## Two Caveats

HollowLock measures whatever answers the TLS connection. For a site behind a CDN
that is the CDN's edge, not the organisation's own servers, so the result
reflects the CDN's configuration. Several sites on the same CDN will often look
the same for exactly that reason.

Run it from behind a corporate proxy or some VPNs and everything can read as
classical, because you are then measuring the proxy that terminates your
traffic, not the site.

## Cryptographic Bill of Materials

After a scan HollowLock builds a CBOM from what it saw on the wire, covering the
key exchange from Probe B, the certificate signature and key, the protocol, any
TLS 1.2 support, and the cipher. Each line is marked quantum-safe, acceptable, a
finding, vulnerable or undetermined, and carries the concrete change where one
applies. TLS 1.2 support is listed as a finding to plan around, not as a
vulnerability.

## Security

The tool connects to servers you name and parses bytes they send back, so it is
hardened on purpose. It has an SSRF guard, a loopback-only server behind a
per-run token, a strict content security policy, XSS-safe rendering and a
bounded parser. The details are in [SECURITY.md](SECURITY.md).

## Scope

It reads the public TLS edge. It cannot see a site's internal systems, so it
grades what faces the internet, not a whole migration programme. Only scan hosts
you are allowed to test.

## Citing

Citation details are in [CITATION.cff](CITATION.cff), and the full list of
what changed since version 1 is in [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE). The Space Grotesk and Space Mono fonts bundled with
the dashboard keep their own licence, the SIL Open Font License 1.1, and its text
is in [LICENSE-FONTS.txt](LICENSE-FONTS.txt).
