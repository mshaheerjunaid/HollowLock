# Changelog

## Unreleased

- Added `LICENSE-FONTS.txt` with the SIL Open Font License 1.1 text for the
  bundled Space Grotesk and Space Mono fonts, which had shipped without it since
  0.1.0. It is also packaged into the wheel. No code changed, so scan results are
  the same as 2.0.0.

## 2.0.0, 17 October 2026

Version 2 rebuilds how HollowLock measures a server, so its numbers can be
relied on in published work. Two version 1 behaviours could produce wrong
results. A failed scan was reported as Hollow, so a site that simply timed out or
blocked the connection looked unprotected. The default probe also sent only an
X25519 key share, unlike a real browser, so a server that answers browsers with
X25519MLKEM768 could be called Partial. Both are fixed below.

### Probes and Parsing

- Probe B is now browser-like. It offers X25519MLKEM768, X25519, secp256r1 and
  secp384r1 in Chrome's order, sends key shares for X25519MLKEM768 and X25519,
  and sends ALPN for `h2` and `http/1.1`. The hybrid share is a real ML-KEM-768
  encapsulation key from `kyber-py` followed by the X25519 key, 1216 bytes in
  all. It also offers TLS 1.2 as a fallback, like a browser does.
- The version 1 default probe is kept as Probe D, the classical-share client. It
  is reported separately and never decides the verdict.
- Each scan runs four probes, the agility probes and a baseline handshake, and
  records for every probe its outcome, group, HelloRetryRequest use, TLS version,
  alert, error text, attempt count and time taken.
- The ServerHello's `supported_versions` extension is now read, so a server that
  answers with TLS 1.2 is recognised as such instead of falling into Hollow.
- Every probe outcome is classified as `group`, `refused`, `tls12` or `error`, so
  a refusal is no longer confused with a failure.
- The reader now reassembles a ServerHello split across records and skips a
  ChangeCipherSpec that arrives first. All length checks stay, and reading stops
  after 64 KiB in total.
- IPv4 addresses are tried first with IPv6 as a fallback, and the address and
  family used are recorded along with every resolved address.
- `scan()` takes `mode`, `probe_gap`, `retries`, `timeout` and `vantage`. Fast
  mode, used by the dashboard, runs at most four connections at once. Paced mode
  runs one connection at a time with a gap between them. Only errors are
  retried, once, never refusals.
- The agility list adds SecP384r1MLKEM1024, pure ML-KEM-768, pure ML-KEM-1024
  and SecP256r1Kyber768Draft00, and every group is labelled as standard hybrid,
  pure ML-KEM, legacy draft or classical.

### Verdicts and Score

- Three verdicts became seven, applied in a fixed order. They are INCONCLUSIVE
  with a machine-readable reason, TLS12_ONLY, STRICT, ENFORCED, PARTIAL,
  LEGACY_HYBRID and HOLLOW. The rules are written out in the README.
- Every report carries `hrr_needed_for_pq`.
- The score is kept for the dashboard only. INCONCLUSIVE and TLS12_ONLY have no
  score, and AES-128 is no longer penalised.

### Signing and Provenance

- Reports are signed by one long-term ML-DSA-65 key per machine instead of a
  fresh key on every run. Verification now needs a trusted public key supplied
  from outside, which closes a hole in version 1 where an edited report re-signed
  with any key would still verify.
- New `hollowlock key` and `hollowlock verify` commands create, show, export and
  rotate the key, and check single reports or whole JSONL files.
- Every report has a provenance block with the tool version, source commit,
  Python, operating system, OpenSSL and library versions, and the scan settings.
- Timestamps use timezone-aware UTC throughout.

### Reports, CBOM and PDF

- The CBOM marks AES-128 as acceptable, lists TLS 1.2 support as a finding with
  "Plan to retire TLS 1.2 once legacy clients allow", takes the key exchange
  from Probe B, reads "undetermined" for INCONCLUSIVE, and respects a
  post-quantum certificate key.
- The PDF is checked against the local key before it is drawn. It describes
  itself as a rendering of a signed report, prints the signer fingerprint, the
  SHA-256 of the signed JSON and how to verify it, and shows a red warning
  instead of any signing claim when verification fails. It now includes the
  four-probe table, the fixed test list and the provenance block.
- The dashboard keeps everything it had and adds the seven verdicts with their
  own colours and explanations, the reason for INCONCLUSIVE, the four-probe
  table with HelloRetryRequest markers, the full fixed test list, the signer
  fingerprint and verification status, a provenance section and a download for
  the signed JSON.
- The baseline HEAD request identifies itself as
  `HollowLock/2.0 (post-quantum TLS research; +https://github.com/mshaheerjunaid/HollowLock)`.
- The TLS 1.2 check reports "Unknown" when its connection fails, instead of
  quietly reporting "No".
- Only one dashboard scan runs at a time, and the API token is compared in
  constant time.
- The baseline waits at most three seconds for a HEAD reply, so a server that
  never answers HEAD no longer stalls a scan for the full timeout.
- A target given as a bare IP address is probed without SNI, as RFC 6066
  requires, instead of putting the address into the server name.

### Project

- README, SECURITY, this changelog and CITATION.cff describe version 2, and the
  package version is 2.0.0.
- A pytest suite covers the hello builder, the hybrid share layout, parsing,
  every verdict rule, signing and the CBOM.
- `kyber-py` is a new runtime dependency, and `cryptography` 42 or later is
  required because the certificate reader uses its timezone-aware date API.

## 0.1.0, 9 September 2026

First release.
