# Security Model

HollowLock connects to servers you name, parses bytes they send back, and runs a
local server for its own UI. All three are attack surface, so the tool is
hardened deliberately. This page describes what is in place and why.

## Network and SSRF

Every target is resolved first, and any address that is loopback, private,
link-local, multicast or reserved is dropped. If nothing public is left the
target is refused, so a tool that connects to user input can't be aimed at
`localhost` or the LAN to reach internal services. IPv4 addresses are preferred
and IPv6 is used only when there is no public IPv4 address. The address is
resolved once and every probe connects to that exact IP, which stops DNS from
flipping to an internal address between the check and the connection. Each
connection has a hard timeout, and only failed probes are retried, once.

The validation harness needs to talk to fake servers on loopback, so the engine
has a lower-level function that takes an address directly. Neither the
dashboard nor any command calls it, and a unit test checks that the public
`scan()` still refuses loopback and private addresses.

## The Local Server

It binds `127.0.0.1`, never `0.0.0.0`, so it is not reachable from the network. A
random token is minted each run and injected into the page. Every request to the
API must echo it back, and the comparison is constant-time, which keeps other
programs and websites in your browser from driving your scanner. Requests with a
foreign `Origin`, or a `Host` that is not loopback, are rejected, and no CORS
headers are ever sent. Scans are rate limited and only one runs at a time.

## The Browser Side

The content security policy is `default-src 'none'` with only same-origin script,
style, font and image. There are no inline scripts and no remote resources, so a
compromised third party has nothing to inject through. Fonts, styles, scripts and
the logo are all served locally. Everything a scanned server returns, its banner
and its certificate fields included, is written to the page with `textContent`
and never `innerHTML`, so a hostile server cannot script your page. Responses
also carry `nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`,
`no-referrer`, COOP, CORP, a locked `Permissions-Policy` and `no-store`.

## Parser Hardening

Record lengths from the server are range-checked before use, and a lying or
oversized length is rejected rather than trusted. The reader reassembles a
ServerHello split across records and skips a ChangeCipherSpec, but it stops
after 64 KiB in total no matter what the server sends. Extension parsing is
bounds-checked against truncated input. The handshake is never completed and no
secret key material is sent, only throwaway public keys, so a probe has nothing
to steal.

## Keys and Files the Tool Writes

HollowLock keeps one long-term ML-DSA-65 signing key per machine. On Windows it
lives in `%APPDATA%\HollowLock\` and elsewhere in `~/.config/hollowlock/`, as
`hollowlock_mldsa65.key` (private) and `hollowlock_mldsa65.pub` (public). The
private key is created with owner-only permissions where the operating system
supports that, and the folder is restricted the same way. The private key is
never printed, exported or sent anywhere. Rotating with `hollowlock key --new`
deletes the old private key and keeps the old public key under its fingerprint,
so older reports can still be checked.

Those key files are the only things the standard edition writes. Scan results
live in memory for the session. The PDF is rendered in memory and streamed to
your browser, and the signed JSON download is saved by your browser, never by the
server. The study edition also writes result files, a log, run metadata and a
signed manifest into the output folder you choose.

## Signatures

Every report is signed over its canonical JSON. Verification always needs a
trusted public key supplied from outside. The key embedded in a report is only
compared against that trusted key, never used on its own, so an edited report
re-signed with someone else's key fails. Before rendering a PDF, the dashboard
checks the signature against the local key, and if that fails the PDF says so in
red at the top and makes no claim about being signed.

## Least Privilege and Supply Chain

The server is the Python standard library, with no web framework. Runtime
dependencies are `cryptography`, the pure-Python `kyber-py` and `dilithium-py`
implementations of ML-KEM and ML-DSA, and `reportlab` for the PDF. There is no
subprocess, no shell and no `eval`, and the TLS hello is built by hand. The tool
sends no telemetry and makes no network calls other than the scans you ask for.

## Scope

HollowLock reads the public TLS edge of a host. It does not see internal systems,
and it is a diagnostic, not a penetration test. Only scan hosts you are allowed
to test. If you find a security problem in HollowLock itself, please report it
through the repository's issue tracker or by email to contact@mshaheerbjunaid.com.
