# Security model

HollowLock connects to servers you name, parses bytes they send back, and runs a
local server for its own UI. All three are attack surface, so the tool is
hardened deliberately. Here is what is in place and why.

## Network and SSRF

Every target is resolved first, and any host that resolves to a loopback,
private, link-local, multicast, or reserved address is refused. Without that, a
tool that connects to user input could be aimed at `localhost` or the LAN to
reach internal services. The address is resolved once and every probe connects
to that exact IP, so DNS cannot flip to an internal address between the check and
the connection. Each probe has a hard timeout.

## The local server

It binds `127.0.0.1`, never `0.0.0.0`, so it is not reachable from the network. A
random token is minted each run and injected into the page; every scan request
must echo it back, which keeps other programs and websites in your browser from
driving your scanner. Requests with a foreign `Origin`, or a `Host` that is not
loopback, are rejected, and no CORS headers are ever sent. Scans are rate limited
and run one at a time.

## The browser side

The content security policy is `default-src 'none'` with only same-origin script,
style, font, and image. There are no inline scripts and no remote resources, so a
compromised third party has nothing to inject through. Fonts, styles, scripts, and
the logo are all served locally. Everything a scanned server returns (its banner,
its certificate fields) is written to the page with `textContent`, never
`innerHTML`, so a hostile server cannot script your page. Responses also carry
`nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `no-referrer`, COOP,
CORP, a locked `Permissions-Policy`, and `no-store`.

## Parser hardening

Record lengths from the server are range-checked before use, and a lying or
oversized length is dropped rather than trusted. Extension parsing is
bounds-checked against truncated input. The handshake is never completed and no
key material is sent, so a probe has nothing to steal.

## The tool's own cryptography

HollowLock signs every report with ML-DSA-65, a post-quantum signature, so a
saved report that was edited fails verification. The signing sits behind one
module, so the algorithm is a single edit to change. There is no network channel
to encrypt because the server only listens on loopback.

## Least privilege and supply chain

The server is the Python standard library, no web framework. Runtime dependencies
are `cryptography` and a pure-Python ML-DSA implementation, both readable and
without a compiled build step. No subprocess, no shell, no `eval`, the TLS is
built by hand. No filesystem writes and no persistence: results live in memory
for the session and are gone when you close the tab. The PDF report is rendered in memory and streamed to your browser, never written to disk on the server.

## Scope

HollowLock reads the public TLS edge of a host. It does not see internal systems,
and it is a diagnostic, not a penetration test. Only scan hosts you are allowed
to test.
