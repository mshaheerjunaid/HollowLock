# render a signed report as a pdf, logo and name up top, then the report.
# the server verifies the signature first and tells us the result, the pdf
# never claims a signature it couldn't check.
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus.flowables import HRFlowable

from .report import LABEL

INK = colors.HexColor("#12202D"); MID = colors.HexColor("#5C6E80")
DIM = colors.HexColor("#8493A2"); LINE = colors.HexColor("#DCE1E7")
BLUE = colors.HexColor("#3F5AC8")
GOOD = colors.HexColor("#1E9C6B"); WARN = colors.HexColor("#B07A1E"); BAD = colors.HexColor("#C0562F")
RED = colors.HexColor("#B42318")
VCOL = {"STRICT": colors.HexColor("#0F7B5F"), "ENFORCED": GOOD, "PARTIAL": WARN,
        "LEGACY_HYBRID": colors.HexColor("#6B4FBB"), "HOLLOW": BAD,
        "TLS12_ONLY": colors.HexColor("#9F2D4E"), "INCONCLUSIVE": colors.HexColor("#5C6E80")}
STATUS_COL = {"safe": GOOD, "acceptable": BLUE, "finding": WARN, "vulnerable": BAD, "undetermined": MID}
CW = 174 * mm


def build(report, logo_path, verified=False, verify_detail="", digest=""):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=32 * mm, bottomMargin=20 * mm,
                            title=f"HollowLock report for {report.get('domain', '')}")
    v = report.get("verdict", "INCONCLUSIVE")
    sig = report.get("signature") or {}
    s = []

    if not verified:
        s.append(_p("Signature check failed against this machine's HollowLock key "
                    f"({verify_detail}). Treat everything below as unverified.", 9.5, RED, bold=True))
        s.append(Spacer(1, 3 * mm))
    s.append(_p("This PDF is a rendering of a signed HollowLock report. The signed JSON is the "
                "verifiable record, this page is only a readable copy of it.", 8, DIM))
    s.append(Spacer(1, 4 * mm))

    s.append(_p(report.get("domain"), 17, INK, bold=True))
    s.append(Spacer(1, 3 * mm))
    score = report.get("score")
    label = LABEL.get(v, str(v))
    s.append(_badge(f"{label.upper()}    {score} / 100" if score is not None else label.upper(),
                    VCOL.get(v, MID)))
    s.append(Spacer(1, 2 * mm))
    s.append(_p(report.get("explanation"), 9, INK))
    if report.get("verdict_reason"):
        s.append(_p(f"Reason, {report['verdict_reason']}. {report.get('reason_text') or ''}", 9, MID))
    s.append(Spacer(1, 1.5 * mm))
    s.append(_p("Scanned " + str(report.get("scanned_at", "")).replace("T", " ").replace("+00:00", " UTC"), 8, DIM))
    s.append(Spacer(1, 3 * mm))

    kx, pr = report["key_exchange"], report["protocol"]
    cert = report.get("certificate") or {}

    _section(s, "Verdict summary", [
        ("Post-quantum key exchange", f"Yes ({kx['pq_group']})" if kx["supports_pq"] else "No"),
        ("Used by default", "Yes" if kx["default_is_pq"] else "No"),
        ("Default group (browser-like probe)", kx["default_group"]),
        ("Post-quantum only through a retry", "Yes" if report.get("hrr_needed_for_pq") else "No"),
    ])
    if report.get("probes"):
        _probes(s, report["probes"])
    if kx.get("agility"):
        _agility(s, kx["agility"])
    _section(s, "Protocol", [
        ("Negotiated", pr.get("negotiated") or "Unknown"),
        ("TLS 1.3", "Supported" if pr.get("tls1_3") else "No"),
        ("TLS 1.2", "Unknown" if pr.get("tls1_2") is None else "Still accepted" if pr.get("tls1_2") else "No"),
        ("Cipher", pr.get("cipher") or "Unknown"),
        ("ALPN", pr.get("alpn") or "Not negotiated"),
        ("HTTP/3", "Advertised" if pr.get("http3") else "Not advertised"),
        ("HSTS", pr.get("hsts") or "Not set"),
    ])
    if cert:
        _section(s, "Certificate", [
            ("Signature", cert.get("sig_alg")),
            ("Public key", f"{cert.get('key_type')} {cert.get('key_bits')}-bit"
             if cert.get("key_bits") else cert.get("key_type")),
            ("Issuer", cert.get("issuer") or "Unknown"),
            ("Subject", cert.get("subject") or "Unknown"),
            ("Valid", f"{cert.get('not_before')} to {cert.get('not_after')} ({cert.get('days_left')} days left)"),
            ("SAN entries", str(cert.get("san_count"))),
        ])
    srv = report.get("server") or {}
    _section(s, "Edge and server", [
        ("Server banner", srv.get("banner") or "Not disclosed"),
        ("Address scanned", f"{report.get('ip') or 'none'} ({report.get('family') or 'n/a'})"),
        ("Resolved IPs", ", ".join(report.get("ips") or []) or "None"),
        ("Handshake latency", f"{srv.get('latency_ms')} ms" if srv.get("latency_ms") is not None else "Unknown"),
    ])
    _section(s, "Post-quantum migration", [
        ("Stage", label),
        ("Notes", (report.get("migration") or {}).get("note") or ""),
    ])
    _cbom(s, report["cbom"])
    prov = report.get("provenance") or {}
    _section(s, "Provenance", [
        ("Tool", f"HollowLock {prov.get('tool_version')} ({prov.get('git_commit')})"),
        ("Runtime", f"Python {prov.get('python')} on {prov.get('platform')}"),
        ("Baseline TLS library", prov.get("openssl")),
        ("Libraries", f"kyber-py {prov.get('kyber_py')}, dilithium-py {prov.get('dilithium_py')}, "
                      f"cryptography {prov.get('cryptography')}"),
        ("Settings", f"mode {prov.get('mode')}, gap {prov.get('probe_gap')} s, timeout "
                     f"{prov.get('timeout')} s, retries {prov.get('retries')}, vantage {prov.get('vantage') or 'none'}"),
    ])
    _signature(s, sig, verified, digest, report.get("domain", "report"))

    frame = lambda c, d: _frame(c, d, logo_path)
    doc.build(s, onFirstPage=frame, onLaterPages=frame)
    return buf.getvalue()


def _p(t, size=9, color=INK, bold=False):
    st = ParagraphStyle("x", fontName="Helvetica-Bold" if bold else "Helvetica",
                        fontSize=size, textColor=color, leading=size + 3)
    return Paragraph(escape(str(t if t is not None else ""))[:900], st)


def _badge(t, color):
    tb = Table([[_p(t, 11, colors.white, bold=True)]], colWidths=[84 * mm])
    tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color),
                            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                            ("LEFTPADDING", (0, 0), (-1, -1), 13)]))
    return tb


def _head(s, title):
    s.append(Spacer(1, 4 * mm))
    st = ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=9, textColor=BLUE, leading=12, spaceAfter=4)
    s.append(Paragraph(escape(title).upper(), st))
    s.append(HRFlowable(width=CW, thickness=0.6, color=LINE, spaceAfter=4))


def _table_style():
    st = [("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
          ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    return TableStyle(st)


def _section(s, title, rows):
    _head(s, title)
    t = Table([[_p(k, 9, MID), _p(v, 9, INK)] for k, v in rows], colWidths=[56 * mm, 118 * mm])
    t.setStyle(_table_style()); s.append(t)


def _probes(s, probes):
    _head(s, "Handshake probes")
    pc = {"good": GOOD, "bad": BAD, "neutral": INK, "warn": WARN}
    data = [[_p(h, 8.5, MID, bold=True) for h in ("Probe", "Result", "HRR", "Version", "Time")]]
    for p in probes:
        name = f"{p['id']}. {p['label']}" + ("" if p.get("used_for_verdict", True) else " (not used for verdict)")
        data.append([_p(name, 8.5, INK), _p(_cap(p["res"]), 8.5, pc.get(p["s"], INK)),
                     _p("Yes" if p.get("hrr") else "", 8.5, INK), _p(p.get("version") or "", 8.5, INK),
                     _p(f"{p.get('elapsed_ms')} ms x{p.get('attempts')}", 8, DIM)])
    t = Table(data, colWidths=[46 * mm, 74 * mm, 12 * mm, 18 * mm, 24 * mm])
    t.setStyle(_table_style()); s.append(t)


def _agility(s, rows):
    _head(s, "Groups from the fixed test list")
    out = {"group": ("Accepted", GOOD), "refused": ("Refused", INK), "tls12": ("TLS 1.2 answer", WARN),
           "error": ("Error", WARN)}
    data = [[_p(h, 8.5, MID, bold=True) for h in ("Group", "Kind", "Result")]]
    for r in rows:
        txt, col = out.get(r["outcome"], (r["outcome"], INK))
        if r["outcome"] == "error" and r.get("error_class"):
            txt += f", {r['error_class']}"
        data.append([_p(f"{r['name']} ({r['code']})", 8.5, INK), _p(r["kind"], 8.5, MID), _p(txt, 8.5, col)])
    t = Table(data, colWidths=[74 * mm, 50 * mm, 50 * mm])
    t.setStyle(_table_style()); s.append(t)


def _cbom(s, cbom):
    _head(s, "Cryptographic bill of materials")
    data = [[_p("Asset", 9, MID, bold=True), _p("Algorithm", 9, MID, bold=True), _p("Status", 9, MID, bold=True)]]
    for c in cbom["components"]:
        alg = [_p(c["algorithm"], 9, INK)]
        if c.get("action"):
            alg.append(_p(c["action"], 7.5, DIM))
        status = c.get("status", "safe" if c.get("quantum_safe") else "vulnerable")
        data.append([_p(c["asset"], 9, INK), alg,
                     _p(c.get("label") or status.title(), 8.5, STATUS_COL.get(status, INK), bold=True)])
    t = Table(data, colWidths=[44 * mm, 92 * mm, 38 * mm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
    s.append(t)
    s.append(Spacer(1, 3 * mm))
    s.append(_p(cbom["summary"], 9, MID))


def _signature(s, sig, verified, digest, domain):
    _head(s, "Report signature")
    if verified:
        s.append(_p(f"Signed with {sig.get('algorithm')} (FIPS 204), and the signature checked out against "
                    "this machine's HollowLock key when the PDF was made.", 9, INK))
    else:
        s.append(_p("The signature on this report did not verify against this machine's key, "
                    "so nothing here should be relied on.", 9, RED, bold=True))
    s.append(Spacer(1, 2 * mm))
    t = Table([[_p("Signer fingerprint", 8.5, MID), _p(sig.get("fingerprint") or "none", 7.5, INK)],
               [_p("SHA-256 of signed JSON", 8.5, MID), _p(digest or "none", 7.5, INK)]],
              colWidths=[48 * mm, 126 * mm])
    t.setStyle(_table_style()); s.append(t)
    s.append(Spacer(1, 2 * mm))
    s.append(_p("To check it yourself, download the signed JSON from the dashboard, get the signer's "
                "public key (hollowlock key --export pub.txt on the machine that made it) and run "
                f"hollowlock verify hollowlock-{domain}.json --pubkey pub.txt. The fingerprint printed "
                "must match the one above.", 8, DIM))


def _frame(c, doc, logo):
    w, h = A4
    top = h - 14 * mm
    c.saveState()
    try:
        c.drawImage(logo, 18 * mm, top - 9 * mm, width=24 * mm, height=13 * mm,
                    preserveAspectRatio=True, anchor="sw", mask="auto")
    except Exception:
        pass
    c.setFillColor(INK); c.setFont("Helvetica-Bold", 15); c.drawString(46 * mm, top - 2 * mm, "HollowLock")
    c.setFillColor(MID); c.setFont("Helvetica", 8); c.drawString(46 * mm, top - 7 * mm, "Post-Quantum TLS Assay")
    c.setFillColor(DIM); c.setFont("Helvetica", 8)
    c.drawRightString(w - 18 * mm, top - 2 * mm, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    c.setStrokeColor(LINE); c.setLineWidth(0.6); c.line(18 * mm, top - 12 * mm, w - 18 * mm, top - 12 * mm)
    c.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
    c.setFillColor(DIM); c.setFont("Helvetica", 7)
    c.drawString(18 * mm, 11 * mm, "Generated by HollowLock. Reads the public TLS edge only.")
    c.drawRightString(w - 18 * mm, 11 * mm, f"Page {doc.page}")
    c.restoreState()


def _cap(t):
    return t[0].upper() + t[1:] if t else t
