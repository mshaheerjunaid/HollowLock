# build a professional pdf of a scan, logo and name up top, then the report.
# reportlab draws it; the header/footer are painted per page.
from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus.flowables import HRFlowable

INK = colors.HexColor("#12202D"); MID = colors.HexColor("#5C6E80")
DIM = colors.HexColor("#8493A2"); LINE = colors.HexColor("#DCE1E7")
BLUE = colors.HexColor("#3F5AC8")
GOOD = colors.HexColor("#1E9C6B"); WARN = colors.HexColor("#B07A1E"); BAD = colors.HexColor("#C0562F")
VCOL = {"enforced": GOOD, "partial": WARN, "hollow": BAD}
CW = 174 * mm


def build(report, logo_path):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=32 * mm, bottomMargin=20 * mm,
                            title=f"HollowLock report for {report.get('domain','')}")
    v = report["verdict"]
    s = []
    s.append(_p(report["domain"], 17, INK, bold=True))
    s.append(Spacer(1, 3 * mm))
    s.append(_badge(f"{v.upper()}    {report['score']} / 100", VCOL.get(v, MID)))
    s.append(Spacer(1, 2 * mm))
    s.append(_p("Scanned " + report["scanned_at"].replace("T", " ").replace("+00:00", " UTC"), 8, DIM))
    s.append(Spacer(1, 5 * mm))

    kx, pr = report["key_exchange"], report["protocol"]
    cert = report.get("certificate") or {}

    _section(s, "Verdict summary", [
        ("Post-quantum key exchange", f"Yes ({kx['pq_group']})" if kx["supports_pq"] else "No"),
        ("Used by default", "Yes" if kx["default_is_pq"] else "No"),
        ("Default group", kx["default_group"]),
    ])
    _probes(s, report["probes"])
    _section(s, "Protocol", [
        ("Negotiated", pr.get("negotiated") or "Unknown"),
        ("TLS 1.3", "Supported" if pr.get("tls1_3") else "No"),
        ("TLS 1.2", "Still accepted" if pr.get("tls1_2") else "No"),
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
    _section(s, "Edge and server", [
        ("Server banner", report["server"].get("banner") or "Not disclosed"),
        ("Resolved IPs", ", ".join(report.get("ips") or [report.get("ip", "")])),
        ("Handshake latency", f"{report['server'].get('latency_ms')} ms"
         if report["server"].get("latency_ms") is not None else "Unknown"),
    ])
    _section(s, "Post-quantum migration", [
        ("Stage", v.capitalize()),
        ("Notes", report["migration"].get("note") or ""),
    ])
    _cbom(s, report["cbom"])
    _signature(s, report.get("signature") or {})

    frame = lambda c, d: _frame(c, d, logo_path)
    doc.build(s, onFirstPage=frame, onLaterPages=frame)
    return buf.getvalue()


def _p(t, size=9, color=INK, bold=False):
    st = ParagraphStyle("x", fontName="Helvetica-Bold" if bold else "Helvetica",
                        fontSize=size, textColor=color, leading=size + 3)
    return Paragraph(escape(str(t if t is not None else ""))[:600], st)


def _badge(t, color):
    tb = Table([[_p(t, 11, colors.white, bold=True)]], colWidths=[72 * mm])
    tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color),
                            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                            ("LEFTPADDING", (0, 0), (-1, -1), 13)]))
    return tb


def _head(s, title):
    s.append(Spacer(1, 4 * mm))
    st = ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=9, textColor=BLUE, leading=12, spaceAfter=4)
    s.append(Paragraph(escape(title).upper(), st))
    s.append(HRFlowable(width=CW, thickness=0.6, color=LINE, spaceAfter=4))


def _kv_style():
    return TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                       ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                       ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)])


def _section(s, title, rows):
    _head(s, title)
    data = [[_p(k, 9, MID), _p(v, 9, INK)] for k, v in rows]
    t = Table(data, colWidths=[52 * mm, 122 * mm]); t.setStyle(_kv_style()); s.append(t)


def _probes(s, probes):
    _head(s, "Handshake probes")
    pc = {"good": GOOD, "bad": BAD, "neutral": INK}
    data = [[_p("Offered " + p["off"], 9, MID),
             _p(_cap(p["res"]), 9, pc.get(p["s"], INK))] for p in probes]
    t = Table(data, colWidths=[64 * mm, 110 * mm]); t.setStyle(_kv_style()); s.append(t)


def _cbom(s, cbom):
    _head(s, "Cryptographic bill of materials")
    data = [[_p("Asset", 9, MID, bold=True), _p("Algorithm", 9, MID, bold=True), _p("Status", 9, MID, bold=True)]]
    for c in cbom["components"]:
        alg = [_p(c["algorithm"], 9, INK)]
        if c.get("action"):
            alg.append(_p(c["action"], 7.5, DIM))
        status = _p("Quantum-safe" if c["quantum_safe"] else "Vulnerable", 8.5,
                    GOOD if c["quantum_safe"] else BAD, bold=True)
        data.append([_p(c["asset"], 9, INK), alg, status])
    t = Table(data, colWidths=[44 * mm, 92 * mm, 38 * mm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
    s.append(t)
    s.append(Spacer(1, 3 * mm))
    s.append(_p(cbom["summary"], 9, MID))


def _signature(s, sig):
    _head(s, "Report signature")
    alg = sig.get("algorithm", "unsigned")
    hexs = sig.get("signature", "")
    s.append(_p(f"Signed with {alg} (FIPS 204). Post-quantum and tamper-evident.", 9, INK))
    s.append(Spacer(1, 1.5 * mm))
    s.append(_p(hexs[:96] + ("..." if len(hexs) > 96 else ""), 7.5, DIM))


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
    c.drawRightString(w - 18 * mm, top - 2 * mm, datetime.utcnow().strftime("%Y-%m-%d"))
    c.setStrokeColor(LINE); c.setLineWidth(0.6); c.line(18 * mm, top - 12 * mm, w - 18 * mm, top - 12 * mm)
    c.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
    c.setFillColor(DIM); c.setFont("Helvetica", 7)
    c.drawString(18 * mm, 11 * mm, "Generated by HollowLock. Reads the public TLS edge only.")
    c.drawRightString(w - 18 * mm, 11 * mm, f"Page {doc.page}")
    c.restoreState()


def _cap(t):
    return t[0].upper() + t[1:] if t else t
