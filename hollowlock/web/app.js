"use strict";

const TOKEN = document.querySelector('meta[name="hl-token"]').content;
const body = document.body;
const el = (id) => document.getElementById(id);
const cap = (s) => (s && s.length) ? s[0].toUpperCase() + s.slice(1) : s;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const C = 2 * Math.PI * 47;   // score ring circumference

wire();

function wire() {
  el("run").addEventListener("click", scan);
  el("domain").addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });
  el("again").addEventListener("click", () => location.reload());
  // clicking the open lock starts fresh
  el("lock").addEventListener("click", () => {
    if (body.classList.contains("state-report")) location.reload();
  });
}

async function scan() {
  const domain = el("domain").value.trim();
  el("err").textContent = "";
  if (!domain) return;

  setState("opening");
  el("dcLabel").textContent = "Probing";
  el("dcScore").textContent = "";

  const pending = doScan(domain);   // network runs while the lock turns
  await openLock();

  let data;
  try {
    data = await pending;
  } catch (e) {
    resetLock();
    setState("idle");
    el("dcLabel").textContent = "Ready"; el("dcScore").textContent = "";
    el("err").textContent = String(e.message || e);
    return;
  }
  renderReport(data);
  setState("report");
}

async function doScan(domain) {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-HollowLock-Token": TOKEN },
    body: JSON.stringify({ domain }),
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || "scan failed");
  return data;
}

// turn the dial like a safe combination, then let it settle open
async function openLock() {
  const img = el("lockImg");
  if (reduced) { body.classList.add("unlocked"); return; }
  for (const s of [{ d: 150, ms: 900 }, { d: -80, ms: 1000 }, { d: 120, ms: 820 }]) {
    img.style.transition = `transform ${s.ms}ms cubic-bezier(.5,0,.15,1)`;
    img.style.transform = `rotate(${s.d}deg)`;
    await wait(s.ms + 80);
  }
  body.classList.add("unlocked");
  await wait(700);
}

function resetLock() {
  body.classList.remove("unlocked");
  const img = el("lockImg");
  img.style.transition = "none";
  img.style.transform = "rotate(0deg)";
}

function setState(s) {
  body.className = "state-" + s;
  if (s !== "report") body.removeAttribute("data-verdict");
}

function alpnName(a) {
  return a === "h2" ? "HTTP/2" : a === "http/1.1" ? "HTTP/1.1" : "Not negotiated";
}

function renderReport(d) {
  body.setAttribute("data-verdict", d.verdict);
  el("dcLabel").textContent = cap(d.verdict);
  el("dcScore").textContent = d.score + "/100";
  el("arc").setAttribute("stroke-dasharray", `${(C * d.score / 100).toFixed(1)} ${C}`);

  const out = el("readout");
  out.replaceChildren();

  const s1 = section(out, "01", "Handshake Probes");
  d.probes.forEach((p) => {
    const b = document.createElement("div"); b.className = "probe";
    const po = document.createElement("div"); po.className = "po";
    po.append(dot(p.s), text(`Offered ${p.off}`));
    const pr = document.createElement("div"); pr.className = "pr"; pr.textContent = cap(p.res);
    b.append(po, pr); s1.appendChild(b);
  });

  const kx = d.key_exchange;
  const s2 = section(out, "02", "Key Exchange and Crypto Agility");
  s2.appendChild(row("Default group", kx.default_group, null, kx.default_is_pq ? "good" : "bad"));
  s2.appendChild(row("Post-quantum", kx.supports_pq ? `Yes (${kx.pq_group})` : "No", null,
    kx.supports_pq ? "good" : "bad"));
  const cr = document.createElement("div"); cr.className = "row";
  cr.append(kv("Groups accepted"));
  const chips = document.createElement("div"); chips.className = "chips v";
  (kx.supported.length ? kx.supported : [{ name: "none", pq: false }]).forEach((g) => {
    const c = document.createElement("span"); c.className = "chip" + (g.pq ? " pq" : "");
    c.textContent = g.name; chips.appendChild(c);
  });
  cr.appendChild(chips); s2.appendChild(cr);

  const p = d.protocol;
  const s3 = section(out, "03", "Protocol");
  s3.appendChild(row("Negotiated", p.negotiated || "Unknown"));
  s3.appendChild(row("TLS 1.3", p.tls1_3 ? "Supported" : "No", null, p.tls1_3 ? "good" : "warn"));
  s3.appendChild(row("TLS 1.2", p.tls1_2 ? "Still accepted" : "No"));
  s3.appendChild(row("Cipher", p.cipher || "Unknown"));
  s3.appendChild(row("ALPN", alpnName(p.alpn)));
  s3.appendChild(row("HTTP/3", p.http3 ? "Advertised" : "Not advertised"));
  s3.appendChild(row("HSTS", p.hsts ? p.hsts : "Not set", null, p.hsts ? "good" : "warn"));

  const c = d.certificate;
  const s4 = section(out, "04", "Certificate");
  if (c) {
    s4.appendChild(row("Signature", c.sig_alg,
      c.is_pq ? "Post-quantum signature" : "Classical, expected until CAs issue PQ certs",
      c.is_pq ? "good" : "neutral"));
    s4.appendChild(row("Public key", c.key_bits ? `${c.key_type} ${c.key_bits}-bit` : c.key_type));
    s4.appendChild(row("Issuer", c.issuer || "Unknown"));
    s4.appendChild(row("Subject", c.subject || "Unknown"));
    s4.appendChild(row("Valid", `${c.not_before} to ${c.not_after} (${c.days_left} days left)`));
    s4.appendChild(row("SAN entries", String(c.san_count)));
  } else {
    s4.appendChild(row("Certificate", "Could not read"));
  }

  const s5 = section(out, "05", "Edge and Server");
  s5.appendChild(row("Server banner", d.server.banner || "Not disclosed"));
  s5.appendChild(row("Resolved IPs", (d.ips || [d.ip]).join(", ")));
  s5.appendChild(row("Handshake latency", d.server.latency_ms != null ? `${d.server.latency_ms} ms` : "Unknown"));

  const s6 = section(out, "06", "Post-Quantum Migration");
  s6.appendChild(row("Stage", cap(d.migration.stage), d.migration.note,
    d.verdict === "enforced" ? "good" : d.verdict === "partial" ? "warn" : "bad"));

  renderCbom(out, d);
  renderTitleblock(out, d);
}

function renderCbom(out, d) {
  const s = section(out, "07", "Cryptographic Bill of Materials");
  const box = document.createElement("div"); box.className = "cbom";
  const head = document.createElement("div"); head.className = "cr";
  ["Asset", "Algorithm", "Status"].forEach((t, i) => {
    const cell = document.createElement("div"); cell.className = "ca"; cell.textContent = t;
    if (i === 2) cell.style.justifySelf = "end";
    head.appendChild(cell);
  });
  box.appendChild(head);
  d.cbom.components.forEach((comp) => {
    const r = document.createElement("div"); r.className = "cr";
    const a = document.createElement("div"); a.className = "ca"; a.textContent = comp.asset;
    const g = document.createElement("div"); g.className = "cg"; g.textContent = comp.algorithm;
    const st = document.createElement("div");
    st.className = "cs " + (comp.quantum_safe ? "safe" : "vuln");
    st.textContent = comp.quantum_safe ? "Quantum-safe" : "Vulnerable";
    r.append(a, g, st);
    if (comp.action) {
      const act = document.createElement("div"); act.className = "cbom-action"; act.textContent = comp.action;
      r.appendChild(act);
    }
    box.appendChild(r);
  });
  s.appendChild(box);

  const foot = document.createElement("div"); foot.className = "cbom-foot";
  const sum = document.createElement("div"); sum.className = "cbom-sum"; sum.textContent = d.cbom.summary;
  const dl = document.createElement("button"); dl.className = "dl"; dl.textContent = "Download PDF report";
  dl.addEventListener("click", () => downloadPdf(d, dl));
  foot.append(sum, dl); s.appendChild(foot);
}

function renderTitleblock(out, d) {
  const tb = document.createElement("div"); tb.className = "titleblock";
  const sig = d.signature || {};
  [["Target", d.domain],
   ["Scanned", d.scanned_at.replace("T", " ").replace("+00:00", " UTC")],
   ["Verdict", `${cap(d.verdict)} · ${d.score}/100`],
   ["Signed", `${sig.algorithm || "unsigned"} · ${(sig.signature || "").slice(0, 16)}…`],
  ].forEach(([k, v]) => {
    const cell = document.createElement("div");
    const tk = document.createElement("span"); tk.className = "tk"; tk.textContent = k;
    const tv = document.createElement("span"); tv.className = "tv"; tv.textContent = v;
    cell.append(tk, tv); tb.appendChild(cell);
  });
  out.appendChild(tb);
}

async function downloadPdf(d, btn) {
  // the pdf is built server-side and saved by the browser. nothing lands on disk here.
  btn.disabled = true; const label = btn.textContent; btn.textContent = "Building…";
  try {
    const res = await fetch("/api/report.pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-HollowLock-Token": TOKEN },
      body: JSON.stringify(d),
    });
    if (!res.ok) throw new Error("pdf failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `hollowlock-${d.domain}.pdf`; a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    btn.textContent = "Failed, retry";
    setTimeout(() => { btn.textContent = label; }, 1600);
    btn.disabled = false; return;
  }
  btn.textContent = label; btn.disabled = false;
}

// ---- dom helpers, text via textContent ----
function section(parent, idx, title) {
  const s = document.createElement("div"); s.className = "section";
  const h = document.createElement("h2");
  const i = document.createElement("span"); i.className = "idx"; i.textContent = idx;
  h.append(i, text(title)); s.appendChild(h); parent.appendChild(s);
  return s;
}
function row(k, v, note, state) {
  const r = document.createElement("div"); r.className = "row";
  r.appendChild(kv(k));
  const val = document.createElement("div"); val.className = "v";
  if (state) val.appendChild(dot(state));
  val.appendChild(text(v)); r.appendChild(val);
  if (note) { const n = document.createElement("div"); n.className = "n"; n.textContent = note; r.appendChild(n); }
  return r;
}
function kv(k) { const d = document.createElement("div"); d.className = "k"; d.textContent = k; return d; }
function dot(s) { const d = document.createElement("span"); d.className = "dot " + s; return d; }
function text(t) { return document.createTextNode(t); }
