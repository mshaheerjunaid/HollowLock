"use strict";

const TOKEN = document.querySelector('meta[name="hl-token"]').content;
const body = document.body;
const el = (id) => document.getElementById(id);
const cap = (s) => (s && s.length) ? s[0].toUpperCase() + s.slice(1) : s;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const C = 2 * Math.PI * 47;   // score ring circumference

const VERDICT_STATE = { STRICT: "good", ENFORCED: "good", PARTIAL: "warn", LEGACY_HYBRID: "warn",
  HOLLOW: "bad", TLS12_ONLY: "bad", INCONCLUSIVE: "neutral" };

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
  el("dcNote").textContent = "";

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
  if (!res.ok || data.error) throw new Error(data.error || "Scan failed");
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

function renderReport(res) {
  const d = res.report, ver = res.verification;
  body.setAttribute("data-verdict", d.verdict.toLowerCase());
  el("dcLabel").textContent = d.verdict_label;
  el("dcScore").textContent = d.score === null ? "No score" : d.score + "/100";
  el("dcNote").textContent = d.verdict_reason ? `${d.explanation} ${d.reason_text}` : d.explanation;
  const pct = d.score === null ? 0 : d.score;
  el("arc").setAttribute("stroke-dasharray", `${(C * pct / 100).toFixed(1)} ${C}`);

  const out = el("readout");
  out.replaceChildren();

  // 1. the four probes
  const s1 = section(out, "01", "Handshake Probes");
  if (d.probes.length) {
    s1.appendChild(probeTable(d.probes));
  } else {
    s1.appendChild(row("Probes", "None ran", d.reason_text, "neutral"));
  }

  // 2. key exchange and the fixed test list
  const kx = d.key_exchange;
  const s2 = section(out, "02", "Key Exchange and Crypto Agility");
  s2.appendChild(row("Default group", kx.default_group, "What the browser-like probe got",
    kx.default_is_pq ? "good" : "bad"));
  s2.appendChild(row("Post-quantum", kx.supports_pq ? `Yes (${kx.pq_group})` : "No", null,
    kx.supports_pq ? "good" : "bad"));
  s2.appendChild(row("Only through a retry", d.hrr_needed_for_pq ? "Yes" : "No",
    "Post-quantum was reached only after a HelloRetryRequest", d.hrr_needed_for_pq ? "warn" : null));
  const cr = document.createElement("div"); cr.className = "row";
  cr.append(kv("Groups accepted"));
  const chips = document.createElement("div"); chips.className = "chips v";
  (kx.supported.length ? kx.supported : [{ name: "none", pq: false }]).forEach((g) => {
    const c = document.createElement("span"); c.className = "chip" + (g.pq ? " pq" : "");
    c.textContent = g.name; chips.appendChild(c);
  });
  cr.appendChild(chips); s2.appendChild(cr);
  if (kx.agility.length) {
    const ar = document.createElement("div"); ar.className = "row";
    ar.append(kv("Fixed test list"));
    const list = document.createElement("div"); list.className = "chips v";
    kx.agility.forEach((g) => {
      const c = document.createElement("span");
      c.className = "chip " + (g.outcome === "group" ? (g.kind === "classical" ? "" : "pq") : g.outcome === "error" ? "err" : "off");
      c.title = `${g.code}, ${g.kind}, ${g.outcome}`;
      c.textContent = g.name; list.appendChild(c);
    });
    ar.appendChild(list);
    const n = document.createElement("div"); n.className = "n";
    n.textContent = "Every group is offered on its own. Outlined groups were accepted, faded ones refused.";
    ar.appendChild(n); s2.appendChild(ar);
  }

  // 3. protocol
  const p = d.protocol;
  const s3 = section(out, "03", "Protocol");
  s3.appendChild(row("Negotiated", p.negotiated || "Unknown"));
  s3.appendChild(row("TLS 1.3", p.tls1_3 ? "Supported" : "No", null, p.tls1_3 ? "good" : "warn"));
  s3.appendChild(row("TLS 1.2", p.tls1_2 === null ? "Unknown" : p.tls1_2 ? "Still accepted" : "No",
    p.tls1_2 === null ? "The TLS 1.2 check could not connect" : null));
  s3.appendChild(row("Cipher", p.cipher || "Unknown"));
  s3.appendChild(row("ALPN", alpnName(p.alpn)));
  s3.appendChild(row("HTTP/3", p.http3 ? "Advertised" : "Not advertised"));
  s3.appendChild(row("HSTS", p.hsts ? p.hsts : "Not set", null, p.hsts ? "good" : "warn"));

  // 4. certificate
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

  // 5. edge / server
  const s5 = section(out, "05", "Edge and Server");
  s5.appendChild(row("Server banner", d.server.banner || "Not disclosed"));
  s5.appendChild(row("Address scanned", d.ip ? `${d.ip} (${d.family})` : "None"));
  s5.appendChild(row("Resolved IPs", d.ips.length ? d.ips.join(", ") : "None"));
  s5.appendChild(row("Handshake latency", d.server.latency_ms != null ? `${d.server.latency_ms} ms` : "Unknown"));

  // 6. migration
  const s6 = section(out, "06", "Post-Quantum Migration");
  s6.appendChild(row("Stage", d.verdict_label, d.migration.note, VERDICT_STATE[d.verdict]));

  renderCbom(out, d, res);
  renderSignature(out, d, ver);
  renderTitleblock(out, d, ver);
}

function probeTable(probes) {
  const t = document.createElement("div"); t.className = "ptable";
  const head = document.createElement("div"); head.className = "pt-row pt-head";
  ["Probe", "Result", "HRR", "Version", "Time"].forEach((h) => head.appendChild(cell("pt-c", h)));
  t.appendChild(head);
  probes.forEach((p) => {
    const r = document.createElement("div"); r.className = "pt-row";
    const name = cell("pt-c pt-name", "");
    name.append(dot(p.s), text(`${p.id}. ${p.label}`));
    const sub = document.createElement("span"); sub.className = "pt-sub";
    sub.textContent = `Offers ${p.groups.join(", ")}` + (p.shares.length ? `, shares ${p.shares.join(" + ")}` : ", empty key share")
      + (p.used_for_verdict ? "" : ". Not used for the verdict");
    name.appendChild(sub);
    r.append(name, cell("pt-c pt-res", cap(p.res)));
    const h = cell("pt-c pt-hrr", p.hrr ? "HRR" : "");
    if (p.hrr) h.classList.add("on");
    r.append(h, cell("pt-c", p.version || ""), cell("pt-c pt-time", `${p.elapsed_ms} ms${p.attempts > 1 ? " x" + p.attempts : ""}`));
    t.appendChild(r);
  });
  return t;
}

function renderCbom(out, d, res) {
  const s = section(out, "07", "Cryptographic Bill of Materials");
  const box = document.createElement("div"); box.className = "cbom";
  const head = document.createElement("div"); head.className = "cr";
  ["Asset", "Algorithm", "Status"].forEach((t, i) => {
    const c = cell("ca", t);
    if (i === 2) c.style.justifySelf = "end";
    head.appendChild(c);
  });
  box.appendChild(head);
  d.cbom.components.forEach((comp) => {
    const r = document.createElement("div"); r.className = "cr";
    r.append(cell("ca", comp.asset), cell("cg", comp.algorithm), cell("cs " + comp.status, comp.label));
    if (comp.action) r.appendChild(cell("cbom-action", comp.action));
    box.appendChild(r);
  });
  s.appendChild(box);

  const foot = document.createElement("div"); foot.className = "cbom-foot";
  const btns = document.createElement("div"); btns.className = "dl-row";
  const pdf = document.createElement("button"); pdf.className = "dl"; pdf.textContent = "Download PDF report";
  pdf.addEventListener("click", () => downloadPdf(d, res.signed_json, pdf));
  const js = document.createElement("button"); js.className = "dl"; js.textContent = "Download signed JSON";
  js.addEventListener("click", () => save(new Blob([res.signed_json], { type: "application/json" }),
    `hollowlock-${d.domain}.json`));
  btns.append(pdf, js);
  foot.append(cell("cbom-sum", d.cbom.summary), btns);
  s.appendChild(foot);
}

function renderSignature(out, d, ver) {
  const s = section(out, "08", "Signature and Provenance");
  const sig = d.signature || {};
  s.appendChild(row("Verification", ver.ok ? "Verified" : "Failed",
    ver.ok ? "Checked against this machine's signing key" : ver.detail, ver.ok ? "good" : "bad"));
  s.appendChild(row("Algorithm", sig.algorithm || "Unsigned"));
  s.appendChild(row("Signer fingerprint", sig.fingerprint || "None", "SHA-256 of the signing public key"));
  s.appendChild(row("Signed JSON SHA-256", ver.digest));
  const pv = d.provenance || {};
  s.appendChild(row("Tool", `HollowLock ${pv.tool_version}`, `Source ${pv.git_commit}`));
  s.appendChild(row("Runtime", `Python ${pv.python}, ${pv.openssl}`, pv.platform));
  s.appendChild(row("Libraries", `kyber-py ${pv.kyber_py}, dilithium-py ${pv.dilithium_py}, cryptography ${pv.cryptography}`));
  s.appendChild(row("Settings", `${cap(pv.mode)} mode, timeout ${pv.timeout} s, ${pv.retries} ${pv.retries === 1 ? "retry" : "retries"}`));
}

function renderTitleblock(out, d, ver) {
  const tb = document.createElement("div"); tb.className = "titleblock";
  const sig = d.signature || {};
  [["Target", d.domain],
   ["Scanned", d.scanned_at.replace("T", " ").replace("+00:00", " UTC")],
   ["Verdict", d.score === null ? d.verdict_label : `${d.verdict_label} · ${d.score}/100`],
   ["Signed", `${sig.algorithm || "unsigned"} · ${(sig.fingerprint || "").slice(0, 16)}… · ${ver.ok ? "verified" : "not verified"}`],
  ].forEach(([k, v]) => {
    const c = document.createElement("div");
    c.append(cell("tk", k, "span"), cell("tv", v, "span"));
    tb.appendChild(c);
  });
  out.appendChild(tb);
}

async function downloadPdf(d, signedJson, btn) {
  // posts the exact signed text so the server can verify it before rendering
  btn.disabled = true; const label = btn.textContent; btn.textContent = "Building…";
  try {
    const res = await fetch("/api/report.pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-HollowLock-Token": TOKEN },
      body: signedJson,
    });
    if (!res.ok) throw new Error("pdf failed");
    save(await res.blob(), `hollowlock-${d.domain}.pdf`);
  } catch (e) {
    btn.textContent = "Failed, retry";
    setTimeout(() => { btn.textContent = label; }, 1600);
    btn.disabled = false; return;
  }
  btn.textContent = label; btn.disabled = false;
}

function save(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

// ---- dom helpers, all text via textContent ----
function section(parent, idx, title) {
  const s = document.createElement("div"); s.className = "section";
  const h = document.createElement("h2");
  h.append(cell("idx", idx, "span"), text(title)); s.appendChild(h); parent.appendChild(s);
  return s;
}
function row(k, v, note, state) {
  const r = document.createElement("div"); r.className = "row";
  r.appendChild(kv(k));
  const val = document.createElement("div"); val.className = "v";
  if (state) val.appendChild(dot(state));
  val.appendChild(text(v)); r.appendChild(val);
  if (note) r.appendChild(cell("n", note));
  return r;
}
function cell(cls, t, tag = "div") { const d = document.createElement(tag); d.className = cls; d.textContent = t; return d; }
function kv(k) { return cell("k", k); }
function dot(s) { const d = document.createElement("span"); d.className = "dot " + s; return d; }
function text(t) { return document.createTextNode(t == null ? "" : String(t)); }
