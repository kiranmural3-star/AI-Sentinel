let samples = {};
let lastResult = null;
let filterLevel = "All";

function esc(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
async function loadSamples() {
  try {
    const r = await fetch("/api/samples");
    samples = await r.json();
    const box = document.getElementById("sampleBtns");
    box.innerHTML = "";
    const labels = {
      "vulnerable_login.py": "Vulnerable login (SQLi)",
      "xss_command.py": "XSS + command injection",
      "payment_ssrf.py": "Payment SSRF + secrets",
      "secure_example.py": "Secure example (clean)",
      "wrong_code_for_testing.py": "All-in-one wrong code (13 flaws)"
    };
    Object.keys(samples).forEach(k => {
      const b = document.createElement("button");
      b.className = "secondary"; b.textContent = labels[k] || k;
      b.onclick = () => { document.getElementById("code").value = samples[k]; document.getElementById("fileName").textContent = k; };
      box.appendChild(b);
    });
    if (samples["vulnerable_login.py"]) {
      document.getElementById("code").value = samples["vulnerable_login.py"];
      document.getElementById("fileName").textContent = "vulnerable_login.py";
    }
  } catch (e) { /* samples optional */ }
}
async function loadSample(name) {
  if (!samples[name]) { await loadSamples(); }
  if (samples[name]) {
    document.getElementById("code").value = samples[name];
    document.getElementById("fileName").textContent = name;
    document.getElementById("analyzer").scrollIntoView({ behavior: "smooth" });
  }
}
document.getElementById("fileInput").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  document.getElementById("code").value = await f.text();
  document.getElementById("fileName").textContent = f.name;
});
function setFilter(l) {
  filterLevel = l;
  document.querySelectorAll("[data-filter]").forEach(b => b.style.outline = b.dataset.filter === l ? "2px solid #1FC2C9" : "none");
  render();
}
function render() {
  const box = document.getElementById("results");
  if (!lastResult) { box.innerHTML = '<p class="empty">Paste code or try a sample, then press Analyze.</p>'; return; }
  const s = lastResult.summary;
  const findings = lastResult.findings.filter(f => filterLevel === "All" || f.level === filterLevel);
  let html = `<div class="score-wrap">
    <div class="ring" style="--p:${s.security_score}%"><div style="position:relative;text-align:center"><b>${s.security_score}</b><small>Grade ${s.grade} / 100</small></div></div>
    <div><h2 style="margin:0">Security report</h2>
    <p class="hint" style="margin:6px 0">${s.total} finding(s) in ${s.lines} lines. Highest risk: ${s.max_risk}/10.
    ${s.routes.length ? "Routes found: " + s.routes.map(esc).join(", ") : "No Flask routes found in this file."}</p>
    <p class="hint">Sorted by risk, not just by severity. A bug on a public route with user input reaching it ranks higher than the same bug hidden inside an internal helper.</p></div></div>
    <div class="stats">
      <div class="stat crit"><b>${s.critical}</b><span>Critical</span></div>
      <div class="stat high"><b>${s.high}</b><span>High</span></div>
      <div class="stat med"><b>${s.medium}</b><span>Medium</span></div>
      <div class="stat low"><b>${s.low}</b><span>Low</span></div>
    </div>
    <div class="row" style="margin-top:14px">
      <button class="primary" id="correctedBtn" onclick="getCorrectedCode()">Get corrected code</button>
    </div>
    <p class="hint">Get the corrected version of this code, with the errors above fixed, to download or copy.</p>
    <div class="row" style="margin-top:14px">
      ${["All","Critical","High","Medium","Low"].map(l => `<button class="secondary" data-filter="${l}" onclick="setFilter('${l}')">${l}</button>`).join("")}
    </div>`;
  if (!findings.length) {
    html += `<p class="empty">No findings at this filter level. ${s.total === 0 ? "Clean scan — no known patterns found. That does not prove the code is perfectly secure, only that none of the checked patterns matched." : ""}</p>`;
  }
  findings.forEach(f => {
    html += `<div class="finding"><h3>${esc(f.title)}<span class="badge ${esc(f.level)}">${esc(f.level)} ${f.risk_score}/10</span></h3>
      <div class="meta">${esc(f.cwe)} &middot; Line ${f.line}${f.context.route ? " &middot; Route " + esc(f.context.route) : ""}${f.context.tainted_flow ? " &middot; User input reaches this code" : ""}${f.context.public_route ? " &middot; Public route, no login check" : ""}</div>
      <p>${esc(f.description)}</p>
      <pre>${esc(f.code)}</pre>
      <h3 style="font-size:14px">Why this score</h3><ul class="why">${f.why.map(w => `<li>${esc(w)}</li>`).join("")}</ul>
      <h3 style="font-size:14px">Secure fix</h3><pre>${esc(f.fix)}</pre></div>`;
  });
  box.innerHTML = html;
  document.querySelectorAll("[data-filter]").forEach(b => b.style.outline = b.dataset.filter === filterLevel ? "2px solid #1FC2C9" : "none");
}
let lastFixedCode = "";
async function getCorrectedCode() {
  const code = document.getElementById("code").value;
  if (!code.trim()) { alert("Paste some Python code first."); return; }
  const btn = document.getElementById("correctedBtn");
  if (btn) { btn.textContent = "Fixing..."; btn.disabled = true; }
  try {
    const r = await fetch("/api/fix", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, deployment: document.getElementById("deployment").value, sensitive_data: document.getElementById("sensitiveData").checked }) });
    const data = await r.json();
    if (!r.ok) { alert(data.error || "Fix failed"); return; }
    lastFixedCode = data.fixed_code;
    document.getElementById("correctedSummary").textContent =
      `Original: ${data.original.summary.security_score}/100 (${data.original.summary.total} findings) → Corrected: ${data.fixed.summary.security_score}/100 (${data.fixed.summary.total} findings).`;
    document.getElementById("correctedChanges").innerHTML = data.changes.map(c => `<li>${esc(c)}</li>`).join("");
    document.getElementById("correctedCode").textContent = data.fixed_code;
    document.getElementById("correctedSection").style.display = "block";
    document.getElementById("correctedSection").scrollIntoView({ behavior: "smooth" });
  } catch (e) { alert("Could not reach the server. Is it running?"); }
  finally { if (btn) { btn.textContent = "Get corrected code"; btn.disabled = false; } }
}
function copyFixed() {
  if (!lastFixedCode) return;
  navigator.clipboard.writeText(lastFixedCode).then(() => alert("Corrected code copied.")).catch(() => alert("Copy failed, select the code manually."));
}
function downloadFixed() {
  if (!lastFixedCode) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([lastFixedCode], { type: "text/plain" }));
  a.download = "corrected_code.py"; a.click(); URL.revokeObjectURL(a.href);
}
function useFixed() {
  if (!lastFixedCode) return;
  document.getElementById("code").value = lastFixedCode;
  document.getElementById("analyzer").scrollIntoView({ behavior: "smooth" });
  analyze();
}
async function analyze() {
  const code = document.getElementById("code").value;
  const btn = document.getElementById("analyzeBtn");
  btn.textContent = "Analyzing..."; btn.disabled = true;
  try {
    const r = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, deployment: document.getElementById("deployment").value, sensitive_data: document.getElementById("sensitiveData").checked }) });
    const data = await r.json();
    if (!r.ok) { alert(data.error || "Analysis failed"); return; }
    lastResult = data; filterLevel = "All";
    document.getElementById("correctedSection").style.display = "none";
    render();
    document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) { alert("Could not reach the server. Is it running?"); }
  finally { btn.textContent = "Analyze code"; btn.disabled = false; }
}
document.getElementById("analyzeBtn").onclick = analyze;
document.getElementById("copyFixedBtn").onclick = copyFixed;
document.getElementById("downloadFixedBtn").onclick = downloadFixed;
document.getElementById("useFixedBtn").onclick = useFixed;
loadSamples(); render();
