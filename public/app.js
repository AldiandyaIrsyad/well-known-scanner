// Renders scan results. All fetching and judging happens in the Go Worker; this file only
// draws the check list (checks.json, generated from internal/checks) and the verdicts that
// stream back from /api/check.

const $ = (id) => document.getElementById(id);
const LABELS = {
  found: "Found",
  deprecated: "Deprecated",
  risky: "Risky",
  redirect: "Redirect",
  soft404: "Fake 200",
  invalid: "Warning",
  error: "Error",
  missing: "Missing",
  pending: "…",
};
// No "missing" chip: the point isn't for a site to have every file, so absences aren't counted.
const ORDER = ["found", "risky", "invalid", "deprecated", "soft404", "redirect", "error"];
const HIDDEN_BY_DEFAULT = ["missing"];
const isWellKnown = (c) => c.path.startsWith("/.well-known/");
const SECTIONS = [
  { title: "/.well-known/ URIs", test: isWellKnown, blurb: "A folder that standards reserve for site-wide metadata (RFC 8615), so tools know exactly where to look." },
  { title: "Root files", test: (c) => !isWellKnown(c), blurb: "Older conventions that predate /.well-known/ and live at the top of the site." },
];

const CHEVRON = `<svg class="chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

let CHECKS = [];
let BATCH_COUNT = 1;
let current = null; // { domain, host, results: Map(path -> event), done, ms }
let runId = 0;

$("showAll").checked = localGet("showAll") === "1";
$("showAll").addEventListener("change", (e) => {
  localSet("showAll", e.target.checked ? "1" : "0");
  render();
});
$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  start($("domain").value);
});
document.querySelectorAll(".examples a").forEach((a) =>
  a.addEventListener("click", (e) => {
    e.preventDefault();
    start(new URL(a.href).searchParams.get("d"));
  })
);
$("export").addEventListener("click", exportJson);

init();

async function init() {
  try {
    const data = await (await fetch("checks.json")).json();
    CHECKS = data.checks;
    BATCH_COUNT = data.batchCount;
  } catch {
    showError("Couldn't load checks.json. Run `npm run build` first.");
    return;
  }
  $("count").textContent = CHECKS.length;
  const d = new URLSearchParams(location.search).get("d");
  if (d) start(d);
}

async function start(input) {
  const domain = String(input || "").trim();
  showError("");
  if (!domain || !CHECKS.length) return;
  $("domain").value = domain;

  const id = ++runId;
  current = { domain, host: domain, results: new Map(), done: false, ms: 0 };
  $("status").hidden = false;
  $("go").disabled = true;
  $("export").disabled = true;
  render();

  const t0 = performance.now();
  try {
    await Promise.all(Array.from({ length: BATCH_COUNT }, (_, b) => runBatch(domain, b, id)));
  } catch (e) {
    if (id === runId) showError(String(e.message || e));
  } finally {
    if (id === runId) {
      current.ms = Math.round(performance.now() - t0);
      current.done = true;
      $("go").disabled = false;
      $("export").disabled = false;
      render();
    }
  }
}

async function runBatch(domain, batch, id) {
  const res = await fetch(`api/check?domain=${encodeURIComponent(domain)}&batch=${batch}`);
  if (!res.ok) {
    let msg = `Check failed (HTTP ${res.status})`;
    try {
      msg = (await res.json()).error || msg;
    } catch {}
    throw new Error(msg);
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (id !== runId) {
      reader.cancel();
      return;
    }
    buf += value;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
}

function onEvent(e) {
  if (e.type === "meta") {
    // The server normalises the input (strips scheme, path, case) and may switch to www.
    current.domain = e.domain;
    current.host = e.host || e.domain;
    $("domain").value = e.domain;
    history.replaceState(null, "", `?d=${encodeURIComponent(e.domain)}`);
    document.title = `${e.domain} · Well-Known Checker`;
  } else if (e.type === "result") {
    current.results.set(e.path, e);
  }
  scheduleRender();
}

let renderQueued = false;
function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    render();
  });
}

const stateOf = (c) => current.results.get(c.path)?.state || "pending";

function render() {
  if (!current) return;
  const showAll = $("showAll").checked;
  const counts = {};
  let doneCount = 0;
  for (const c of CHECKS) {
    const s = stateOf(c);
    if (s !== "pending") doneCount++;
    counts[s] = (counts[s] || 0) + 1;
  }

  $("bar").style.width = `${(doneCount / CHECKS.length) * 100}%`;
  const chips = ORDER.filter((s) => counts[s])
    .map((s) => `<span class="chip s-${s}">${counts[s]} ${LABELS[s].toLowerCase()}</span>`)
    .join("");
  const timing = current.done ? `<span class="chip s-pending">${(current.ms / 1000).toFixed(1)}s</span>` : "";
  $("chips").innerHTML = chips + timing;

  // Keep open <details> open across re-renders.
  const open = new Set([...document.querySelectorAll("#results details[open]")].map((d) => d.dataset.path));

  let html = "";
  for (const sec of SECTIONS) {
    const checks = CHECKS.filter(sec.test);
    const found = checks.filter((c) => !["missing", "pending"].includes(stateOf(c))).length;
    let body = "";
    for (const cat of new Set(checks.map((c) => c.cat))) {
      const shown = checks.filter((c) => c.cat === cat && (showAll || !HIDDEN_BY_DEFAULT.includes(stateOf(c))));
      if (!shown.length) continue;
      body += `<div class="group"><h3>${esc(cat)}</h3><div class="list">`;
      for (const c of shown) body += row(c, open.has(c.path));
      body += `</div></div>`;
    }
    if (!body && current.done) {
      body = `<p class="empty">Nothing here on <b>${esc(current.domain)}</b>. Tick “Show files it doesn't have” to browse all ${checks.length} and what each one is for.</p>`;
    }
    html += `<section class="section"><h2>${esc(sec.title)} <span class="count">${found} found</span></h2><p class="blurb">${esc(sec.blurb)}</p>${body}</section>`;
  }
  const moved =
    current.host !== current.domain
      ? `<p class="hostnote"><b>${esc(current.domain)}</b> redirects to <b>${esc(current.host)}</b>, so the files were checked there.</p>`
      : "";
  $("results").innerHTML = moved + html;
}

function urlFor(c) {
  return `https://${c.sub ? `${c.sub}.${current.domain}` : current.host}${c.path}`;
}

function row(c, isOpen) {
  const r = current.results.get(c.path);
  const state = r?.state || "pending";
  const p = r?.probe;
  const url = p?.url || urlFor(c);
  const tag = c.experimental ? `<span class="tag">experimental</span>` : c.deprecated ? `<span class="tag">deprecated</span>` : "";

  let detail = `<div class="detail"><p class="learn">${esc(c.learn)}</p><p class="docs">`;
  if (c.mdn) detail += `<a href="${esc(c.mdn)}" target="_blank" rel="noopener">MDN docs ↗</a>`;
  detail += `<a href="${esc(c.spec)}" target="_blank" rel="noopener">Spec · ${esc(hostOf(c.spec))} ↗</a></p>`;
  const meta = [
    ["URL", `<a href="${esc(url)}" target="_blank" rel="noopener nofollow">${esc(url)}</a>`],
    p?.status && ["Status", esc(p.status)],
    p?.location && ["Location", esc(p.location)],
    p?.contentType && ["Content-Type", esc(p.contentType)],
    p && !p.error && ["Size", `${p.size.toLocaleString()} bytes${p.truncated ? " (truncated)" : ""}`],
    p?.cors && ["CORS", esc(p.cors)],
    p && ["Time", `${p.ms} ms`],
  ].filter(Boolean);
  detail += `<dl class="meta">${meta.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join("")}</dl>`;
  if (state === "found" && c.kind === "image") {
    // <img> loads cross-origin without CORS, so the browser shows the icon straight from the site.
    detail += `<img class="preview" src="${esc(url)}" alt="${esc(c.path)} from ${esc(current.domain)}" loading="lazy">`;
  } else if (p?.body && !["missing", "pending"].includes(state)) {
    detail += `<pre>${esc(pretty(p.body, p.contentType))}</pre>`;
  }
  detail += `</div>`;

  const shownPath = c.sub ? `<span class="sub">${esc(c.sub)}.</span>${esc(c.path)}` : esc(c.path);
  return `<details class="${state}" data-path="${esc(c.path)}"${isOpen ? " open" : ""}>
    <summary>
      ${CHEVRON}
      <span class="path">${shownPath}${tag}</span>
      <span class="badge s-${state}">${LABELS[state] || state}</span>
      <span class="desc">${esc(c.desc)}${r?.note ? `<span class="note">${esc(r.note)}</span>` : ""}</span>
    </summary>${detail}</details>`;
}

function pretty(body, ct) {
  const t = body.trim();
  if (/json/i.test(ct || "") || /^[\[{]/.test(t)) {
    try {
      return JSON.stringify(JSON.parse(t), null, 2);
    } catch {}
  }
  return body.length > 8000 ? body.slice(0, 8000) + "\n…" : body;
}

function exportJson() {
  if (!current) return;
  const out = {
    domain: current.domain,
    host: current.host,
    checkedAt: new Date().toISOString(),
    results: CHECKS.map((c) => {
      const r = current.results.get(c.path) || {};
      const p = r.probe || {};
      return { path: c.path, url: p.url || urlFor(c), state: r.state, note: r.note, status: p.status, contentType: p.contentType, size: p.size };
    }),
  };
  const blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `well-known-${current.domain}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function showError(msg) {
  $("error").hidden = !msg;
  $("error").textContent = msg;
}

function hostOf(u) {
  try {
    return new URL(u).hostname.replace(/^www\./, "");
  } catch {
    return u;
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function localGet(k) {
  try {
    return localStorage.getItem(k);
  } catch {
    return null;
  }
}
function localSet(k, v) {
  try {
    localStorage.setItem(k, v);
  } catch {}
}
