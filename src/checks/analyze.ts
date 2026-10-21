import { isWellKnown } from "./checks.ts";
import type { Check, Probe, Verdict } from "./types.ts";

/**
 * Judges one probe. `canary` is the probe of a random path in the same area (/.well-known/ or
 * root), used to spot servers that answer 200 for everything.
 */
export function analyze(c: Check, p: Probe, canary?: Probe, now = new Date()): Verdict {
  const v = judge(c, p, canary, now);
  if (c.deprecated && v.state === "found") {
    return { state: "deprecated", note: `Deprecated since ${c.deprecated} · ${v.note}` };
  }
  return v;
}

function judge(c: Check, p: Probe, canary: Probe | undefined, now: Date): Verdict {
  if (p.error) {
    // Most domains have no mta-sts.<domain>; a host that doesn't resolve means "not set up".
    if (c.sub && !/timed out/i.test(p.error)) return { state: "missing", note: `${c.sub} subdomain not reachable` };
    return { state: "error", note: p.error };
  }
  const s = p.status ?? 0;
  const body = p.body ?? "";
  if (s === 429) return { state: "error", note: "HTTP 429 (rate limited; file availability unknown)" };
  if (s >= 500 && s < 600) return { state: "error", note: `HTTP ${s} (upstream server error; file availability unknown)` };

  // The homepage is supposed to be HTML and to look like every other page, so it skips the fake-200 rules.
  if (c.kind === "homepage") return judgeHomepage(p);

  if (s >= 300 && s < 400) {
    const where = p.location ? ` → ${p.location}` : "";
    if (c.kind === "redirect" || c.kind === "endpoint") return { state: "found", note: `Redirects${where}` };
    return { state: "redirect", note: `HTTP ${s}${where}` };
  }
  if (c.kind === "webfinger" && s === 400) {
    return { state: "found", note: "Endpoint exists (400 without ?resource= is the expected reply)" };
  }
  if (c.kind === "endpoint" && s === 401) return { state: "found", note: "Endpoint exists (asks for login)" };
  if (s === 404 || s === 410) return { state: "missing", note: `HTTP ${s}` };
  if (s === 401 || s === 403) return { state: "missing", note: `HTTP ${s} (forbidden)` };
  if (s < 200 || s >= 300) return { state: "missing", note: `HTTP ${s}` };

  // 2xx from here on. Catch-all servers (SPAs, some CDNs) return the same page for every path.
  if (
    canary && !canary.error && (canary.status ?? 0) >= 200 && (canary.status ?? 0) < 300 &&
    canary.size === p.size && canary.contentType === p.contentType
  ) {
    return { state: "soft404", note: "Same response as a random path: the server answers 200 for everything" };
  }
  if (isHtml(p.contentType, body) && c.kind !== "redirect") {
    return { state: "soft404", note: "Returned an HTML page instead of the expected file" };
  }

  switch (c.kind) {
    case "json":
    case "webfinger": {
      let data: unknown;
      try {
        data = JSON.parse(body);
      } catch {
        if (p.truncated) return { state: "found", note: "Large file (JSON not fully checked)" };
        return { state: "invalid", note: "Present but not valid JSON" };
      }
      return { state: "found", note: summarizeJson(c, data) };
    }
    case "securitytxt":
      return judgeSecurityTxt(c, body, now);
    case "mtasts": {
      const f = fields(body);
      if (f.version !== "STSv1" || !f.mode) return { state: "invalid", note: "Missing version: STSv1 or mode:" };
      return { state: "found", note: `mode: ${f.mode}${f.mode === "testing" ? " (reports only, doesn't enforce yet)" : ""}` };
    }
    case "xml":
      return judgeXml(body, p.truncated);
    case "cftrace": {
      const f = fields(body.replace(/=/g, ":"));
      if (!f.colo) return { state: "invalid", note: "Not a Cloudflare trace page" };
      const parts = [`answered by Cloudflare data center ${f.colo}`, f.http?.toUpperCase(), f.tls].filter(Boolean);
      return { state: "found", note: parts.join(" · ") };
    }
    case "robots":
      return judgeRobots(body);
    case "adstxt":
      return judgeAdsTxt(body, p.truncated);
    case "crossdomain":
      return judgeCrossDomain(body);
    case "image": {
      const ct = (p.contentType ?? "").toLowerCase();
      if (ct.startsWith("image/") || ct.includes("octet-stream")) {
        return { state: "found", note: `${ct.split(";")[0].trim()} · ${fmtSize(p.size, p.truncated)}` };
      }
      // Some servers send real images with the wrong label; the file's first bytes tell the truth.
      const actual = sniffImage(body);
      if (actual) return { state: "invalid", note: `${actual} image, but served as "${ct || "no content-type"}" instead of an image type` };
      return { state: "invalid", note: `Not an image (${ct || "no content-type"})` };
    }
    case "text":
      if (!body.trim()) return { state: "invalid", note: "Empty file" };
      return { state: "found", note: firstLine(body) };
    default:
      return { state: "found", note: p.size ? fmtSize(p.size, p.truncated) : "Present (empty body)" };
  }
}

const isHtml = (ct = "", body = "") =>
  /text\/html|application\/xhtml/i.test(ct) || /^\s*(<!doctype html|<html|<head|<body)/i.test(body);

/** Trimmed lines with # comments removed, empty ones dropped. */
const lines = (body: string) =>
  body.split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean);

/** Splits "Key: value" into a lower-cased key and a trimmed value. */
function keyValue(line: string): [string, string] | null {
  const i = line.indexOf(":");
  if (i < 0) return null;
  return [line.slice(0, i).trim().toLowerCase(), line.slice(i + 1).trim()];
}

/** First value for each key in a "Key: value" file. */
function fields(body: string): Record<string, string> {
  const m: Record<string, string> = {};
  for (const l of lines(body)) {
    const kv = keyValue(l);
    if (kv && !(kv[0] in m)) m[kv[0]] = kv[1];
  }
  return m;
}

function judgeSecurityTxt(c: Check, body: string, now: Date): Verdict {
  let contacts = 0;
  let expires = "";
  const hiring: string[] = [];
  for (const l of body.split("\n")) {
    const kv = keyValue(l);
    if (kv?.[0] === "contact") contacts++;
    if (kv?.[0] === "expires" && !expires) expires = kv[1];
    if (kv?.[0] === "hiring") hiring.push(kv[1]);
  }
  if (!contacts) return { state: "invalid", note: "No Contact: field (required by RFC 9116)" };
  let note = `${contacts} contact${contacts > 1 ? "s" : ""}`;
  let bad = false;
  if (!expires) {
    note += " · no Expires: field (required)";
    bad = true;
  } else {
    const d = new Date(expires);
    if (!isNaN(d.getTime())) {
      const day = d.toISOString().slice(0, 10);
      bad = d < now;
      note += bad ? ` · EXPIRED ${day}` : ` · expires ${day}`;
    }
  }
  if (body.includes("-----BEGIN PGP SIGNED MESSAGE-----")) note += " · signed";
  if (!isWellKnown(c)) note += " · old location";
  // Hiring is ordinary security.txt metadata, not a hidden message.
  if (hiring.length) note += " · hiring link";
  return { state: bad ? "invalid" : "found", note };
}

function judgeXml(body: string, truncated?: boolean): Verdict {
  const t = body.replace(/^﻿/, "").trim();
  if (!t.startsWith("<")) return { state: "invalid", note: "Not an XML document" };
  const name = t.replace(/<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<![^>]*>/g, "").trim().match(/^<([A-Za-z][\w:.-]*)/)?.[1] ?? "";
  const plus = truncated ? "+" : "";
  if (/^urlset$/i.test(name)) return { state: "found", note: `${(t.match(/<url>/gi) ?? []).length}${plus} page URLs` };
  if (/^sitemapindex$/i.test(name)) return { state: "found", note: `Index of ${(t.match(/<sitemap>/gi) ?? []).length}${plus} sitemaps` };
  if (/^OpenSearchDescription$/i.test(name)) {
    const short = t.match(/<ShortName>([^<]*)<\/ShortName>/i)?.[1]?.trim();
    return { state: "found", note: short ? `Browser search engine: "${short}"` : "Browser search engine" };
  }
  return { state: "found", note: name ? `<${name}> document` : "XML document" };
}

/** Crawler user-agents that collect data for AI models or AI answers. */
export const AI_BOTS = [
  "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-User", "Claude-SearchBot", "anthropic-ai",
  "Google-Extended", "CCBot", "PerplexityBot", "Bytespider", "Applebot-Extended", "meta-externalagent",
  "Amazonbot", "cohere-ai", "Diffbot", "FacebookBot", "MistralAI-User", "DeepSeekBot",
];

function judgeRobots(body: string): Verdict {
  type Group = { agents: string[]; blockAll: boolean; hasRules: boolean };
  const groups: Group[] = [];
  let cur: Group | null = null;
  let sitemaps = 0;
  let signal = "";
  let recognised = false;

  for (const l of lines(body)) {
    const kv = keyValue(l);
    if (!kv) continue;
    const [k, v] = kv;
    if (k === "user-agent") {
      recognised = true;
      // Consecutive User-agent lines share the rules that follow them.
      if (!cur || cur.hasRules) groups.push((cur = { agents: [], blockAll: false, hasRules: false }));
      cur.agents.push(v.toLowerCase());
    } else if (k === "disallow" || k === "allow") {
      recognised = true;
      if (cur) {
        cur.hasRules = true;
        if (k === "disallow" && v === "/") cur.blockAll = true;
      }
    } else if (k === "sitemap") {
      recognised = true;
      sitemaps++;
    } else if (k === "content-signal" && !signal) {
      signal = v;
    }
  }
  if (!recognised) return { state: "invalid", note: "No User-agent / Disallow / Sitemap lines" };

  const blocks = (agent: string) => groups.some((g) => g.blockAll && g.agents.includes(agent));
  const blocked = AI_BOTS.filter((b) => blocks(b.toLowerCase()));
  const everyone = blocks("*");

  const parts: string[] = [];
  if (everyone) parts.push("blocks all crawlers");
  if (blocked.length) {
    const list = blocked.slice(0, 4).join(", ") + (blocked.length > 4 ? "…" : "");
    parts.push(`blocks ${blocked.length} AI bot${blocked.length > 1 ? "s" : ""}: ${list}`);
  } else if (!everyone) parts.push("no AI bots blocked");
  if (signal) parts.push(`Content-Signal: ${signal}`);
  if (sitemaps) parts.push(`${sitemaps} sitemap${sitemaps > 1 ? "s" : ""}`);
  const egg = robotsEgg(body);
  if (egg) parts.push("hidden message in comments");
  return { state: "found", note: parts.join(" · "), egg };
}

function judgeAdsTxt(body: string, truncated?: boolean): Verdict {
  let total = 0;
  let direct = 0;
  for (const l of lines(body)) {
    const f = l.split(",").map((x) => x.trim());
    if (f.length < 3 || !f[0] || !f[1]) continue;
    const rel = f[2].toUpperCase();
    if (rel === "DIRECT") direct++;
    if (rel === "DIRECT" || rel === "RESELLER") total++;
  }
  if (!total) return { state: "invalid", note: "No valid seller lines (domain, id, DIRECT|RESELLER)" };
  return { state: "found", note: `${total}${truncated ? "+" : ""} sellers · ${direct} direct, ${total - direct} reseller` };
}

function judgeCrossDomain(body: string): Verdict {
  if (/<allow-access-from[^>]*domain\s*=\s*["']\*["']/i.test(body) || /<domain[^>]*uri\s*=\s*["']\*["']/i.test(body)) {
    return { state: "risky", note: "Wildcard policy: any website may read this domain's responses" };
  }
  if (!/^\s*﻿?\s*</.test(body)) return { state: "invalid", note: "Not an XML document" };
  return { state: "found", note: "Restricted to listed domains" };
}

function summarizeJson(c: Check, d: unknown): string {
  const p = c.path.replace("/.well-known/", "");
  const o = (d && typeof d === "object" && !Array.isArray(d) ? d : {}) as Record<string, any>;
  const count = (v: unknown) => (Array.isArray(v) ? v.length : v && typeof v === "object" ? Object.keys(v).length : 0);
  try {
    switch (p) {
      case "openid-configuration":
      case "oauth-authorization-server":
        if (o.issuer) return `issuer: ${o.issuer}`;
        break;
      case "oauth-protected-resource":
        if (o.resource) return `resource: ${o.resource}`;
        break;
      case "jwks.json":
        return `${count(o.keys)} key(s)`;
      case "assetlinks.json":
        if (Array.isArray(d)) {
          const names = [...new Set(d.map((s: any) => s?.target?.package_name || s?.target?.site).filter(Boolean))];
          return `${d.length} statement(s): ${names.slice(0, 3).join(", ")}`;
        }
        break;
      case "apple-app-site-association":
        return Object.keys(o).sort().join(", ");
      case "nodeinfo":
        return `${count(o.links)} schema link(s)`;
      case "matrix/server":
        if (o["m.server"]) return `server: ${o["m.server"]}`;
        break;
      case "matrix/client":
        if (o["m.homeserver"]) return `homeserver: ${o["m.homeserver"].base_url}`;
        break;
      case "nostr.json":
        return `${count(o.names)} name(s)`;
      case "gpc.json":
        if ("gpc" in o) return `gpc: ${o.gpc}`;
        break;
      case "web-identity":
        return `${count(o.provider_urls)} provider config(s)`;
      case "agent-card.json":
      case "agent.json":
      case "ai-plugin.json":
        if (o.name || o.name_for_human) return o.name || o.name_for_human;
        break;
      case "http-message-signatures-directory":
        return `${count(o.keys)} bot signing key(s)`;
      case "did.json":
        if (o.id) return `id: ${o.id}`;
        break;
      case "/site.webmanifest":
      case "/manifest.json":
        return `${o.name || o.short_name || "unnamed"} · ${count(o.icons)} icon(s)${o.display ? ` · ${o.display}` : ""}`;
      case "/sellers.json":
        return `${count(o.sellers)} sellers`;
    }
  } catch {
    /* odd shapes fall through to the generic summary */
  }
  if (Array.isArray(d)) return `Valid JSON · array of ${d.length}`;
  return `Valid JSON · ${Object.keys(o).slice(0, 4).join(", ")}`;
}

// ───── Easter eggs ─────
// Developers hide jokes and job ads where only other developers look. These detectors are
// deliberately conservative: a few known patterns rather than guessing at every comment.

const EGG_WORDS =
  /\b(we(?:'| a)?re hiring|hiring|careers?|recruit\w*|join (?:us|our team)|reading this|hello,? (?:there|developer|friend|world)|curious|easter egg|clacks)\b/i;

/** Mostly drawing characters over several lines: ASCII art. */
function isAsciiArt(text: string) {
  const rows = text.split("\n").filter((l) => l.trim());
  if (rows.length < 3) return false;
  const chars = text.replace(/\s/g, "");
  const drawing = chars.replace(/[A-Za-z0-9]/g, "").length;
  return chars.length >= 30 && drawing / chars.length >= 0.5;
}

/** Comment lines in robots.txt that read like a message to humans. */
function robotsEgg(body: string): string | undefined {
  const comments = body
    .split("\n")
    .filter((l) => l.trimStart().startsWith("#"))
    .map((l) => l.trimStart().replace(/^#\s?/, "").trimEnd());
  const text = comments.join("\n").trim();
  if (!text || !(EGG_WORDS.test(text) || isAsciiArt(text))) return undefined;
  return clip(text, 30);
}

// Headers whose values routinely mention other domains or job-like words for boring reasons.
const NOISY_HEADERS = new Set([
  "content-security-policy", "content-security-policy-report-only", "set-cookie", "link", "location",
  "report-to", "reporting-endpoints", "nel", "permissions-policy", "feature-policy", "alt-svc", "server-timing",
]);

function headerEggs(headers: Record<string, string> = {}): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (NOISY_HEADERS.has(k) || k.startsWith("access-control-") || v.length > 300) continue;
    if (k === "x-clacks-overhead" || EGG_WORDS.test(`${k} ${v}`)) out.push(`${k}: ${v}`);
  }
  return out;
}

function commentEggs(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<!--([\s\S]*?)-->/g)) {
    const text = m[1].replace(/^\s*\n/, "").trimEnd();
    if (text.trim().length < 10 || text.length > 4000 || /^\s*\[(?:if|endif)/i.test(text)) continue;
    if (EGG_WORDS.test(text) || isAsciiArt(text)) out.push(clip(text, 25));
    if (out.length === 3) break;
  }
  return out;
}

function judgeHomepage(p: Probe): Verdict {
  const s = p.status ?? 0;
  if (s >= 300 && s < 400) return { state: "missing", note: `Homepage redirects${p.location ? ` to ${p.location}` : ""} (not followed)` };
  if (s < 200 || s >= 300) return { state: "missing", note: `HTTP ${s}` };
  const headers = headerEggs(p.headers);
  const comments = commentEggs(p.body ?? "");
  if (!headers.length && !comments.length) return { state: "missing", note: "No hidden messages found" };
  const sections: string[] = [];
  if (headers.length) sections.push(`In the HTTP response headers:\n${headers.join("\n")}`);
  if (comments.length) sections.push(`In the page's HTML comments:\n${comments.join("\n\n---\n\n")}`);
  const n = headers.length + comments.length;
  return { state: "found", note: `${n} hidden message${n > 1 ? "s" : ""}`, egg: sections.join("\n\n") };
}

/** First `maxLines` lines, so one giant comment can't flood the page. */
function clip(text: string, maxLines: number) {
  const rows = text.split("\n");
  return rows.length > maxLines ? rows.slice(0, maxLines).join("\n") + "\n…" : text;
}

/**
 * Recognises an image from its "magic number". The body arrives as decoded text, so bytes above
 * 0x7F (like PNG's leading 0x89) may have become U+FFFD; the checks only rely on ASCII bytes.
 */
function sniffImage(body: string): string | null {
  if (body.slice(1, 4) === "PNG") return "PNG";
  if (body.startsWith("GIF8")) return "GIF";
  if (body.startsWith("RIFF") && body.slice(8, 12) === "WEBP") return "WebP";
  if (body.startsWith("\0\0\u0001\0")) return "ICO";
  if (/^\s*(<\?xml[^>]*>\s*)?<svg[\s>]/i.test(body)) return "SVG";
  return null;
}

function fmtSize(n: number, truncated?: boolean) {
  if (truncated) return `${Math.floor(n / 1024)}+ KB`;
  return n < 1024 ? `${n} bytes` : `${(n / 1024).toFixed(1)} KB`;
}

function firstLine(body: string) {
  const line = body.trim().split(/\r?\n/)[0].trim();
  return line.length > 80 ? line.slice(0, 77) + "…" : line;
}
