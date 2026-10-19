import { describe, expect, it } from "vitest";
import { analyze } from "../src/checks/analyze.ts";
import { BATCH_COUNT, BATCH_SIZE, batchOf, normalizeDomain, urlFor } from "../src/checks/checks.ts";
import { CHECKS } from "../src/checks/list.ts";
import type { Probe, State } from "../src/checks/types.ts";

const check = (path: string) => {
  const c = CHECKS.find((c) => c.path === path);
  if (!c) throw new Error(`no check for ${path}`);
  return c;
};
const ok = (body: string, contentType = "text/plain"): Probe => ({ url: "", status: 200, contentType, body, size: body.length, ms: 0 });
const status = (s: number, extra: Partial<Probe> = {}): Probe => ({ url: "", status: s, size: 0, ms: 0, ...extra });

const NOW = new Date("2026-10-20T00:00:00Z");
const FUTURE = "2027-10-20T00:00:00Z";

const cases: [name: string, path: string, probe: Probe, want: State, note: string, canary?: Probe][] = [
  ["404 is missing", "/.well-known/security.txt", status(404), "missing", "HTTP 404"],
  ["network error", "/.well-known/nodeinfo", { url: "", size: 0, ms: 0, error: "connection refused" }, "error", "refused"],
  ["unresolvable subdomain is missing", "/.well-known/mta-sts.txt", { url: "", size: 0, ms: 0, error: "internal error" }, "missing", "subdomain"],
  ["subdomain timeout is still an error", "/.well-known/mta-sts.txt", { url: "", size: 0, ms: 0, error: "Timed out after 8s" }, "error", "Timed out"],

  ["security.txt valid", "/.well-known/security.txt", ok(`Contact: mailto:sec@example.com\nExpires: ${FUTURE}\n`), "found", "1 contact · expires 2027-10-20"],
  ["security.txt expired", "/.well-known/security.txt", ok("Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z\n"), "invalid", "EXPIRED 2020-01-01"],
  ["security.txt without Expires", "/.well-known/security.txt", ok("Contact: mailto:a@b.c\nContact: https://b.c/r\n"), "invalid", "2 contacts · no Expires"],
  ["security.txt without Contact", "/.well-known/security.txt", ok(`Expires: ${FUTURE}`), "invalid", "No Contact"],
  ["root security.txt notes old location", "/security.txt", ok(`Contact: mailto:a@b.c\nExpires: ${FUTURE}`), "found", "old location"],

  ["HTML instead of JSON is a fake 200", "/.well-known/assetlinks.json", ok("<!DOCTYPE html><html></html>", "text/html"), "soft404", "HTML page"],
  ["same as canary is a fake 200", "/.well-known/nodeinfo", ok(`{"a":1}`, "application/json"), "soft404", "random path",
    { url: "", status: 200, contentType: "application/json", size: 7, ms: 0 }],
  ["canary 404 doesn't affect a real file", "/.well-known/nodeinfo", ok(`{"links":[{},{}]}`, "application/json"), "found", "2 schema link(s)", status(404, { size: 17 })],
  ["broken JSON", "/.well-known/jwks.json", ok(`{"keys": [`, "application/json"), "invalid", "not valid JSON"],
  ["truncated JSON is still found", "/.well-known/jwks.json", { ...ok(`{"keys": [`), truncated: true }, "found", "Large file"],
  ["openid issuer", "/.well-known/openid-configuration", ok(`{"issuer":"https://id.example.com"}`, "application/json"), "found", "issuer: https://id.example.com"],

  ["change-password redirect is the answer", "/.well-known/change-password", status(302, { location: "/account/password" }), "found", "→ /account/password"],
  ["unexpected redirect", "/.well-known/nodeinfo", status(301, { location: "https://www.example.com/x" }), "redirect", "HTTP 301"],
  ["webfinger 400 proves the endpoint", "/.well-known/webfinger", status(400), "found", "resource"],
  ["jmap 401 proves the endpoint", "/.well-known/jmap", status(401), "found", "login"],
  ["403 elsewhere is missing", "/.well-known/nodeinfo", status(403), "missing", "forbidden"],

  ["mta-sts enforce", "/.well-known/mta-sts.txt", ok("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"), "found", "mode: enforce"],
  ["mta-sts testing", "/.well-known/mta-sts.txt", ok("version: STSv1\nmode: testing\n"), "found", "doesn't enforce"],
  ["mta-sts missing version", "/.well-known/mta-sts.txt", ok("mode: enforce\n"), "invalid", "STSv1"],

  ["sitemap urlset", "/sitemap.xml", ok(`<?xml version="1.0"?><urlset><url><loc>a</loc></url><url><loc>b</loc></url></urlset>`, "application/xml"), "found", "2 page URLs"],
  ["sitemap index with BOM and comment", "/sitemap.xml",
    ok(`﻿<?xml version="1.0"?><!-- hi --><sitemapindex><sitemap></sitemap><sitemap></sitemap></sitemapindex>`, "text/xml"), "found", "Index of 2 sitemaps"],
  ["host-meta root element", "/.well-known/host-meta", ok(`<?xml version='1.0'?><XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'></XRD>`, "application/xrd+xml"), "found", "<XRD>"],

  ["ads.txt counts", "/ads.txt", ok("# comment\ngoogle.com, pub-1, DIRECT, f08c47fec0942fa0\nappnexus.com, 2, RESELLER\nbad line\n"), "found", "2 sellers · 1 direct, 1 reseller"],
  ["ads.txt with no sellers", "/ads.txt", ok("# nothing here\n"), "invalid", "No valid seller"],

  ["crossdomain wildcard is risky", "/crossdomain.xml", ok(`<cross-domain-policy><allow-access-from domain = "*" /></cross-domain-policy>`, "text/xml"), "risky", "Wildcard"],
  ["crossdomain restricted", "/crossdomain.xml", ok(`<cross-domain-policy><allow-access-from domain="*.example.com"/></cross-domain-policy>`, "text/xml"), "found", "Restricted"],
  ["silverlight wildcard", "/clientaccesspolicy.xml", ok(`<access-policy><allow-from><domain uri='*'/></allow-from></access-policy>`, "text/xml"), "risky", "Wildcard"],

  ["favicon", "/favicon.ico", { url: "", status: 200, contentType: "image/x-icon", size: 1660, ms: 0 }, "found", "image/x-icon · 1.6 KB"],
  ["favicon served as text", "/favicon.ico", ok("nope"), "invalid", "Not an image"],

  ["deprecated file", "/.well-known/related-website-set.json", ok(`{"primary":"https://example.com"}`, "application/json"), "deprecated", "Deprecated since 2026-04"],
  ["empty text file", "/humans.txt", ok("  \n"), "invalid", "Empty"],
];

describe("analyze", () => {
  it.each(cases)("%s", (_name, path, probe, want, note, canary) => {
    const v = analyze(check(path), probe, canary, NOW);
    expect(v.state).toBe(want);
    expect(v.note).toContain(note);
  });

  it("reports AI crawler rules in robots.txt", () => {
    const body = `# AI crawlers
User-agent: GPTBot
User-agent: ClaudeBot
Disallow: /

User-agent: CCBot
Disallow: /private/

User-agent: *
Allow: /
Content-Signal: search=yes, ai-train=no

Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/news.xml
`;
    expect(analyze(check("/robots.txt"), ok(body)).note).toBe(
      "blocks 2 AI bots: GPTBot, ClaudeBot · Content-Signal: search=yes, ai-train=no · 2 sitemaps"
    );
    expect(analyze(check("/robots.txt"), ok("User-agent: *\nDisallow: /\n")).note).toBe("blocks all crawlers");
    expect(analyze(check("/robots.txt"), ok("hello world")).state).toBe("invalid");
  });
});

describe("normalizeDomain", () => {
  it.each([
    ["example.com", "example.com"],
    ["  Example.COM.  ", "example.com"],
    ["https://www.example.com/path", "www.example.com"],
    ["http://example.com:8080", "example.com"],
    ["sub.domain.co.uk", "sub.domain.co.uk"],
    ["localhost", null],
    ["127.0.0.1", null],
    ["10.0.0.1", null],
    ["[::1]", null],
    ["printer.local", null],
    ["metadata.internal", null],
    ["-bad.com", null],
    ["under_score.com", null],
    ["", null],
  ])("%j -> %j", (input, want) => {
    expect(normalizeDomain(input)).toBe(want);
  });
});

describe("check list", () => {
  it("is split into batches that fit the subrequest limit", () => {
    const sizes = Array.from({ length: BATCH_COUNT }, (_, i) => batchOf(i).length);
    expect(sizes.every((n) => n > 0 && n <= BATCH_SIZE)).toBe(true);
    expect(sizes.reduce((a, b) => a + b)).toBe(CHECKS.length);
  });

  it("has unique, complete entries", () => {
    expect(new Set(CHECKS.map((c) => c.path)).size).toBe(CHECKS.length);
    for (const c of CHECKS) {
      expect(c.path.startsWith("/") && c.desc && c.learn && c.spec.startsWith("http"), c.path).toBeTruthy();
    }
  });

  it("builds URLs on the right host", () => {
    expect(urlFor(check("/.well-known/mta-sts.txt"), "example.com", "www.example.com")).toBe("https://mta-sts.example.com/.well-known/mta-sts.txt");
    expect(urlFor(check("/robots.txt"), "example.com", "www.example.com")).toBe("https://www.example.com/robots.txt");
  });
});
