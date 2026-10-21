import { describe, expect, it } from "vitest";
import { BATCH_COUNT } from "../src/checks/checks.ts";
import { CHECKS } from "../src/checks/list.ts";
import type { ScanEvent } from "../src/checks/types.ts";
import { FROM, MAX_BODY, USER_AGENT, scanBatch } from "../src/scan.ts";

type Handler = (url: URL, init?: RequestInit) => Response | Promise<Response>;

/** A fetch that routes to handlers by URL path; anything unrouted is a 404. */
function fakeFetch(routes: Record<string, Handler>, fallback: Handler = () => new Response("not found", { status: 404 })) {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    return (routes[url.host + url.pathname] ?? routes[url.pathname] ?? fallback)(url, init);
  }) as typeof fetch;
}

async function scanAll(domain: string, f: typeof fetch, timeoutMs = 2000) {
  const events: ScanEvent[] = [];
  for (let b = 0; b < BATCH_COUNT; b++) await scanBatch(domain, b, (e) => void events.push(e), { fetch: f, timeoutMs });
  const results = new Map(events.flatMap((e) => (e.type === "result" ? [[e.path, e] as const] : [])));
  const meta = events.find((e) => e.type === "meta");
  return { meta, results };
}

describe("scanBatch", () => {
  it("finds files, follows nothing, caps bodies", async () => {
    let ua = "";
    let from = "";
    const f = fakeFetch({
      "/.well-known/nodeinfo": (_u, init) => {
        ua = new Headers(init?.headers).get("user-agent") ?? "";
        from = new Headers(init?.headers).get("from") ?? "";
        return Response.json({ links: [{ rel: "x" }] });
      },
      "/.well-known/change-password": () => new Response(null, { status: 302, headers: { location: "/settings/password" } }),
      "/robots.txt": () => new Response("User-agent: GPTBot\nDisallow: /\n"),
      "/.well-known/jwks.json": () => new Response("x".repeat(MAX_BODY * 2), { headers: { "content-type": "application/json" } }),
    });
    const { meta, results } = await scanAll("example.com", f);

    expect(meta).toMatchObject({ domain: "example.com", host: "example.com" });
    expect(results.size).toBe(CHECKS.length);
    expect(ua).toBe(USER_AGENT);
    expect(from).toBe(FROM);
    expect(results.get("/.well-known/nodeinfo")?.state).toBe("found");
    expect(results.get("/.well-known/change-password")?.state).toBe("found");
    expect(results.get("/robots.txt")?.note).toContain("GPTBot");
    expect(results.get("/humans.txt")?.state).toBe("missing");
    const jwks = results.get("/.well-known/jwks.json")!.probe;
    expect(jwks.truncated).toBe(true);
    expect(jwks.size).toBe(MAX_BODY);
  });

  it("reports homepage easter eggs without shipping the page or its headers", async () => {
    const f = fakeFetch({
      "/": () => new Response("<html><!-- Hello, developer! We're hiring. --></html>", {
        headers: { "content-type": "text/html", "x-clacks-overhead": "GNU Terry Pratchett" },
      }),
    });
    const { results } = await scanAll("example.com", f);
    const home = results.get("/")!;
    expect(home.state).toBe("found");
    expect(home.egg).toContain("GNU Terry Pratchett");
    expect(home.egg).toContain("We're hiring");
    expect(home.probe.body).toBeUndefined();
    expect(home.probe.headers).toBeUndefined();
  });

  it("switches to the www host when the homepage redirects there", async () => {
    const f = fakeFetch({
      "example.com/": () => new Response(null, { status: 301, headers: { location: "https://www.example.com/" } }),
      "www.example.com/humans.txt": () => new Response("Made by people"),
    });
    const { meta, results } = await scanAll("example.com", f);
    expect(meta).toMatchObject({ host: "www.example.com" });
    expect(results.get("/humans.txt")).toMatchObject({ state: "found", probe: { url: "https://www.example.com/humans.txt" } });
  });

  it("does not follow redirects to other domains", async () => {
    const f = fakeFetch({
      "example.com/": () => new Response(null, { status: 301, headers: { location: "https://evil.example.net/" } }),
    });
    const { meta } = await scanAll("example.com", f);
    expect(meta).toMatchObject({ host: "example.com" });
  });

  it("flags catch-all servers as fake 200s", async () => {
    const f = fakeFetch({}, () => Response.json({ app: "spa" }));
    const { results } = await scanAll("example.com", f);
    for (const path of ["/.well-known/nodeinfo", "/sitemap.xml", "/manifest.json"]) {
      expect(results.get(path)?.state, path).toBe("soft404");
    }
  });

  it("times out slow responses", async () => {
    const f = fakeFetch({
      "/humans.txt": (_u, init) =>
        new Promise((_, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason))),
    });
    const { results } = await scanAll("example.com", f, 200);
    expect(results.get("/humans.txt")).toMatchObject({ state: "error", note: "Timed out after 0.2s" });
  });
});
