// Cloudflare Worker. Static files in /public are served by Workers Assets (free, not billed as
// invocations); only /api/* reaches this code (see run_worker_first in wrangler.toml).
//
//   GET /api/health                  -> {"ok":true,"batches":N}
//   GET /api/check?domain=x&batch=i  -> NDJSON stream of ScanEvent
//
// The browser fires all batches in parallel and renders events as they arrive.

import { BATCH_COUNT, normalizeDomain } from "./checks/checks.ts";
import { scanBatch } from "./scan.ts";

export interface Env {
  /** Optional; see wrangler.toml. Absent (e.g. in tests) means no limit. */
  RATE_LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") return json({ ok: true, batches: BATCH_COUNT });
    if (url.pathname !== "/api/check") return json({ error: "Not found" }, 404);
    if (request.method !== "GET") return json({ error: "GET only" }, 405);

    const domain = normalizeDomain(url.searchParams.get("domain"));
    if (!domain) return json({ error: "Enter a public domain name, e.g. example.com" }, 400);
    const batch = Number(url.searchParams.get("batch") ?? 0);
    if (!Number.isInteger(batch) || batch < 0 || batch >= BATCH_COUNT) return json({ error: "Bad batch" }, 400);

    if (env.RATE_LIMITER) {
      const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
      const { success } = await env.RATE_LIMITER.limit({ key: ip });
      if (!success) return json({ error: "Too many checks. Wait a minute and try again." }, 429);
    }

    const { readable, writable } = new TransformStream<Uint8Array>();
    const writer = writable.getWriter();
    const enc = new TextEncoder();
    ctx.waitUntil(
      scanBatch(domain, batch, (e) => writer.write(enc.encode(JSON.stringify(e) + "\n")), { cacheTtl: 300 })
        .catch((e) => writer.write(enc.encode(JSON.stringify({ type: "fatal", error: String(e?.message ?? e) }) + "\n")))
        .finally(() => writer.close())
    );
    return new Response(readable, {
      headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store" },
    });
  },
} satisfies ExportedHandler<Env>;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
