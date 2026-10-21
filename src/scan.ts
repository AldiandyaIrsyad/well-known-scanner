import { analyze } from "./checks/analyze.ts";
import { batchOf, canaryPaths, isWellKnown, urlFor } from "./checks/checks.ts";
import type { Probe, ScanEvent } from "./checks/types.ts";

export const MAX_BODY = 64 * 1024; // bytes kept per response
// Many sites (Tokopedia, for one) silently stall any request whose User-Agent isn't a plain
// browser string, even with a browser string plus our name appended. So we send a normal Chrome
// User-Agent, and identify ourselves in the standard From header instead, so admins reading
// their logs can still see what this is. Bump the Chrome version now and then: very old
// versions start to look suspicious too.
export const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
export const FROM = "https://wellknown.aldiandyainf.com/#about";

export interface ScanOptions {
  /** Injected for tests; defaults to the global fetch. */
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Workers allow 6 open connections per invocation; more just queue. */
  concurrency?: number;
  /** Cloudflare edge-cache TTL for upstream responses, so repeat scans are cheap. */
  cacheTtl?: number;
  /** Collect every response header into the probe (only the homepage check needs them). */
  keepHeaders?: boolean;
}

/**
 * Scans one batch of checks for `domain` (already normalised) and calls `emit` for each event:
 * meta first, then one result per check in completion order, then done.
 */
export async function scanBatch(domain: string, batch: number, emit: (e: ScanEvent) => void | Promise<void>, opts: ScanOptions = {}) {
  const started = Date.now();
  const probe = (url: string) => probeUrl(url, opts);

  const host = await canonicalHost(domain, probe);
  await emit({ type: "meta", domain, host, batch });

  // Canaries first: every verdict needs them to tell real files from catch-all 200 pages.
  const paths = canaryPaths(crypto.randomUUID().slice(0, 8));
  const [wkCanary, rootCanary] = await Promise.all([
    probe(`https://${host}${paths.wellKnown}`),
    probe(`https://${host}${paths.root}`),
  ]);

  await pool(batchOf(batch), opts.concurrency ?? 6, async (c) => {
    const p = await probeUrl(urlFor(c, domain, host), { ...opts, keepHeaders: c.kind === "homepage" });
    const v = analyze(c, p, isWellKnown(c) ? wkCanary : rootCanary);
    // Binary images are shown straight from the site; the homepage's HTML and headers are only
    // needed to find the hidden messages, which travel in `egg`.
    if (c.kind === "image" || c.kind === "homepage") {
      delete p.body;
      delete p.headers;
    }
    await emit({ type: "result", batch, path: c.path, state: v.state, note: v.note, egg: v.egg, probe: p });
  });

  await emit({ type: "done", batch, ms: Date.now() - started });
}

/**
 * Many sites send everything on example.com to www.example.com (or the reverse); without this
 * every check would just report that redirect. Only that one hop is followed, so the scanner
 * can't be steered to arbitrary hosts.
 */
async function canonicalHost(domain: string, probe: (url: string) => Promise<Probe>) {
  const p = await probe(`https://${domain}/`);
  if (p.error || !p.status || p.status < 300 || p.status >= 400 || !p.location) return domain;
  try {
    const to = new URL(p.location, `https://${domain}/`).hostname.toLowerCase();
    if (to === `www.${domain}` || `www.${to}` === domain) return to;
  } catch {}
  return domain;
}

export async function probeUrl(url: string, opts: ScanOptions = {}): Promise<Probe> {
  const t0 = Date.now();
  const timeoutMs = opts.timeoutMs ?? 8000;
  try {
    const res = await (opts.fetch ?? fetch)(url, {
      method: "GET",
      redirect: "manual", // a redirect is part of the answer
      headers: { "user-agent": USER_AGENT, from: FROM, accept: "*/*" },
      signal: AbortSignal.timeout(timeoutMs),
      ...(opts.cacheTtl ? { cf: { cacheTtl: opts.cacheTtl, cacheEverything: true } } : {}),
    });
    const { text, size, truncated } = await readCapped(res);
    return {
      url,
      status: res.status,
      contentType: res.headers.get("content-type") ?? "",
      location: res.headers.get("location") ?? "",
      cors: res.headers.get("access-control-allow-origin") ?? "",
      size,
      truncated,
      body: text,
      ms: Date.now() - t0,
      ...(opts.keepHeaders ? { headers: Object.fromEntries(res.headers) } : {}),
    };
  } catch (e: any) {
    const error = e?.name === "TimeoutError" ? `Timed out after ${timeoutMs / 1000}s` : String(e?.message ?? e);
    return { url, size: 0, error, ms: Date.now() - t0 };
  }
}

/** Reads at most MAX_BODY bytes, then cancels the rest of the download. */
async function readCapped(res: Response) {
  if (!res.body) return { text: "", size: 0, truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > MAX_BODY) {
      chunks.push(value.subarray(0, MAX_BODY - size));
      size = MAX_BODY;
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  const buf = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return { text: new TextDecoder().decode(buf), size, truncated };
}

async function pool<T>(items: T[], n: number, fn: (item: T) => Promise<void>) {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) await fn(items[i++]);
    })
  );
}
