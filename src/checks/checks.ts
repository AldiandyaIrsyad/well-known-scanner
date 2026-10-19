import { CHECKS } from "./list.ts";
import type { Check } from "./types.ts";

const WK = "/.well-known/";

export const isWellKnown = (c: Check) => c.path.startsWith(WK);

/**
 * Where to fetch a check. `host` is where the site actually lives (e.g. www.example.com when
 * example.com redirects there); subdomain checks like mta-sts.<domain> always hang off the
 * domain the user typed.
 */
export function urlFor(c: Check, domain: string, host = domain): string {
  return `https://${c.sub ? `${c.sub}.${domain}` : host}${c.path}`;
}

/**
 * Workers on the free plan may make 50 subrequests per invocation. Each batch also makes one
 * homepage request (canonical host) and two canary requests: 46 + 1 + 2 = 49.
 */
export const BATCH_SIZE = 46;
export const BATCH_COUNT = Math.ceil(CHECKS.length / BATCH_SIZE);
export const batchOf = (i: number) => CHECKS.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);

/** Random paths that should 404. A server that answers them with 200 answers everything with 200. */
export function canaryPaths(seed: string) {
  return { wellKnown: `${WK}wk-checker-${seed}`, root: `/wk-checker-${seed}.txt` };
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const RESERVED = /\.(local|localhost|internal|lan|home|arpa|test|invalid|example)$/;

/**
 * Accepts "example.com", "https://Example.com/foo" or "example.com." and returns "example.com".
 * Returns null for anything that isn't a public DNS name: IP literals, localhost, single labels
 * and reserved TLDs are rejected so the scanner can't be pointed at internal hosts.
 */
export function normalizeDomain(input: string | null | undefined): string | null {
  let s = String(input ?? "").trim().toLowerCase();
  if (!s) return null;
  if (!s.includes("://")) s = "https://" + s;
  let host: string;
  try {
    host = new URL(s).hostname.replace(/\.$/, "");
  } catch {
    return null;
  }
  const labels = host.split(".");
  if (host.length > 253 || labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
  if (!/^[a-z]/.test(labels.at(-1)!)) return null; // rejects IPv4 literals like 10.0.0.1
  if (RESERVED.test(host)) return null;
  return host;
}
