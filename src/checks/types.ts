// How a response is judged.
export type Kind =
  | "json" // must parse as JSON
  | "text" // any non-HTML, non-empty body
  | "xml" // an XML document
  | "securitytxt" // RFC 9116: needs Contact: and Expires:
  | "redirect" // a 3xx elsewhere is the expected answer
  | "endpoint" // an API: 2xx, 3xx or 401 all prove it exists
  | "webfinger" // 400 without ?resource= still proves it exists
  | "mtasts" // RFC 8461 policy
  | "robots" // robots.txt, reports AI crawler rules
  | "adstxt" // ads.txt / app-ads.txt seller lines
  | "crossdomain" // Flash/Silverlight policy, wildcard = risky
  | "image" // an image file
  | "homepage" // the site's front page, searched for hidden messages in headers and HTML comments
  | "cftrace" // Cloudflare's /cdn-cgi/trace diagnostics page
  | "any"; // anything non-HTML with a 2xx

export interface Check {
  path: string;
  cat: string;
  kind: Kind;
  /** Fetched from <sub>.<domain> instead of the site host. */
  sub?: string;
  /** When it was deprecated, e.g. "2026-04". */
  deprecated?: string;
  experimental?: boolean;
  /** Shown in the first group of useful starting points, before topic groups. */
  featured?: boolean;
  desc: string;
  spec: string;
  /** MDN page, only where one genuinely covers this file. */
  mdn?: string;
  learn: string;
}

/** The raw outcome of fetching one URL. */
export interface Probe {
  url: string;
  status?: number;
  contentType?: string;
  location?: string;
  cors?: string;
  size: number;
  truncated?: boolean;
  body?: string;
  ms: number;
  error?: string;
  /** All response headers; only collected for the homepage check. */
  headers?: Record<string, string>;
}

export type State =
  | "found"
  | "deprecated" // found, but the standard is retired
  | "risky" // found, and configured dangerously
  | "redirect" // an unexpected 3xx
  | "soft404" // 200, but the same page the server returns for anything
  | "invalid" // present but doesn't follow its spec
  | "error" // network error or timeout
  | "missing";

export interface Verdict {
  state: State;
  note: string;
  /** A hidden message found in the response: a job ad, a joke header, ASCII art. */
  egg?: string;
}

/** One line of the NDJSON stream from /api/check. */
export type ScanEvent =
  | { type: "meta"; domain: string; host: string; batch: number }
  | { type: "result"; batch: number; path: string; state: State; note: string; egg?: string; probe: Probe }
  | { type: "done"; batch: number; ms: number };
