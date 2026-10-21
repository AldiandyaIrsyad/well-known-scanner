# Well-Known Checker

Enter a domain and see which `/.well-known/` URIs (security.txt, OpenID discovery, app links,
WebFinger, MTA-STS, A2A agent cards, …) and root files (robots.txt, ads.txt, llms.txt, humans.txt,
crossdomain.xml, …) it serves, whether each is valid, and what each one is for. It's meant as a way
for developers to discover files they didn't know existed.

**Live: https://wellknown.aldiandyainf.com/**

Built with TypeScript on Cloudflare Workers; the frontend is plain HTML/CSS/JS.

## How it works

```
browser ──GET index.html, app.js, checks.json──▶ Workers Assets (static, free)
        ──GET /api/check?domain=x&batch=0──┐
        ──GET /api/check?domain=x&batch=1──┤ in parallel
                                           ▼
                          Worker, for its batch of checks:
                            1. GET https://x/  → follow one hop only if it's x ⇄ www.x
                            2. GET two random paths (canaries) to detect catch-all 200s
                            3. GET each file, 6 at a time, 8 s timeout, 64 KB cap
                            4. judge each response, stream it back as one NDJSON line
```

- **Why a backend at all:** browsers can't read `https://other-site/.well-known/*` unless that site
  sends CORS headers, and most don't.
- **Why batches:** a Worker invocation on the free plan may make 50 outbound requests. 90 checks
  are split into 2 batches of ≤46 (+1 homepage +2 canaries = 49).
- **Capacity on Workers Free:** static asset requests are free and unlimited. Each complete scan
  uses 2 Worker requests, so the account's shared 100,000-request daily allowance supports up to
  ~50,000 scans, less other API requests and usage by other Workers. The allowance resets at
  midnight UTC (07:00 in Jakarta). This is a request-budget estimate, not a load-test result;
  the Free plan also limits each invocation to 10 ms of CPU time. Upstream responses are cached
  at the edge for 5 minutes, but cached upstream fetches do not reduce the 2 API calls per scan.
- **Abuse guards:** only fetches paths from the fixed list, never follows redirects (except the
  www hop), rejects IPs, `localhost` and internal TLDs, keeps at most 64 KB per response, and
  rate-limits each IP to 20 calls/min (10 scans).

## Layout

```
src/checks/list.ts     every check and its plain-language explanation
src/checks/analyze.ts  validation rules: response → verdict (pure, unit-tested)
src/checks/checks.ts   domain normalisation, URLs, batching
src/scan.ts            fetching, canaries, timeouts, body cap
src/index.ts           Worker entry: /api/health, /api/check (NDJSON stream)
public/                frontend; renders checks.json and the streamed verdicts
scripts/dump-checks.ts generates public/checks.json from the list (runs on dev/deploy)
test/                  Vitest suites
```

To add a check, append to `src/checks/list.ts` with a `learn` explanation. If it needs a new kind
of validation, add a case in `analyze.ts` and a test. Batches are computed automatically.

## Develop

```bash
npm install
npm run dev         # http://localhost:8787
npm test            # Vitest
npm run typecheck
```

## Deploy

```bash
npx wrangler login  # once, opens the browser
npm run deploy      # prints https://well-known-checker.<your-subdomain>.workers.dev
```

`wrangler.toml` attaches `wellknown.aldiandyainf.com` as a Custom Domain and also enables the
`workers.dev` address. Deploy from the Cloudflare account that owns the active
`aldiandyainf.com` zone. Cloudflare creates the Custom Domain's DNS record and certificate.
