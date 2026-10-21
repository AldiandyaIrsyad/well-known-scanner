# Well-Known Checker

Find out which `/.well-known/` files a website serves, whether they're valid, and what each one is for.

**Try it: https://wellknown.aldiandyainf.com/**

Enter a domain and the checker looks for about 90 standard files, including `security.txt`, OpenID
discovery, app links, WebFinger, MTA-STS and A2A agent cards. It also checks root files such as
`robots.txt`, `ads.txt`, `llms.txt`, `humans.txt` and `crossdomain.xml`. Each result is validated
and comes with a plain-language explanation, so it's a good way to discover files you didn't know
existed.

## Features

- Scans `/.well-known/` URIs and common root files in one pass, with results streamed as they arrive
- Validates content, not just status codes, and detects catch-all servers that return 200 for everything
- Explains every check: what the file is, who reads it, and why you might want it
- No accounts and no data stored; the frontend is plain HTML, CSS and JS

## How it works

Browsers can't read `https://other-site/.well-known/*` unless that site sends CORS headers, and most
don't. So the scan runs in a Cloudflare Worker (TypeScript) that fetches the files and returns a
verdict for each one.

```
browser ──GET index.html, app.js, checks.json──▶ Workers Assets (static)
        ──GET /api/check?domain=x&batch=0──┐
        ──GET /api/check?domain=x&batch=1──┤ in parallel
                                           ▼
                          Worker, for its batch of checks:
                            1. GET https://x/  → follow one hop only if it's x ⇄ www.x
                            2. GET two random paths (canaries) to detect catch-all 200s
                            3. GET each file, 6 at a time, 8 s timeout, 64 KB cap
                            4. judge each response, stream it back as one NDJSON line
```

The checks are split into two batches because a Worker invocation on the Cloudflare free plan may
make at most 50 outbound requests.

### Safety

The checker only fetches paths from its fixed list. It never follows redirects (apart from the
`www` hop), rejects IP addresses, `localhost` and internal TLDs, keeps at most 64 KB per response,
and rate-limits each IP to 20 calls per minute.

## Project layout

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

## Run locally

```bash
npm install
npm run dev         # http://localhost:8787
npm test            # Vitest
npm run typecheck
```

## Contributing

To add a check, append an entry to `src/checks/list.ts` with a `learn` explanation. If it needs a new
kind of validation, add a case in `analyze.ts` and a test. Batches are computed automatically.

## Deploy your own

```bash
npx wrangler login  # once, opens the browser
npm run deploy      # prints https://well-known-checker.<your-subdomain>.workers.dev
```

`wrangler.toml` attaches `wellknown.aldiandyainf.com` as a Custom Domain and also enables the
`workers.dev` address. To deploy your own copy, change or remove the `routes` entry so it points at
a zone in your Cloudflare account.
