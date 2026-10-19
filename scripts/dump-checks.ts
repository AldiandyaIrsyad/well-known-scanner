// Writes public/checks.json (the check list and explanations) for the frontend, so the list
// lives in one place (src/checks/list.ts) and the browser gets it as a free static file.
// Runs before `wrangler dev` / `wrangler deploy` via [build] in wrangler.toml.
import { writeFileSync } from "node:fs";
import { BATCH_COUNT } from "../src/checks/checks.ts";
import { CHECKS } from "../src/checks/list.ts";

const out = new URL("../public/checks.json", import.meta.url);
writeFileSync(out, JSON.stringify({ batchCount: BATCH_COUNT, checks: CHECKS }, null, 1) + "\n");
console.log(`wrote public/checks.json (${CHECKS.length} checks, ${BATCH_COUNT} batches)`);
