# Triage: GLips/Figma-Context-MCP

**Verdict at HEAD: clean / by design. Nothing to report.** The repo's one published bug
(CVE-2025-53967) became the scanner's 4th recall benchmark and exposed a priority-queue gap.

- Commit `c083d65` (2026-06-24, remote `main` HEAD today), `figma-developer-mcp@0.13.2`,
  16k stars, 150k npm downloads/week. SECURITY.md → GitHub private advisories.
- Reviewed 2026-11-02 by reading source; nothing run. Stdio and Streamable HTTP transports.
- Scanner: 7 helper rows, 0 priority, 2 tools (`get_figma_data`, `download_figma_images`).

## Why it is clean

| surface | guard |
|---|---|
| `download_figma_images.localPath` | `resolveLocalPath` confines to the configured `--image-dir` with `path.relative` (lexical; symlinks documented as out of scope, issue #353 → PRs #355/#367) |
| `fileName` | `^[a-zA-Z0-9_.-]+\.(png|svg|gif)$` |
| `fileKey`, `nodeId` | strict regexes |
| image URLs fetched | come from Figma's API response, not from tool input; `figma-url.ts` pins `figma.com` for user-supplied URLs |
| HTTP mode | per-request `x-figma-token` / Bearer; **falls back to the operator's env key** when a request carries none. Standard local-dev pattern (SDK `createMcpExpressApp` host validation), not a claim of auth; not reportable |
| Helper rows | all inside `downloadFigmaImage`/`writeLogs` on already-confined paths, or `fetch` of API-supplied URLs |

Public history shows the maintainers have been through this: traversal fixes #206/#228/#238,
image-dir confinement #297/#301, symlink canonicalization #355, ambiguous paths #367, SSRF
allowlist PR #408, and the advisory below.

## CVE-2025-53967 as a recall benchmark

`figma-developer-mcp <= 0.6.2`: `fetchWithRetry` falls back to
`execAsync(\`curl ... "${url}"\`)` with the API URL built from tool arguments (GHSA-gxw4-4fc5-9gr5,
CVSS 7.5, fixed in 0.6.3 by commit 7f4b585). At tag `v0.6.2` the scanner **found** the sink
(`fetch-with-retry.ts:43`, helper tier) but did **not** prioritize it: `reach_hint` was
"unknown function" because `export async function fetchWithRetry<T>(` has a type parameter
my function-name regex rejected, so the reverse call walk never started.

Getting it into the queue took five fixes to the reach walk, each a general TS idiom:
type parameters on definitions (`fetchWithRetry<T>(`) and call sites
(`fetchWithRetry<GetFileResponse>(`); following generic-named methods (`request`) through
`this.`/`self.` calls instead of refusing them; counting a handler passed **by reference**
in a tool file (`handler: getFigmaData`) as reaching tool code, outside strings/comments and
import blocks; recognising tool-definition modules (`{ name, parameters, handler }` or
`metadata` + `export function handler`) as tool files; and raising the priority depth from 3
to 4 hops (handler → service → `this.request` → helper). `bench/recall.sh` now checks this
CVE: 4/4. These are scanner changes discovered in round 6, so the "two clean rounds" counter
for unattended mode restarts.
