# Batch 8 verdicts: funnel repos 71-80 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-08/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 71 | stripe/ai | clean over taint | 0 priority |
| 72 | AgentWorkforce/relayhistory | no bug; `spawn(executable,[])` is plugin discovery, argv | 1 row read |
| 73 | benborla/mcp-server-mysql | no new bug; write-permission bypass already a cluster of open issues | 2 SQL rows read |
| 74 | ktnyt/cclsp | no bug; LSP reads project files / spawns configured LSP, by design | 3 rows read |
| 75 | pijusz/mcp-gsc | clean | 0 priority |
| 76 | angelogiacco/elevenlabs-mcp | **public dup, fixed upstream** (issue #92 / PR #97,#103); clone is a stale fork | file-read path traced end-to-end |
| 77 | microsoft/clarity-mcp-server | clean; SSRF to configured Clarity API | 1 row read |
| 78 | contentful/contentful-mcp-server | no new bug; SSRF/cred-exfil already CVE-2026-53957 | 0 priority |
| 79 | mui/mui-x | clean | 0 priority |
| 80 | appium/appium-mcp | no new bug; udid shell-inj + filtergraph overwrite already advisories | 12 rows read |

## elevenlabs-mcp (76) — real bug, but a public, upstream-fixed duplicate in a stale fork

The scanner surfaced 12 taint-level path rows and the prior-report lookup said "nothing
public." A full read found a genuine **arbitrary-file-read**: the MCP resource handler
`@mcp.resource("elevenlabs://{filename}")` → `get_elevenlabs_resource(filename)` enforces a
`base_dir` containment check **only on the relative-path branch**; an *absolute* `filename`
takes `candidate.resolve()` with no check and is read back, so `elevenlabs:///etc/passwd`
would be returned to the agent.

Before treating it as a finding, the dedup step (this project's rule: always check
issues/PRs first) resolved it:

- It is exactly **issue #92** ("Security Audit: Path traversal in resource handler — absolute
  paths bypass base_dir check", 2026-02-13), **fixed** in PR #97 ("apply base_dir check to
  absolute paths in resource handler") and PR #103 ("close traversal bypass").
- My clone is `angelogiacco/elevenlabs-mcp` — a **fork** of `elevenlabs/elevenlabs-mcp`,
  frozen at v0.9.1 / 2026-01-06, i.e. *before* the fix. Canonical upstream is at v0.12.2 and
  carries the fix. The batch's prior-report lookup returned "nothing public" because it
  searched the fork's slug, not the parent repo where #92 lives.

Verdict: **public duplicate, already fixed upstream — not filed.**

The "active use" signal was a **funnel mis-attribution**, not real exposure. The funnel
ranked the repo `angelogiacco/elevenlabs-mcp` by the npm downloads of
`@angelogiacco/elevenlabs-mcp-server` (~25k/week). But that npm package is a **separate,
self-contained TypeScript MCP server** (`bin/mcp-server.js` built from `src/**/*.ts`; deps
`@modelcontextprotocol/sdk`, axios, yargs; latest 1.0.4, 2025-03-09) — **not** the Python code
I scanned, and not a launcher for it (no python/uvx/pip anywhere). So:

- The vulnerable code is the **Python fork** `AngeloGiacco/elevenlabs-mcp` @ v0.9.1 (git HEAD
  2026-01-06), which is **dormant** and whose real-world usage is **unknown**.
- The 25k downloads/week belong to an **unrelated JS package** that does not contain this bug.

Verdict: do not act. The bug is public and fixed upstream (#92/#97/#103), it lives in a
dormant fork with no established active use, and the download count that made it look "active"
is a different package. No disclosure, nothing sent.

## Already-public clusters (73, 78, 80)

- **mcp-server-mysql (73):** `execute_sql` running SQL is the tool; the real concern —
  write-permission bypass (`SELECT INTO OUTFILE`, `REPLACE`/`RENAME`/`CALL`/`SET`/`LOCK`/
  `GRANT`, schema-permission short-circuits) — is a cluster of open and closed issues
  (#128, #133, #134, #126, #118). Nothing new.
- **contentful (78):** `export_space`/`import_space` SSRF + credential exfil via LLM-controlled
  `host`/`proxy` is CVE-2026-53957; export file paths fixed in PR #475.
- **appium (80):** the genuine issues are advisories already — shell injection via `udid`
  in `prepare_ios_simulator`, screen-recording filtergraph host-file overwrite/SSRF, and the
  MCP-UI XSS (CVE-2026-58500). The flagged rows (internal session-file persistence, localhost
  WDA readiness) are not those.

## What this batch showed about the scanner / methodology

- **Funnel repo↔package↔downloads mapping can be wrong (affects *ranking*, not just dedup).**
  Here the repo `angelogiacco/elevenlabs-mcp` (a dormant Python fork) was ranked by the
  downloads of `@angelogiacco/elevenlabs-mcp-server` — which turned out to be a *separate,
  unrelated TypeScript server*, not that repo's package. The popularity signal that put this
  repo in the top 200 does not belong to the code we scanned. Three consequences:
  1. Verify the repo↔npm-package link when ranking (does the repo actually publish that
     package?), or the dataset's "top by downloads" framing is undermined for such rows.
  2. The dedup lookup must resolve the **parent/canonical** repo (GitHub `parent.full_name`),
     not just the funnel slug — otherwise a public, fixed bug reads as "nothing public." Add
     parent-repo resolution to `hunt.py:prior_reports` in the post-run pass.
  3. Dormant-fork + public-fixed-upstream + mis-attributed-popularity is a clean worked
     example of why "found a bug" must survive provenance checks before it means anything.
- This is the counterpart to the context-mode over-call: there, the scanner flagged a
  declared-safe tool that was not a bug; here, it flagged a real bug that dedup correctly
  demoted to a public duplicate. Both are the triage layer doing its job.
