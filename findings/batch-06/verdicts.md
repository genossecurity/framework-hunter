# Batch 6 verdicts: funnel repos 51-60 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-06/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 51 | mksglu/context-mode | **not a bug** (investigated end-to-end): declared code executor, no confinement to bypass | full read; see `mksglu__context-mode.md` |
| 52 | bytebase/dbhub | no new bug; read-only bypass already 3 CVEs | 13 SQL rows read |
| 53 | thedotmack/claude-mem | no new bug; loopback-trust already open (#5141) | 148 rows; SSRF/path are the tracked surface |
| 54 | corsairdev/corsair | no new bug; run_script `new Function` already public (#1652) | code-injection row + SSRF read |
| 55 | Cotal-AI/Cotal | no new bug; 759 rows are `*.smoke.ts` test noise | ERROR rows traced to smoke tests |
| 56 | browserstack/mcp-server | no new bug; upload confinement added (MCP_UPLOAD_BASE_DIR) | `safePath` guard confirmed; SSRF to BS API |
| 57 | apify/apify-mcp-server | no new bug; 3 CVEs + "sql" rows are SDK calls | 5 rows read |
| 58 | jgraph/drawio-mcp | no bug; `search_shapes` path confined by `assertPagePath` | taint row traced to the guard |
| 59 | Flux159/mcp-server-kubernetes | no new bug; exhaustively audited (11 advisories) | 3 rows are the CVE-fix wrappers |
| 60 | meshy-dev/meshy-mcp-server | no bug; by-design local 3D-asset file output; internal exec | 14 rows read |

## Notes

**context-mode (51) — the one to flag.** `ctx_execute` / `ctx_execute_file` /
`ctx_batch_execute` are a **code-execution** surface: executing caller-supplied code in a
detected runtime is the tool's documented purpose, and `executor.ts`'s `spawn(..., shell:true)`
(Windows `.cmd` shims, JSON-quoted args) is that feature, not a slip. It ships a real
permission model in `security.ts` — `allow`/`deny`/`ask` decisions, bash deny-patterns that
resist prepend-bypass, a project-boundary guard (#852), and `permissions.allow`/`deny` globs
read from settings files. So this is a *sanctioned executor with guardrails*. The meaningful
question is whether those guardrails can be bypassed — a CWE-863-style audit that needs a
dedicated PoC against the specific allow/deny logic, not a batch-triage glance. There are **no
public security reports** to deduplicate against. I am **not** calling this clean, and **not**
claiming a bug: it is the batch-6 candidate for deeper, end-to-end review if we choose to
invest there. Recorded under Open candidates in `findings/README.md`.

**dbhub (52).** `execute_sql` running arbitrary SQL is the tool. The real concern — read-only
mode being bypassable — is already three CVEs (CVE-2026-61789 MySQL/MariaDB write bypass,
CVE-2026-61788 read-only doesn't block writes, CVE-2026-61742 DNS-rebinding unauth SQL). No
new finding.

**claude-mem (53).** The SSRF rows are loopback worker / configured sync-hub fetches; the path
rows are npm install/uninstall CLI housekeeping. The genuine issue — the worker API and MCP
transport trusting any loopback process (unauthenticated read/write) — is already filed and
**open as issue #5141** (plus closed credential-leak PRs #3680/#3861). Nothing new.

**corsair (54).** The `tools.ts` `return (async () => { ${code} })()` is the `run_script`
tool; its unisolated `new Function()` RCE is already public (**issue #1652 open**, PR #1043
open), and the `tokenUrl` SSRF is fixed (PR #1663). No new finding.

**Cotal (55).** 759 priority rows, but essentially all are in `bin/smoke/*.smoke.ts` (a
smoke-test suite) and `bin/daemon/` — not shipped MCP tools; the reach chains originate in
`*.smoke.ts`. `.smoke.*` is a test-naming convention the excludes don't yet catch (noted
below). The maintainers are already doing traversal/credential-confinement hardening (PRs
#4733, #4188, issues #795, #1171). No new confirmed bug.

**kubernetes (59).** The single most-audited server in the funnel — **eleven** advisories
covering flag injection, arbitrary file read (`kubectl_create --from-file`, `valuesFile`),
`port_forward` arg injection, DNS rebinding, and access-control bypass. The three flagged rows
are the *remediation* code (`execFileSyncSafe`, the argv-guarded `port_forward`, the
`wx`/0o600 temp-file write). No new finding.

**meshy (60).** A 3D-asset tool: `downloadFileToLocal` / `resolveProjectDir` /
`fixObjForPrinting` write generated models and metadata to a caller-named project directory
(by design), the SSRF rows download assets from the Meshy API, and the `which ${entry.linuxExe}`
exec iterates an internal slicer list (PrusaSlicer, ...), not tool input. No public reports;
by-design local file output. No bug found, but like other local-output tools, a confinement
expectation (if any) was not deeply audited.

## What this batch showed about the scanner

- **`.smoke.ts` exclusion gap:** Cotal's 759 rows were almost entirely smoke tests. Add
  `*.smoke.*` to `TEST_PATH_RE` / `EXCLUDES` in the post-run cleanup (alongside the earlier
  `explorations` / `probe` / `.spike-*` additions, now applied from batch 7 on).
- The minified-file speedup worked: context-mode's `cli.bundle.mjs` / `server.bundle.mjs`
  still show as TIMEOUT rows here because batch 6 repos 1-2 were scanned under the **old**
  rules (pre-restart); repos scanned after the restart no longer waste time on them.
- Batch 6 reinforces the pattern and adds nuance: the first genuinely interesting target in
  40+ repos is **context-mode**, and it's interesting precisely because it's a code executor
  with *no* public audit — i.e. the gap is in a less-scrutinized server, not the famous ones.
