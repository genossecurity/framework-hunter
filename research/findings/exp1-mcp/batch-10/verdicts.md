# Batch 10 verdicts: funnel repos 91-100 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-10/report.md`. Source review only.
One confirmed bug: crewly, published 2026-11-04 as GHSA-v7q6-5mpg-q47w, CVE pending (see the
update below).

| # | repo | verdict | depth of review |
|---|---|---|---|
| 91 | decocms/studio | no new bug; 274 SQL rows are DB migrations; heavily audited | taint + ERROR rows; migrations noise |
| 92 | asklokesh/loki-mode | no new bug; autonomy agent w/ active security backlog | taint argv + shell=True traced |
| 93 | XeroAPI/xero-mcp-server | clean | 0 findings |
| 94 | ubugeeei-prod/vize | no bug; 307 rows are `.github/actions` + test fixtures | ERROR rows traced to CI/fixtures |
| 95 | remorses/goke | clean | 0 priority |
| 96 | agentistics/agentistics | no new bug; path guards (isRootPath/hasSymlinkPart); API fetches | taint + path rows read |
| 97 | artokun/comfyui-mcp | no new bug; image-path traversal already fixed (#329/#83/#2623) | taint image rows + process-kill noise |
| 98 | stevehuang0115/crewly | **CONFIRMED finding** (PoC): read-only Auditor → RCE via `create_github_issue` shell injection | full investigation; see `crewly/` |
| 99 | freee/freee-mcp | no new bug; DNS-rebinding SSRF already advisory (GHSA-f9mp) | 3 rows read |
| 100 | IgniteUI/igniteui-theming | no bug; platform-detect reads project config files, by design | 3 rows read |

## crewly (98) — CONFIRMED (update)

> Superseded by deeper investigation. The first-pass read below judged this "likely moot"
> because normal crewly agents already have bash. That was the wrong context: the tool belongs
> to the **Auditor** agent, which `auditor-tools.ts` documents as read-only "without any
> ability to modify system state" and which has **no** bash tool. So the `create_github_issue`
> shell injection is a genuine privilege escalation to RCE, **confirmed by a local sandboxed
> PoC**. Full package: [`crewly/`](crewly/) — `finding.md`, `advisory.md` (published as GHSA-v7q6-5mpg-q47w),
> `cvss.md`/`cvss.pdf` (3.1 = 8.8 High, up to 10.0 Critical), `poc/`. No public report found at
> review time. **Published 2026-11-04; CVE pending.** The original first-pass analysis is kept
> below for the record.

### Original first-pass analysis (kept for the record)
real escaping smell, but likely not a privilege-crossing vuln

`create_github_issue` (an agent tool; `title`/`body`/`labels` are tool args) runs:

```
execSync(`gh issue create --title "${title.replace(/"/g,'\\"')}" --body "${body.replace(/"/g,'\\"')}" ${labelFlag}`)
```

Escaping only `"` is insufficient: inside the double-quoted shell string, `$(...)` and
backticks still execute, so a `title` of `$(…)` would run commands. As *code* this is a bug
(it should use `execFile('gh', [...argv])`).

Why it is **not** flagged as a reportable vulnerability here:

- **The caller already has command execution.** crewly is a multi-agent dev platform; the same
  agent tool-registry runs shell by design — `tool-registry.ts:271 childProcess.exec(cmd)`
  (git), terminal tools, and owner-scheduled commands. An agent that can call
  `create_github_issue` can already run commands directly, so the injection grants no new
  capability within that context (triage checklist: a tool that runs commands is a design
  choice unless it crosses a boundary).
- **The only boundary that would make it matter** — agent→owner identity, i.e. the gh/shell
  running with the owner's credentials rather than the agent's — is exactly what crewly has
  been hardening in public (#906 "each agent's commands run with its own identity, not the
  orchestrator's" (closed); #999/#1012/#1023/#1040 owner-vs-agent terminal/endpoint
  boundaries). Determining whether `create_github_issue`'s `execSync` runs under owner identity
  needs an execution-context trace I did not complete at batch depth.
- **Dedup:** no public issue/PR specifically reports this `create_github_issue` escaping.

Verdict: recorded as a **low-confidence candidate** in `research/findings/exp1-mcp/README.md` — a genuine
insufficient-escaping bug whose exploitability as a vuln depends on an unverified
agent/owner execution-context question, in a project actively hardening that exact boundary.
**Not filed.** Worth an argv-conversion fix regardless; worth a deeper trace only if we decide
to invest.

## Big noise sources (methodology)

- **decocms (91):** 274 of 398 "sql-injection" rows are `apps/api/migrations/*.ts` DDL
  (`sql\`...\`.execute(db)`), reached via a false `campaign-suggest.ts -> up` chain. DB
  migrations are not tool-reachable. decocms is heavily audited (STDIO cmd-injection RCE
  #4023, sandbox orgId path-traverse #8140, /read confinement #7936, SSRF guards).
- **vize (94):** 307 rows are `.github/actions/*`, `*.fixture(s).ts`, and `native_api_probe`
  test code — not MCP tools. Exclude gaps: `.github/actions`, `*.fixture.ts`/`*.fixtures.ts`.
- **comfyui-mcp (97):** path traversal in image upload/get tools is already fixed
  (#329, #83, #2623); the 161 count is inflated by per-backend `killProcessTree` (taskkill
  `${pid}`, numeric) repeated across ~8 orchestrator backends.

## What this batch showed about the scanner

- Post-run exclude list now also wants: `migrations` (or at least treat migration DDL as
  non-tool), `.github/actions`, `*.fixture.ts`/`*.fixtures.ts` — on top of the earlier
  `repos` (vendored), `*.smoke.*`, `*.spec-d.*`, `explorations`, `probe`, `.spike-*`.
- Running tally (100 repos, batches 1-10): **0** new bugs filed; 1 low-confidence candidate
  (crewly escaping smell, likely moot); context-mode and elevenlabs both resolved no-action.
  The consistent finding remains that popular MCP servers are already audited, and the real
  value is fast triage + provenance discipline.
