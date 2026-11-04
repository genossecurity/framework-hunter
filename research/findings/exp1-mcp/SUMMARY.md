# framework-hunter — dataset & results summary

Static taint analysis + manual triage of the most-downloaded MCP servers, for coordinated
disclosure and a reproducible dataset. This file aggregates the run; per-repo verdicts are in
`research/findings/exp1-mcp/batch-NN/verdicts.md`, raw data in
`~/mcp-hunt-work/scan/{findings.csv,repos.csv}` and `research/targets/funnel.csv`. **One finding is disclosed: crewly, published as GHSA-v7q6-5mpg-q47w, CVE
pending.**

## Dataset

**Target selection (funnel, `research/targets/funnel.csv`).** Top 200 npm packages by weekly downloads whose
repo was reachable, filtered to those that actually build an MCP server exposing tools:

| stage | count |
|---|---|
| **MCP server with tool registrations (scanned)** | **141** |
| server, but no tool registrations | 4 |
| server in a language the scanner can't read (Go/C#/Java/…) | 9 |
| no MCP server found | 28 |
| repo private/deleted (404) | 18 |
| **top-200 start** | **200** |

**Scanned corpus (141 servers, `repos.csv`).** All 141 scanned successfully (status `ok`).

| metric | value |
|---|---|
| Servers scanned | 141 |
| Source files analysed | 106,510 |
| Tools exposed (sum) | 5,799 |
| Tool registration sites (sum) | 7,110 |
| Taint-tier findings | 236 |
| Helper-tier findings | 27,507 |
| Audit-tier findings | 0 (tier off by default) |

## Candidate findings (`findings.csv`)

27,743 total rows; **10,201 priority** (taint-tier, or helper-tier reaching tool code, minus
context-demoted). Priority is a *triage input, not a confirmed-bug count* — the helper tier's
breadth (9,998) reflects the name-based reach walk over large monorepos; the **203 taint-tier
priority** rows are the high-signal set.

| CWE | rule | priority rows |
|---|---|---|
| CWE-22 | path-traversal | 7,179 |
| CWE-89 | sql-injection | 1,048 |
| CWE-88 | argument-injection | 949 |
| CWE-918 | ssrf | 827 |
| CWE-78 | command-injection | 174 |
| CWE-94 | code-injection | 24 |

(SQL-tier counts are inflated by the bind-method sink matching non-SQL `.get()`/`.all()`
callers — HTTP clients, `Map.get`, IndexedDB; those are auto-demoted when no SQL context is
nearby. See "scanner notes.")

## Results after manual triage (141/141 assessed)

| verdict category | repos (approx.) |
|---|---|
| **New, non-public bug confirmed** | **1** (crewly) |
| Low-confidence code smell, not escalated | 1 (SAP/mdk-mcp-server) |
| Real issue already public (CVE / GHSA / open fix PR) | ~20 |
| Clean over MCP, or by-design local-path/exec/API with no confinement claim, or already-confined | remainder |
| Volume = reach-walk / vendored-dep / test-file noise | (orthogonal; affects counts, not verdicts) |

**The one net-new finding — crewly (batch 10).** A role documented read-only ("Auditor …
without any ability to modify system state", no bash tool) reaches arbitrary OS command
execution: `create_github_issue` builds a `gh` shell string with only `"` escaped, so `$(...)`
in the model-controlled `title`/`body` executes. It bypasses the `validateBashCommand` denylist
and the approval gate via a classification gap (the tool is in neither `WRITE_TOOLS` nor
`TOOL_SENSITIVITY`, defaulting to `'safe'`). Confirmed by sandboxed PoC (secrets exfil +
backdoor write), independently source-reviewed, deduped (no GHSA/PR at review time).
Full package: `batch-10/crewly/`. **Published 2026-11-04 as
[GHSA-v7q6-5mpg-q47w](https://github.com/stevehuang0115/crewly/security/advisories/GHSA-v7q6-5mpg-q47w),
filed by the maintainer; CVE pending. Affects ≤ 1.20.471, patched in 1.20.472.**

## What the run shows (for the paper)

1. **The top-downloaded MCP servers are already heavily audited.** ~20 of the 141 carry a CVE,
   GHSA, or open fix PR for their real issue; many ship explicit confinement (path roots,
   allowlists, approval gates, `O_NOFOLLOW`/`0o600`). The pipeline's demonstrated value is fast
   triage and provenance discipline — confirming the *absence* of a new bug and not mistaking
   public or by-design behaviour for a finding.
2. **The one net-new bug was in a less-scrutinised server** (crewly), not a famous one — and it
   was a logic/classification gap (a `safe`-classified tool that shells out), not a pattern a
   signature would flag.
3. **"By design" dominates the long tail.** Most path/exec/SSRF sinks are the tool's documented
   capability (a deploy tool runs builds; a browser tool navigates; an API wrapper calls its
   configured backend). A finding requires a *claimed* confinement (read-only, sandbox,
   allowlist, path root) that the sink escapes — the crewly criterion.

## Methodology findings (each worth a paragraph, independent of any CVE)

- **Semgrep OSS silently drops taint findings in large handlers.** Its taint fixpoint has a
  per-function time budget with no CLI knob; over-budget functions drop *all* taint findings
  with the notice only under `--debug`, and the result set is nondeterministic near the budget.
  Mitigated here by 2–3× unioned runs + per-registration chunked re-scan (`unstable_results`,
  `chunks`, `chunk_only_findings` columns quantify it).
- **Download-ranked targeting can select stale forks / wrong packages.** `elevenlabs-mcp`:
  the scanned repo was a fork frozen before a public fix (#92 → #97/#103), and the ranking
  download count actually belonged to a *separate* TypeScript package of the same name. Dedup
  must resolve the canonical/parent repo (now implemented in `prior_reports`).
- **"Sandbox" is overloaded.** context-mode's "sandbox" means context/memory isolation, not
  capability confinement — a declared arbitrary-code executor, not a bug. Triage must read what
  a tool *claims to confine* before scoring an execution sink.

## Scanner notes / tuning applied this run

- Content-based minified/bundled-file detection (avg line > 2 KB) + build-artifact excludes —
  eliminated multi-hour stalls on 1 MB single-line vendor bundles.
- Post-run excludes added for non-shipped code: `repos` (vendored deps), `*.smoke.*`,
  `*.spec-d.*`, `*.fixture(s).ts`, `.github`, `probe`, `.spike-*`, `explorations`, `e2e-tests`,
  `.claude`, `.cursor`, `.smithery`. (Take effect on the next full scan; this run's reprocess
  applied the post-processing fixes only.)
- SQL-tier `.get()/.all()/.run()` false positives auto-demoted when no SQL context is nearby
  (HTTP clients, `Map.get`, IndexedDB). Reprocess-applied.
- `prior_reports` now resolves renamed repos and fork parents for dedup.
