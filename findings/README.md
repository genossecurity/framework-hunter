# Findings

Each `batch-NN/` covers 10 repos of the tool-only funnel, in download order. `verdicts.md`
has the verdict and how much was reviewed for each repo. Nothing here has been filed.

| batch | funnel repos | status |
|---|---|---|
| [01](batch-01/verdicts.md) | 1-10 | assessed |
| [02](batch-02/verdicts.md) | 11-20 | assessed |
| [03](batch-03/verdicts.md) | 21-30 | assessed |
| [04](batch-04/verdicts.md) | 31-40 | assessed |
| [05](batch-05/verdicts.md) | 41-50 | assessed |
| [06](batch-06/verdicts.md) | 51-60 | assessed |
| [07](batch-07/verdicts.md) | 61-70 | assessed |
| [08](batch-08/verdicts.md) | 71-80 | assessed |
| [09](batch-09/verdicts.md) | 81-90 | assessed |
| [10](batch-10/verdicts.md) | 91-100 | assessed |
| [11](batch-11/verdicts.md) | 101-110 | assessed |
| [12](batch-12/verdicts.md) | 111-120 | assessed |
| [13](batch-13/verdicts.md) | 121-130 | assessed |
| [14](batch-14/verdicts.md) | 131-140 | assessed |
| [15](batch-15/verdicts.md) | 141 | assessed |

**All 141 funnel repos assessed.** Outcome: **1 confirmed non-public finding** (crewly,
below — packaged, not filed); 1 low-confidence code smell (SAP/mdk-mcp-server, batch 11,
not escalated). Every other repo was clean over MCP, already public (CVE/advisory/open fix PR),
by-design local-path/exec/API behavior with no confinement claim to bypass, already-confined,
or reach-walk/vendored/test noise. The recurring lesson: the top-downloaded MCP servers are
heavily audited already, so the pipeline's value is fast triage + provenance discipline — and
the one net-new bug was in a less-scrutinized server (crewly's read-only Auditor), not a famous
one. Scanner-tuning follow-ups (post-run excludes, SQL-tier `.get()` false positives,
`prior_reports` parent-repo resolution) are noted across the batch verdicts.

## Open candidates

- **stevehuang0115/crewly** (batch 10) — **CONFIRMED (code-level), not filed, awaiting your
  disclosure decision.** `create_github_issue` runs `execSync` on a `gh` command string
  escaping only `"`, so `$(...)`/backticks in the `title`/`body` tool args execute. The tool
  belongs to the **Auditor agent**, which `auditor-tools.ts` documents as read-only "without
  any ability to modify system state" and which has no bash tool — so this is a privilege
  escalation to **arbitrary RCE** that also bypasses the `validateBashCommand` denylist
  (curl/wget/rm) + approval gate. Reachable via indirect prompt injection (Auditor composes
  titles from audited logs). HEAD `537cf52` / v1.20.470; no public dedup. **Confirmed by local
  sandboxed PoC.** Disclosure package in [batch-10/crewly/](batch-10/crewly/):
  [finding.md](batch-10/crewly/finding.md), [advisory.md](batch-10/crewly/advisory.md) (draft,
  not sent), [cvss.pdf](batch-10/crewly/cvss.pdf) (3.1 = 8.7 High), and
  [poc/](batch-10/crewly/poc/). Fix: `execFile('gh',[argv])`. Nothing filed.

## Resolved (investigated, not a bug)

- **mksglu/context-mode** (batch 6) — flagged, then investigated end-to-end:
  [batch-06/mksglu__context-mode.md](batch-06/mksglu__context-mode.md). It is a *declared*
  arbitrary-code-execution tool (`destructiveHint: true`, "full network access", credential
  passthrough, stdio-only, host-approval-gated); its "sandbox" is context/memory isolation,
  not capability confinement, so there is no boundary to bypass. Not a vulnerability; no PoC
  warranted. The batch-6 flag was an over-call.
