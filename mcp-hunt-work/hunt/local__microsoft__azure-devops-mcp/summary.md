# mcp-hunt scan summary — 2026-11-02 23:50

- Targets: 1 (1 scanned, 0 with no JS/TS/Python files scanned, 0 failed)
- Tiers run: taint, helper
- Tools exposed across scanned servers (heuristic count): 0
- taint findings: 13
- helper findings: 4
- **Priority queue** (taint, or helper reached from tool code): 14 in 1 repos

Candidates are not vulnerabilities. Each needs: reachable from a tool arg, no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.

## Priority findings by rule

| rule | count |
|---|---|
| mcp-js-ssrf | 12 |
| mcp-js-path-traversal | 2 |

## Triage queue (priority findings, highest severity first)

| sev | tier | repo | tool / function | rule | reach | location |
|---|---|---|---|---|---|---|
| WARNING | helper | local__microsoft__azure-devops-mcp | getCurrentUserDetails() | mcp-js-ssrf | called from tool file: repositories.ts -> getCurrentUserDetails | src/tools/auth.ts:16 |
| WARNING | helper | local__microsoft__azure-devops-mcp | updateBuildStage() | mcp-js-ssrf | inside tool file | src/tools/pipelines.ts:115 |
| WARNING | taint | local__microsoft__azure-devops-mcp | isAbsolutePath() | mcp-js-ssrf | inside tool handler | src/tools/pipelines.ts:505 |
| WARNING | taint | local__microsoft__azure-devops-mcp | isAbsolutePath() | mcp-js-path-traversal | inside tool handler | src/tools/pipelines.ts:515 |
| WARNING | taint | local__microsoft__azure-devops-mcp | isAbsolutePath() | mcp-js-path-traversal | inside tool handler | src/tools/pipelines.ts:517 |
| WARNING | taint | local__microsoft__azure-devops-mcp | configureTestPlanTools() | mcp-js-ssrf | inside tool handler | src/tools/test-plans.ts:77 |
| WARNING | taint | local__microsoft__azure-devops-mcp | configureWikiTools() | mcp-js-ssrf | inside tool handler | src/tools/wiki.ts:132 |
| WARNING | taint | local__microsoft__azure-devops-mcp | configureWikiTools() | mcp-js-ssrf | inside tool handler | src/tools/wiki.ts:204 |
| WARNING | taint | local__microsoft__azure-devops-mcp | configureWikiTools() | mcp-js-ssrf | inside tool handler | src/tools/wiki.ts:296 |
| WARNING | taint | local__microsoft__azure-devops-mcp | ? | mcp-js-ssrf | inside tool handler | src/tools/wiki.ts:325 |
| WARNING | taint | local__microsoft__azure-devops-mcp | ? | mcp-js-ssrf | inside tool handler | src/tools/wiki.ts:347 |
| WARNING | taint | local__microsoft__azure-devops-mcp | ? | mcp-js-ssrf | inside tool handler | src/tools/work-items.ts:1000 |
| WARNING | taint | local__microsoft__azure-devops-mcp | ? | mcp-js-ssrf | inside tool handler | src/tools/work-items.ts:1023 |
| WARNING | taint | local__microsoft__azure-devops-mcp | Wiki | mcp-js-ssrf | inside tool handler | src/tools/work-items.ts:1346 |

3 lower-priority finding(s) are in findings.csv after the priority rows (3 demoted by a context check — see auto_notes; the rest are helper findings not traced to tool code, or audit tier).

## Per-repo

| repo | status | tools | taint | helper | audit | version |
|---|---|---|---|---|---|---|
| local__microsoft__azure-devops-mcp | ok | 0 | 13 | 4 | 0 | @azure-devops/mcp@2.11.0 |
