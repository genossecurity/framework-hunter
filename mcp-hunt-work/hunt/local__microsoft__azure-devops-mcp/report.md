# mcp-hunt report: /home/sam/mcp-hunt-work/scan/src/microsoft__azure-devops-mcp

- commit `7f2a6b9fae78`, package `@azure-devops/mcp@2.11.0`, 30 files scanned
- MCP server code: yes; transports: stdio; SECURITY.md: yes
- tools: 0 named (44 registration sites) in 10 tool file(s): src/prompts.ts, src/tools/advanced-security.ts, src/tools/core.ts, src/tools/pipelines.ts, src/tools/repositories.ts, src/tools/search.ts ...
- scan health: 1 match(es) unstable across Semgrep runs (unioned); 3 finding(s) only the chunked re-scan saw; taint fixpoint gave up in: pipelines.ts, repositories.ts, test-plans.ts, wiki.ts, work-items.ts, work.ts (chunked re-scan covers tool code there)

## Priority queue: 14 candidate(s)

| sev | tier | rule | where | tool / function | reach | sink |
|---|---|---|---|---|---|---|
| WARNING | helper | ssrf | src/tools/auth.ts:16 | getCurrentUserDetails() | called from tool file: repositories.ts -> getCurrentUserDetails | `const response = await fetch(url, {` |
| WARNING | helper | ssrf | src/tools/pipelines.ts:115 | updateBuildStage() | inside tool file | `const response = await fetch(endpoint, {` |
| WARNING | taint | ssrf | src/tools/pipelines.ts:505 | isAbsolutePath() | inside tool handler | `const response = await fetch(artifact.resource.downloadUrl, {` |
| WARNING | taint | path-traversal | src/tools/pipelines.ts:515 | isAbsolutePath() | inside tool handler | `mkdirSync(fullDestinationPath, { recursive: true });` |
| WARNING | taint | path-traversal | src/tools/pipelines.ts:517 | isAbsolutePath() | inside tool handler | `const writeStream = createWriteStream(fileDestinationPath);` |
| WARNING | taint | ssrf | src/tools/test-plans.ts:77 | configureTestPlanTools() | inside tool handler | `const response = await fetch(url, { method: "GET", headers });` |
| WARNING | taint | ssrf | src/tools/wiki.ts:132 | configureWikiTools() | inside tool handler | `const response = await fetch(fetchUrl, {` |
| WARNING | taint | ssrf | src/tools/wiki.ts:204 | configureWikiTools() | inside tool handler | `const resp = await fetch(restUrl, {` |
| WARNING | taint | ssrf | src/tools/wiki.ts:296 | configureWikiTools() | inside tool handler | `const createResponse = await fetch(url, {` |
| WARNING | taint | ssrf | src/tools/wiki.ts:325 | ? | inside tool handler | `const getResponse = await fetch(url, {` |
| WARNING | taint | ssrf | src/tools/wiki.ts:347 | ? | inside tool handler | `const updateResponse = await fetch(url, {` |
| WARNING | taint | ssrf | src/tools/work-items.ts:1000 | ? | inside tool handler | ``${orgUrl}/${encodeURIComponent(resolvedProject)}/_apis/wit/workItems/${workItemId}/commen` |
| WARNING | taint | ssrf | src/tools/work-items.ts:1023 | ? | inside tool handler | ``${orgUrl}/${encodeURIComponent(resolvedProject)}/_apis/wit/workItems/${workItemId}/commen` |
| WARNING | taint | ssrf | src/tools/work-items.ts:1346 | Wiki | inside tool handler | `const pageResponse = await fetch(`${orgUrl}/${encodeURIComponent(resolvedProject)}/_apis/w` |

Confirm each by hand: argument really reaches the sink; no allowlist/containment/quoting in between; it is not the tool's advertised purpose. PoC only in `tools/sandbox.sh`.

## Demoted by a context check: 3

- 2 × URL host looks fixed (https://vssps.dev.azure.com/...) — path-only?
- 1 × containment check nearby — verify it is correct
These stay in findings.csv; a containment check can be wrong, so skim them.

## Prior public reports for microsoft/azure-devops-mcp

- PR #1552 closed 2026-08-26: Enhance error handling and security for attachment updates
- issue #1735 closed 2026-10-27: Upgrade `zod` to v4 (GHSA-mrhx-c7xc-m3w5: no fix in 3.x)
- PR #1557 closed 2026-08-27: Implement Personal Access Token fetch interceptor for security
- PR #1597 closed 2026-09-11: chore(deps): bump step-security/harden-runner from 2.21.0 to 2.21.1 in the github-actions 
- PR #1652 closed 2026-09-30: fix: decode project and wiki identifiers in parseWikiUrl function  [mentions Wiki]
Search `repo:microsoft/azure-devops-mcp <tool_name>` before building any PoC; both real findings so far were already public.

Files: `/home/sam/mcp-hunt-work/hunt/local__microsoft__azure-devops-mcp/findings.csv` (dataset + triage columns), `/home/sam/mcp-hunt-work/hunt/local__microsoft__azure-devops-mcp/summary.md`, raw Semgrep JSON in `/home/sam/mcp-hunt-work/hunt/local__microsoft__azure-devops-mcp/results`.
