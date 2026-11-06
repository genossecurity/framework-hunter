# mcp-hunt report: /home/sam/mcp-hunt-work/scan/src/firecrawl__firecrawl-mcp-server

- commit `aa409c905f0e`, package `firecrawl-mcp@3.36.0`, 33 files scanned
- MCP server code: yes; transports: http server, stdio, streamable-http; SECURITY.md: no
- tools: 30 named (40 registration sites) in 8 tool file(s): src/developer.ts, src/gov.ts, src/mcp/runtime.ts, src/monitor.ts, src/research.ts, src/server.ts ...
  firecrawl_agent, firecrawl_agent_status, firecrawl_check_crawl_status, firecrawl_crawl, firecrawl_credit_usage, firecrawl_developer_search, firecrawl_extract, firecrawl_feedback, firecrawl_find_tools, firecrawl_gov_search, firecrawl_interact, firecrawl_interact_stop, firecrawl_map, firecrawl_monitor_check, firecrawl_monitor_checks, firecrawl_monitor_create, firecrawl_monitor_delete, firecrawl_monitor_get, firecrawl_monitor_list, firecrawl_monitor_run, firecrawl_monitor_update, firecrawl_parse, firecrawl_research_inspect_paper, firecrawl_research_read_paper, firecrawl_research_related_papers, firecrawl_research_search_github, firecrawl_research_search_papers, firecrawl_scrape, firecrawl_search, firecrawl_search_feedback
- scan health: 2 finding(s) only the chunked re-scan saw; taint fixpoint gave up in: server.ts (chunked re-scan covers tool code there)

## Priority queue: 5 candidate(s)

| sev | tier | rule | where | tool / function | reach | sink |
|---|---|---|---|---|---|---|
| WARNING | helper | ssrf | src/monitor.ts:85 | monitorRequest() | inside tool file | `const response = await fetch(url, {` |
| WARNING | helper | ssrf | src/server.ts:1505 | apiPostJson() | inside tool file | `const response = await fetch(`${resolveApiBaseUrl()}${pathName}`, {` |
| WARNING | helper | ssrf | src/server.ts:2068 | keylessPost() | inside tool file | `const response = await fetch(`${resolveApiBaseUrl()}${path}`, {` |
| WARNING | taint | ssrf | src/server.ts:2365 | firecrawl_search_feedback | inside tool handler | `const response = await fetch(endpoint, {` |
| WARNING | taint | path-traversal | src/server.ts:3184 (chunk) | firecrawl_parse | inside tool handler | `const buffer = await readFile(absPath);` |

Confirm each by hand: argument really reaches the sink; no allowlist/containment/quoting in between; it is not the tool's advertised purpose. PoC only in `tools/sandbox.sh`.

## Prior public reports for firecrawl/firecrawl-mcp-server

- issue #210 open 2026-04-08: [SECURITY] SSRF Vulnerability in firecrawl_crawl Tool (FIRECRAWL-001)
- issue #194 open 2026-03-23: Security consideration: SSRF via unvalidated URLs and JavaScript execution in self-hosted 
- issue #152 open 2026-02-03: Security scan results for your MCP server
- PR #595 open 2026-10-22: fix(security): refresh MCP runtime dependencies
- issue #233 open 2026-05-12: Security scan results for firecrawl-mcp-server — MCPSafe AIVSS 62/100 (Grade D)
- issue #199 open 2026-03-30: Free MCP security scan report for firecrawl-mcp
- issue #416 open 2026-09-19: OpenTrustBench security assessment for firecrawl-mcp-server
- PR #594 closed 2026-10-22: fix(security): patch body-parser crash (GHSA-27r3-jxmh-p828)
- PR #217 open 2026-04-22: fix(security): validate firecrawl_extract URLs with z.string().url()
- issue #306 open 2026-07-08: Arbitrary local file read via firecrawl_parse (no path confinement) in firecrawl-mcp
- PR #213 closed 2026-04-21: fix(crawl): use z.string().url() instead of z.string() for SSRF prevention
- PR #70 closed 2025-06-29:   Fix: Enhance Robustness, Security, and Consistency Across Server Components
- issue #586 open 2026-10-21: [Bug] firecrawl_parse accepts unrestricted local file paths  [mentions firecrawl_parse]
- PR #543 open 2026-10-15: Describe the inputs of firecrawl_scrape, firecrawl_search and firecrawl_parse  [mentions firecrawl_parse]
- PR #447 open 2026-09-25: fix(mcp): keep firecrawl_parse inside the parse root  [mentions firecrawl_parse]
Search `repo:firecrawl/firecrawl-mcp-server <tool_name>` before building any PoC; both real findings so far were already public.

Files: `/home/sam/mcp-hunt-work/hunt/local__firecrawl__firecrawl-mcp-server/findings.csv` (dataset + triage columns), `/home/sam/mcp-hunt-work/hunt/local__firecrawl__firecrawl-mcp-server/summary.md`, raw Semgrep JSON in `/home/sam/mcp-hunt-work/hunt/local__firecrawl__firecrawl-mcp-server/results`.
