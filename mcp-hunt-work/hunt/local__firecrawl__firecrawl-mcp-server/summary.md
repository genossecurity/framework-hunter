# mcp-hunt scan summary — 2026-11-02 23:44

- Targets: 1 (1 scanned, 0 with no JS/TS/Python files scanned, 0 failed)
- Tiers run: taint, helper
- Tools exposed across scanned servers (heuristic count): 30
- taint findings: 2
- helper findings: 3
- **Priority queue** (taint, or helper reached from tool code): 5 in 1 repos

Candidates are not vulnerabilities. Each needs: reachable from a tool arg, no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.

## Priority findings by rule

| rule | count |
|---|---|
| mcp-js-ssrf | 4 |
| mcp-js-path-traversal | 1 |

## Triage queue (priority findings, highest severity first)

| sev | tier | repo | tool / function | rule | reach | location |
|---|---|---|---|---|---|---|
| WARNING | helper | local__firecrawl__firecrawl-mcp-server | monitorRequest() | mcp-js-ssrf | inside tool file | src/monitor.ts:85 |
| WARNING | helper | local__firecrawl__firecrawl-mcp-server | apiPostJson() | mcp-js-ssrf | inside tool file | src/server.ts:1505 |
| WARNING | helper | local__firecrawl__firecrawl-mcp-server | keylessPost() | mcp-js-ssrf | inside tool file | src/server.ts:2068 |
| WARNING | taint | local__firecrawl__firecrawl-mcp-server | firecrawl_search_feedback | mcp-js-ssrf | inside tool handler | src/server.ts:2365 |
| WARNING | taint | local__firecrawl__firecrawl-mcp-server | firecrawl_parse | mcp-js-path-traversal | inside tool handler | src/server.ts:3184 |

## Per-repo

| repo | status | tools | taint | helper | audit | version |
|---|---|---|---|---|---|---|
| local__firecrawl__firecrawl-mcp-server | ok | 30 | 2 | 3 | 0 | firecrawl-mcp@3.36.0 |
