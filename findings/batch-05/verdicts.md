# Batch 5 verdicts: funnel repos 41-50 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-05/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 41 | mclenhard/mcp-evals | clean | 0 priority |
| 42 | mcp-use/mcp-use | no new bug; RCE already public+fixed (#2816/#1718/#1569) | 21 rows read; all LLM/OAuth/telemetry fetches + config reads |
| 43 | brave/brave-search-mcp-server | clean; SSRF is the fixed Brave API host | 1 row read |
| 44 | lobehub/mcp-hello-world | clean | 0 priority (demo) |
| 45 | winor30/mcp-server-datadog | clean | 0 findings |
| 46 | ericthered926/duckduckgo-mcp-server | clean | 0 findings |
| 47 | Serdnaley/metabase-mcp | clean | 182 tools, 0 priority (API wrapper) |
| 48 | MetaMask/device-mcp | no bug; `exec` is execFile(argv), binaries not tool args | all 13 rows read |
| 49 | upstash/context7 | no new bug; SSRF to configured API base; traversal fixed (#2235) | 2 rows read |
| 50 | Unleash/unleash-mcp | clean | 0 priority |

## Notes

**mcp-use (42).** The genuine, serious issue was already found and closed: sandbox escape /
RCE via the `execute_code` tool (issues #2816, #1718) and a path traversal in
`FileSystemSessionStore` (#1569). The 21 current rows are none of those: the SSRF rows are
LLM-provider calls (`google.ts`, `ollama`, `openai-chat-completions`), OAuth
discovery/token/userinfo fetches to configured endpoints, and PostHog telemetry; the
path-traversal rows are config-file reads and CLI `writePrivateJson` (mode-0o700 atomic write
to a CLI-managed path). `servePublicFile` serves a favicon/static asset. No new finding.

**MetaMask/device-mcp (48).** Mobile-device automation over `idb` (iOS) and `adb` (Android).
The four ERROR "command-injection" rows are false positives: `exec`/`execStrict` are thin
wrappers over `child_process.execFile` (argv, **no shell**), the executed `command` is the
discovered `idb`/`adb` binary path from a fixed candidate list (not a tool argument), and the
`args` are argv arrays, so metacharacters stay literal. The SSRF rows target localhost
debugging ports (CDP `127.0.0.1`, WebDriver, Metro `localhost`); the path reads/writes are
device screenshots/recordings to a caller-named artifact path (the documented behavior of a
local device tool). MetaMask also runs a security code scanner (PR #2). No bug.

**context7 (49).** Two SSRF rows: an admin-MCP `fetch(url)` and a JWT `fetchEntraConfig`
against the configured `CONTEXT7_API_BASE_URL`. A prior skill-file directory traversal is
fixed (PR #2235) and the repo has a closed audit history. No new finding.

**Clean/small (41, 43-47, 50).** mcp-evals, brave-search (single SSRF to the fixed Brave API
host), mcp-hello-world (demo), mcp-server-datadog, duckduckgo-mcp-server, metabase-mcp (182
tools but a pure Metabase REST wrapper, 0 priority) and unleash-mcp all came back with no
priority rows or only fixed-host fetches.

## Running tally (batches 1-5, 50 repos)

- New, non-public bug confirmed and filed: **0**.
- Repos where the real issue was already public (CVE / advisory / open fix PR): supabase,
  firecrawl, agentic-flow, cline, claude-flow, nitrostack, XcodeBuildMCP, ms-365, figma-console,
  MCPJam, mastra, netlify, mcp-framework, n8n-mcp, mcp-use, context7.
- The rest were clean over MCP, by-design local-path/exec behavior, or reach-walk noise.
- The consistent story: the top-downloaded MCP servers have already been audited; this scanner
  is earning its keep as a fast triage/confirmation tool, not (yet) a net-new-bug finder.
