# mcp-hunt report: vercel/next-devtools-mcp

- commit `1e8dcfa47897`, package `next-devtools-mcp@0.4.1`, 16 files scanned
- MCP server code: yes; transports: stdio; SECURITY.md: no
- tools: 4 named (2 registration sites) in 5 tool file(s): src/index.ts, src/tools/browser-eval.ts, src/tools/nextjs-docs.ts, src/tools/nextjs_call.ts, src/tools/nextjs_index.ts
  browser_eval, nextjs_call, nextjs_docs, nextjs_index
- scan health: stable, no timeouts

## Priority queue: 4 candidate(s)

| sev | tier | rule | where | tool / function | reach | sink |
|---|---|---|---|---|---|---|
| ERROR | helper | command-injection | src/_internal/nextjs-runtime-manager.ts:170 | getPortsViaSs() | called from tool file: nextjs_index.ts -> getAllAvailableServers -> fi | `const { stdout } = await execAsync(`ss -tlnp 2>/dev/null \| grep "pid=${pid}" \|\| true`)` |
| WARNING | helper | ssrf | src/_internal/nextjs-runtime-manager.ts:85 | probeMCPEndpoint() | called from tool file: nextjs_index.ts -> detectProtocol -> probePort  | `const response = await fetch(url, {` |
| WARNING | helper | path-traversal | src/tools/nextjs-docs.ts:78 | resolveNextVersion() | inside tool file | `const { version } = JSON.parse(fs.readFileSync(installedPkg, "utf8"))` |
| WARNING | helper | path-traversal | src/tools/nextjs-docs.ts:88 | resolveNextVersion() | inside tool file | `const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"))` |

Confirm each by hand: argument really reaches the sink; no allowlist/containment/quoting in between; it is not the tool's advertised purpose. PoC only in `tools/sandbox.sh`.

## Prior public reports for vercel/next-devtools-mcp

- issue #124 closed 2026-02-18: Dependency security risk - Anthropic's MCP TypeScript SDK has a ReDoS vulnerability
- PR #140 closed 2026-06-01: fix(deps): bump @modelcontextprotocol/sdk to 1.25.2 (CVE-2026-0621 ReDoS)
- issue #114 closed 2026-01-09: CVE-2026-0621
- PR #106 closed 2025-12-10: fix: upgrade Next.js to 16.0.7 (CVE-2025-55182)
- issue #120 closed 2026-02-06: Security: next-devtools-mcp pins vulnerable undici (GHSA-g9mf-h72j-4rw9)
- PR #107 closed 2025-12-11: fix: upgrade @modelcontextprotocol/sdk to 1.24.3 (CVE-2025-66414)
- issue #103 closed 2025-12-09: CVE-2025-66414
- issue #119 open 2026-01-29: Issues with `nextjs_docs` and `nextjs-docs://llms-index`  [mentions nextjs-docs]
- PR #147 closed 2026-06-24: Tighten README to match the thin-connector scope  [mentions nextjs-docs]
Search `repo:vercel/next-devtools-mcp <tool_name>` before building any PoC; both real findings so far were already public.

Files: `/home/sam/mcp-hunt-work/hunt/vercel__next-devtools-mcp/findings.csv` (dataset + triage columns), `/home/sam/mcp-hunt-work/hunt/vercel__next-devtools-mcp/summary.md`, raw Semgrep JSON in `/home/sam/mcp-hunt-work/hunt/vercel__next-devtools-mcp/results`.
