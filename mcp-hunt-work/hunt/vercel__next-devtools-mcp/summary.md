# mcp-hunt scan summary — 2026-11-02 23:42

- Targets: 1 (1 scanned, 0 with no JS/TS/Python files scanned, 0 failed)
- Tiers run: taint, helper
- Tools exposed across scanned servers (heuristic count): 4
- taint findings: 0
- helper findings: 4
- **Priority queue** (taint, or helper reached from tool code): 4 in 1 repos

Candidates are not vulnerabilities. Each needs: reachable from a tool arg, no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.

## Priority findings by rule

| rule | count |
|---|---|
| mcp-js-path-traversal | 2 |
| mcp-js-ssrf | 1 |
| mcp-js-command-injection | 1 |

## Triage queue (priority findings, highest severity first)

| sev | tier | repo | tool / function | rule | reach | location |
|---|---|---|---|---|---|---|
| ERROR | helper | vercel__next-devtools-mcp | getPortsViaSs() | mcp-js-command-injection | called from tool file: nextjs_index.ts -> getAllAvailableServers -> findNextJsServers -> getListeningPort -> getPortsViaSs | [src/_internal/nextjs-runtime-manager.ts:170](https://github.com/vercel/next-devtools-mcp/blob/1e8dcfa47897/src/_internal/nextjs-runtime-manager.ts#L170) |
| WARNING | helper | vercel__next-devtools-mcp | probeMCPEndpoint() | mcp-js-ssrf | called from tool file: nextjs_index.ts -> detectProtocol -> probePort -> probeMCPEndpoint | [src/_internal/nextjs-runtime-manager.ts:85](https://github.com/vercel/next-devtools-mcp/blob/1e8dcfa47897/src/_internal/nextjs-runtime-manager.ts#L85) |
| WARNING | helper | vercel__next-devtools-mcp | resolveNextVersion() | mcp-js-path-traversal | inside tool file | [src/tools/nextjs-docs.ts:78](https://github.com/vercel/next-devtools-mcp/blob/1e8dcfa47897/src/tools/nextjs-docs.ts#L78) |
| WARNING | helper | vercel__next-devtools-mcp | resolveNextVersion() | mcp-js-path-traversal | inside tool file | [src/tools/nextjs-docs.ts:88](https://github.com/vercel/next-devtools-mcp/blob/1e8dcfa47897/src/tools/nextjs-docs.ts#L88) |

## Per-repo

| repo | status | tools | taint | helper | audit | version |
|---|---|---|---|---|---|---|
| vercel__next-devtools-mcp | ok | 4 | 0 | 4 | 0 | next-devtools-mcp@0.4.1 |
