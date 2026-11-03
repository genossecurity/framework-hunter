# Triage: vercel/next-devtools-mcp

**Verdict: clean. No PoC, nothing to report. First end-to-end round that needed no scanner change.**

- Commit `1e8dcfa` (2026-09-14), `next-devtools-mcp@0.4.1`, 835 stars, 155k npm downloads/week.
- Reviewed 2026-11-02 by reading source; nothing run. Stdio transport only.
- Policy: no SECURITY.md; Vercel runs <https://hackerone.com/vercel>.
- Scanner: 4 helper rows, 0 priority, 0 taint, 4 tools, 1,672 lines. Prior public reports are
  dependency CVEs only (#114, #120, #124, #140).

## Tools and why each is fine

| tool | input | what happens | note |
|---|---|---|---|
| `nextjs_index` | `port?` | `fetch(\`${protocol}://${MCP_HOST}:${port}/_next/mcp\`)` with a `tools/list` body | host is `localhost` (or `NEXT_DEVTOOLS_HOST` env), path fixed; probing local ports is the tool's purpose |
| `nextjs_call` | `port`, `toolName`, `args` | same URL, JSON-RPC `tools/call` forwarded to the Next.js dev server | localhost-only relay by design; the dev server's own MCP is the real attack surface, not this |
| `nextjs_docs` | `topic?`, `project_path?` | `createRequire(<path>/package.json).resolve('next/package.json')`, `readFileSync` of both package.json files | returns only version strings, a docs directory path and whether it exists; no file contents leave the process. `topic` is echoed into instructions |
| `browser_eval` | `task?` | `execSync("command -v agent-browser")`, `execSync("agent-browser --version")` | constants; `task` only echoed |

Helper rows: `getPortsViaSs(pid)` builds `ss -tlnp | grep "pid=${pid}"` from a numeric PID found
by process discovery, not from tool input; `probeMCPEndpoint`'s URL as above; the two
`readFileSync` calls as above.

## Not covered

The Next.js dev server's `/_next/mcp` endpoint itself (a different repo, `vercel/next.js`).
