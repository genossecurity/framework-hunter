# mcp-hunt report: /home/sam/mcp-hunt-work/scan/src/vouchington__vouchington-tooling

- commit `205dad764fb5`, package `vouchington-tooling-workspace@0.0.0`, 1609 files scanned
- MCP server code: yes; transports: http server, sse, stdio; SECURITY.md: no
- tools: 0 named (14 registration sites) in 2 tool file(s): packages/vouchington-tooling/src/mcp-server/sdk.mts, packages/vouchington-tooling/src/mcp-server/server.mts
- scan health: stable, no timeouts

## Priority queue: 0 candidate(s)

None. Remember: zero candidates is not a clean bill. Check the tool list above is complete, and audit authorization logic (scope / read-only guards) by hand; taint rules cannot see it.

## Demoted by a context check: 21

- 19 × containment check nearby — verify it is correct
- 2 × uses '--' separator
These stay in findings.csv; a containment check can be wrong, so skim them.

## Lower priority: 218 helper/audit row(s) not traced to tool code

- 106 × path-traversal (no path to tool code found)
- 48 × path-traversal (no call sites found (outside tests))
- 21 × argument-injection (no path to tool code found)
- 14 × argument-injection (no call sites found (outside tests))
- 7 × path-traversal (called at module level in type-query-api.mts)
- 6 × command-injection (no path to tool code found)
- 4 × ssrf (no call sites found (outside tests))
- 3 × argument-injection (unknown function)

## Prior public reports for vouchington/vouchington-tooling

- PR #643 closed 2026-10-23: feat(postgres-test-faults): query-failure injection and lock-wait observers
- issue #375 closed 2026-10-04: feat(markdown): expose prunable HTML-block context traversal
- issue #635 closed 2026-10-23: postgres-test-faults: query-failure injection and lock-wait observers
- PR #205 closed 2026-09-07: fix(scc-complexity): harden scoped boundaries
- issue #336 closed 2026-09-29: openapi-document: emit servers, components.securitySchemes and per-operation security
Search `repo:vouchington/vouchington-tooling <tool_name>` before building any PoC; both real findings so far were already public.

Files: `/home/sam/mcp-hunt-work/hunt/local__vouchington__vouchington-tooling/findings.csv` (dataset + triage columns), `/home/sam/mcp-hunt-work/hunt/local__vouchington__vouchington-tooling/summary.md`, raw Semgrep JSON in `/home/sam/mcp-hunt-work/hunt/local__vouchington__vouchington-tooling/results`.
