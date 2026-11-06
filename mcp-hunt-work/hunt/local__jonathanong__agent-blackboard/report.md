# mcp-hunt report: /home/sam/mcp-hunt-work/scan/src/jonathanong__agent-blackboard

- commit `bfd86c07329f`, package `agent-blackboard-workspace@0.0.0`, 178 files scanned
- MCP server code: yes; transports: http server, stdio; SECURITY.md: no
- tools: 8 named (2 registration sites) in 1 tool file(s): packages/agent-blackboard/src/mcp/server.mts
  entry_append, entry_get, session_archive, session_create, session_ensure, session_patch, session_search, snapshot_export
- scan health: stable, no timeouts

## Priority queue: 5 candidate(s)

| sev | tier | rule | where | tool / function | reach | sink |
|---|---|---|---|---|---|---|
| WARNING | helper | ssrf | packages/agent-blackboard/src/client/http.mts:124 | rawRequest() | called from tool file: server.mts -> export -> rawRequest | `response = await fetch(url, init)` |
| WARNING | helper | path-traversal | packages/agent-blackboard/src/client/snapshot-artifact-ownership.mts:134 | writeMarker() | called from tool file: server.mts -> export -> createDestination -> wr | `path,` |
| WARNING | helper | path-traversal | packages/agent-blackboard/src/client/snapshot-artifact-removal.mts:51 | removeDetached() | called from tool file: server.mts -> export -> removeOwnedFile -> remo | `await rename(path, detached)` |
| WARNING | helper | path-traversal | packages/agent-blackboard/src/client/snapshot-artifact-removal.mts:59 | removeDetached() | called from tool file: server.mts -> export -> removeOwnedFile -> remo | `await rm(detached, { force: true })` |
| WARNING | helper | path-traversal | packages/agent-blackboard/src/client/snapshots.mts:50 | createDestination() | called from tool file: server.mts -> export -> createDestination | `const file = await open(path, 'wx', 0o600)` |

Confirm each by hand: argument really reaches the sink; no allowlist/containment/quoting in between; it is not the tool's advertised purpose. PoC only in `tools/sandbox.sh`.

## Lower priority: 21 helper/audit row(s) not traced to tool code

- 15 × path-traversal (no path to tool code found)
- 3 × path-traversal (no call sites found (outside tests))
- 2 × argument-injection (no path to tool code found)
- 1 × argument-injection (no call sites found (outside tests))

## Prior public reports for jonathanong/agent-blackboard

- PR #25 closed 2026-08-29: feat(client): add secure snapshot partition tooling
Search `repo:jonathanong/agent-blackboard <tool_name>` before building any PoC; both real findings so far were already public.

Files: `/home/sam/mcp-hunt-work/hunt/local__jonathanong__agent-blackboard/findings.csv` (dataset + triage columns), `/home/sam/mcp-hunt-work/hunt/local__jonathanong__agent-blackboard/summary.md`, raw Semgrep JSON in `/home/sam/mcp-hunt-work/hunt/local__jonathanong__agent-blackboard/results`.
