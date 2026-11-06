# mcp-hunt scan summary — 2026-11-02 23:54

- Targets: 1 (1 scanned, 0 with no JS/TS/Python files scanned, 0 failed)
- Tiers run: taint, helper
- Tools exposed across scanned servers (heuristic count): 8
- taint findings: 0
- helper findings: 26
- **Priority queue** (taint, or helper reached from tool code): 5 in 1 repos

Candidates are not vulnerabilities. Each needs: reachable from a tool arg, no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.

## Priority findings by rule

| rule | count |
|---|---|
| mcp-js-path-traversal | 4 |
| mcp-js-ssrf | 1 |

## Triage queue (priority findings, highest severity first)

| sev | tier | repo | tool / function | rule | reach | location |
|---|---|---|---|---|---|---|
| WARNING | helper | local__jonathanong__agent-blackboard | rawRequest() | mcp-js-ssrf | called from tool file: server.mts -> export -> rawRequest | packages/agent-blackboard/src/client/http.mts:124 |
| WARNING | helper | local__jonathanong__agent-blackboard | writeMarker() | mcp-js-path-traversal | called from tool file: server.mts -> export -> createDestination -> writeSnapshotMarker -> writeMarker | packages/agent-blackboard/src/client/snapshot-artifact-ownership.mts:134 |
| WARNING | helper | local__jonathanong__agent-blackboard | removeDetached() | mcp-js-path-traversal | called from tool file: server.mts -> export -> removeOwnedFile -> removeDetached | packages/agent-blackboard/src/client/snapshot-artifact-removal.mts:51 |
| WARNING | helper | local__jonathanong__agent-blackboard | removeDetached() | mcp-js-path-traversal | called from tool file: server.mts -> export -> removeOwnedFile -> removeDetached | packages/agent-blackboard/src/client/snapshot-artifact-removal.mts:59 |
| WARNING | helper | local__jonathanong__agent-blackboard | createDestination() | mcp-js-path-traversal | called from tool file: server.mts -> export -> createDestination | packages/agent-blackboard/src/client/snapshots.mts:50 |

21 lower-priority finding(s) are in findings.csv after the priority rows (0 demoted by a context check — see auto_notes; the rest are helper findings not traced to tool code, or audit tier).

## Per-repo

| repo | status | tools | taint | helper | audit | version |
|---|---|---|---|---|---|---|
| local__jonathanong__agent-blackboard | ok | 8 | 0 | 26 | 0 | agent-blackboard-workspace@0.0.0 |
