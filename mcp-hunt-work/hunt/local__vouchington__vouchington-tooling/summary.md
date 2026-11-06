# mcp-hunt scan summary — 2026-11-02 23:54

- Targets: 1 (1 scanned, 0 with no JS/TS/Python files scanned, 0 failed)
- Tiers run: taint, helper
- Tools exposed across scanned servers (heuristic count): 0
- taint findings: 0
- helper findings: 239
- **Priority queue** (taint, or helper reached from tool code): 0 in 0 repos

Candidates are not vulnerabilities. Each needs: reachable from a tool arg, no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.

## Priority findings by rule

| rule | count |
|---|---|

## Triage queue (priority findings, highest severity first)

| sev | tier | repo | tool / function | rule | reach | location |
|---|---|---|---|---|---|---|

239 lower-priority finding(s) are in findings.csv after the priority rows (21 demoted by a context check — see auto_notes; the rest are helper findings not traced to tool code, or audit tier).

## Per-repo

| repo | status | tools | taint | helper | audit | version |
|---|---|---|---|---|---|---|
| local__vouchington__vouchington-tooling | ok | 0 | 0 | 239 | 0 | vouchington-tooling-workspace@0.0.0 |
