# Batch 4 verdicts: funnel repos 31-40 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-04/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 31 | QuantGeekDev/mcp-framework | no bug over MCP; the 1 row is CLI scaffolding | row traced; DoS advisory CVE-2026-39313 already public |
| 32 | exa-labs/exa-mcp-server | clean; the 1 "sql" row is an SDK `.get()` call | row read; repo exhaustively audited (all closed) |
| 33 | czlonkowski/n8n-mcp | no new bug; 10 advisories already cover this surface | 3 rows read; SSRF/DB rows are config/internal |
| 34 | BrowserMCP/mcp | no bug; daemon relay is localhost | 3 rows read; prior 0.0.0.0-bind issue closed |
| 35 | letoribo/mcp-graphql-enhanced | clean | 0 priority |
| 36 | abhigyanpatwari/GitNexus | no new bug; scope confinement already tracked (issue #1089) | 125 rows are hook-lock/eval, not tools |
| 37 | eslint/rewrite | clean | 0 priority |
| 38 | JKHeadley/instar | no new bug; exec sinks key on internal ids, argv calls, lint-funneled | ERROR cmd-injection cluster traced; 963 rows mostly non-tool noise |
| 39 | zencoderai/slack-mcp-server | clean | 0 priority, 2 files |
| 40 | fiberplane/mcp-lite | clean | 0 priority (framework lib) |

## Notes

**mcp-framework (31).** The single row, `writeFile(join(promptsDir, fileName))`, is in
`src/cli/project/add-prompt.ts` — the `mcp add prompt` CLI scaffolding command, not a runtime
tool; the reach chain through `MCPServer.ts -> getMessages` is a generic-name false link. The
public issue here is DoS (CVE-2026-39313, unbounded `readRequestBody`), not this write.

**exa-mcp-server (32).** The lone "sql-injection" row is `client.agent.runs.get(runId)` — an
Exa SDK API call whose `.get()` matched the bind-method sink pattern; not SQL, `runId` goes to
Exa's API. The repo has an unusually long, fully-closed security-audit history. Clean.

**n8n-mcp (33).** One of the most heavily audited servers in the funnel: **ten** GHSA
advisories already cover SSRF (trailing-dot/`*.localhost`, IPv6 cloud-metadata), session
isolation, prototype pollution, telemetry leakage and placeholder-auth. The three flagged
rows are a `Map.get` (not SQL), an `axios.create({baseURL: apiUrl})` where `apiUrl` is the
configured n8n endpoint, and a `db.prepare(sql)` wrapper over the internal node-metadata
SQLite DB (not tool-controlled SQL). Nothing new.

**BrowserMCP/mcp (34).** The path read is an internal daemon-info file; the two SSRF rows
build `http://${RELAY_HOST}:${port}` against the localhost relay. The prior "binds to 0.0.0.0"
issue (#158) is closed. Local browser-automation tool. No bug.

**GitNexus (36).** 125 priority rows, but essentially all are in `eval/` harness scripts and
the per-plugin `hooks/hook-lock.*` PID-lockfile utilities (reached by false `release` /
`evictStaleSlot` chains), not shipped MCP tools. GitNexus is a code-analysis server; limiting
its analysis root in server mode is already an open tracked feature request (**issue #1089**).
No new confirmed bug.

**instar (38).** The highest-signal cluster in the batch: ERROR-level command-injection rows
in `PipeSessionSpawner.ts`, `greenPrAutomergeWiring.ts`, `PlatformProbe.ts`,
`InstarWorktreeManager.ts`. Traced:
- `PipeSessionSpawner` tmux `execSync` strings interpolate `sessionName = \`pipe-${threadId}\``
  — an internal thread id, and `spawn()` is called from internal topic/login drivers, not
  from a tool with raw user input.
- `greenPrAutomergeWiring` and `InstarWorktreeManager` call `exec([...argv])` / `gh api`
  with **argv arrays** (no shell); `opts.repo` comes from PR-monitoring config and lands in a
  URL path argument, not a shell string.
- The project enforces a large bespoke lint suite (`lint-no-unfunneled-tmux-literal-send`,
  `lint-no-unfunneled-headless-launch`, `lint-no-direct-destructive`,
  `lint-sync-subprocess-chokepoint`, `lint-no-unfunneled-credential-write`, ...) that funnels
  every subprocess / destructive / credential op through audited chokepoints, and wraps FS in
  `SafeFsExecutor`.

The remaining ~950 rows are reach-walk noise through `dashboard/console/*.js` (frontend),
`.claude/hooks/*`, `console/prototype/*.py` and monitoring code — none a tool handler taking
the interpolated value from MCP input. I could not hand-verify all 963 rows; depth here is the
ERROR-tier exec cluster plus a sample of the path/ssrf rows. No new confirmed bug; a solo
project with heavy self-imposed guardrails.

## What this batch showed about the scanner

- The deferred exclusion gap keeps biting: GitNexus (`eval/`, per-plugin `hooks/`) and instar
  (`dashboard/console/`, `.claude/hooks/`, `console/prototype/`) produced 125 and 963 priority
  rows that are almost entirely non-tool code. Post-run exclude candidates now also include
  `hooks` (plugin lockfiles), `dashboard`, `console/prototype`, and `.claude/`-nested JS.
- The prior-report lookup again earned its place: it surfaced the DoS CVE for mcp-framework,
  the ten-advisory wall for n8n-mcp, and the closed-audit history for exa — each of which is
  what turns a big priority count into "already known / already hardened."
- Pattern across batches 1-4: the real, confirmable MCP bugs in popular servers are already
  public (CVEs/advisories/open fix PRs). The scanner's value so far is triage speed and
  confirming *absence* of a new bug, not net-new discovery. Worth saying plainly in the paper.
