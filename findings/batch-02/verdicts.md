# Batch 2 verdicts: funnel repos 11-20 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-02/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 11 | getsentry/XcodeBuildMCP | no new bug; flagged sinks already hardened publicly | path/exec sinks read; argv exec, no shell by default |
| 12 | mongodb-js/mongodb-mcp-server | no bug found | 1 priority row (config-driven mkdir); readOnly + JS-disable guards noted |
| 13 | SAP/open-ux-tools | no bug found; mostly reach-walk noise | server.ts entry + 6 flagged tools read; many rows in non-server packages |
| 14 | nrwl/nx-console | no new bug; cmd-injection already addressed (PR #3195) | managed-process shell path + nx-mcp tools read |
| 15 | ruvnet/agentic-flow | real cmd injection, but **already public** (CVE-2026-58195) | shipped tools use execFileSync; shell-string sink is in a non-shipped docker copy |
| 16 | UI5/mcp-server | low; writes to a user-given absolute path by design | all 9 rows read; isAbsolute + regex guards |
| 17 | cline/cline | no new bug; real issues already public (CVE-2026-59723/44211) | taint + ERROR rows read; most chains are name-walk noise |
| 18 | ruvnet/claude-flow | no new bug; RCE already public (CVE-2026-59726) | terminal/github/sql rows read; most of 1273 tool names unread |
| 19 | nitrocloudofficial/nitrostack | no bug found; audit already open (PR #351) | CLI init + core server rows read |
| 20 | googleapis/gcloud-mcp | no bug; read-local-file is the documented tool behavior | both tool packages read; command path is ACL-gated |

## Notes

**XcodeBuildMCP (11).** Repo renamed to `getsentry/MobileBuildMCP`; the prior-report lookup
now resolves it. The flagged `readFileSync`/`spawnSync` sinks take `projectPath`,
`workspacePath`, `filePath` tool arguments. `utils/command.ts` spawns with an argv array
(`spawn(executable, args)`), not a shell; `shellEscapeArg` is only applied to the display
string. This is a local Xcode build tool whose purpose is to operate on local paths the
caller names. The two sink classes the scanner raised are already addressed in public:
PR #289 / #488 (CWE-78 shell-argument hardening) and PR #380 (path-traversal protection for
schema file loading, which is exactly the `structured-output-schema.ts` row). No new finding.

**mongodb-mcp-server (12).** The single priority row, `fs.mkdir(config.logPath)`, is driven
by a config value, not a tool argument. `userConfig` has a server-side-JS disable and a
read-only mode; `$out`/`$merge`/`$where` are validated. Prior PR #1332 already added path
validation for streams. Nothing new over MCP at `3.2.2`.

**open-ux-tools (13).** The MCP server is `packages/fiori-mcp-server`. Its tools take a local
`appPath`/`projectPath`. `open-adaptation-editor` and `runCmdArgs`/`execNpmCommand` spawn
`npx`/`npm` through nano-spawn / argv `spawn` (no shell). The `sql-injection` rows are in a
Playwright bridge (not SQL); many path rows are in sibling packages (`axios-extension`,
`preview-middleware-client`) linked only by the name-based reach walk. A local scaffolding
tool over local paths. No confinement claim to break. Deeper per-tool review not done.

**nx-console (14).** `spawnManagedProcess` has a `shell: true` branch that builds
`/bin/sh -c "<command> <args>"`; line 153 uses it. Command injection via the Nx Cloud CIPE
branch name is already fixed in PR #3195, and a compromised-package advisory (CVE-2026-48027)
is unrelated to this path. SSRF rows fetch nx-cloud artifacts/docs. Local workspace tool.

**agentic-flow (15).** `docker/claude-agent-sdk/.../http-streaming.ts` builds a shell string
and runs it with `execSync` — the classic injection pattern. But the shipped servers
(`src/mcp/fastmcp/servers/*.ts`) use `execFileSync('npx', [...argv])`, which the maintainer
switched to in PR #156/#170 ("CWE-78 fixed in 2.0.14"). The remaining shell-string file sits
under `docker/` and is not in the package `files` list (`dist`, `docs`, `.claude`, ...). The
command-injection class is already public as **CVE-2026-58195**. Duplicate.

**UI5/mcp-server (16).** Create-app / create-card tools write under a caller-supplied
`basePath`. The schema requires `isAbsolute(basePath)` and restricts `appNamespace` by regex.
Writing to the operator's chosen absolute path is the documented behavior, same shape as
batch 1's agent-blackboard. Low / by design.

**cline/cline (17).** Coding agent that runs commands and edits files as its purpose. The
`Function(...)` code-injection row is in a dev debug-harness; the command-injection rows are
in hub/cloud client plumbing reached through generic names (`cleanup`, `dispose`, `shutdown`)
in `plugin-registry.ts` — likely false chains. The genuine, already-public issues are the
cross-origin WebSocket hijacks (CVE-2026-59723, CVE-2026-44211) and the unchecked `web-fetch`
loopback SSRF (issue #13494). No new finding; most of 48 tools unread in depth.

**claude-flow (18).** 655 priority rows reflect repo size (1273 tool names). `terminal_execute`
runs `execSync(command)` directly — command execution is the tool's stated function, with
env-denylist re-validation. `github-tools.ts` carefully splits a static-string `run()` from
an argv `runArgv()` and validates `owner`/`repo`/`branch` with `validateIdentifier`. The
`buildKHopCTE` SQL interpolates `relation` only after `validateIdentifier`. The public
**CVE-2026-59726** (unauthenticated RCE in the ruflo MCP bridge default docker-compose)
covers the deployment-level exposure. The repo (renamed to `ruvnet/ruflo`) also runs a
continuous self-audit: dozens of open "security"/"Dream Cycle" PRs and issues cover plugin
registry, SSRF, prompt-injection and MCP permission-boundary gaps. Most tools unread; no new
confirmed bug, and the project is already triaging this surface in the open.

**nitrostack (19).** A framework/CLI for building MCP servers. CLI `init` tools write a new
project under a caller-given `targetDir`; `server.ts` reads widget HTML from
`process.cwd()`-relative candidate paths (not a user path). A security-audit remediation PR
(**#351**) is already open. No new finding.

**gcloud-mcp (20).** The single priority row is `uploadObjectSafe` doing
`fs.readFileSync(params.file_path)` — but the tool's documented job is to upload a named
local file to a GCS bucket, so reading that path is the feature, and it runs under the
operator's own gcloud credentials. The main `run_gcloud_command` tool routes every command
through an allow/deny `AccessControlList` (denylist always on) plus `gcloud meta
lint-gcloud-commands`, and spawns `gcloud` with an argv array (no shell). Google ships a
`SECURITY.md` pointing at g.co/vulnz. No bug.

## What this batch showed about the scanner

- Large monorepos (claude-flow 655, cline 94, open-ux-tools 37 priority) are dominated by
  reach-walk chains through generic method names (`cleanup`, `dispose`, `save`, `replace`).
  Reading taint (`t/`) rows first, then ERROR-severity helper rows, remains the right order.
- Most batch-2 "sinks" are **by-design** in local developer tools (build, scaffold, run a
  CLI, upload a named file). The recurring question is confinement intent: does the tool
  claim a sandbox/root it then escapes? When the tool's documented job is to operate on a
  caller-named local path, an unconstrained path is not a vulnerability.
- Three repos had the genuine issue already public as a CVE (agentic-flow, cline, claude-flow)
  and one had an open audit PR (nitrostack). The GitHub prior-report lookup caught all four.
- Two repos (XcodeBuildMCP, claude-flow) returned HTTP 422 because they had been **renamed**
  (→ MobileBuildMCP, → ruflo); the search endpoint 422s on a stale slug. Fixed in
  `hunt.py`: resolve the canonical `full_name` via the repos API first, and isolate each
  sub-request so one failure no longer aborts the whole lookup. Re-run showed XcodeBuildMCP
  had already publicly hardened the exact sinks the scanner flagged.
