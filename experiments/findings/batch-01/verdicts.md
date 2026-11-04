# Batch 1 verdicts: funnel repos 1-10 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-01/report.md`. Source review only unless
stated. Nothing filed.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 1 | haydenbleasel/blume | clean over MCP | full on MCP code; `haydenbleasel__blume.md` |
| 2 | supabase/mcp | real scope bypass, public (PR #351) | PoC against mocks; `supabase__mcp.md` |
| 3 | ruvnet/agentdb | clean over MCP | taint and SQL rows read; `ruvnet__agentdb.md` |
| 4 | microsoft/azure-devops-mcp | no bug found | artifact download and wiki URL building read; the other 8 tool files were not |
| 5 | vouchington/vouchington-tooling | no bug found | exec sinks only: argv-based `execFile`/`spawn`, no shell; schema grep found no path arguments, but `spawn(request.command, ...)` in `policy-spawn.mts` was not traced |
| 6 | jonathanong/agent-blackboard | design weakness, low | `snapshot_export` traced; rest not read |
| 7 | firecrawl/firecrawl-mcp-server | real local file read, public (#306, PR #447) | `firecrawl__firecrawl-mcp-server.md` |
| 8 | vercel/next-devtools-mcp | clean | all 4 tools read; `vercel__next-devtools-mcp.md` |
| 9 | GLips/Figma-Context-MCP | clean at HEAD | `GLips__Figma-Context-MCP.md` |
| 10 | ruvnet/ruvector | no new bug; path gap public (PR #1308) | path validator, exec calls and decompiler read; most of the 215 tools were not |

## Notes

**agent-blackboard, `snapshot_export`.** `path` is a tool argument with only an `isAbsolute`
check, so an agent can create a file anywhere the user can write. `open(path, 'wx', 0o600)`
refuses to overwrite, and contents are JSONL of session entries, so injected lines arrive
JSON-escaped. Stdio only. The schema documents an absolute path as the feature. Not worth
reporting without a concrete file that a JSON line can weaponise.

**ruvector, decompiler.** `reconstructRunnable` and `checkFunctionalEquivalence` run package
code in `node:vm` with host functions in the sandbox, which is escapable. Not reachable over
MCP: `decompile_package/file/url` pass only `minConfidence`, and `reconstruct`/`validate`
default to false. No code in `mcp-server.js` turns them on. `reconstructRunnable` is exported
from the package, so a library caller could reach it. Worth rechecking if a tool ever exposes
those options.

**ruvector, `workers_*`.** The missing path confinement and option injection are in the
owner's open PR #1308 (2026-11-02). Duplicate.

## What the batch showed about the scanner

- Priority counts mostly reflect repo size and my name-based reach walk, not risk. agentdb
  (32) and ruvector (105) are mostly false chains through common method names like `save` and
  `load`. Read taint rows first, then ERROR-level helper rows.
- The bugs in this batch's public record (supabase, ruvector's confinement gap) are missing
  authorization or confinement checks. Taint rules do not model those well, so each triage
  has to read how path and scope arguments are validated.
