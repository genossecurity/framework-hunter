# Experiment 2 — Agent frameworks, batch 1 (the 10 least-used of frameworks-top100.txt)

Scope: static taint scan (MCP rules extended with agent-framework tool sources —
`@tool`/`@function_tool`/`@kernel_function`/`@agent.tool_plain`, `BaseTool._run`/`Tool.forward`,
LangChain.js `tool(fn,{schema})`/`DynamicTool`) + manual triage. Finding criterion unchanged
from exp1: a candidate requires a **claimed confinement** (sandbox / read-only / allowlist /
path-root) that an LLM-controllable tool argument escapes. Scans local-only; nothing filed.

Work dir: `~/mcp-hunt-work/exp2` (findings.csv, repos.csv, summary.md).
Prior-report (GitHub) dedup was **not** run in-scan; do it before any disclosure.

## Result: 0 net-new findings. All priority rows are by-design, already-confined, or FP.

| # | repo | files | taint | priority | verdict |
|---|---|---|---|---|---|
| 1 | Fosowl/agenticSeek | 67 | 0 | 0 | clean over tool surface |
| 2 | nanobrowser/nanobrowser | 286 | 0 | 2 | by-design (browser agent fetches URLs) |
| 3 | alibaba/page-agent | 131 | 0 | 1 | by-design (in-page GUI agent navigates) |
| 4 | ruc-datalab/DeepAnalyze | 602 | 1 | 2 | by-design declared code executor |
| 5 | Zipstack/unstract | 1904 | 0 | 6 | by-design (file inputs / configured backend) |
| 6 | mvschwarz/openrig | 1459 | 8 | 283 | FP (HTTP-as-SQL) + CLI/daemon internals |
| 7 | callstack/agent-device | 2019 | 0 | 41 | by-design (device/file control layer) |
| 8 | open-multi-agent/open-multi-agent | 208 | 7 | 13 | **already-confined** (sandbox correctly enforced) |
| 9 | harbor-framework/harbor | 940 | 0 | 22 | by-design benchmark adapters (eval harness) |
| — | BuilderIO/agent-native | 20098 | — | — | **SKIPPED** (see below) |

## Per-repo notes

**open-multi-agent — closest to a finding; verified safe.** Its built-in `file_read`/
`file_write`/`file_edit`/`glob`/`grep` tools *explicitly claim a sandbox* ("Built-in filesystem
tools are sandboxed to this directory", default `./.agent-workspace`). All 7 taint hits route
through `resolvePathWithinCwd` (`packages/core/src/tool/built-in/path-safety.ts`), which is a
textbook-correct containment: requires absolute paths, `realpath`s the root, checks containment
with `relative()` (`rel===''||(!startsWith('..')&&!isAbsolute)` — not the naive prefix bug),
fully resolves symlinks (ELOOP / dangling / `..`-across-symlink handled like the kernel), and
**re-checks containment after symlink resolution** to close the TOCTOU window. No bypass found;
the claimed confinement holds. (Its `shell/local.ts` is explicitly documented "not a sandbox or
security boundary" — a declared executor, not a bug.)

**ruc-datalab/DeepAnalyze — by-design.** `@tool def python(code)` runs `python -c <code>`
(`.../skyrl-gym/skyrl_gym/tools/python.py`, class `PythonCodeExecutorToolGroup`) with only a
timeout. A declared arbitrary-code executor in an RL-gym env; no confinement claimed → the
context-mode case from exp1, not a vuln.

**mvschwarz/openrig — FP + by-design.** 8 taint + 17 helper "sql-injection" are the documented
`.get()`/`client.get(...)` HTTP false positives (`client` is an HTTP client to a daemon URL
`http://host:7433`, fixed host, `encodeURIComponent`'d path params — not SQL, not SSRF). The
226 path-traversal and 10 command-injection priority rows are in `packages/cli/commands/`
(doctor/setup/start/whoami), `daemon/`, `tmux-*.ts`, `openshell-driver.ts` — CLI/daemon
internals that orchestrate local tools (tmux, openshell via argv arrays, no shell), linked only
by generic names (`exec`/`run`/`command`). Not reachable from the MCP tool handlers.

**callstack/agent-device — by-design.** 39 path-traversal + 1 command-injection in the
device-control layer (ADB/file ops); controlling the device is the tool's documented purpose.
`createAndroidCommandExecutorOverride→exec` is an intentional executor override.

**harbor-framework/harbor — by-design harness.** `exec(func_code)` (GAIA2 sidecar
`are_mcp_server.py`, `# noqa: S102`) and `_execute_bash(action.code)` (spider2-dbt adapter) are
benchmark/eval adapter code, not harbor's shipped agent-evaluation framework surface.

**nanobrowser / page-agent — by-design.** SSRF-class hits are browser/navigation agents
fetching/navigating model-supplied URLs — the documented capability (cf. browser-use). Not
exhaustively hand-verified line-by-line; no claimed URL allowlist to bypass was found.

**Zipstack/unstract — by-design.** Path-traversal on document-input paths and SSRF on the
configured extraction backend; no bypassed confinement claim surfaced.

**agenticSeek — clean** over the tool surface (0 priority; 51 helper rows all non-tool-reachable).

## BuilderIO/agent-native — SKIPPED (per user)
542 MB / 20,098 source files; mostly `templates/` UI (12,243 files). Exhaustive scan is
intractable in-budget; its agent tool definitions concentrate in `packages/toolkit` (35 sites)
and `packages/core` (27). Revisit scoped to those packages if desired.

## Scanner changes made for this batch (local; not committed)
- `tools/gen_rules.py`: added agent-framework tool sources (above). `make test` 21/21,
  `make recall` 4/4 CVEs still re-found.
- `scan.py`: recognize agent-framework tool files (`PY_DECO_RE`, `TOOLFILE_RE`, `TOOL_SITE_RE`);
  big-file guard in `minified_files()` now also drops >400 KB / big-generated files (a 32k-line
  `*.bridge.ts` slipped past avg-line minification detection and stalled the scan); semgrep
  pinned to all cores. Added `.generated`/`*.bridge.ts`/`*.generated.*` excludes.
