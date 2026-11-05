# Integration prompt — merge MCP-source support into the CodeQL hunt

Paste this to your coding agent, pointed at your real `codeql-hunt` working copy.
It integrates the MCP changes already made to the Python pack and builds the
missing JS/TS equivalent (the part that actually matters for the MCP corpus,
since the reference MCP SDK is TypeScript).

---

You are extending a CodeQL batch-scanning harness that hunts injection bugs in
GenAI tool code. It has two corpora: **MCP servers** (Exp 1, Semgrep found 0) and
**agent frameworks** (Exp 2, Semgrep found 3). The Python pack (`ql/python/`)
already models tool-handler parameters as taint sources via `AgentSources.qll`,
which now defines:

- `isAgentToolHandler(Function)` — framework handlers (`@tool`, Tool-subclass methods).
- `isMcpToolHandler(Function)` — MCP handlers: FastMCP `@mcp.tool`/`@mcp.resource`/
  `@mcp.prompt`, and the low-level dispatcher (`@server.call_tool`, or a
  `call_tool`/`handle_call_tool` fn with an `arguments`/`args` param).
- `ToolParamSource` — the union; both `agent_cmdi.ql` (CWE-78) and
  `agent_codeexec.ql` (CWE-94) use it as `isSource`.

## Tasks

1. **Validate the Python pack.** Run `codeql query compile ql/python`. The
   dataflow API drifts between CodeQL versions — fix any predicate that fails to
   compile (likely culprits: `DataFlow::parameterNode`, `Function.getArg`,
   `getADecorator`). Do NOT change the source *semantics*, only make it compile.

2. **Build the JS/TS pack `ql/javascript/`** — this is the priority; most MCP
   servers are TypeScript and currently get only the built-in JS suite, which
   does not model tool handlers as sources (so a "clean" JS MCP server today just
   means "not covered"). Port `AgentSources.qll` → `ql/javascript/AgentSources.qll`
   with a `ToolParamSource` class covering these MCP shapes:
   - `server.tool(name, schema, async (args) => { ... })` — `args` is the source
     (the callback's first non-context parameter).
   - `server.setRequestHandler(CallToolRequestSchema, async (req) => { ... })` —
     `req.params.arguments` is the source.
   - FastMCP-TS / decorator forms if present (`@Tool()` method params).
   Also port framework shapes (`new Tool({ func })`, `tool(...)` helpers) so the
   agent corpus still scans. Then add `ql/javascript/agent_cmdi.ql` (sink:
   `SystemCommandExecution`) and `ql/javascript/agent_codeexec.ql` (sink:
   `eval`/`Function`/`vm` code execution), mirroring the Python queries, plus a
   `qlpack.yml` depending on `codeql/javascript-all`.

3. **Prove the sources fire.** Add a minimal fixture repo for each language under
   `tests/` (a decorated tool handler whose parameter flows to `subprocess`/
   `child_process.exec`), build a DB, analyze, and confirm `agent_cmdi` reports a
   path. If it reports nothing, the source predicate is wrong — fix it, don't
   loosen the sink.

4. **Leave the driver/diff as-is.** `run_codeql_hunt.py` already takes `--corpus`
   and auto-detects languages; `diff_semgrep.py` already treats a missing
   `--semgrep` as a 0 baseline (the MCP case). Don't touch them unless a test fails.

## Acceptance

- `codeql query compile ql/python` and `codeql query compile ql/javascript` both pass.
- Each fixture produces exactly one `agent_cmdi` path result.
- `python3 run_codeql_hunt.py --corpus mcp --repos mcp_repos.txt --dry-run` runs clean.

## Honest caveats to preserve

- These predicates are heuristics; expect false positives from the broad
  decorator regex (`resource`, `prompt`). Every finding is a *candidate* to
  hand-verify against source, not a confirmed bug.
- Report the two corpora separately. The MCP number is "what Semgrep's 0 missed";
  the agent number is a miss-rate against a real baseline. Don't merge them.
