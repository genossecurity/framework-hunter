# Experiment 2 — Agent frameworks, batch 7 (ranks 31–40 of frameworks-top100.txt)

Same method/criterion. Scans local-only; **nothing filed**. Work dir `~/mcp-hunt-work/exp2`.

## Result: 0 net-new findings. The batch is dominated by *declared* code-execution tools
## (CodeAct / python-executor / Bash) — by-design, no confinement claim to bypass.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| omnigent-ai/omnigent | 5747 | 6 | 213 | by-design coding meta-harness (`Bash`/`Read`/`Write`/`Grep` + runner internals) |
| The-Pocket/PocketFlow | 274 | 0 | 0 | clean |
| simular-ai/Agent-S | 261 | 0 | 0 | clean |
| neuml/txtai | 409 | 5 | 27 | by-design agent coding tools (`bash`/`edit`/`grep`/`write`) |
| microsoft/agent-framework | 1452 | 0 | 31 | by-design CodeAct executor + parameterized vector stores (FP) |
| livekit/agents | 1241 | 0 | 7 | by-design realtime/voice tool I/O |
| GreyDGL/PentestGPT | 82 | 0 | 0 | clean |
| ag-ui-protocol/ag-ui | 2095 | 0 | 5 | by-design (UI protocol demo tools) |
| pipecat-ai/pipecat | 1703 | 0 | 7 | by-design voice-agent file/audio I/O |
| QwenLM/Qwen-Agent | 241 | 0 | 15 | by-design code interpreter (`python_executor`) + API wrappers |

## Notes

**Declared code executors (by-design — the context-mode criterion from exp1).** None claims a
sandbox/read-only boundary that the execution escapes; they are the tool's documented purpose:
- **microsoft/agent-framework** `LocalCodeAct/Resources/runner.py` — `compile()`+`exec(compiled)`
  is the CodeAct runner (`# nosec B102 - this runner exists to execute`). `_typing_utils.py`
  `eval(type_annotation)` resolves developer-declared workflow type strings (not model input).
- **QwenLM/Qwen-Agent** `tools/python_executor.py` — `exec(code_piece)` / `eval(expr)` is the
  code-interpreter tool.
- **omnigent** `client_tools/coding.py` — `Bash` (`subprocess(command)`), `Read`/`Write` (file I/O),
  `Grep` (argv). It is a coding meta-harness ("orchestrate Claude Code, Codex, …") that runs
  commands and edits files with the user's own permissions by design. `runner/gitlab_client.py`
  `glab` is argv (no shell).
- **neuml/txtai** `agent/tool/{bash,edit,grep,write}.py` (`forward`) — a coding-agent toolset;
  `bash` runs commands, `write`/`edit` write files, by design.

**microsoft/agent-framework SQL — FP / safe.** All 8 sql rows are in `_vector_store.py` backends
(duckdb/oracle/postgres/sql-server): `cursor.execute(statement, parameters/binds)` is parameterized;
collection DROPs use identifier quoting (`_quote_identifier`, psycopg `sql.SQL(...).format`). The
`_edge_runner._execute_on_target(message)` is workflow dispatch (`.execute` name collision). Not SQL
injection from tool input.

**livekit / pipecat / ag-ui / Agent-S / PocketFlow / PentestGPT — clean or by-design.** Realtime
voice / UI-protocol / computer-use frameworks; the few path/ssrf rows are by-design media/file I/O
or fixed-host fetches; no bypassed confinement claim surfaced (low counts, not exhaustively
line-verified).
