# Experiment 2 — Agent frameworks, batch 8 (ranks 21–30 of frameworks-top100.txt)

Same method/criterion. Scans local-only; **nothing filed**. Work dir `~/mcp-hunt-work/exp2`.
This batch is the upper-mid of the most-used list (camel, pydantic-ai, adk-python, langchainjs,
swarm, …). **taint tier = 0** across all 10.

## Result: 0 net-new findings. All priority rows by-design / declared-executor / FP.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| TransformerOptimus/SuperAGI | 517 | 0 | 22 | by-design tool I/O (path/ssrf) |
| camel-ai/camel | 1161 | 0 | 124 | by-design broad toolkit + declared browser code-exec |
| Canner/WrenAI | 260 | 0 | 17 | by-design text-to-SQL (executing generated SQL is the product) |
| microsoft/agent-lightning | 127 | 0 | 0 | clean |
| agent0ai/agent-zero | 1644 | 0 | 33 | by-design (intentionally-powerful agent: code/terminal/file) |
| pydantic/pydantic-ai | 2414 | 0 | 108 | FP (`.execute`/`text()` collisions) + by-design plugin/IPython exec |
| camel-ai/owl | 61 | 0 | 6 | by-design (API wrappers) |
| langchain-ai/langchainjs | 2249 | 0 | 4 | by-design (4 ssrf, fetch tools) |
| google/adk-python | 2287 | 0 | 36 | by-design artifact/tool I/O + parameterized sessions |
| openai/swarm | 62 | 0 | 36 | by-design (educational multi-agent; tool examples) |

## Notes

**camel — declared browser code executor + broad toolkit.** `toolkits/browser_toolkit.py` (and
`async_browser_toolkit.py`) `_fix_action_code` builds `code = "self.browser." + action_code` from
LLM-generated browser actions and `eval(code)`/`exec(code)` it — a documented browser-automation
mechanism (execute generated actions), not a bypassed sandbox. The other 83 path-traversal + 24
ssrf are its large tool collection (file tools, API wrappers) — by-design, no single
claimed-confinement boundary.

**pydantic-ai — FP + by-design (and none in pydantic-ai core).** The 54 "sql" rows are name
collisions on `.execute`: `durable_exec` `call.execute(workspace)`, `ipython_code_mode` Jupyter
`client.execute(code)` (a declared IPython code-execution mode), a `text()` session-JSON helper,
and an internal `PRAGMA table_info({table})` on a store-owned table name. The code-exec rows:
`_callable._resolve` `eval(annotation)` (= `typing.get_type_hints`, developer types),
`capability_creation/_validate` compile+exec and `factories.import_file` (`# Explicitly trusted`
plugin loading), `builtin_plugins/hooks` subprocess (CLI hooks). All in the `pydantic_ai_harness`/
`pydantic_clai2` CLI/harness packages, trusted/developer-controlled — not model-reachable RCE.

**WrenAI — by-design text-to-SQL.** 12 sql rows are its generated-SQL execution against the user's
database (the product). No read-only confinement claim found to bypass.

**agent-zero — by-design.** An intentionally capable agent (code execution, terminal, file tools);
these are declared capabilities, not a bypassed confinement.

**google/adk-python — by-design / FP.** 36 priority (no taint, no RCE-class): artifact/file tool
I/O and parameterized session-service SQL; well-maintained, nothing escaped a stated boundary (not
exhaustively line-verified).

**SuperAGI / owl / langchainjs / swarm / agent-lightning — clean or by-design** API-wrapper / tool
examples.
