# Experiment 2 — Agent frameworks, batch 10 (ranks 1–10 of frameworks-top100.txt — the most-used)

Same method/criterion. Scans local-only; **nothing filed**. Work dir `~/mcp-hunt-work/exp2`.

## Result: 0 net-new findings. The 10 most-used frameworks are clean / by-design / confined / FP.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| agno-agi/agno | 5434 | 2 | 357 | cookbook EXAMPLES (shell) + by-design code_mode + parameterized SQL |
| langchain-ai/langgraph | 490 | 0 | 7 | parameterized SQL + by-design |
| AstrBotDevs/AstrBot | 890 | 0 | 29 | by-design plugin/file tools |
| HKUDS/nanobot | 1825 | 0 | 30 | by-design file tools |
| run-llama/llama_index | 3780 | 0 | 218 | by-design integrations (model/index load) + parameterized SQL |
| crewAIInc/crewAI | 1476 | 13 | 104 | **already-confined** (`safe_path`: realpath + `commonpath`) + parameterized DB |
| microsoft/autogen | 680 | 0 | 20 | by-design tool-from-config `exec(source_code)` (trusted) |
| FoundationAgents/MetaGPT | 913 | 0 | 2 | by-design |
| browser-use/browser-use | 418 | 0 | 3 | by-design code-exec tool |
| langchain-ai/langchain | 2651 | 0 | 15 | parameterized SQL + by-design file/fetch |

## Notes

**crewAI — already-confined (correct).** `crewai-tools/security/safe_path.py` `validate_file_path`
does `os.path.realpath(join(base, path))` (symlink + `..` safe) then
`os.path.commonpath([resolved_base, resolved_path]) == resolved_base` — the correct containment
(no sibling-prefix bug), safe basename fallback on failure. `FileWriterTool` documents "Writes are
confined to base_dir … Set base_dir to widen that sandbox deliberately." The `CREWAI_UNSAFE_PATHS`
escape hatch is a documented operator opt-out, not a bypass. file_read/DB-search tools are
parameterized (`cursor.execute(sql, params)`) or by-design; jina/contextual scrape are by-design
fetch tools (`https://r.jina.ai/{url}`).

**agno — examples + by-design.** The 2 taint (`execute_shell_command` `subprocess(..., shell=True)`)
are in `cookbook/` (human-in-the-loop *examples*, not shipped lib). `libs/agno/.../code/code_mode.py`
`dill.loads(base64…)` is the CodeAct tool's result round-trip (declared executor; dill is a sharp
edge like smolagents' pickle, but the framework's own execution channel). 164 sql are parameterized
toolkit DB tools; 135 path-traversal are the broad toolkit (by-design, like camel/PraisonAI).

**llama_index — by-design integrations.** `embeddings-adapter/utils.py` torch-model load and
`vector-stores-txtai` `from_persist_path` `pickle.load` are persistence/model-loading of the user's
own saved artifacts (trusted). 80 sql are parameterized vector-store adapters; 85 path / 50 ssrf are
reader/integration file & API I/O, by-design.

**microsoft/autogen — by-design tool serialization.** `autogen-core/tools/_function_tool.py`
`_from_config` `exec(import_code)` / `exec(config.source_code)` reconstructs a FunctionTool from its
serialized config — a developer/trusted config channel (loading an untrusted agent config would be
the risk, a known/documented property), not a model-controllable tool argument.

**browser-use — by-design.** `mcp/cli_mcp.py` `exec(code, ns)` is a declared code-execution tool.

**langchain / langgraph / AstrBot / nanobot / MetaGPT — by-design / parameterized.** SQL rows are
parameterized ORM/driver calls; path/ssrf are by-design file and fetch tools; no bypassed
confinement claim surfaced (not exhaustively line-verified at these volumes).

## Cross-batch observation (path-confinement implementations)
Of all frameworks that ship a file-path sandbox, only **one implemented it incorrectly** — nexent
(`startswith` without a separator, batch 4). The rest got it right with the correct primitive:
crewAI (`commonpath`), openai-agents-python (`.parents`), ag2 / Upsonic (`relative_to`), genkit
(`rootDir + sep`), hive `resolve_safe_path` (`root + os.sep`), open-multi-agent (`relative()` +
symlink re-check). The net-new file bug was in the least-scrutinized of them.
