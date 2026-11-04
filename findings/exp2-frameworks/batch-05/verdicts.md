# Experiment 2 — Agent frameworks, batch 5 (ranks 51–60 of frameworks-top100.txt)

Same method/criterion. Scans local-only; **nothing filed**. Work dir `~/mcp-hunt-work/exp2`.

## Result: 0 net-new findings. All priority rows already-confined / by-design / not-tool-reachable / FP.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| julep-ai/julep | 488 | 0 | 7 | CLI/config/artifact-store internals + workflow `callTool` (not model-reachable) |
| tensortrade-org/tensortrade | 209 | 0 | 0 | clean |
| kyegomez/swarms | 1037 | 0 | 1 | by-design (1 ssrf, API wrapper) |
| 2FastLabs/agent-squad | 236 | 0 | 0 | clean |
| steel-dev/steel-browser | 212 | 0 | 0 | clean (by-design browser API) |
| plastic-labs/honcho | 780 | 0 | 6 | CLI subprocess internals + SQLAlchemy ORM `.execute` **FP** |
| Upsonic/Upsonic | 968 | 13 | 84 | **already-confined** (FS toolkit) + by-design (shell/e2b/mail) |
| GetStream/Vision-Agents | 550 | 0 | 4 | by-design RAG document ingestion |
| anthropics/claude-agent-sdk-python | 112 | 0 | 8 | SDK session-lifecycle internals, not tool-reachable |
| lastmile-ai/mcp-agent | 622 | 0 | 12 | CLI internals (install/config/api-client), not tool-reachable |

## Per-repo notes

**Upsonic — already-confined + by-design.** `autonomous_agent/filesystem_toolkit.py` confines
correctly: `self.workspace = Path(workspace).resolve()`, `_validate_path` → `Path(path).resolve()`
(or `(workspace/path).resolve()`) then `resolved.relative_to(self.workspace)` raising `ValueError`
on escape — symlink-safe via `.resolve()`. So `move_file`/`delete_file`/`rmtree` are guarded.
`shell_toolkit.py` / `ralph/tools/filesystem.py` `run_command` are **declared** shell executors
(`subprocess.run(command, shell=...)`, docstring examples `pip install…`); `_validate_command`
is a defense-in-depth denylist, not a confinement contract — by-design, not the crewly case.
`tools/custom_tools/e2b.py` (upload/download) and `mail.py`/`gmail.py` attachment tools read/write
local paths by design (file transfer), no bypassed confinement claim.

**anthropics/claude-agent-sdk-python — not tool-reachable.** The 8 path-traversal rows are in
`_internal/session_mutations.py` (`delete_session` → `rmtree(path.parent / session_id)`) and
`session_resume.py` (`_rmtree_with_retry`, `_copy_auth_files` reading `~/.claude`). `session_id`/
paths are SDK-generated session identifiers, not LLM/tool arguments; the SDK even ships
`_is_safe_subpath`. Reach-walk linked them via generic names (`rmtree`/`path`). Internal lifecycle
ops, not a model-controllable sink.

**lastmile-ai/mcp-agent — CLI internals.** All rows under `src/mcp_agent/cli/` (install flow
`subprocess`/`os.remove`, `_load_config` open, `api_client` post to the configured cloud API).
Operator CLI paths, not agent tool handlers.

**julep — CLI/workflow internals.** `cli/{config,ledger,runcache}`, `artifact_store`, `blobstore`
use operator-config roots; `effects.py callTool(url)` is workflow-defined (developer) tool dispatch.
Not untrusted-model-reachable.

**honcho — CLI + ORM FP.** `honcho-cli` runs `exe`/`docker compose` (operator CLI). `src/crud/*`
`select(...).where(...)` + `db.execute(stmt)` are SQLAlchemy ORM (parameterized) — the `.execute`
sink is a false positive, not string SQL.

**Vision-Agents — by-design.** RAG ingestion tools (`rag.py add_directory`, Gemini `file_search`
`_upload_file`/`add_documents`) read user-supplied document paths/dirs for indexing; expected
capability, no confinement claim to bypass.

**swarms / tensortrade / agent-squad / steel-browser — clean** over the tool surface (0–1 priority,
by-design API wrapper).
