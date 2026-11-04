# Experiment 2 — Agent frameworks, batch 9 (ranks 11–20 of frameworks-top100.txt)

Same method/criterion. Scans local-only; **nothing filed**. Work dir `~/mcp-hunt-work/exp2`.
**mastra-ai/mastra is DEFERRED** (ran >22 min — the densest repo in the corpus; to be scanned
after batch 10). The other 9 of the slice are covered here. openai-agents-python re-verified clean
(see `adhoc/openai-agents-python.md`).

## Result: 0 net-new findings. All deserialization/exec/SQL rows resolve to safe / by-design / FP.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| topoteretes/cognee | 3992 | 1 | 163 | FP (parameterized vector SQL) + by-design codegen-exec (low-reach) |
| deepset-ai/haystack | 603 | 0 | 16 | safe (YamlLoader = SafeLoader) + by-design file/fetch |
| vercel/ai | 7724 | 1 | 48 | by-design sandbox bash tools (`sandbox.run`/`runShell`) across harness pkgs |
| microsoft/semantic-kernel | 1290 | 1 | 15 | confined (`validated_path` session upload) + parameterized |
| mem0ai/mem0 | 1040 | 0 | 53 | FP (`exec`=local dispatcher) + parameterized store + by-design fetch |
| TencentCloud/TencentDB-Agent-Memory | 1027 | 0 | 43 | FP (ClickHouse `.command`, internal table) + memory-proxy file ops |
| ComposioHQ/composio | 2016 | 0 | 21 | by-design tool-integration platform (API wrappers + tool file I/O) |
| huggingface/smolagents | 75 | 0 | 18 | by-design CodeAgent (exec/pickle, warned) + web fetch |
| openai/openai-agents-python | 1034 | 0 | 13 | already-confined (robust sandbox; see adhoc note) |
| — mastra-ai/mastra | ~7954 eff | — | — | **DEFERRED (after batch 10)** |

## Notes (the sinks that mattered)

- **haystack `yaml.load(Loader=YamlLoader)`** (`marshal/yaml.py`): `class YamlLoader(yaml.SafeLoader)`
  — a SafeLoader subclass that only adds a `python/tuple` constructor (safe). Not unsafe YAML. Safe.
- **smolagents** (`serialization.py` `pickle.loads`, `tools.py from_code` `exec`): pickle path emits
  a `FutureWarning` "security risk if the data is untrusted" and is used for the framework's own
  remote-executor serialization (trusted round-trip); `exec(tool_code)` is the CodeAgent's declared
  code-execution mechanism. By-design + warned, not a net-new confinement bypass.
- **mem0** (`pi-agent-plugin/src/memory/tools.ts` `exec(params)`): `exec` is a local variable
  (`const exec = buildToolExecute(mem0, ...)`), a memory-tool dispatcher — not `child_process.exec`.
  False positive. The 14 "sql" are the memory store (parameterized), 21 ssrf are configured
  LLM/embedding endpoints (by-design).
- **cognee** (`graph_model_utils.py` `exec(result)`): datamodel-code-generator output from a
  DataPoint JSON schema (`# noqa: S102 ... on purpose`) — same class as agency-swarm's secondary
  note; exploitable only if the schema is attacker-controlled (it is cognee's own ontology). The 88
  "sql" are `TursoVectorAdapter`/other vector adapters with `execute(sql, tuple(params))` —
  parameterized, FP.
- **vercel/ai**: every code/command-injection row is `sandbox.run({command})` / `runShell(...)` in
  `tool-bash`, `anthropic/.../bash_2025*`, `harness-cline`, `harness-pi`, `harness/utils` — declared
  bash/computer-use tools that execute in a configured sandbox (the boundary), with `shellQuote` on
  interpolated paths. By-design.
- **TencentDB-Agent-Memory**: `wecom-identity.ts` `client.command({query: \`...${table}\`})` is a
  ClickHouse client command with an internal table name — `.command(` matched the execa sink. FP.
- **semantic-kernel**: `sessions_python_plugin.upload_file` → `open(validated_path)`; `validated_path`
  is the plugin's containment for the Azure Container Apps session sandbox. Confined/by-design.
- **composio**: a 1000+ tool integration platform; path/ssrf/sql are API-wrapper and tool file I/O,
  by-design (not exhaustively line-verified).
