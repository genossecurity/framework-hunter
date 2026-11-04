# Experiment 2 — Agent frameworks, batch 3 (ranks 71–80 of frameworks-top100.txt)

Same method/criterion as batches 1–2. Scans local-only; **nothing filed**. Work dir
`~/mcp-hunt-work/exp2`.

## Result: 1 net-new finding (youtu-agent `eval` RCE, PoC-confirmed, deduped non-public, NOT filed);
## 1 secondary low-confidence note (agency-swarm). Rest by-design / already-confined / FP.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| darrenhinde/OpenAgentsControl | 211 | 0 | 7 | by-design file tools (not escalated) |
| ag2ai/ag2 | 1245 | 1 | 24 | **already-confined** (FilesystemToolkit base_dir guard) |
| FellouAI/eko | 127 | 0 | 0 | clean |
| superduper-io/superduper | 253 | 0 | 0 | clean |
| Integuru-AI/Integuru | 13 | 0 | 0 | clean |
| rowboatlabs/rowboat | 1571 | ~12 | 137 | by-design local coworker FS; `file` param confined, `appFolder` weak (not escalated) |
| aipotheosis-labs/aci | 374 | 0 | 0 | clean |
| VRSEN/agency-swarm | 440 | 1 | 31 | **secondary**: `exec` of codegen from OpenAPI schema (dev-supplied → low) |
| TencentCloudADP/youtu-agent | 323 | 1 | 18 | **FINDING: `eval()` of model output → RCE (react runner)** |
| vercel/eve | 5047 | 2 | 163 | by-design (E2B `sandbox.run`; templates); SSRF FP (fixed hosts) |

---

## FINDING — TencentCloudADP/youtu-agent: RCE via `eval()` of model output in the ReAct parser

**Status: PoC-confirmed (local, sandboxed, benign); deduped — no public report/GHSA; NOT filed.
Awaiting user disclosure decision.** Local clone only; HEAD today.

**Location:** `utu/models/react_converter.py`, `ReactConverter._parse_react_output()` (~L202–207).

```python
try:
    action = json.loads(text_output)
except json.JSONDecodeError:
    try:
        action = eval(text_output)          # <-- CWE-94
    except Exception as e:
        raise ValueError(f"Invalid action: {text_output}") from e
assert "name" in action and "arguments" in action      # runs AFTER eval's side effects
```

**Reachable & live.** `ReactModel(OpenAIChatCompletionsModel)` (`utu/models/react.py`) wires
`converter.postprocess(model_response.output)` → `_parse_react_output`. Selected by config
`agent_config.py:78` `runner: Literal["openai","react"]` — the `react` runner (used for models/
providers that emit ReAct-style `Action:` text rather than native tool-calls). `text_output` is
the model's generated text after the `Action:` marker.

**Why `eval` is reached on normal output, not just malicious:** `json.loads` is tried first, but
the ReAct format emits Python-literal dicts with single quotes (the docstring's own sample:
`{'query': 'smolagents package'}`), which is invalid JSON → falls through to `eval`. So `eval`
is the routine parse path, not a rare branch.

**Impact (CWE-94, RCE).** A model Action that is non-JSON but valid Python executes arbitrary
Python in the agent host *before* the `name/arguments` validation. Threat model = indirect
prompt injection: untrusted content in context (web page, tool output, retrieved doc) steers the
model to emit e.g.
`__import__('os').system('…') or {'name':'x','arguments':{}}` → RCE under the agent-runner
identity. Same injection→RCE model as exp1's crewly.

**PoC (confirmed — against the REAL code).** Two PoCs in `youtu-agent-poc/`, both run under
`tools/sandbox.sh` (bwrap, net off, `$HOME` tmpfs, `/` ro), benign canary only:
- `poc_real.py` executes the **unmodified** `react_converter.py` (copied as
  `react_converter.sample.py`, sha256 `5377ddb…`, verified to contain `action = eval(text_output)`)
  with its heavy imports stubbed, and calls the real `ReactConverter._parse_react_output()`. A
  benign Action `__import__('os').system('touch …') or {'name':'search','arguments':{'q':'x'}}`
  creates the canary and the parser returns a valid-looking item → **silent RCE confirmed on the
  repo's own bytes**. Transcript: `run-transcript.txt`. PDF report: `poc.pdf` (3 pp.).
- `poc.py` is the minimal faithful repro of the same two lines.
json.loads fails first (single quotes), eval executes the side effect before validation.

**Dedup — appears non-public.** No GHSA (`security-advisories` empty). Issue/PR search for
eval / code injection / `_parse_react_output` / arbitrary code returned only *evaluation*-benchmark
threads (GAIA/SWE-bench), no security report.

**Reachability caveat (state honestly):** gated on `runner: react`. The default is `openai`
(native tool-calls), which does **not** hit this path. So it affects deployments that select the
ReAct runner — typical for open/non-OpenAI models lacking native function-calling.

**Fix:** use `ast.literal_eval(text_output)` (parses Python literals, executes nothing); or require
strict JSON. One-line change.

---

## SECONDARY (low confidence) — VRSEN/agency-swarm: `exec()` of generated model code
`src/agency_swarm/tools/utils.py:470` `exec(result, exec_globals)` in `generate_model_from_schema`,
where `result` is Python emitted by datamodel-code-generator. Callers (`tool_factory_utils/
openapi_importer.py`) feed it an **OpenAPI schema's** `properties.parameters` / request body. Only
exploitable if the OpenAPI spec is attacker-controlled (e.g. an agent importing a spec from an
untrusted URL). Developer-supplied specs → low risk. No public report (GHSA 0; #645 "harden
security defaults" is unrelated). Flag for the record; not escalated without a model-controlled
spec-import path.

## Dismissed
- **ag2 (AutoGen):** `FilesystemToolkit` (`ag2/tools/toolkits/filesystem.py`) resolves every path
  through `_resolve_path`→`_check_within` (`resolved.is_relative_to(base_dir)`, raises on escape),
  symlink-aware `_is_within`, and `_delete_file` refuses the base dir itself. Documented
  "path-traversal guard"; correctly enforced. Already-confined.
- **rowboat:** `read-data`/`app-set-data` confine `file` correctly (`normalize`+reject `..`/abs+
  `resolve`+`startsWith(dataRoot+sep)`). `appFolder` is unnormalized but only selects a dir that
  must hold a valid `rowboat-app.json` → weak read-only info-disclosure; rowboat is a local
  single-user "AI coworker" acting with the user's own FS access. Not escalated.
- **vercel/eve:** 27 code-injection are all E2B `sandbox.run(...)` in computer-use/code tools —
  the sandbox is the confinement; running commands in it is the documented capability. 107
  path-traversal largely in `apps/templates/*` example agents. SSRF rows target fixed hosts
  (`discord.com/api/...`, `encodeURIComponent`'d params). By-design / FP.
- **OpenAgentsControl:** JS file tools; by-design, no bypassed confinement claim surfaced (not
  exhaustively line-verified).
- **eko / superduper / Integuru / aci:** 0 priority over tool surface.
