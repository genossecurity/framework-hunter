# Experiment 3 — CodeQL vs Semgrep delta, triage verdicts (batches 1–4)

CodeQL hunt over the Exp 2 agent-framework corpus (`repos.txt`, smallest-first), built-in
`*-security-extended` suites + custom agent-tool-source pack (`ql/python`). Work dir
`~/mcp-hunt-work/exp3`; SARIF per repo under `sarif/`. Machine-usable FP records in
`~/mcp-hunt-work/exp3/fp_ledger.csv` (used by `diff_semgrep.py --fp-ledger` to subtract
inflated delta). **Nothing filed.**

## Result so far (80/100 repos): 0 net-new reportable findings.
Every real-code agent hit is a **by-design** capability (shell/code/query tool, full-access agent);
every high-value non-agent hit is **FP** (sanitizer CodeQL can't model), **trusted-input**, or
**known-public**. On the 2 confirmed Exp-2 PoCs in this corpus, **CodeQL flagged neither** (see
"CodeQL misses").

## Two structural signals
1. **The CodeQL-only delta is inflated by sanitizer-blindness.** CodeQL flags path/tar code guarded
   by `is_relative_to`, `commonpath`, `validate_path_segment`, `resolve_safe_path`, `'..' in parts`,
   and per-member tar `validate()` loops — none of which it models as barriers. The raw
   `diff_semgrep.py` CodeQL-only count must have these subtracted; after triage the real missed-bug
   count is ~0 so far.
2. **CodeQL = capability detector for agent-exec.** The agent-tool-param → `subprocess`/`eval` query
   fires true-positive on every framework that ships a shell/code/query tool. These are features,
   not bugs.

## CodeQL misses (confirmed bugs it did NOT flag) — the honest counterweight
| repo | confirmed bug (Exp 2) | why CodeQL missed it |
|---|---|---|
| TencentCloudADP/youtu-agent | `eval()` of model ReAct output (RCE) `react_converter.py:207` | eval sink recognized, but source is model output, not a tool-handler param → agent/* queries can't connect source→sink |
| aden-hive/hive | `csv_sql` DuckDB `read_text/read_csv` guard bypass → arbitrary file read | semantic guard-bypass, not a taint source→sink flow; 0 hits in `csv_tool.py`/`excel_tool.py` |

Both are guard-bypass / semantic bugs — the class a generic taint query structurally cannot catch.

---

## Batch 1 (repos 1–20)
| repo | top CodeQL hit | verdict |
|---|---|---|
| TransformerOptimus/SuperAGI | `/verify_end_point` full-SSRF (unauth) | **known-public** (issue #1476 + PR #1502); clone stale (Jan 2025 HEAD) |
| simular-ai/Agent-S | shell-cmd in `show_permission_dialog` ×8 | **FP** — function never called (dead code) |
| crestalnetwork/intentkit | path-injection ×3, partial-SSRF ×3 | **FP** — `is_relative_to` guard / fixed API hosts |
| TencentCloudADP/youtu-agent | (none in csv/eval) | **codeql-missed** — confirmed eval RCE not flagged |
| others | log-injection / jinja2-autoescape / cert-validation noise | not triaged (low-value rules) |

## Batch 2 (repos 21–40)
First batch where the custom agent queries fired on real code.
| repo | CodeQL hit | verdict |
|---|---|---|
| ApodexAI/FrontierAgent | `agent/cmd-injection` `sandbox.py:257` | **by-design** — `run_shell` in bwrap jail (also already triaged Exp2 batch-2) |
| Upsonic/Upsonic | `agent/cmd-injection` `filesystem.py:433`, `shell_toolkit.py:146` | **by-design** — shell tools (matches Exp2 batch-5 verdict) |
| Fosowl/agenticSeek | path-injection ×8 `files_api.py` | **FP** — `resolve_workspace_path` (realpath+commonpath). Minor: `files_router` is unauth but workspace-confined + host-allowlisted |

## Batch 3 (repos 41–60)
First genuine delta data (tarslip — Semgrep found 0 of this class corpus-wide).
| repo | CodeQL hit | verdict |
|---|---|---|
| neuml/txtai | SQLi ×3 (`client.py`,`rdbms.py`); tarslip `tar.py:38`; `agent/cmd-injection` `bash.py:62` | **by-design** (query API on user's own DB; bash tool) / **FP** (tar per-member validate + filter=data) |
| FoundationAgents/MetaGPT | tarslip `download_data.py:33` | **trusted-input** — hardcoded GDrive dataset URLs |
| truefoundry/trueforge | tarslip `skill_downloader.py:420` | **trusted-input** — registry presigned tar; filter=data on 3.12+ |
| QwenLM/Qwen-Agent, katanaml/sparrow | full-SSRF (OVERLAP, not delta) | by-design SSRF-to-configured-endpoint |

## Batch 4 (repos 61–80)
Two full web-app repos (`hive`, `agent-zero`) dominate the path-injection delta.
| repo | CodeQL hit | verdict |
|---|---|---|
| aden-hive/hive | path-injection ×15 `routes_colonies.py`; `agent/cmd-injection` `file_ops`/`terminal_tools` | **FP** (`'..' in parts` + `resolve_safe_path`) / **by-design** (file/terminal tools). **csv_sql PoC: codeql-missed** |
| agent0ai/agent-zero | path-injection ×40 (`api_files_get.py`, `files.py`, `skills.py`) | **by-design** — full-system-access agent, API-key gated, Docker-sandboxed |
| pipecat-ai/pipecat | path-injection `run.py:1108` (`/files/{filename:path}`) | **FP** — `_resolve_download_path` = `resolve()` + `is_relative_to` → 403 |
| google/adk-python | path-injection ×2 (eval managers) | **FP** — `validate_path_segment` module |
| OpenPipe/ART | path-injection ×3 (`checkpoints.py`,`s3.py`) | **trusted-input** — internal training paths |

## Not yet triaged (flagged, no verdict)
- vercel/eve `js/request-forgery` (Discord gateway, 24 steps) — batch 3
- rowboatlabs/rowboat `js/unvalidated-dynamic-method-call` `server.ts:537` — batch 3
- FoundationAgents/MetaGPT mineflayer `js/code-injection` (minecraft bot JS) — batch 3
- steel-dev/steel-browser `js/path-injection` ×4 `file.service.ts`, `js/request-forgery` `fetchPdf.ts` — batch 4
- agent0ai/agent-zero `py/command-line-injection` `helpers/git.py:448` (21 steps) — batch 4
- lavague-ai/LaVague `js/unvalidated-dynamic-method-call` `driver.ts:144` — batch 4
