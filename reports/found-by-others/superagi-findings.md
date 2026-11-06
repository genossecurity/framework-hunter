# SuperAGI — found-by-others (already disclosed upstream)

Real bugs in [TransformerOptimus/SuperAGI](https://github.com/TransformerOptimus/SuperAGI),
**already public** — recorded here for completeness/dedup, not for us to report first. The
scanned clone was stale (~Jan 2025).

## 1. `eval()` of LLM output → RCE (CWE-94) — known-public

**Files:** `superagi/agent/output_handler.py:149` (BaseOutputHandler), `:180`
(ReplaceTaskOutputHandler), `superagi/agent/queue_step_handler.py:79`.

The agent passes the LLM response to `eval()`. Influence the model output → arbitrary Python
execution in the SuperAGI process.

**PoC (shape):** drive a step whose LLM reply is `__import__('os').system('id')` → `eval()`.

**Public:** issues #1560, #1489, #1567; fix PRs #1492, #1493, #1568.

## 2. SSRF in `/verify_end_point` (CWE-918) — known-public

**File:** `superagi/llms/hugging_face.py:109`. Unauthenticated route fetches a user-supplied
endpoint URL server-side → SSRF to internal services / cloud metadata.

**PoC:** `POST /verify_end_point` with `end_point=http://169.254.169.254/…`.

**Public:** issue #1476, PR #1502 (open).

---

### Note on the `candidates/` subfolder
Exploratory MCP-hunt triage queues (not confirmed). **firecrawl/firecrawl-mcp-server** overlaps
public SSRF issues #210/#194/#152 (clearly found-by-others). The rest
(azure-devops-mcp, vouchington-tooling, agent-blackboard, next-devtools-mcp) are unconfirmed
leads — left here until triaged/deduped rather than claimed as novel.
