# Findings — mcp-hunt (CodeQL two-lane audit)

Security findings from the CodeQL audit of the agent-framework + MCP-server ecosystem
(1,030 repos: exp1 141 MCP, exp2 100 agent, fw-500 400 frameworks, mcp-500 392 servers).
Two lanes per repo: **lane 1** = agent-tool-source injection (custom pack); **lane 2** =
conventional CWEs (built-in `security-extended`).

Sorted into **[novel/](novel/)** (our original, undisclosed discoveries) and
**[found-by-others/](found-by-others/)** (already public upstream).

## 🆕 novel/ — our original findings (not previously disclosed)

| Repo | Class | Severity (CVSS 3.1) | PoC | Report |
|------|-------|---------------------|-----|--------|
| [amantus-ai/vibetunnel](https://github.com/amantus-ai/vibetunnel) | OS command injection → RCE (CWE-78) | **8.8 High** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` | `GET /api/fs/diff?path=$(touch /tmp/pwned)` | [novel/vibetunnel-cmdi-report.md](novel/vibetunnel-cmdi-report.md) |
| [steel-dev/steel-browser](https://github.com/steel-dev/steel-browser) | Reflected XSS (CWE-79) | **6.1 Medium** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | `GET /v1/sessions/debug?interactive=0;alert(document.domain)//` | [novel/steel-browser-xss-report.md](novel/steel-browser-xss-report.md) |
| [TencentCloudADP/youtu-agent](https://github.com/TencentCloudADP/youtu-agent) | `eval()` of model output (CWE-94) | High (RCE) | ReAct step output = Python expr → `eval()` | [novel/youtu-agent-eval-report.md](novel/youtu-agent-eval-report.md) |
| [aden-hive/hive](https://github.com/aden-hive/hive) | `csv_sql` DuckDB guard-bypass → file read | Medium-High | `csv_sql("SELECT content FROM read_text('/etc/passwd')")` | [novel/hive-csvsql-report.md](novel/hive-csvsql-report.md) |

- **vibetunnel / steel-browser**: confirmed live on current `main`, deduped (0 advisories, no
  matching issues). Drafted for private disclosure.
- **youtu-agent / hive**: our-PoC; CodeQL *missed* both (model-output eval; semantic
  guard-bypass) — the headline "CodeQL blind spot" results.
- All four: authored by humans, not Claude-generated.

## 🤖 vs 🧑 Who wrote the vulnerable code?

Blame on the exact vulnerable line(s) vs. how much the repo uses Claude Code (share of the
latest 100 commits co-authored by Claude). **Every bug was human-authored — none Claude-generated**,
including in `hive`, which is 85% Claude-co-authored.

| Finding | Repo uses Claude | Vulnerable line author(s) | Verdict |
|---------|------------------|---------------------------|---------|
| vibetunnel RCE | 0 / 100 | Armin Ronacher (`isPathSafe` stub), Peter Steinberger (`execAsync` sink) | 🧑 human |
| steel-browser XSS | 4 / 100 | "nas" (`6d9981b7` — ui fixes + sessions logic) | 🧑 human |
| youtu-agent eval RCE | 3 / 100 | easonsshi (`#feat ReactModel`, 2025-06-27) | 🧑 human |
| hive `csv_sql` file-read | **85 / 100** | hundao + Juttiga Bheemeswar (`feat/fix(csv_sql)`) | 🧑 human |
| SuperAGI eval RCE (public) | 0 / 100 | — (pre-Claude era) | 🧑 human |

Note: hive's `csv_sql` has a `fix(csv_sql): prevent SQL injection via DuckDB` commit (2026-03-30) —
our `read_text()` file-read needs verifying as a **bypass of that fix** before filing.

## 📋 found-by-others/ — already disclosed upstream

| Repo | Class | Public ref |
|------|-------|-----------|
| TransformerOptimus/SuperAGI | `eval()` of LLM output → RCE | issues #1560/#1489/#1567, PRs #1492/#1493 |
| TransformerOptimus/SuperAGI | SSRF `/verify_end_point` | issue #1476, PR #1502 |
| firecrawl/firecrawl-mcp-server | SSRF (tool handlers) | issues #210/#194/#152 |

See [found-by-others/superagi-findings.md](found-by-others/superagi-findings.md). The
[found-by-others/candidates/](found-by-others/candidates/) folder holds unconfirmed MCP-hunt
leads (azure-devops-mcp, vouchington, agent-blackboard, next-devtools) pending triage.

## Dismissed (notable non-bugs)
- **MaxKB** `ResourceProxy` — unauth SSRF *sink* but **dead code** (defined, never routed).
- **InsForge / butterbase / faraday / textbee** — SQL-injection flags, all guarded
  (parameterized / zod regex / `getattr` allowlist) or MongoDB ODM (not SQL).

## Evidence (in-repo)
Ledgers: `../mcp-hunt-work/exp3-fw-500/{fp_ledger,lane2_ledger,lane2_backfill_exp1_exp2}.csv`,
`../mcp-hunt-work/exp3-mcp-500/mcp_ledger.csv`. Scan records: `../mcp-hunt-work/<corpus>/done.jsonl`.
Heavy artifacts (CodeQL DBs, SARIFs) gitignored under `../mcp-hunt-work/<corpus>/{db,sarif}/`.

## Ecosystem stat
~61.7% of the 1,030 scanned repos had **Claude as a commit co-author**; neither new confirmed
bug (vibetunnel, steel-browser) was Claude-authored.
