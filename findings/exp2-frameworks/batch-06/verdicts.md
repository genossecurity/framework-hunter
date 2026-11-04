# Experiment 2 — Agent frameworks, batch 6 (ranks 41–50 of frameworks-top100.txt)

Same method/criterion. Scans local-only; **nothing filed**. Work dir `~/mcp-hunt-work/exp2`.

## Result: 1 confirmed finding (hive csv_sql file-read bypass — but heavily-audited component,
## novelty uncertain). Rest by-design / already-confined / FP / not-tool-reachable.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| strands-agents/sdk-python | 2211 | 1 | 91 | by-design harness file tools + declared `shell_tool` |
| SWE-agent/mini-swe-agent | 115 | 0 | 0 | clean |
| MervinPraison/PraisonAI | 6035 | 4 | 709 | by-design broad tool library (no claimed-confinement bypass surfaced) |
| oumi-ai/oumi | 730 | 0 | 81 | by-design ML I/O (model/dataset paths, operator config) |
| ntegrals/openbrowser | 100 | 0 | 0 | clean |
| HKUDS/AutoAgent | 110 | 0 | 0 | clean |
| OpenPipe/ART | 859 | 0 | 0 | clean (RL trainer) |
| mcp-use/mcp-use | 1360 | 0 | 22 | by-design MCP client (connects to configured servers) |
| VoltAgent/voltagent | 1653 | 2 | 24 | by-design (docs-mcp changelog read; JS file tools) |
| aden-hive/hive | 1352 | 63 | 291 | **FINDING: csv_sql arbitrary file read via DuckDB fns** + rest by-design/FP |

---

## FINDING — aden-hive/hive: `csv_sql` arbitrary file read via DuckDB table functions

**Status: PoC-confirmed (local, benign); dedup inconclusive on novelty — csv_sql is heavily
audited; NOT filed.** PoC: `hive-csv-sql-poc/`.

**Location:** `tools/src/aden_tools/tools/csv_tool/csv_tool.py`, `csv_sql(path, query)`.

**Claimed confinement (two controls):** (1) file paths go through `resolve_safe_path()`, which
confines to `~/.hive` / `exports/` — and is itself **correct** (`.resolve()` + `startswith(root +
os.sep)`, symlink-safe); (2) the query is gated "Only SELECT queries are allowed for security
reasons": must start `SELECT`/`WITH`, a `_WRITE_PATTERN` blocks INSERT/UPDATE/DELETE/DROP/CREATE/
ALTER/TRUNCATE/EXEC(UTE), and `;`/`--`/`/* */` are rejected.

**Bug (CWE-22 / CWE-732):** the query runs on `duckdb.connect(":memory:")` with **no**
`enable_external_access=false` / `disabled_filesystems`. DuckDB's file-reading **table functions**
are not blocked by the SELECT-only guard, so a model-supplied query bypasses *both* controls:

```
SELECT content FROM read_text('/home/user/.ssh/id_rsa')
SELECT * FROM read_csv_auto('/etc/passwd')
SELECT * FROM glob('/**')
```

reads any file the process can access — outside `~/.hive`, defeating `resolve_safe_path`. The
model only needs one valid `.csv` under `~/.hive` to pass the `path` precondition (it can make one
with `csv_write`); the `query` then reads anywhere. **Confidentiality impact: arbitrary file read**
(read-only — write keywords and `COPY`/stacked statements are blocked; no RCE in a default SELECT).

**PoC (confirmed).** `hive-csv-sql-poc/poc.py` lifts the guard verbatim and runs it + `duckdb`:
query `SELECT content FROM read_text('<file outside the sandbox>')` **passes the guard** and
returns the file contents (benign canary). Transcript: `run-transcript.txt`.

**Dedup — distinct vector, verified apparently-unreported (novelty confidence now HIGH).** Read the
full bodies of every known csv_sql security issue (#1256, #1261, #1915, #2099 → fixed by #1408):
**all** are the *SQL-injection-via-CSV-path* vector — a quote in the `secure_path` filename
breaking out of `read_csv_auto('{secure_path}')` — fixed by parameter binding (`read_csv_auto(?)`).
**None** concerns the **query body** calling DuckDB file-read functions (`read_text`/`read_csv_auto`/
`read_blob`/`glob`) to read files outside the sandbox. The repo sets **no** `enable_external_access`
guard anywhere (confirmed at HEAD `4ede549`, 2026-11-02). Notably #1408 *added* the "SELECT-only"
guard believing it made queries safe — the exact assumption this finding breaks — and #5086 shows
the maintainers treat "LLM-controlled tool call → arbitrary file access" as a valid bug class. GHSA:
0. So this is a genuinely distinct, apparently-unreported gap. (Still: confirm with the maintainer
before disclosure, given how actively csv_sql is audited.)

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` = **6.5 Medium** (arbitrary file read, read-only;
→ 7.5 High if `UI:N`/autonomous, or ~7.4 if the sandbox escape is scored `S:C`). See `cvss.md`.

**Fix:** `con.execute("SET enable_external_access=false")` (or `SET disabled_filesystems='LocalFileSystem'`)
on the `:memory:` connection, or an allowlist of table functions — so the query cannot name the
local filesystem at all.

---

## Dismissed / other
- **strands-agents/sdk-python:** the 1 taint is `vended_tools/shell/shell.py` `shell_tool` →
  `active.execute(command)` — a **declared** shell tool (flagged as `.execute` SQL FP). The ~90
  path-traversal are its `read`/`write`/`file_editor` vended tools — a coding-agent harness where
  file access is the documented capability (operates with the user's own permissions); no bypassed
  confinement claim surfaced (not exhaustively line-verified).
- **MervinPraison/PraisonAI (709 priority):** a very broad general tool library (6k files). Only 4
  taint rows: `artifact_load` reads a model-named `*.meta.json` (minor), `github_tools` build
  `git` **argv** (not shell; `git check-ref-format` validates the branch). The 491 helper
  path-traversal span many by-design file tools with no single claimed-confinement boundary to
  bypass. By-design broad library (not exhaustively verified).
- **oumi:** 70 path-traversal in training/data/model loading — operator-config ML I/O, not
  model-tool-reachable.
- **mcp-use:** MCP client/framework; SSRF/path hits are connecting to configured MCP servers
  (by-design) and client internals.
- **voltagent:** `docs-mcp` changelog read (near-fixed path); JS file tools; by-design.
- **hive (non-csv_sql):** 164 SSRF are fixed-host API wrappers (`{APIFY_API}`, `{CALENDAR_API_BASE}`,
  `api.endpoints.huggingface.cloud{path}`, GSC) — by-design; `http_headers_scan(url)` is a declared
  URL-fetch tool; file tools use the correct `resolve_safe_path`; `excel_sql` has the same DuckDB
  exposure as csv_sql (same root cause).
- **mini-swe-agent / openbrowser / AutoAgent / ART:** 0 priority over the tool surface.
