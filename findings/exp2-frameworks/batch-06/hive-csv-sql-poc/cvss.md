# CVSS 3.1 — hive csv_sql arbitrary file read via DuckDB table functions

Self-assessed (not an official NVD/CNA score).

**Primary vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`
**Base score: 6.5 (Medium)**

| metric | value | justification |
|---|---|---|
| AV | Network | The malicious `query` is model-generated; steered via content the agent ingests (indirect prompt injection) or an operator task. |
| AC | Low | A single allowed `SELECT ... read_text('/path')` reads any file; the only precondition — a valid `.csv` under `~/.hive` to pass the `path` check — is trivially met (e.g. via `csv_write`). |
| PR | None | Attacker supplies the query/content; no account needed. |
| UI | Required | An operator runs the agent task over the attacker-influenced content. |
| S | Unchanged | Read occurs with the agent process's own OS authority (the broken boundary is a logical in-process sandbox, not a separate authority). |
| C | High | Arbitrary file read as the agent user — SSH keys, `.env`, credentials, `/etc/passwd`, source. |
| I | None | Read-only: write/DDL keywords, `COPY`, `;`/comments are blocked; no file write via this path. |
| A | None | No availability impact. |

**Sensitivity / notes**
- If the agent autonomously ingests attacker content with no operator action, `UI:N` → **7.5 (High)**.
- If the escape from the declared `~/.hive` sandbox is scored as a scope change, `S:C` → **~7.4 (High)**.
- Confidentiality-only by design of the finding; it is *not* RCE (a default DuckDB SELECT has no
  code-exec function; `COPY ... TO PROGRAM` is a write/COPY and is blocked by the SELECT-only guard).
- Fix: `SET enable_external_access=false` (or `disabled_filesystems='LocalFileSystem'`) on the
  `:memory:` connection. Same root cause in `excel_sql`.
