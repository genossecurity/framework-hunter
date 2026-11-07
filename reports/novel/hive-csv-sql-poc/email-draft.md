# Email draft — hive csv_sql file-read report

> Written for: the hive maintainer, to send to contact@adenhq.com per hive's SECURITY.md.
> **The report was submitted to the maintainer on 2026-11-04.** This is the local draft, so the
> submitted text may differ. The structured write-up is in `advisory.md`.

---

**To:** contact@adenhq.com
**Subject:** Security report: arbitrary local file read in the `csv_sql` MCP tool (DuckDB table functions)
**Attachments:** poc.py, run-transcript.txt, poc.pdf

---

Hi hive security team,

I'm reporting a vulnerability in hive's `csv_sql` tool, found during local-only security
research. Following your SECURITY.md, I'm sending it here rather than opening a public issue, and
I'd like to coordinate disclosure on your timeline (I default to 90 days, happy to adjust).

**Summary.** The `csv_sql` tool (and `excel_sql`, same root cause) lets a model-supplied SQL
query read any file the agent process can access, escaping the `~/.hive` sandbox. It bypasses both
of the tool's controls at once.

**Description.** `csv_sql` applies two safeguards: the `path` argument is confined to `~/.hive` /
`exports/` by `resolve_safe_path()` (which is correct), and the `query` is restricted to SELECT —
it must start with SELECT/WITH, write keywords (INSERT/UPDATE/DELETE/DROP/…) are blocked, and `;`,
`--`, `/* */` are rejected. However, the query runs on `duckdb.connect(":memory:")` with no
`enable_external_access=false` set, so DuckDB's file-reading table functions — `read_text`,
`read_csv_auto`, `read_blob`, `glob` — still work. They're ordinary SELECTs, so the SELECT-only
guard doesn't stop them, and they name the filesystem directly, so `resolve_safe_path` (which only
guards the `path` argument) doesn't apply. The net effect is that a query body can read files
outside the sandbox. The relevant lines are in
`tools/src/aden_tools/tools/csv_tool/csv_tool.py`, in `csv_sql(path, query)`.

This is a different vector from the csv_sql SQL-injection issue fixed in #1408 (a quote in the CSV
*path*, fixed by parameter binding). #1408 added the SELECT-only guard on the assumption it made
query bodies safe; this report is about what that guard doesn't cover. I didn't find a published
advisory for this vector.

**Steps to reproduce** (benign, local only):

1. Ensure a valid CSV exists under the sandbox so the `path` check passes — a model could create
   one via `csv_write`; manually: `mkdir -p ~/.hive && printf 'a,b\n1,2\n' > ~/.hive/data.csv`
2. Create a sentinel outside the sandbox to stand in for a secret:
   `printf 'CANARY-OUTSIDE-SANDBOX' > ~/not_in_hive_canary.txt`
3. Call `csv_sql` with an in-sandbox path and a crafted query:
   `path = "~/.hive/data.csv"`,
   `query = "SELECT content FROM read_text('/home/<user>/not_in_hive_canary.txt')"`
4. The query passes the SELECT-only guard and returns the outside file's contents. Other working
   payloads: `SELECT * FROM read_csv_auto('/etc/passwd')`, `SELECT file FROM glob('/**')`.

I've attached a self-contained PoC (`poc.py`) that lifts your guard verbatim and runs it with a
real DuckDB connection, plus the captured output (`run-transcript.txt`). It touches only a benign
canary file I created; no third-party systems are involved.

**Impact.** Arbitrary local file read with the agent process's authority, escaping `~/.hive` —
e.g. SSH keys, `.env` / credential files, `~/.hive/configuration.json`, source. The realistic
trigger is indirect prompt injection: untrusted content the agent reads can steer the model into
emitting the query, so no direct host access is needed. It's read-only (write keywords, COPY, and
stacked statements remain blocked), so it's confidentiality-only, not code execution. I'd score it
CVSS 3.1 6.5 (Medium): `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`.

**Suggested mitigation.** Disable external access on the connection, after loading the trusted
confined CSV but before running the untrusted query:

    con = duckdb.connect(":memory:")
    con.execute("CREATE TABLE data AS SELECT * FROM read_csv_auto(?)", [str(secure_path)])
    con.execute("SET enable_external_access=false")   # or SET disabled_filesystems='LocalFileSystem'
    result = con.execute(query)

The same change applies to `excel_sql` in `excel_tool.py`. As an interim workaround, operators can
avoid granting the `spreadsheet_advanced` tool category to agents that handle untrusted input.

Happy to clarify anything or verify a patch. Thanks for your work on hive.

Best,
genossecurity
