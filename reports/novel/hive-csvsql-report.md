# hive — `csv_sql` DuckDB guard-bypass → arbitrary file read

**Status:** our-PoC (confirmed; CodeQL missed it — semantic guard-bypass, not a taint flow).
**Repo:** [aden-hive/hive](https://github.com/aden-hive/hive)
**Files:** `tools/src/aden_tools/tools/csv_tool/csv_tool.py` (+ `excel_tool.py`)
**Class:** Guard-bypass → arbitrary file read (information disclosure) · **Severity:** Medium-High

## Summary

The `csv_sql` tool runs model-supplied SQL against **DuckDB**, behind a guard intended to
restrict access to the loaded CSV only. DuckDB's built-in file functions — `read_text()`,
`read_csv()`, etc. — **bypass that guard**, giving the model arbitrary host **file read**
(and broader DuckDB file access) well beyond the intended CSV.

## Affected code

`tools/src/aden_tools/tools/csv_tool/csv_tool.py` — the `csv_sql` handler executes the
model's SQL on DuckDB; the containment check does not account for DuckDB's file-reading
functions.

## PoC

```
csv_sql("SELECT content FROM read_text('/etc/passwd')")
```

The guard doesn't block DuckDB's `read_text()` → the file's contents are returned to the
caller. Swap the path for any host file the process can read (configs, keys, `/proc`, …).

## Why CodeQL missed it (and why it matters)

This is a **semantic guard-bypass**, not a source → sink taint flow. A taint query can see
"model input reaches `duckdb.execute()`" but cannot model "the guard in front of it is
insufficient against DuckDB's file functions." No amount of source/sink modeling surfaces it —
it requires understanding DuckDB semantics. Headline Exp-2/Exp-3 result: **CodeQL's blind spot
for guard-bypass bugs**, which is exactly where a human-in-the-loop pass adds value over the
automated scan.

## Dedup — ⚠️ verify as a bypass before filing

Blame shows a **`fix(csv_sql): prevent SQL injection via DuckDB`** commit (2026-03-30, by
Juttiga Bheemeswar + hundao) on `csv_tool.py:298`. So the DuckDB-injection class was **already
known and partially patched**. Before filing, confirm the `read_text()` / `read_csv()`
file-read **still works against the current patched code** — i.e. that this is a *bypass of
their fix*, not the thing they already closed. If the fix blocks file functions, downgrade this
to found-by-others/fixed.

Separately, a hive path-injection finding (`routes_colonies.py`) was advisory-confirmed/guarded
(tracked as FP in the ledger) — distinct from this. Author of the vulnerable code: human
(hundao / Juttiga Bheemeswar), despite hive being ~85% Claude-co-authored at the repo level.
