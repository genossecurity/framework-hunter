# Triage: ruvnet/agentdb

**Verdict: clean on the MCP tool surface. No PoC, nothing to report.**

- Commit: `d3df60d4f94f` (2026-11-01), package `agentdb@3.3.0`, 95 stars, 187k npm
  downloads/week. No SECURITY.md; stdio transport only (`StdioServerTransport`), no HTTP.
- Reviewed: 2026-11-02 by reading source. Nothing installed or run.
- Scanner (final rules): 2 taint candidates, both `agentdb_delete_batch`; ~90 helper rows
  (count drifts by 1–2 between identical Semgrep runs, see below).

## MCP surface

`src/mcp/agentdb-mcp-server.ts` (2,967 lines), one `setRequestHandler(CallToolRequestSchema)`
switch over 22 `agentdb_*` tools plus ~30 legacy ones (41 advertised in the README; the
scanner's literal-name count is 53 because of duplicates in `attention-mcp-integration.ts`).
Tool arguments are strings, numbers, arrays and one enum (`table`). **No argument is a
file path, URL or shell string.**

## Candidates and why each is not a bug

| where | what | disposition |
|---|---|---|
| `agentdb-mcp-server.ts:2822-2823` `DELETE FROM ${embTable} WHERE ${embColumn} IN (...)` / `DELETE FROM ${requestedTable}` | `table` arg interpolated as identifier | `requestedTable` checked with `Object.prototype.hasOwnProperty.call(embeddingTables, …)` against a 2-entry map; `embTable`/`embColumn` come from that map; ids via `toRecordId`; values bound with `?`. Safe. Also `enum` in the input schema |
| `:1179-1180` `deleteEpisodesWhere(condition, value)` | `${condition}` | both callers pass literals (`'session_id = ?'`, `'ts < ?'`) |
| `:1814` `SELECT COUNT(*) FROM ${tableName}` | identifier | 10 callers, all literals |
| controllers `UPDATE … SET ${sets.join(', ')}` (ReasoningBank:826, SkillLibrary:1047, ReflexionMemory:1135) | field list from `agentdb_update`/`pattern_update` | every branch pushes a fixed `'col = ?'` string and binds the value; unknown fields are rejected |
| controllers `WHERE ${conditions.join(' AND ')}` | filters | fixed predicates with `?` |
| `BatchOperations.bulkDelete` | `${validatedTable} WHERE ${clause}` | `validateTableName` + `buildSafeWhereClause` allowlists |
| `backends/ExactSearch.ts:34,40` | `${spec.table}`, `${spec.idColumn}` | backend config, not tool input |
| 70+ `fs.*` helper rows (HNSWLibBackend save/load) | paths | derive from `AGENTDB_PATH` env / `dbPath`, never from a tool arg |
| 50+ `stmt.run(v)` / `.get(v)` rows | — | prepared-statement binds; rule noise, now fixed |

## Not covered

- Vector/graph backends behind `ruvector` (Rust/NAPI) and the Cypher builders in
  `GraphDatabaseAdapter.ts` / `ReflexionMemory.ts:646` (`LIMIT ${positiveInt(k)}` looked
  guarded; not traced further).
- `QUICServer.ts` and the CLI, which are not MCP tools.
- The `malicious`/prompt-injection angle of storing attacker text as memory: by design.

## Scanner lessons from this repo

1. `$VM.run($X)` matched every `.run(` → 58 false code-injection rows. Constrained to
   sandbox-like receivers.
2. Prepared-statement binds (`stmt.run(v)`, `db.prepare(q).run(v)`) counted as SQL sinks →
   ~30 false rows. Sink split into query-text methods and bind methods; a chained
   `prepare(\`${t}\`).run(v)` fixture guards against the regression this fix first caused.
3. New `auto_notes`: "identifier allowlist/quoting nearby" demotes allowlisted identifier
   interpolation out of the priority queue (still in `findings.csv`).
4. **Semgrep drops taint matches nondeterministically.** On this repo, 1 run in ~4–6 of
   the identical command returned the result set minus exactly the two taint matches in
   the 1,500-line handler function (no error, no timeout; diffed good vs bad raw output).
   Helper counts also drift by 1–2. The scanner now runs Semgrep twice per repo (a third
   time if they disagree), unions the matches, reports `unstable_results` in `repos.csv`,
   and saves raw output in `<work>/results/<slug>.semgrep.json`. For agentdb: 3 unstable
   matches per scan, taint rows present in every scanner run since.
