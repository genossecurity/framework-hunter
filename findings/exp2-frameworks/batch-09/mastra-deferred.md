# Experiment 2 — mastra-ai/mastra (batch 9 slice, deferred & run alone)

Deferred because it is the densest repo in the corpus (~37 min; 18k raw / ~8k effective source
files, 64 unstable across semgrep runs, 26 chunk-only). Scans local-only; **nothing filed**.

## Result: 0 confirmed net-new findings. 1 secondary (zod `new Function` deserialization).

1150 priority / 1780 total; **taint=38**. By rule: path-traversal 407, sql 522, ssrf 110,
command-injection 58, argument-injection 50, code-injection 3. By dir: **templates 343**,
packages 276, stores 269, mastracode 99.

### Why 0 confirmed
- **The 58 "command-injection" are almost all FP.** `stores/clickhouse/.../command({query:…})` is the
  **ClickHouse client** `.command()` and `stores/valkey/…` + `pubsub/valkey-streams/…`
  `this.command([...])` is the **Valkey/Redis client** `.command()` — not shell. The rule matched
  `.command(`. Interpolated identifiers are internal table names in the storage layer, not tool
  input. The genuine exec sinks are a declared `run-command-tool` (`packages/core/src/loop/network/`,
  by-design), `explorations/` scratch code, and CLI/deployer internals (`mastracode` git wrapper,
  `deployer` spawn).
- **343 priority are in `templates/`** — mastra's example apps (template-browsing-agent,
  template-chat-with-pdf, template-text-to-sql `db.execute(trimmed)`, weather-agent, etc.). These
  are by-design example tools (browser `page.goto`, `fetch(csvUrl)`, text-to-SQL), **not** the
  shipped framework. (Scanner note below.)
- **522 "sql"** are the storage adapters (ClickHouse/PG/etc.) — parameterized or internal-identifier
  DDL; plus the text-to-SQL template (by-design).
- Shipped-package taint (`packages/core/workspace/tools/lsp-inspect`, `packages/mcp-docs-server`,
  `browser/agent-browser/goto`) is workspace/docs/browser tool I/O — by-design, confinement names
  (`absolutePath`) to verify but no bypass surfaced.

### SECONDARY (worth investigating, not confirmed) — zod schema `new Function` deserialization
`packages/core/src/utils.ts`:
```js
export function resolveSerializedZodOutput(schema: string): z.ZodType {
  return Function('z', `"use strict";return (${schema});`)(z);   // CWE-94 if `schema` is attacker-influenced
}
// caller: resolveSerializedZodOutput(jsonSchemaToZod(schema))
```
`new Function` executes a zod-expression string built by `jsonSchemaToZod(schema)` from a **JSON
Schema**. If mastra feeds an **untrusted** tool JSON-schema here — e.g. the `inputSchema` of a tool
advertised by a **connected (malicious) MCP server**, or a tool definition supplied by a client —
and `jsonSchemaToZod` output is injectable from a crafted schema (needs confirming: a field
name/`pattern`/`description` that breaks out of the generated expression), this is **RCE in the
mastra host** at tool-registration time. Same class as agency-swarm/cognee codegen-exec:
reachability hinges on whether an untrusted party controls the schema. Not traced to a confirmed
untrusted source in this pass — flag for a focused follow-up (trace `jsonSchemaToZod` callers from
the MCP-client / server-adapter boundary, and test injectability of its output).
Fix direction: don't `new Function` schema strings — use a safe json-schema→zod builder that emits a
value, not evaluated code.

### Scanner tuning note
`templates/` is **not** in `scan.py` EXCLUDES (only `examples`/`example` are). For frameworks that
ship example apps under `templates/`, add it to EXCLUDES — it accounted for 343 of mastra's 1150
priority rows (example-app noise, not shipped surface).
