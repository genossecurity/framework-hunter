# Triage: haydenbleasel/blume

**Verdict: no reportable MCP vulnerability found. No PoC or disclosure.**

- Commit: `16862e1d28d5` (package `blume@2.2.6`)
- Reviewed: 2026-11-02, by reading source only. No repo code was installed or run.
- Scanner: 576 files, 196 helper-tier candidates, 0 taint, 0 priority, 0 tools detected.

## MCP surface

`packages/blume/src/ai/mcp/`, served over stdio and stateless Streamable HTTP.

| entry point | input | where it goes |
|---|---|---|
| `search_docs` | `query`, `limit`, `locale`, `version`, `contentTypes`, `filters` | in-memory Orama index built from the snapshot |
| `get_page` | `route` | `data.pages[route]` lookup |
| `list_pages` | `locale`, `version`, `contentTypes`, `filters` | filter over `data.routes` |
| `get_navigation` | `locale`, `version` | lookup in the snapshot's navigation trees |
| `resources/read` | `uri` | same lookup as `get_page` |

## Why it is clean

- **No sinks reachable.** Tools only read `McpData`, a snapshot built ahead of time. The
  runtime import closure of `server.ts` and `stdio.ts` (10 files) has no file, process,
  network, eval or dynamic import calls. `data.ts`, the snapshot builder, is imported by
  those files for types only.
- **No prototype lookup through `get_page`.** `normalizeRoute` always returns a key with a
  leading `/`, and `stripBasePath` keeps it, so `__proto__` cannot be the key.
- **The 196 candidates are not tool-reachable.** They sit in build, CLI and config code.
  Sampled false positives: `exec` in `openapi/overlay.ts:123` is `jsonpath-rfc9535`, not
  `child_process`; `notion.ts:692` is a Notion API call, not SQL.
- **`Access-Control-Allow-Origin: *`** is on a public, read-only endpoint that uses no
  credentials. POST bodies are capped at 64 KB.

## Minor, not a security issue

`get_navigation` reads `data.navigationByLocale[locale]` on i18n sites, so `locale:
"constructor"` should select a function and return a malformed result. It exposes no data.
Inferred from the code, not run.

## Not covered

- Third-party dependencies: `@modelcontextprotocol/sdk`, `@orama/orama`, `ufo`, `zod`.
- The sink check on the import closure matches by name, so it is strong evidence, not proof.
- The rest of the framework (docs build, CLI, assistant route) as a non-MCP attack surface.
- `ai/api/handlers.ts`, the JSON docs API. It is described as a transport over the same
  `query.ts` operations, but was not read.

## Scanner gaps this exposed

Blume is an MCP server with 4 tools, yet the scanner reported 0 tools and no tool files.

1. `server.fallbackRequestHandler` dispatch for `tools/call` is not recognized.
2. `setRequestHandler(ReadResourceRequestSchema, ...)` is not treated as attacker input.
3. Tools defined in a separate metadata array (`MCP_TOOLS`) are not counted.

The verdict here comes from manual review. The zero priority count alone would not have
justified it.
