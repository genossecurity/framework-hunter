# Triage: supabase/mcp

**Verdict: one real scope bypass, confirmed locally, but already public upstream as
PR supabase/mcp#351 (open since 2026-07-30). Recommendation: do not file; it would be
closed as a duplicate. Optionally note on #351 that the gap is still open at HEAD.**

- Commit: `ed5084d19575` (2026-10-30), package `@supabase/mcp-server-supabase@0.15.0`
- Reviewed: 2026-11-02. Scanner + manual review + local PoC against the repo's own mocked
  Management API. Nothing contacted Supabase; nothing ran outside a bwrap sandbox with
  network off.
- Security policy: `SECURITY.md` → HackerOne (<https://hackerone.com/supabase>). It explicitly
  lists "acting outside the project scope the server was started with" as in scope, and
  "automated scanner output with no working exploit" as not.

## Scanner result: 3 candidates, 0 real

| candidate | why it is not a bug |
|---|---|
| `mcp-server-postgrest/src/server.ts:55` fetch(apiUrl) | `apiUrl` is operator config, not tool input |
| `mcp-server-postgrest/src/server.ts:90` fetch(url) | `path` is reduced to pathname+search via `new URL(path, 'http://mock/')`, then appended to the fixed `apiUrl`; host cannot change. Caller already holds the API key, so any route is reachable anyway (SECURITY.md: "path-looking parameter only sent to an API") |
| `mcp-server-supabase/src/platform/feedback.ts:42` | base URL is a constant; `path` is a literal or `encodeURIComponent`-ed |

The rules model injection-to-sink. They cannot see the real bug below, which is a missing
authorization check, not a tainted sink. **The finding came from manual review, not the
scanner.**

## Finding: destructive branch tools ignore project scope

When the server is started project-scoped (`--project-ref`, or `projectId` in the handler
library), tools that take a `project_id` have it injected and the argument removed from the
schema (`injectableTool`). Four tools take a `branch_id` instead and are plain `tool(...)`
with no scope check:

```
packages/mcp-server-supabase/src/tools/branching-tools.ts
  delete_branch  execute({ branch_id }) -> branching.deleteBranch(branch_id)   :322-333
  merge_branch   execute({ branch_id }) -> branching.mergeBranch(branch_id)    :335-345
  reset_branch   execute({ branch_id, migration_version }) -> resetBranch(...) :347-359
  rebase_branch  execute({ branch_id }) -> branching.rebaseBranch(branch_id)   :360-
```

`api-platform.ts:747-801` forwards the id straight to `/v1/branches/{branch_id_or_ref}`.
The only guard is `readOnly`. So a server scoped to Project A can delete, merge, reset or
rebase a development branch of Project B, if the access token covers both (same org
OAuth grant or a broad PAT) and the caller knows B's `branch_id`.

- CWE-863 (incorrect authorization). Needs: a non-read-only, project-scoped server; a
  token covering both projects; the foreign branch id (not enumerable through the scoped
  server, since `list_branches` is scoped). Delivery path is prompt injection or a
  malicious MCP client.
- `branching` is in `DEFAULT_FEATURES`, so the tools are present by default.

## PoC (local, mocked API)

`research/findings/exp1-mcp/batch-01/supabase__mcp-scope-poc.test.ts`, copied into
`packages/mcp-server-supabase/src/` and run with `vitest` inside `tools/sandbox.sh`
(network off, deps installed with `--ignore-scripts`). Result, 6/6 passing:

```
control: list_branches does not show the Project B branch      ✓
control: a project_id argument is rejected                      ✓
control: account-level tools are unavailable                    ✓
control: read-only mode blocks delete_branch                    ✓
POC: delete_branch removes a Project B branch                   ✓
POC: merge, reset and rebase accept a Project B branch          ✓   (all three "accepted")
```

The mock reproduces the Management API's behaviour as the repo's own tests assume it. It
was not run against the real API or the hosted server.

## Upstream status

- PR #351 "fix: enforce project_ref scope on destructive branch tools" by a repo MEMBER,
  2026-07-30, describes exactly this. Review: CHANGES_REQUESTED (the fix assumes the scope
  id is always a parent project; a branch's own `project_ref` is also accepted as scope).
  No activity since 2026-08-06. Code at HEAD (2026-10-30) is unchanged.
- Related: issue #255 (branch-scoped access), PR #249 (tool-level policies).
- No GitHub security advisories on the repo.

## Not covered

- Hosted `mcp.supabase.com` (would need a real account; out of scope for local-only rules).
- Whether the real Management API itself enforces anything on `/v1/branches/{id}` beyond
  the token's org grant (PR #351's author says it does not).
- The other 36 tools beyond the inject/guard audit (every mutating tool has a `readOnly`
  guard; every `project_id` tool is injected).
