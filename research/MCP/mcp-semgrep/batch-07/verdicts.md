# Batch 7 verdicts: funnel repos 61-70 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-07/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 61 | tidewave-ai/tidewave_js | no bug; design-canvas write to caller path (`wx`), by design | 3 rows read |
| 62 | argoproj-labs/mcp-for-argocd | clean over taint; bind-IP issue already public (GHSA-rp45) | 0 priority |
| 63 | AlaeddineMessadi/opencode-mcp | no bug; "sql" rows are HTTP API path-building (false positives) | 11 rows read |
| 64 | ChristopherVR/ooxml | no new bug; 9k-file doc-viewer frontend, rows are UI/CLI/IndexedDB | ERROR rows traced to frontend/CLI |
| 65 | tavily-ai/tavily-mcp | clean | 0 findings |
| 66 | florentine-ai/mcp | clean | 0 findings |
| 67 | nspady/google-calendar-mcp | no bug; cred paths are config, "sql" is `Map.get` | 4 rows read |
| 68 | nulab/backlog-mcp-server | clean | 0 priority |
| 69 | basementstudio/xmcp | no bug; framework + marketing-site internals | 5 rows read |
| 70 | VoltAgent/voltagent | no new bug; FS backend root-confined; real issues already open | FS confinement + eval verified |

## Notes

**opencode-mcp (63).** All ten "sql-injection" rows are `client.get(\`/session/${id}/...\`)` —
HTTP REST path-building against the local opencode server, mislabeled because `.get()` matches
the bind-method sink pattern. `opencode_project_init`'s `mkdir(resolvedPath)` creates a project
directory (its documented purpose). No SQL, no public reports, no confirmable bug — worst case
is API-path shaping against the caller's own opencode backend.

**ooxml (64).** 9,132 files, 0 registered tool names — an Office-document viewer/editor whose
MCP surface is thin. The 24 rows resolve to Angular UI components
(`*.component.ts`/`*.tsx`), a `shell:true` build CLI (`run-command.ts`), and IndexedDB
`objectStore.get(id)` (the "sql-injection" rows) — none a tool handler carrying MCP taint to a
sink. Reach-walk noise, not a finding.

**voltagent (70).** Checked the two substantive items:
- The 11 filesystem rows (`write`/`mkdir`/`rmdir` on `resolvedPath`) all pass through
  `resolvePath()`, which computes `path.relative(cwd, full)` and throws if it starts with `..`
  or is absolute, plus a realpath containment check (`targetReal.startsWith(baseReal + sep)`),
  with `contained = true` by default. The workspace FS tool is **root-confined**.
- The `eval(expression)` code-injection row is in `agent.spec-d.ts` — a *type-test* fixture
  (`expectTypeOf(...)`, `biome-ignore ... noGlobalEval`), not shipped code; the real calculator
  tool's eval was replaced by a safe parser in PR #926.

voltagent's genuine exposure is already public and open: unauthenticated MCP execution routes
under legacy auth (**issue #1493**) and a command-injection gap in `updateAllPackages`
(**issue #1205**). No new finding.

**tidewave / xmcp / google-calendar / argocd / backlog (61, 69, 67, 62, 68).** Design-canvas
write to a caller path with an overwrite guard (tidewave); framework runtime + marketing-site
template reads (xmcp); service-account / credential file reads from config paths and a `Map.get`
mislabeled SQL (google-calendar); an already-public unrestricted-bind advisory and OAuth
hardening. None a new confirmable bug.

## What this batch showed about the scanner

- **`.spec-d.ts` exclusion gap:** voltagent's `eval` row was in a TypeScript *type-test*
  (`agent.spec-d.ts`). The `*.spec.*` glob does not match `spec-d.ts`. Add `*.spec-d.*` to the
  post-run exclude cleanup.
- The "sql-injection" tier keeps firing on non-SQL `.get()` bind-method calls: HTTP clients
  (`client.get(path)`), `Map.get`, and IndexedDB `objectStore.get(id)`. These are consistently
  false positives in practice. Worth a rule refinement (require a SQL-ish receiver/context) or
  at least a triage note — recorded for the post-run rule pass.
- Running tally (70 repos, batches 1-7): **0** new non-public bugs filed; 1 flagged candidate
  (context-mode, batch 6) pending a deeper guardrail audit; everything else already public,
  by-design, or noise.
