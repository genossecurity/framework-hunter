# Batch 14 verdicts: funnel repos 131-140 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-14/report.md`. Source review only.
Nothing filed. No new, confirmed non-public bug.

| # | repo | verdict | depth |
|---|---|---|---|
| 131 | dswbx/jsonv-ts | clean | 0 priority |
| 132 | ivo-toby/mcp-openapi-server | clean (dep CVEs only) | 0 priority |
| 133 | useshortcut/mcp-server-shortcut | clean | 0 priority |
| 134 | TinyCloudLabs/js-sdk | no bug; credential/delegation files with O_NOFOLLOW/O_EXCL/0o600; argv exec | 96 rows read |
| 135 | jaminsmoke/codarch | no bug; reads/writes the caller's project `.codarch` artifacts, by design | 21 rows read |
| 136 | growthbook/growthbook-mcp | no bug; SSRF row is the configured GrowthBook API | 1 row |
| 137 | heroku/heroku-mcp-server | no bug; reads app.json/packs app sources to deploy (by design); argv taskkill | 6 rows read |
| 138 | vuluu2k/sbuilder-mcp | no bug; 54 "SSRF" rows are calls to the configured sbuilder backend | 59 rows read |
| 139 | nikolai-vysotskyi/trace-mcp | no new bug; mutating writes confined to project root (#1361); argv git; safePath | 248 rows read |
| 140 | transcend-io/tools | no bug; policy-bundle read/pack/publish (by design); "sql" rows are API paths; argv tar | 16 rows read |

## Notes

**sbuilder-mcp (138).** 59 priority rows, 54 of them "ssrf" — but every one is
`request({ base: ctx.base, path: '/api/sites/...', token: siteToken(ctx) })`: HTTP calls to the
**configured** site-builder backend (`ctx.base`) with the site token, not fetches to an
attacker-chosen URL. The `api.ts callOperation` path rows read/write a local file for an
up/download operation (`args.file.path`, a tool arg, with `wx`). An API-wrapper MCP; the
"SSRF" tier fires on its own backend client. No public reports, nothing to report.

**trace-mcp (139).** 248 rows over a 1,190-file app. The project runs an active security
program: mutating-tool writes are **confined to the project root** (PR #1361 / TRA-1848), root
path-traversal false alarms were fixed (#1134), `.env` secrets are kept out of `search_text`
(#1375/#1376), and `get_env_vars` reads a `safePath`. The git call is `execFileSync('git',
[argv])`; the apply-recommendations file writes are the (root-confined) startup-recommendation
applier. No new confirmable bug.

**js-sdk (134), codarch (135), heroku (137), transcend (140).** Credential/delegation file
storage with `O_NOFOLLOW`/`O_EXCL`/`0o600` owner-only hardening (js-sdk); code-architecture
analysis reading the caller's own `.codarch` project artifacts (codarch); a Heroku deploy tool
reading `app.json` and packing your app sources into a tarball to deploy (heroku, argv
`taskkill`); and policy-bundle read/pack(`tar` argv)/publish to a configured policy engine
(transcend, whose "sql" rows are `got.get('v1/policy-engine/...')` API paths). All by-design
local-file / configured-API behavior with no confinement claim to bypass.
