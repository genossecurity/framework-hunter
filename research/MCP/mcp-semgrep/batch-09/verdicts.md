# Batch 9 verdicts: funnel repos 81-90 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-09/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 81 | harsha-iiiv/openapi-mcp-generator | no bug; SSRF/$ref/template-inj history all closed | 1 row read |
| 82 | griffinwork40/agent-afk | no new bug; heavily self-audited (path/SSRF hardening) | ERROR rows + sample of 45 priority |
| 83 | agentfront/mcp-from-openapi | no new bug; 2 SSRF advisories + fix PRs already public | 0 priority |
| 84 | ihor-sokoliuk/mcp-searxng | clean now; 9 advisories all remediated | 0 findings |
| 85 | poe-platform/poe-code | no new bug; sandbox platform (safe-bash/fs) with dedicated audits | ERROR rows across 914; depth-limited |
| 86 | postmanlabs/postman-mcp-server | no bug; "sql" rows are HTTP API paths | 4 rows read |
| 87 | b1ff/atlassian-dc-mcp | no bug; attachment read/write to caller path (`wx`), by design | 4 rows read |
| 88 | auth0/auth0-mcp-server | clean; 0 priority (all demoted); cred-write sandbox PR #192 | 0 priority |
| 89 | foldkit/foldkit | no bug; 124 rows are vendored Effect lib + doc snippets | ERROR rows traced to `repos/effect/` |
| 90 | ioBroker/mcp-package | no bug; file tools go through adapter FS API + user ACLs | taint `write_file`/transfer traced |

## Notes

**agent-afk (82).** 632 findings / 45 priority, but the repo has an unusually deep security
track record: path-traversal filename validation (#1706/#1783/#1798), SSRF egress guards
(#1413/#1439, browser_open #2301/#2313, #4141/#4145), CodeQL enablement (#2938/#4311), and an
open refactor to "collapse the 6+ layered path checks into one resolve-then-decide policy"
(#3847). The ERROR rows are git worktree/checkpoint ops (`exec(cwd, [...argv])`,
`spawn(command,{shell:true})` for git) and the priority path rows are internal agent stores
(schedules, manifests, plugins, journals) reached via generic `tool-card -> formatElapsed ->
now` chains. No new confirmable bug; a heavily-hardened agent runtime.

**poe-code (85).** 914 priority rows reflect a 7,415-file platform that *is* a sandboxed
execution environment — `safe-bash` (a shell interpreter), `safe-fs`, `safe-playwright`,
`process-runner`. Every exec/fs sink in a bash/fs sandbox fires. The maintainers run dedicated
security reviews on exactly this surface ("safe-bash audit v2", "safe-fs security review":
#600 curl default-deny bypass, #618 DNS-rebinding, #656 CGNAT, #725/#726 safe-fs containment),
all closed. The ERROR rows are the sandbox's own runtime (`safe-bash/src/shell/runtime.ts`,
`process-runner` docker probes, an `eval` in a Playwright CLI helper). Depth-limited across 914
rows; no new confirmable bug in a security-focused, audited sandbox platform.

**foldkit (89).** 124 priority rows are almost entirely **vendored dependencies**: the repo
checks a full copy of the Effect library into `repos/effect/`, so the ClickHouse/SQLite
`exec(PRAGMA ...)` and `client.execute(request)` rows are Effect internals, and the
`packages/website/src/snippet/*` rows are documentation code examples (`/api/weather?zip=...`).
The actual foldkit MCP (`packages/devtools-mcp`) uses argv `ChildProcess.make('/bin/ls', [...,
'--', component])`. Vendored-dep noise, not a finding. (Exclude gap — see below.)

**ioBroker/mcp-package (90).** The taint `write_file` row and the file-transfer handlers look
like raw-FS path traversal but are not: `write_file` parses `"<adapter>/<dir>/<file>"` and
calls `this.adapter.writeFileAsync(adapterName, fileName, data, { user: this.user })` — a write
into ioBroker's **adapter file-storage** (a namespaced object store), executed *as a user* so
the platform's ACLs apply; `read_file`/`delete_file`/`list_files` use the same ACL'd API. The
`handleDownload`/`handleUpload` paths (`transfer.file`) are server-generated temp files keyed
by a random token with `MAX_UPLOAD_BYTES` enforced and `basename()` on the disposition, not
caller paths. `icmpPing` uses `execFile(bin, args)` (argv). `write_file` is
`destructiveHint: true`. No public reports; behavior is by-design, ACL-gated platform file
management. (A raw-FS traversal would live in js-controller's `writeFileAsync`, a separate and
well-audited platform codebase — out of scope here.)

**searxng (84).** Worth highlighting as a positive control: nine advisories/CVEs
(`web_url_read` SSRF variants, credential-log leaks, response-size bypass), and the scanner
now reports **0 findings** at the patched HEAD — i.e. it does not re-flag remediated code.

## What this batch showed about the scanner

- **Vendored-dependency exclusion gap.** foldkit checks a whole copy of Effect into
  `repos/effect/`; those rows dominated its priority count. Add `repos` (and the general
  vendored-deps pattern) to the post-run exclude cleanup, alongside `*.smoke.*`, `*.spec-d.*`,
  `explorations`, `probe`, `.spike-*`.
- The non-SQL `.get()` false positive recurred again (postman `client.get('/collections/...')`).
  Still queued for the SQL-tier rule refinement.
- Running tally (90 repos, batches 1-9): **0** new non-public bugs filed; 0 open candidates
  (context-mode resolved not-a-bug, elevenlabs resolved public-dup); everything else already
  public, by-design/ACL-gated, audited, or vendored/noise.
