# Triage: firecrawl/firecrawl-mcp-server

**Verdict: one real arbitrary local file read (`firecrawl_parse`, self-hosted/local mode),
confirmed by code review, but public since 2026-07-08 as issue #306 with an open fix PR
(#447) and a second report (#586). Do not file; it would be a duplicate. The scanner missed
it (see below).**

- Commit: `aa409c905f0e` (2026-11-02), package `firecrawl-mcp@3.36.0`. 158k npm
  downloads/week.
- Reviewed 2026-11-02 by reading source only; nothing run.
- Disclosure channel: no SECURITY.md in the repo; `firecrawl.dev/.well-known/security.txt`
  → Bugcrowd VDP <https://bugcrowd.com/engagements/firecrawl-vdp-ess>. The repo has heavy
  public security traffic (46 issues/PRs match "security", several automated scanner
  reports).

## Scanner result: 4 helper candidates, 0 real

All four are `fetch()` to `${resolveApiBaseUrl()}${path}` or `${apiUrl}/v2/...`: the host
is operator config (`FIRECRAWL_API_URL` or the cloud default) and every id interpolated
into a path is `encodeURIComponent`-ed and mostly `.uuid()`-validated. Tool `url`
parameters are sent to the Firecrawl API, which does the fetching; SSRF against
self-hosted Firecrawl via those URLs is the product's known shape (issues #194, #210, PR
#242 "block private URLs").

## Finding the scanner missed: `firecrawl_parse` reads any local file

```ts
// src/server.ts:3140-3195, local mode (config.fileAccess !== 'upload', FIRECRAWL_API_URL set)
const { filePath, contentType: overrideContentType, ...options } = args as { filePath: string } & Record<string, unknown>;
const absPath = path.resolve(filePath);
const buffer = await readFile(absPath);          // no base dir, no allowlist
... form.append('file', blob, filename); fetch(`${apiUrl}/v2/parse`, { method: 'POST', body: form })
```

- `filePath` is a tool argument with no confinement (`path.resolve` only normalises). The
  file is uploaded to the configured API and its parsed text is returned to the agent.
  Effect: arbitrary file read for the server's user, exfiltrated to the API host, reachable
  by prompt injection. CWE-22 / CWE-200.
- Only in local mode: hosted mode (`fileAccess === 'upload'`) returns upload instructions
  and never touches the filesystem. The tool's own annotations say "Local mode reads a
  file", so the capability is intended; the missing root confinement is the bug, and the
  maintainers' own PR #447 ("keep firecrawl_parse inside the parse root") agrees.
- Upstream: #306 (2026-07-08) reports exactly this; PR #447 (2026-09-25) adds a parse
  root; #586 (2026-10-21) re-reports it. All open at HEAD.

No PoC built: the code path is three lines and the issue is already public with a fix in
review. Also noted, already fixed: #587 (HTTP mode without Host/Origin checks) closed by
PR #618 on 2026-10-27, present in this commit.

## Why the scanner missed it (now fixed)

Two independent causes, both found by bisecting this handler:

1. **Semgrep's taint fixpoint has a fixed per-function time budget.** All 13 tools live
   inside one 3,286-line `createServer()`; `semgrep-core` logs "Fixpoint timeout while
   performing taint analysis at server.ts:653" (only visible with `--debug`) and drops
   every taint result for that function. The same 102-line `addTool` block scanned alone
   is flagged. There is no CLI knob. `scan.py` now re-scans each tool registration as its
   own small file and maps lines back (`scan_path=chunk` in `findings.csv`); this finding
   is recovered that way.
2. **`const { k } = args as { k: string }` loses taint** because Semgrep parses the type
   literal as an object value and assigns `k <- string`. Fixed by naming bindings
   destructured from the handler's args as sources (taint and helper tiers), with
   fixtures. This did not affect firecrawl's exact statement (its type literal has `;`
   and `?`, which does not parse as a value), but it does affect simpler ones.
