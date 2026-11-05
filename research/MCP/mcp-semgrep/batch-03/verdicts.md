# Batch 3 verdicts: funnel repos 21-30 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-03/report.md`. Source review only.
Nothing filed. No new, non-public bug confirmed in this batch.

| # | repo | verdict | depth of review |
|---|---|---|---|
| 21 | Softeria/ms-365-mcp-server | no new bug; already audited (2 advisories + static audit #651) | 8 priority rows read; cert/token paths are config, not tool args |
| 22 | southleft/figma-console-mcp | no new bug; writes confined, prior findings fixed (#104/#59) | taint rows traced; `abs` is a fixed filename under the output dir |
| 23 | ruvnet/metaharness | no bug found; self-auditing (open Dream-Cycle issues) | 2 priority rows; argv exec |
| 24 | cap-js/mcp-server | clean | 1 row, internal runtime-detect path |
| 25 | armitage-labs/creem | clean | 0 priority |
| 26 | MCPJam/inspector | no new bug; real issues already public (GHSA-39g4, CVE-2026-23744) | taint rows read; 200+ rows are non-shipped probe scripts |
| 27 | currents-dev/currents-mcp | clean | 0 priority |
| 28 | chrisryugj/kordoc | no bug; output/input paths validated (PR #101) | taint rows traced to `safePath`/`safeOutputPath` |
| 29 | mastra-ai/mastra | no new bug; docs-server read matches public CVE-2025-61685 | taint rows read; 1200+ rows are templates/explorations/e2e |
| 30 | netlify/netlify-mcp | no new bug; design-import SSRF already public (GHSA-hmhc-fgcq-m7rx) | all 5 rows read |

## Notes

**ms-365-mcp-server (21).** The flagged `readFileSync(certPath)` / `readFileSync(tokenPath)`
take their paths from config/env (client-certificate auth), not from tool arguments; the two
SSRF rows are fetches to the Microsoft Graph / login endpoints. The repo already carries two
advisories (GHSA-42wc dot-segment path handling, GHSA-9w34 untrusted search path via
`MS365_MCP_AUTH_CACHE_COMMAND`) and a closed static audit (issue #651, "no exploitable
findings, two scanner bugs fixed"). Destructive tools already require `confirm:true` (PR #463).
No new finding.

**figma-console-mcp (22).** The taint writes (`figma_ds_extract_tokens`, `figma_ds_scaffold`,
`figma_export_animation`) go to `join(resolvedOut, file.path)` where `file.path` comes from a
**fixed filename map** (`tokens/tokens.json`, `tokens/tokens.css`, ...), not from caller input,
and `resolvedOut` is the tool's declared output directory. The `eval(wrappedCode)` row is in
the Figma desktop plugin bridge (runs in Figma's own plugin VM). The `execSync` rows in
`port-discovery.ts` interpolate a numeric PID / port discovered internally. A prior arbitrary
-file-read (issue #59) and a 7-finding security pass (issue #104) are both closed. No new bug.

**metaharness (23).** Same author/pattern as ruflo: only 2 priority rows (argv `execFileSync
('python3', ['-I','-B', ...])`, one config read), and a large body of open "Dream Cycle"
security issues/PRs shows the project self-audits this surface in the open. No new finding.

**MCPJam/inspector (26).** 232 priority rows, but ~200 are in `.spike-codex-appserver/probe/`
— one-off research probe scripts, not shipped server tools (a scanner-exclusion gap, noted
below). The genuine tool rows (`skill-tools.ts` readSkillFile, `effective-skill-tools.ts`
fetch) belong to an MCP inspector/debugger whose security exposure is already public:
GHSA-39g4 (unauthenticated cross-origin access to the JSON-RPC bridge) and CVE-2026-23744
(RCE via exposed HTTP endpoint), plus open issues on auth bypass and unauthenticated tool
execution. No new finding.

**kordoc (28).** A Korean-document (HWP/HWPX) conversion server. Every flagged read goes
through `readValidatedFile` → `safePath(filePath, allowedExts)` and every write through
`safeOutputPath(output_path, ...)`; `isSameFile` prevents output clobbering input/templates.
Image-directory confinement and MCP-output gaps were closed in PR #101 / #100. The
`execFileSync("powershell", ...)` Hancom-COM calls use argv (no shell). No bug.

**mastra (29).** 1301 priority rows reflect a 10,875-file monorepo; the overwhelming majority
are in `templates/`, `explorations/`, `e2e-tests/` and `mastracode/factory` example code, not
shipped tools. The one shipped tool that matches a real class is `@mastra/mcp-docs-server`'s
`readMastraDocs`, which does `fs.readFile(path.join(topicPath, args.file))` with `args.topic`
/ `args.file` as tool arguments and no `..` rejection — this is the shape of the already
-published **CVE-2025-61685** ("@mastra/mcp-docs-server leads to Information Exposure").
`run-command-tool.ts`'s `execAsync(command)` is an intentional command tool. Duplicate of a
public CVE; verify the installed version carries the fix, but nothing new to file.

**netlify-mcp (30).** The SSRF rows (`import-claude-design` `fetchDesignHtml`,
`unauthenticatedFetch`) are the subject of the public advisory **GHSA-hmhc-fgcq-m7rx** ("SSRF
via `new URL(userInput, base)` host bypass in the proxy edge function and the Claude design
import"). The path reads are of `netlifySiteStatePath`, an internal state file. No new finding.

## What this batch showed about the scanner

- **Exclusion gap (noise, not a miss):** two repos were dominated by non-shipped code the
  excludes don't yet catch — MCPJam's `.spike-codex-appserver/probe/*.mjs` (~200 rows) and
  mastra's `templates/`, `explorations/`, `e2e-tests/` (~1000+ rows). Candidates to add to
  `EXCLUDES` / `TEST_PATH_RE`: `explorations`, `e2e-tests`, `probe`, and dot-prefixed `.spike-*`
  spike dirs. Deferred to after the run so all 15 batches share one rule set (EXCLUDES does
  not change the checkpoint digest, so this can be applied with `--reprocess` afterward).
- The prior-report lookup is doing real work this batch: every already-public issue
  (5 of the 6 non-trivial repos) was surfaced by it, including two GHSA advisories and two CVEs.
