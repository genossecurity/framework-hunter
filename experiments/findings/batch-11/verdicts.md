# Batch 11 verdicts: funnel repos 101-110 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-11/report.md`. Source review only.
Nothing filed. No new, confirmed non-public bug; one low-confidence code smell noted (SAP mdk).

| # | repo | verdict | depth |
|---|---|---|---|
| 101 | samuraikun/aws-s3-mcp | clean over taint; CORS-wildcard SSRF reported (#35) | 0 priority |
| 102 | runpod/runpod-mcp | no bug; SSRF rows are configured API/ingest fetches | 3 rows |
| 103 | joshuayoes/ios-simulator-mcp | no new bug; cmd-injection already public (CVE-2025-52573), path-trav #50 fixed | taint argv row |
| 104 | DayuanJiang/next-ai-draw-io | no new bug; export path-traversal fixed (#754); heavily audited | 13 rows read |
| 105 | dataforseo/mcp-server-typescript | clean | 0 priority |
| 106 | RajwardhanShinde/elk-mcp (→elasticsearch-mcp) | clean | 0 priority |
| 107 | SAP/mdk-mcp-server | low-confidence code smell: shell-string `execSync` in deploy/build; no confinement claim | runCommand + paths traced |
| 108 | nabheet/google-services-mcp | no new bug; `saveToPath` writes already confined (#161/#175); `safeName` on store | 10 rows read |
| 109 | qase-tms/qase-mcp-server | no bug; attachment read of caller path, by design | 2 rows |
| 110 | eyaltoledano/claude-task-master | no new bug; path traversal already open (#1711/#1712/#1715) | 89 rows read |

## Notes

**SAP/mdk-mcp-server (107) — low-confidence code smell, not escalated.** `runCommand()` runs
`execSync(command)` on built shell strings, e.g. `${mdkBinary} deploy --name "${CONFIG.projectName}"
--project "${CONFIG.projectPath}" ...` (`src/index.ts:1147`), where `projectPath` is the
`folderRootPath` tool arg and `projectName` derives from service metadata, with no visible
charset/shell validation — so metacharacters in those inputs inject into the shell. **But**
unlike crewly this server makes **no read-only/sandbox/allowlist claim**: running
`mdk deploy`/build/validate/yeoman on the caller's project is its documented purpose, and the
caller already drives those commands. So it is a defense-in-depth smell (should pass argv via
`execFile`, not a shell string), not a confinement bypass. No public security reports. Recorded
here; not packaged. Fix: argv for all `runCommand` call sites (deploy/build/validate/migrate).

**Already public / already fixed (103, 104, 108, 110).** ios-simulator-mcp cmd-injection is
CVE-2025-52573 and its screenshot/record_video path traversal is fixed (#50/#59);
next-ai-draw-io's `export_diagram` arbitrary file write is fixed (#754) amid a deep audit
(CVE-2026-40608, SSRF #918/#921, stored XSS); google-services confined `saveToPath` to a save
root (#161/#175) and uses `safeName` on the account store; claude-task-master's path traversal
is already filed and **open** (#1711/#1712 CWE-23 tag injection, #1715 absolute `prdPath` read).
The task-master 89-row count is dominated by `src/profiles/*.js` rule-file install/remove into
IDE config dirs — the same path-handling surface those issues track.
