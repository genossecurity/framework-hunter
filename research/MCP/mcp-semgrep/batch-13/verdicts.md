# Batch 13 verdicts: funnel repos 121-130 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-13/report.md`. Source review only.
Nothing filed. No new, confirmed non-public bug.

| # | repo | verdict | depth |
|---|---|---|---|
| 121 | SocketDev/socket-mcp | clean over taint; org-tool auth scoped (PR #182) | 0 priority |
| 122 | primefaces/primeuix | clean | 0 priority |
| 123 | sweetrb/apple-mail-mcp | no new bug; AppleScript injection already fixed (PR #5/#96) | 2 rows read |
| 124 | chrisryugj/korean-law-mcp | no new bug; cmd+SQL injection already fixed (#25); doc save by design | 3 rows read |
| 125 | harness/mcp-server | no new bug; path traversal across toolsets already reported (#1091) + being fixed | 2 SSRF rows |
| 126 | t8y2/dbx | no new bug; unauth SQL exec is CVE-2026-55642; SSRF rows internal | 2 rows |
| 127 | tufantunc/ssh-mcp | no new bug; command approval-gate bypasses exhaustively advisoried (10+ GHSA) | 5 path rows read |
| 128 | antfu/nuxt-mcp-dev | clean | 0 priority |
| 129 | kshivam1177/android-mcp-framwork | no bug; writes test artifacts to caller paths, argv exec; by design | 108 rows read |
| 130 | mantinedev/mantine | clean over taint; form prototype-pollution is a GHSA | 0 priority |

## Notes

**ssh-mcp (127).** An SSH-command MCP whose command-classification/approval-gate surface is the
most heavily advisoried in the funnel — **ten+ GHSA advisories** on approval-gate and
classifier bypasses (exec carriers, interpreter carriers, variable-headed commands, readOnly
profile escapes, osascript/powershell, authorized_keys/cron writes). The 5 flagged rows are
config loading and SFTP-style local file transfer (`rename` temp→`target.destination`, a tool
arg, by design for a transfer tool). No new finding against that already-exhaustive record.

**android-mcp-framwork (129).** 108 rows, no security public reports, but all are test-artifact
file ops — screenshots, recordings, knowledge manifests, run reports, run locks — written to
caller-provided artifact/profile paths (many via atomic `wx`/0o600 writes), plus `spawn(
TESSERACT_PATH||'tesseract', [...argv])` and adb via argv (no shell). An Android test framework
writing artifacts to the paths you give it; by design, no confinement claim. Not a bug.

**Already public / already fixed (123, 124, 125, 126).** apple-mail-mcp fixed AppleScript
injection + path traversal (PR #5/#6, body escaper #96); korean-law-mcp fixed a CVSS-9.8
command injection + SQL injection (#25) and the doc-save `writeFile(target)` is by design;
harness/mcp-server's "path traversal across 4 toolsets" is reported (#1091) with fixes in
flight (PR #1579/#1581) and an extensive regression-guard suite; dbx's unauthenticated
arbitrary SQL execution is CVE-2026-55642 and the flagged rows are internal desktop-backend
`apiUrl()` fetches.
