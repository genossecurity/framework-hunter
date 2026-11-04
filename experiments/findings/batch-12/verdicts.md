# Batch 12 verdicts: funnel repos 111-120 of 141

Raw scanner report: `~/mcp-hunt-work/scan/batches/batch-12/report.md`. Source review only.
Nothing filed. No new, confirmed non-public bug.

| # | repo | verdict | depth |
|---|---|---|---|
| 111 | pdogra1299/bitbucket-mcp-server | no bug; path-steer/exfil hardened (PR #31) | 0 priority |
| 112 | Aureliolo/gdharness | no bug; reads/writes the caller's Godot project files, by design | 99 rows read |
| 113 | nteract/semiotic | no bug; `world.spawn` is physics, not OS; SVG/CSS allowlist (#1651) | 4 rows read |
| 114 | webpro-nl/knip | no bug; config/doc file reads in a dead-code finder | 2 rows |
| 115 | hermoso-ai/hermoso | no bug; `--args-file` is an operator CLI flag | 1 row |
| 116 | anis-marrouchi/agentx | no new bug; file/http/shell are framework actions; write-confirm gap open (#1736) | 320 rows read |
| 117 | SmartBear/smartbear-mcp | clean; SSRF/session-isolation fixed | 0 priority |
| 118 | cyanheads/obsidian-mcp-server | clean; folder-scoped perms + OBSIDIAN_DENY_PATHS | 0 priority |
| 119 | jmagly/aiwg | no new bug; path-traversal + shell-injection already fixed (#288/#299/PR #303) | 1101 rows; mostly addon memory + fixtures |
| 120 | hypequery/hypequery | no new bug; SQLi is CVE-2026-54658; path rows are 0o700 deploy dirs | 6 rows |

## Notes

**gdharness (112).** 99 priority rows, all reads/writes of the caller's Godot project files
(`project.godot`, scene files, boot/breakpoint/class notes, engine slot pid/lock files) keyed
on the `projectPath` tool argument plus internal note paths. A Godot test harness operating on
the project you point it at — operating on that project is the documented purpose, no
confinement claim. No public reports. Not a bug.

**agentx (116).** `agentix-cli` exposes `file.read/write`, `http.fetch/post`, and shell
`exec`/`execa("sh",["-c",command])` as **builtin actions** — running commands/fetching/writing
is the framework's advertised capability. Its security model (owner/loopback auth, memory
trust tiers) is actively hardened with many closed issues, and the one directly relevant gap —
**write tools run without a confirm step** — is already **open as #1736**. No new finding.

**aiwg (119).** 1101 rows reflect a 3,139-file agent platform; the volume is addon memory
stores (`line-memory`, `compound-memory`, `droid-bridge`) doing atomic `wx`/0o600 writes, plus
fixtures. The real issues were already reported and fixed: artifact read/write path traversal +
symlink escape (#288), template/storage path containment (#299), and shell-injection→argv
(PR #303). No new confirmable bug.

**Already public (111, 113, 117, 118, 120).** bitbucket-mcp hardened path-steering/exfil
(PR #31); semiotic's `spawn` rows are physics-engine `world.spawn` (not OS) and it enforces an
SVG/CSS allowlist (#1651); smartbear fixed SSRF + session isolation; obsidian-mcp has
folder-scoped read/write perms and `OBSIDIAN_DENY_PATHS`; hypequery's SQL injection is
CVE-2026-54658 and the path rows are internal 0o700 deployment-store dirs.
