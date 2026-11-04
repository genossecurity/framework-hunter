# stevehuang0115/crewly — read-only Auditor agent → RCE via shell injection in `create_github_issue`

**Status: confirmed by local sandboxed PoC + independent source review; published 2026-11-04 as
[GHSA-v7q6-5mpg-q47w](https://github.com/stevehuang0115/crewly/security/advisories/GHSA-v7q6-5mpg-q47w),
filed by the maintainer; CVE pending. Affects ≤ 1.20.471, patched in 1.20.472.** Local clone only;
no deployed instance touched; benign payload.

## PoC (local, sandboxed, benign) — CONFIRMED
See `poc/REPORT.md` for the full report (what it is, reproducibility, real-world impact).
`poc/poc.mjs` reproduces `create_github_issue.execute()`'s exact command construction and
calls it with a benign injected title `x$(touch /work/CANARY_PWNED)y`; `poc/run.sh`
checks the canary. Run under `tools/sandbox.sh` (bubblewrap: `--unshare-net`, empty tmpfs
`$HOME`, cleared env):

```
tools/sandbox.sh <poc-dir> sh -c 'PATH=/work/bin:$PATH sh /work/run.sh'
→ RESULT: INJECTION CONFIRMED — $() in the Auditor's issue title executed a shell command (canary created).
```

Key observations:
- The canary file was created by the `$(...)` in the **title**; a benign control title in the
  same run created nothing.
- `gh` itself failed (no token, no network in the sandbox), yet the canary was still created —
  the shell expands `$(...)` while parsing the command line, **before** and independent of
  whether `gh` authenticates or reaches GitHub. The injection therefore does not depend on a
  configured/authenticated `gh` or network access.


- Repo: `stevehuang0115/crewly`, `crewly@1.20.470`, commit `537cf5208f38` (2026-11-02, HEAD).
- File: `packages/crewly-agent/src/runtime/auditor-tools.ts`, tool `create_github_issue`.
- Class: CWE-78 / CWE-77 OS command injection → **confinement bypass** of a tool set the code
  explicitly documents as read-only.
- Dedup: GitHub issue/PR search for `create_github_issue`, `validateBashCommand`, `gh issue`,
  `injection`, `bypass`, `auditor` returned **no** matching report. Appears non-public.

## The claimed confinement
`auditor-tools.ts` module header, verbatim:

> "Read-only tools for the Auditor agent. These tools allow the auditor to observe agent
> activity, read logs, check task alignment, and write structured bug reports — **without any
> ability to modify system state.**"

The Auditor is wired with only these tools (observe/read/report); it has **no** `bash_exec`
tool. Separately, normal crewly agents' `bash_exec` is `destructive` (approval-gated) and
filtered by `validateBashCommand`, a "security policy" denylist that **permanently blocks**
`rm`, `curl`, `wget`, `docker …`, `npm publish`, `git reset --hard`.

## The bug
`create_github_issue` (args `title`, `body`, `labels` — all model-controlled) builds shell
strings and runs them with `execSync`, escaping only double-quotes:

```js
// dedup search
execSync(`gh issue list --state open --search "${searchQuery.replace(/"/g,'\\"')}" --json ...`)
// create
const labelFlag = labels.map(l => `--label "${l}"`).join(' ');
execSync(`gh issue create --title "${title.replace(/"/g,'\\"')}" --body "${body.replace(/"/g,'\\"')}" ${labelFlag}`)
```

Replacing only `"` does not neutralize shell expansion: inside the double-quoted string,
`$(...)` and backticks still execute. A `title` (or `body`, or a `label`) containing
`$(<command>)` runs `<command>`. `searchQuery` is derived from `title`, so even the dedup
`gh issue list` call is injectable.

## Impact
The read-only Auditor agent gains **arbitrary OS command execution** on the crewly host —
directly contradicting its "no ability to modify system state" contract, and bypassing both
the `validateBashCommand` denylist and the `bash_exec` approval gate that constrain every other
agent (the Auditor doesn't even have bash, yet reaches full command exec through a tool
nominally classed as safe reporting).

**Reachability / threat model.** The Auditor is an LLM agent; it composes the issue `title`/
`body` from the agent activity and logs it audits — attacker-influenced content (a malicious
repo, a crafted log line, prompt-injected agent output) can steer the Auditor into emitting
`$(...)` in a title, yielding RCE under the crewly agent-runner's identity. This is the
indirect-prompt-injection path that the whole denylist/approval model exists to contain.

## Fix (for the maintainer)
Use argv, no shell: `execFile('gh', ['issue','create','--title',title,'--body',body,
...labels.flatMap(l=>['--label',l])])` (and the same for the `gh issue list --search` call).
That removes the shell entirely; metacharacters become literal argv bytes.

## Enforcement bypass — it is a *classification gap*, not just an unenforced comment (verified)
crewly has a real policy engine: `agent-runner.service.ts:2221 checkApproval()` has two gates —
(1) `if (securityPolicy.readOnlyMode && WRITE_TOOLS.includes(toolName))` block (line 2223), and
(2) `if (securityPolicy.requireApproval.includes(sensitivity))` block (line 2241).
`create_github_issue` slips **both**:
- It is **absent from `WRITE_TOOLS`** (`types.ts:379`; the list is `edit_file`, `write_file`,
  `start_agent`, `stop_agent`, `handle_agent_failure`, `delegate_task`, `send_message`,
  `reply_slack`, `broadcast`, `schedule_check`, `cancel_schedule`, `register_self`,
  `report_status`, `remember`, `complete_task`) — so `readOnlyMode` does **not** block it.
- It is **absent from `TOOL_SENSITIVITY`** (`tool-registry.ts:571`), so it falls through to the
  `|| 'safe'` default (`tool-registry.ts:658`) — while `bash_exec` is `destructive`. So even an
  operator running `readOnlyMode:true` **and** `requireApproval:['destructive']` still executes
  this tool.

So a tool that reaches `execSync` with model-influenced input is classified `safe`, is not a
write tool, and is never approval-gated. That is the confinement bypass, stated as a concrete
classification gap with file:line evidence — not "the comment says read-only."

**Second sink.** The injection is not a single line: the dedup `gh issue list --search
"${searchQuery...}"` (`auditor-tools.ts:233/237`, `searchQuery` derived from `title`) has the
same `"`-only escaping and **executes first**, before the `gh issue create` call.

**Honesty caveat on defaults.** The *default* policy is `readOnlyMode:false` /
`requireApproval:[]` (`types.ts:682/685`) — out of the box nothing is gated anyway. The bypass
therefore matters specifically for operators who **explicitly enabled** read-only / approval
mode expecting it to contain the Auditor; it defeats a confinement a security-conscious
operator turned on. It is not "confinement is on by default."

## Prior-disclosure check (dedup, as of 2026-11-02) — none found; unfixed on `main` at that time
- GitHub **security advisories (GHSA): none** for `stevehuang0115/crewly`.
- Issue/PR search (`command injection`, `execFile`, `create_github_issue`, `shell injection`,
  `auditor`/`gh issue`): no security report. `#178` is the *feature* issue that added auditor
  auto-triage + issue creation, not a vuln report.
- `CHANGELOG.md`: no `execFile`/command-injection/`gh` fix entry.
- `auditor-tools.ts` last changed at `d1b89f94` (2026-06-11) and is **unchanged through the
  current default branch** (`main`, pushed 2026-11-02) — i.e. still present and unfixed live.
- Externally verified at HEAD `537cf52` by an independent reviewer (clone pulled, sink + policy
  classification confirmed line-for-line); the one step they could not do from a read-only
  clone — the GitHub GHSA/PR dedup above — is closed here.

## Why this one is reportable (vs. context-mode / the earlier crewly read)
- Unlike context-mode (a *declared* arbitrary-executor), crewly's Auditor **claims** a
  read-only, no-state-change boundary — and this bypasses it. Triage-checklist criterion met:
  "a tool is a design choice unless it claims a sandbox/allowlist/read-only mode you can bypass."
- Unlike the first-pass read (where it looked moot because normal agents already have bash),
  the correct framing is the **Auditor** context: it has no bash and is contract-bound to
  read-only, so the injection is a real privilege escalation, not a redundant capability.

## Next steps
1. Done: local, sandboxed PoC (`poc/`).
2. Done: disclosed and published as GHSA-v7q6-5mpg-q47w, patched in 1.20.472.
3. To do: add `crewly@1.20.470` + this commit to `bench/recall.sh`.

## Package contents (this folder)
- `finding.md` — this root-cause writeup.
- `advisory.md` — local pre-submission copy of the advisory (published as GHSA-v7q6-5mpg-q47w).
- `cvss.md` / `cvss.pdf` — CVSS 3.1 assessment (8.8 High; up to 10.0 Critical). `cvss.pdf` still shows the earlier 8.7 and 9.9.
- `poc/` — local sandboxed reproduction. `REPORT.md` + `poc.pdf` (standalone guide with files
  embedded). Two PoCs: `scenario.sh` + `exfil-poc.mjs` (realistic end-to-end — a read-only
  Auditor exfiltrates mock secrets + an SSH key and writes a backdoor file via an issue title,
  modelling indirect prompt injection from audited logs), and `poc.mjs` + `run.sh` (minimal
  single-payload confirmation). All benign; mock/fake data; no network.

**Decision needed from the user before any disclosure or PoC that touches anything outside the
local clone.**
