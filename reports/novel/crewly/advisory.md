# Security advisory (published as GHSA-v7q6-5mpg-q47w)

> Written for: the crewly maintainer, for coordinated disclosure via GitHub private security
> advisory. **Published 2026-11-04 as
> [GHSA-v7q6-5mpg-q47w](https://github.com/stevehuang0115/crewly/security/advisories/GHSA-v7q6-5mpg-q47w);
> CVE pending.** This is the local pre-submission copy; the published advisory is authoritative.

**Title:** OS command injection in the read-only Auditor agent's `create_github_issue` tool
(shell-metacharacter injection via issue `title`/`body`) leads to arbitrary command execution

**Affected product:** `crewly` (npm `crewly`) — `packages/crewly-agent` Auditor runtime
**Affected versions:** ≤ 1.20.471 (per the published advisory). The vulnerable `auditor-tools.ts`
was unchanged from commit `d1b89f94` (2026-06-11) through `main` as reviewed on 2026-11-02.
**Fixed in:** 1.20.472.
**Prior disclosure:** none found — no GHSA advisory, no security issue/PR, no CHANGELOG fix
entry (issue `#178` is the *feature* that added the tool, not a vuln report).
**CWE:** CWE-78 (OS Command Injection), CWE-77; secondary CWE-184 (incomplete escaping)
**Severity:** High — CVSS 3.1 **8.8** `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (see `cvss.md` /
`cvss.pdf` for scoring and the range under alternative assumptions).
**Reporter:** genossecurity · **Disclosure policy:** 90-day coordinated.

---

## Summary
The Auditor agent is documented as a read-only role — `auditor-tools.ts`: *"Read-only tools for
the Auditor agent … without any ability to modify system state."* It is provisioned with only
observation/reporting tools and has **no** `bash`/command tool. One of its tools,
`create_github_issue`, builds a shell command string from the model-controlled `title`, `body`,
and `labels` and runs it with `child_process.execSync`, escaping only the double-quote
character. Because `$(...)` and backticks are still interpreted inside a double-quoted shell
string, a crafted `title` executes arbitrary OS commands. This escapes the Auditor's
read-only confinement and also bypasses the global `validateBashCommand` denylist
(`rm`/`curl`/`wget`/`docker`/`npm publish`/`git reset --hard`) and the approval gate that
constrain the `bash_exec` tool available to other agents.

## Affected code
`packages/crewly-agent/src/runtime/auditor-tools.ts`, tool `create_github_issue`:

```js
// dedup search (searchQuery is derived from title → also injectable)
execSync(`gh issue list --state open --search "${searchQuery.replace(/"/g,'\\"')}" --json number,title --limit 5`, …)
// create
const labelFlag = labels.map(l => `--label "${l}"`).join(' ');
execSync(`gh issue create --title "${title.replace(/"/g,'\\"')}" --body "${body.replace(/"/g,'\\"')}" ${labelFlag}`, …)
```

`title`, `body`, `labels` are the tool's input schema fields, supplied by the Auditor LLM.
Escaping only `"` does not prevent command substitution: inside the double quotes, `$(cmd)` and
`` `cmd` `` execute. Both `execSync` calls are injectable (via `title`/`body`/`labels` and via
`searchQuery`, which is `title` with a leading `[...]` stripped).

## Proof of concept
Local, benign, network-isolated PoCs are in `poc/` (run under bubblewrap, `--unshare-net`;
mock/fake data only). Two variants:
- **Realistic end-to-end** (`scenario.sh` + `exfil-poc.mjs`): plants a mock operator
  environment (fake API tokens + SSH key under `$HOME`) and an attacker-controlled line in the
  "audited activity" the Auditor reviews, then runs the real `create_github_issue` path. The
  read-only Auditor **exfiltrates the secrets/SSH key to an attacker-drop file and writes a
  backdoor file** — demonstrating confidentiality and integrity impact via an issue title.
- **Minimal** (`poc.mjs` + `run.sh`): single benign `$(touch marker)` payload with a control
  title, for the smallest repro.

Both reproduce `execute()`'s exact construction. The injection fires even though `gh` fails for
lack of a token/network — the shell expands `$(...)` before `gh` runs — so a configured
`gh` and outbound connectivity are **not** required. Full method, captured output, and the
CIA-impact mapping: `poc/REPORT.md` (and `poc/poc.pdf`).

## Why the policy engine does not stop it (classification gap)
crewly's `checkApproval()` (`agent-runner.service.ts:2221`) has two gates: `readOnlyMode`
blocks any tool in `WRITE_TOOLS`, and `requireApproval` blocks tools whose `sensitivity` is
listed. `create_github_issue` is in **neither** list — absent from `WRITE_TOOLS`
(`types.ts:379`) and absent from `TOOL_SENSITIVITY` (`tool-registry.ts:571`), so it falls
through to the `|| 'safe'` default (`tool-registry.ts:658`). Consequently it executes even with
`readOnlyMode: true` **and** `requireApproval: ['destructive']` set. This is the core issue: a
tool that reaches `execSync` is classified `safe` and is never gated.

*Caveat (please keep in the report):* the default policy is `readOnlyMode: false` /
`requireApproval: []` (`types.ts:682/685`), so out of the box nothing is gated regardless. The
bypass matters specifically for operators who **explicitly enabled** read-only / approval mode
to contain the Auditor — it defeats a protection they turned on, rather than one on by default.

## Impact
Arbitrary OS command execution on the operator's host, with the agent-runner's privileges,
reachable from a role intended to be read-only. Realistically triggered by **indirect prompt
injection**: the Auditor composes issue titles from the agent logs/activity it reviews, so
attacker-influenced content (a malicious repo, a crafted log line, a prompt-injected sibling
agent) can steer it into emitting `$(...)`. Consequences include reading operator secrets/SSH
keys, modifying files, and lateral movement.

## Remediation
Do not build a shell string; pass arguments as argv so the shell never parses them:

```js
import { execFile } from 'node:child_process';
const args = ['issue','create','--title',title,'--body',body,
              ...labels.flatMap(l => ['--label', l])];
execFile('gh', args, { timeout: 30000 }, cb);   // and likewise for `gh issue list --search`
```

`execFile('gh', [...])` (or `spawn` with an argv array and `shell:false`) passes each value as
one literal argv element, so `$`, backticks, quotes and spaces are inert. Apply the same change
to the `gh issue list --search` call. (Defense in depth: route Auditor-initiated external
actions through the same policy/approval path as other tools.)

## Workarounds (for operators, pre-fix)
- Do not run the Auditor agent against untrusted repositories/logs.
- Remove/disable the `create_github_issue` tool from the Auditor's toolset.

## Disclosure timeline (template)
- [YYYY-MM-DD] Reported privately to the maintainer via GitHub security advisory.
- [YYYY-MM-DD] Maintainer acknowledged.
- [YYYY-MM-DD] Fix released in [version].
- [report date + 90d] Public disclosure (or earlier by mutual agreement).

## References
- `finding.md` — root-cause analysis and why this is a confinement bypass.
- `poc/REPORT.md`, `poc/poc.mjs`, `poc/run.sh` — reproduction.
- `cvss.md` / `cvss.pdf` — CVSS scoring and justification.
