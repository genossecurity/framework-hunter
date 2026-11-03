# CVSS assessment — crewly Auditor `create_github_issue` command injection

**Finding:** Read-only Auditor agent reaches arbitrary OS command execution via shell-
metacharacter injection in the `create_github_issue` tool (`title`/`body`/`labels`).
**Product:** crewly ≤ 1.20.470 (commit `537cf5208f38`). **CWE:** CWE-78 / CWE-77.

## Primary score — CVSS 3.1

**Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
**Base score: 8.7 — High**

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | **Local (L)** | The vulnerable component is the crewly agent runtime executing on the operator's host. Exploitation is through content the local Auditor agent processes. (If the audited content is supplied over the network, AV:N applies — see range below.) |
| Attack Complexity (AC) | **Low (L)** | No special conditions; include `$(...)` in content the Auditor turns into an issue title. Deterministic (PoC). |
| Privileges Required (PR) | **Low (L)** | The attacker needs a foothold to place content into what the Auditor reviews (e.g., a task/log entry, a repo the agent audits). Not fully unauthenticated in the typical deployment. (PR:N if any untrusted audited input suffices — see range.) |
| User Interaction (UI) | **None (N)** | The Auditor runs autonomously, and `create_github_issue` is never approval-gated: it is absent from `WRITE_TOOLS` (`types.ts:379`, so `readOnlyMode` skips it) and from `TOOL_SENSITIVITY` (`tool-registry.ts:571`), falling through to `'safe'` (`tool-registry.ts:658`) — unlike `bash_exec` (`destructive`). It executes even under `readOnlyMode:true` + `requireApproval:['destructive']`. |
| Scope (S) | **Changed (C)** | A `safe`-classified agent tool reaches host OS command execution, crossing the confinement boundary the policy engine (`checkApproval`, `agent-runner.service.ts:2221`) is supposed to hold — a different security scope than the agent was granted. |
| Confidentiality (C) | **High (H)** | Arbitrary command execution → read any file the agent-runner can (secrets, keys, source). |
| Integrity (I) | **High (H)** | Arbitrary command execution → modify files, state, other agents. |
| Availability (A) | **High (H)** | Arbitrary command execution → terminate processes, delete data, exhaust resources. |

## Score range under alternative, defensible assumptions
The confinement bypass + RCE impact (`S:C/C:H/I:H/A:H`) is stable; severity moves with the
reachability metrics for the attacker's input:

| Assumption | Vector change | Base score |
|---|---|---|
| Primary (local agent input, low-priv foothold) | `AV:L/PR:L` | **8.7 High** |
| Untrusted audited input needs no privilege | `AV:L/PR:N` | 9.3 Critical |
| Audited content arrives over the network | `AV:N/PR:L` | 9.9 Critical |
| Remote + unauthenticated | `AV:N/PR:N` | 9.9 Critical |

Recommended headline: **High (8.7)**, with a note that it reaches **Critical (up to 9.9)** when
the Auditor audits attacker-supplied or network-sourced content — the platform's intended use.

**Default-policy caveat (keep in the report).** crewly's default policy gates nothing
(`readOnlyMode:false` / `requireApproval:[]`, `types.ts:682/685`). The confinement-bypass
framing applies to operators who explicitly enabled read-only / approval mode to contain the
Auditor; this tool executes anyway. The RCE impact itself does not depend on that policy.

## Note on CVSS 4.0
Under CVSS 4.0 the equivalent vector is approximately
`CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` (subsequent-system impact High,
reflecting the host compromise beyond the agent sandbox), scoring in the High band. The 3.1
score above is used as the primary figure for GHSA compatibility.

## Basis
Confirmed by local sandboxed PoC (`poc/`): a `$(touch canary)` payload in the Auditor's issue
title executes; benign control title does not; works without a valid `gh`/network because the
shell expands `$(...)` before `gh` runs. No deployed instance was tested.
