# CVSS 3.1 — youtu-agent RCE via eval() of model output (ReAct parser)

Self-assessed (not an official NVD/CNA score).

**Primary vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
**Base score: 8.8 (High)**

| metric | value | justification |
|---|---|---|
| AV Attack Vector | Network | Exploit arrives as content the agent ingests (web page, tool/API output, retrieved doc) that steers the model's `Action:` text — indirect prompt injection over the network. |
| AC Attack Complexity | Low | In the `react` runner the eval path is routine (single-quoted dicts already bypass `json.loads`); the attacker only appends a call. eval runs before validation. |
| PR Privileges Required | None | Attacker only supplies content the agent reads. |
| UI User Interaction | Required | An operator initiates the agent task over the attacker-influenced content. |
| S Scope | Unchanged | Code executes in the agent-runner process authority. |
| C/I/A | High/High/High | Arbitrary OS command execution as the agent-runner user. |

**Sensitivity / honest notes**
- If the agent autonomously ingests attacker content with no operator action, `UI:N` → **9.8 Critical**.
- **Configuration gate (environmental):** only reachable with `runner: "react"` (default is
  `openai`, native tool-calls, which does not hit the eval path). This lowers *real-world*
  exposure; the base score reflects the vulnerable configuration. Environmental with the gate
  modeled as reduced exposure lands ~6–7.
