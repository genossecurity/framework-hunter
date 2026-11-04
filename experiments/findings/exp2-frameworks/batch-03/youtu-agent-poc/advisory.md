# Security advisory (DRAFT — not sent)

> Written for: the youtu-agent maintainer (Tencent Cloud ADP), for coordinated disclosure via a
> GitHub private security advisory. This is a scaffold for the reporter to review and submit;
> **nothing has been sent or filed.** Fill the bracketed fields before submitting.

**Title:** Remote code execution via `eval()` of model output in the ReAct response parser
(`ReactConverter._parse_react_output`)

**Affected product:** `youtu-agent` (TencentCloudADP/youtu-agent)
**Affected versions:** v0.1.0, v0.1.1, v0.1.2, v0.1.3 and the current `main` (HEAD `c2caa53`,
pushed 2026-03-21). The vulnerable line is unchanged since commit `d8248f2` (2025-06-27, "#feat
ReactModel") — present on every tagged release. [Confirm earliest intended-supported release.]
**Fixed in:** none as of this writing.
**Prior disclosure:** none found — no published GHSA, private vulnerability reporting is disabled,
no security issue/PR. (PR #263 "three high-quality bug fixes" hardened *other* files —
`file_edit.py` traversal, `phoenix_utils.py` SQLi — not this parser.)
**CWE:** CWE-94 (Code Injection); secondary CWE-95 (eval injection)
**Severity:** High — CVSS 3.1 **8.8** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` (see `cvss.md`;
→ 9.8 if the agent ingests attacker content autonomously, lower when the ReAct runner is unused).
**Reporter:** [your name / handle], [contact] · **Disclosure policy:** 90-day coordinated.

---

## Summary
When an agent is configured with the **ReAct runner** (`runner: react`), the model's generated
`Action:` text is parsed by `ReactConverter._parse_react_output()`, which calls Python's built-in
`eval()` on that text when it is not valid JSON. Because the model's output is attacker-influenced
via indirect prompt injection (any untrusted content the agent reads — a web page, a tool result,
a retrieved document — can steer what the model emits), a crafted `Action:` executes arbitrary
Python in the agent-runner process, i.e. arbitrary OS command execution on the host.

## Affected code
`utu/models/react_converter.py`, `ReactConverter._parse_react_output()` (~L192–210):

```python
text_output = text_output.split(self.action_str)[1].strip()   # text after "Action:"
try:
    action = json.loads(text_output)
except json.JSONDecodeError:
    try:
        action = eval(text_output)          # <-- CWE-94: eval of model-generated text
    except Exception as e:
        raise ValueError(f"Invalid action: {text_output}") from e
assert "name" in action and "arguments" in action   # validation runs AFTER eval's side effects
```

The `eval` is not a rare branch: the ReAct format emits Python-literal dicts with single quotes
(the method's own docstring sample is `{'query': 'smolagents package'}`), which are invalid JSON,
so `json.loads` fails and `eval` becomes the routine parse path. `eval` runs *before* the
`name`/`arguments` validation, so side effects fire even when the payload also returns a
well-formed action.

## Root cause / tainted path
```
untrusted content in the agent's context (indirect prompt injection)
  -> model emits `Action:\n<python>` text
  -> ReactModel.get_response (utu/models/react.py:76) -> converter.postprocess(...)
  -> ReactConverter._parse_react_output()  (react_converter.py:190)
  -> eval(text_output)                     (react_converter.py:207)   # arbitrary Python
```
Reachability gate: the ReAct path is active only when `AgentConfig.runner == "react"`
(`utu/config/agent_config.py:78`; selected by `get_runner`, `utu/runner/__init__.py`). The
default is `runner: "openai"` (native tool-calls), which does **not** reach this parser — so this
affects deployments that select the ReAct runner, typical for models/providers without native
function-calling.

## Proof of concept
Tested locally against a self-hosted checkout; no third-party systems involved; benign canary
only (`poc_real.py` / `poc.py`, `run-transcript.txt` in this directory).

`poc_real.py` loads the **unmodified** `react_converter.py` (sha256 `5377ddb…`, verified to
contain `action = eval(text_output)`) with heavy third-party imports stubbed, and calls the real
`ReactConverter._parse_react_output()` with a model `Action:` that is valid Python but not JSON:

```
Action:
__import__('os').system('touch /tmp/YT_CANARY') or {'name':'search','arguments':{'q':'x'}}
```

Observed: `json.loads` raises `JSONDecodeError` (single quotes + call), `eval` runs the
`os.system` side effect, the canary file is created, and the parser then returns a well-formed
action so the agent continues normally — a silent RCE. Transcript in `run-transcript.txt`.

## Impact
Arbitrary Python / OS command execution in the agent-runner process, with that process's
privileges and credentials. The practical delivery is indirect prompt injection: untrusted
content the agent reads steers the model into emitting the malicious `Action:`, so no direct
network access to the agent is required. Consequences include reading secrets/API keys/SSH keys,
file modification, and lateral movement from the host.

## Suggested fix
Parse data, don't execute it. Replace the fallback with a literal-only parser:

```python
import ast
try:
    action = json.loads(text_output)
except json.JSONDecodeError:
    action = ast.literal_eval(text_output)   # parses Python literals, executes nothing
```

`ast.literal_eval` handles the single-quoted-dict case that motivated the `eval` without
evaluating code. (Even stricter: require strict JSON from the ReAct prompt and reject non-JSON.)

## Disclosure timeline (template)
- [YYYY-MM-DD] Reported privately (GitHub Security → "Report a vulnerability"; private reporting
  is currently disabled — if it stays disabled, email the maintainer: `easonsshi@tencent.com`,
  the `pyproject.toml` author, requesting a private channel).
- [YYYY-MM-DD] Maintainer acknowledged.
- [YYYY-MM-DD] Fix released in [version].
- [report date + 90d] Public disclosure (or earlier by mutual agreement).

## References
- `../verdicts.md` — batch-3 analysis and dedup.
- `poc_real.py`, `poc.py`, `run-transcript.txt`, `poc.pdf` — reproduction.
- `cvss.md` — scoring and the configuration-gate sensitivity analysis.
