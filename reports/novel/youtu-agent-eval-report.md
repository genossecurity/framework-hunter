# youtu-agent — `eval()` of model output → code injection (CWE-94)

**Status:** our-PoC (confirmed; CodeQL run-1 missed it, run-2's `ModelOutputSource` caught it).
**Repo:** [TencentCloudADP/youtu-agent](https://github.com/TencentCloudADP/youtu-agent)
**File:** `utu/models/react_converter.py:207`
**Class:** Code injection (CWE-94) · **Severity:** High (RCE)

## Summary

The ReAct output converter passes model-generated text to `eval()`. An attacker who can
influence the model's output — directly, or **indirectly via prompt injection** through tool
content / documents the agent reads — achieves arbitrary Python execution in the agent process.

## Affected code

`utu/models/react_converter.py:207` — model output flows into `eval()` during ReAct
step parsing.

## PoC (shape)

Drive the agent to a ReAct step whose model output is a Python expression payload, e.g.:

```
__import__('os').system('id')
```

It reaches `eval()` → command execution. In practice, deliver via an indirect prompt-injection
vector (a web page / file the agent is told to read) so the malicious "model output" is
attacker-seeded.

## Why CodeQL missed it (and why it matters)

The taint **source is model output**, not a tool-handler parameter. Run-1's agent-source
queries only treated tool-call arguments as sources, so they couldn't connect source → `eval()`
sink. Run-2 added `ModelOutputSource`, which catches this class (validated here and on the
known-public SuperAGI instance). This is a core Exp-2/Exp-3 result: the eval-of-model-output
RCE class is invisible unless model output is modeled as a taint source.

## Dedup

Same *class* as the (already public) SuperAGI `eval()` bug, but an **independent instance** in
a different project — our own confirmation. Verify against youtu-agent's advisories/issues
before filing.
