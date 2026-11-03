# Coordinated disclosure template — MCP server vulnerability

Use for a GitHub private security advisory (Security tab → Advisories → "Report a
vulnerability") or a huntr submission. Keep it factual and reproducible. One
report per vuln. Do not post publicly until the maintainer has patched or the
agreed embargo (usually 90 days) elapses.

---

## Title
`<Command injection | Path traversal | SSRF | Unsafe deserialization> in <tool_name> tool of <package> (<version>)`

## Summary
One or two sentences. What the bug is, which tool exposes it, what an attacker
gets. Example: "The `<tool>` tool passes its `<param>` argument to
`child_process.exec` without sanitization, allowing arbitrary command execution
on the host running the MCP server."

## Affected
- Package / repo: `<name>`
- Version(s): `<= x.y.z` (give the exact version you tested; check the tag)
- File / line: `src/tools/<file>:<line>`
- Component: the `<tool_name>` MCP tool

## Severity
- CWE: `<CWE-78 command injection | CWE-22 path traversal | CWE-918 SSRF | CWE-502 deserialization>`
- CVSS 3.1 vector: `<e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8>`
  (adjust: if the tool requires an authenticated/approved MCP session, PR/UI go up)

## Root cause
The tainted path, source to sink:

```
<tool_name>(param: <param>)        # attacker-controlled MCP tool argument
  -> <intermediate calls>
  -> <sink, e.g. subprocess.run(f"cmd {param}", shell=True)>
```

Quote the exact vulnerable lines:

```<lang>
<paste the 2-5 relevant lines>
```

## Proof of concept
Tested locally against a self-hosted instance. No third-party systems involved.

1. Install/run the server:
   ```
   <how you started it locally>
   ```
2. Invoke the tool with this payload (via MCP client / direct call):
   ```json
   { "name": "<tool_name>", "arguments": { "<param>": "<payload>" } }
   ```
   Payloads used (benign markers only):
   - command injection: `; id` or `$(id)`
   - path traversal: `../../../../etc/passwd`
   - SSRF: `http://127.0.0.1:<canary-port>/` (a listener you own)
3. Observed result:
   ```
   <paste: id output / file contents / canary hit log>
   ```

## Impact
What an attacker who controls the tool input can do. Include the AI-delivery
path where it applies: untrusted content the agent reads (web page, file, other
tool output) can carry the injection that drives the tool call, so no direct
network access to the server is required.

## Suggested fix
Concrete remediation:
- command injection: use `execFile` / `subprocess.run([...])` with an args array; no shell.
- path traversal: `realpath` + prefix containment against an allowed base dir; reject `..`.
- SSRF: host allowlist; block link-local/loopback/metadata ranges.
- deserialization: `yaml.safe_load`; never `pickle.load` on tool input.

## Disclosure timeline
- `<date>` reported privately to maintainer
- `<date>` (planned) public disclosure after fix / 90-day embargo

## Reporter
`<name / handle>` — findings from independent, local-only testing. Happy to
verify a patch.
