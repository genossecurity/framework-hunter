# mksglu/context-mode — not a vulnerability (declared code executor, no confinement to bypass)

`context-mode@1.0.169`, commit `7164222685f7`. Source review only. **Nothing filed.**
Resolution of the batch-6 "open candidate": after a full read of the tool surface and the
"security" code, this is **not a reportable bug**. Recorded as a negative result for the
dataset (a declared-dangerous tool with no bypassable boundary).

## Why it looked interesting
Batch-6 triage flagged it because the scanner showed command-injection ERROR rows
(`executor.ts` `spawn(fullCmd, [], { shell: true })`, `execSync` probes) in a server with a
`security.ts` permission model and **no public security reports** to deduplicate against.

## What it actually is
`ctx_execute` / `ctx_execute_file` / `ctx_batch_execute` run caller-supplied code in 12
language runtimes. This is the tool's entire, documented purpose ("Think-in-Code": run the
derivation in code so raw bytes never enter the LLM context window). Specifically:

- **Advertised as arbitrary execution.** Tool title: *"Run code in a sandbox (executes the
  supplied code)"*; annotations `destructiveHint: true`, `openWorldHint: true`; description
  says *"runs arbitrary code in a sandbox with full network access"*; the tool's own examples
  are `require('child_process').execSync('npm test')` and `execSync('gh issue list ...')`.
- **"Sandbox" = context/process isolation, not capability confinement.** README "How the
  Sandbox Works": each call *"spawns an isolated subprocess with its own process boundary.
  Scripts can't access each other's memory or state"*, and *"Authenticated CLIs work through
  credential passthrough — `gh`, `aws`, `gcloud`, `kubectl`, `docker` inherit environment
  variables and config."* Full network and inherited credentials are **features**, not leaks.
- **Host-gated.** Transport is stdio only (`StdioServerTransport`, no HTTP listener). Both
  execute tools are `destructiveHint: true`, so the MCP host renders an approval prompt whose
  title (#852) says the code will execute. The threat model is a prompt-injected agent, and
  the mitigation is that host approval — not a server-side sandbox.
- **The one real security control is not a code-confinement boundary.** `executor.ts` strips
  a `DENIED` set of environment variables from the child process (`LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES`, `DOTNET_*`/`COMPlus_*` profiler knobs, `GIT_SSH`/`GIT_*`,
  `OPENSSL_CONF`, `CC`/`CXX`, `BASH_FUNC_*`), with PR #546 closing a `COMPlus_` alias bypass.
  This hardens the executor against the *parent* environment being used to hijack a runtime
  via library/hook injection. It does not, and does not claim to, limit what the executed code
  can do — code that already has arbitrary execution can set any env for its own children.
- **Host-hook deny routing is the host's, not the server's.** The Codex/Kiro `PreToolUse`
  "deny rules block dangerous commands" is host-side hook routing for the host's own
  Bash/Read/Grep tools; it is not a guarantee that `ctx_execute` is confined, and the README
  states it is deny-only and host-dependent.

## Verdict
No claimed sandbox, allowlist, or read-only mode applies to the executed code, so there is
nothing to bypass. Per this project's triage checklist, a tool whose declared purpose is
running arbitrary code — labeled destructive, host-approval-gated, stdio-only — is a design
choice, not a CVE. **No PoC built** (a PoC would only reproduce advertised behavior). The
batch-6 flag was an over-call; corrected here.

## Methodology note (for the paper)
"Sandbox" is overloaded. context-mode uses it for **context-window / memory isolation**, the
opposite of a **capability-confinement sandbox**. A scanner or triager must read what a tool
*claims to confine* before treating an execution sink as a finding; the command-injection
rows here are the tool working as documented. Good negative-result exemplar for the dataset.
