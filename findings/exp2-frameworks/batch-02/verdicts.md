# Experiment 2 — Agent frameworks, batch 2 (ranks 81–90 of frameworks-top100.txt)

Same method/criterion as batch 1. Scans local-only; **nothing filed**. GitHub prior-report
dedup NOT yet run. Work dir `~/mcp-hunt-work/exp2`.

## Result: 0 reportable. FrontierAgent write_file traversal confirmed in code, but dedup shows
## the reachable variant is already public/fixed and the survivor is an edge-config residual.
## (Updated after dedup + PoC — the earlier "candidate" framing overstated reachability.)

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| truefoundry/trueforge | 2868 | 0 | 275 | FP (DB migrations / query builder, not tool-reachable) |
| withastro/flue | 531 | 0 | 1 | FP (Redis `.command()`, not a shell sink) |
| zai-org/Open-AutoGLM | 40 | 0 | 0 | clean over tool surface |
| TencentQQGYLab/AppAgent | 12 | 0 | 0 | clean |
| katanaml/sparrow | 103 | 0 | 0 | clean |
| droidrun/mobilerun | 208 | 0 | 0 | clean (by-design device control) |
| camel-ai/oasis | 102 | 0 | 0 | clean |
| sentient-agi/ROMA | 361 | 0 | 9 | config/CLI/ORM internals, not tool-reachable |
| icip-cas/PPTAgent | 11 | 0 | 0 | clean |
| **ApodexAI/FrontierAgent** | 573 | 9 | 49 | traversal real in code, but **dedup: already-public fix + edge residual → not reportable** |

## CANDIDATE — ApodexAI/FrontierAgent `write_file`: `/tmp/agent-outputs/` confinement bypass

**Status: code-level analysis only. NOT PoC-confirmed, NOT deduped, NOT filed.**

`plugins/tools/write_file.py` documents, for no-sandbox local mode: *"Without sandbox, writes to
/tmp/agent-outputs/ only."* The enforcement is bypassable by `..`:

```python
_LOCAL_OUTPUT_DIR = "/tmp/agent-outputs"        # note: no trailing slash
...
path = resolve_runtime_path(path)               # returns the path UNCHANGED for non-alias paths
local_path, _ = _authorized_local_path(path, write_access=True)   # -> None for an unauth path
if local_path is not None: ...                  # skipped
if sandbox_available(): ...                     # skipped in no-sandbox mode
# Local fallback — "restricted to /tmp/agent-outputs/"
if not path.startswith(_LOCAL_OUTPUT_DIR):      # startswith on the UN-normalized path
    path = os.path.join(_LOCAL_OUTPUT_DIR, os.path.basename(path))
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, mode) as f: f.write(content)    # open() resolves `..` at the OS level
```

A model-supplied `path = "/tmp/agent-outputs/../../home/<user>/.bashrc"` (or `/etc/cron.d/x`,
`~/.ssh/authorized_keys`) **starts with** `/tmp/agent-outputs`, so the basename-redirect is
skipped, and `open()` writes outside the directory → **arbitrary file write as the agent-runner
user** → persistence / RCE. `resolve_runtime_path` only `normpath`s internally for mount-alias
matching and returns the original string for non-alias paths (`return path`); `_authorized_
local_path` normalizes its own copy and returns `None`, so nothing collapses the `..` before the
fallback's `startswith`.

**Why it meets the criterion:** a *claimed* confinement ("/tmp/agent-outputs/ only") escaped by an
LLM-controllable tool argument. Reachable via indirect prompt injection (model emits the path).

**Asymmetry (supports it being a real bug):** the sibling `delete_file` (`apodex/local_tools.py`)
does it *correctly* — `os.path.realpath(raw)` then `target==cwd or startswith(cwd+os.sep)` —
collapsing `..`/symlinks before the containment check. `write_file`'s fallback does not.

**Reachability caveat (must verify before escalating):** the vulnerable fallback runs only when
`sandbox_available()` is False — backend `auto`/`local`/`bwrap`, **no** E2B API key, and `bwrap`
not on PATH (e.g. a macOS `pip install` CLI run, or a minimal Linux host). With E2B, a container,
or bwrap present, control takes the sandbox branch instead (different confinement, not analyzed
here). So this is a bypass of the *documented no-sandbox-mode* restriction, not an all-configs RCE.

### Dedup + PoC done — REASSESSED to not-reportable

**PoC (confirmed, local, benign, sandboxed).** `frontieragent-poc/poc.py` faithfully reproduces
the HEAD fallback lines (cited in the file) and runs under `tools/sandbox.sh` (bwrap, net off,
`$HOME` tmpfs, `/` ro). Result: input `/tmp/agent-outputs/../PWNED_OUTSIDE.txt` writes to
`/tmp/PWNED_OUTSIDE.txt` (outside confinement); both control inputs stay inside. The traversal
is real in the code at HEAD (`cc32d88`, 2026-11-03).

**Dedup — the reachable variant is already public and fixed.** The maintainers surveyed exactly
this area and merged (2026-10-06):
- **#59** `fix(paths): make the path gate binding for in-process writes and shell commands` — body:
  *"A refused write reached the host anyway. write_file … fall back to the sandbox when _path_auth
  refuses a local write. For a CurrentSandbox (container and native mode) that fallback is
  sandbox_write_file, whose first branch is a plain open() … as root in container mode."* Fixed;
  `CHANGELOG.md:138` = *"A write the path gate refused no longer reaches the host."*
- **#60** `fix(runtime): derive every filesystem path from one trusted state`, **#61** bash-policy
  path identity. Added `tests/test_path_gate_is_binding.py`.

So the **reachable** fallback (native/container, where `sandbox_available()` is True) is fixed.

**The survivor is edge-config only.** The still-present `/tmp/agent-outputs` branch (write_file.py
:106, raw `startswith` on an un-normalized path) is reached only when `sandbox_available()` is
False — backend `auto`/`bwrap` with no `bwrap` binary and no E2B key. But `_get_sandbox_backend`
documents the CLI resolving a concrete backend at startup (**macOS → `native`**; Linux → bwrap/
container), and `native`/`container` make `sandbox_available()` return True → the fixed branch,
not this one. So this branch is hit only by a non-CLI embedding that runs with no usable sandbox
backend — a degraded mode, not the shipped CLI default.

**Verdict: not reportable as a new finding.** It is a residual of an already-public, already-fixed
hardening (#59/#60) in a branch the CLI's own boundary resolution avoids. A courtesy hardening
note (normalize/realpath in the `/tmp` fallback, as the sibling `delete_file` already does) is the
most it warrants — the maintainers are actively porting more path-gate fixes ("handoff items 4a–4c").
No disclosure pursued. Nothing filed.

## Notes on the dismissed high-count repos
- **trueforge (270 "sql"):** sinks are `sql\`CREATE SCHEMA ...\`.execute(db)` and Kysely
  migrations under `packages/trueforge/src/db/` — static internal SQL, not reachable from a tool
  arg. The `.execute(db)` query-builder method matches the SQL sink. FP.
- **flue:** `redis-adapter.ts` `this.runner.command(command, args)` is a Redis client command,
  not execa/shell. The `.command(` sink matched. FP. (flue is "the sandbox agent framework" — the
  branding made this worth confirming; it is not a shell escape.)
- **ROMA:** SSRF/path/SQL rows are in `cli.py`, `config/*`, `*storage*`, `subprocess_toolkit`
  `__init__`, TUI client — operator-config / constructor / compiled-ORM paths, linked by generic
  names (`load_config`, `__init__`), not model tool arguments.
