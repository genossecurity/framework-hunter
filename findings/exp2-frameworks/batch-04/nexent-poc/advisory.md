# Security advisory (DRAFT — not sent)

> Written for: the nexent maintainer (ModelEngine-Group / Huawei), for coordinated disclosure.
> nexent has private vulnerability reporting enabled and a SECURITY.md — prefer the GitHub
> private advisory, with the SECURITY.md email as backup. This is a scaffold for the reporter to
> review and submit; **nothing has been sent or filed.** Fill the bracketed fields first.

**Title:** Workspace-confinement bypass via unbounded `startswith` prefix match in the built-in
file tools (`_validate_path`) — read/write/delete/move outside the declared workspace

**Affected product:** `nexent` (ModelEngine-Group/nexent), SDK package `nexent` file tools
**Affected versions:** ≤ 2.8.4 (current release; HEAD `d289f67` on `develop`). The flawed guard is
present at least since v1.6.0 (`sdk/nexent/core/tools/create_file_tool.py` sha `5086526`), i.e.
since the filesystem tools were added (commit `48f8088`, 2025-07-22). [Confirm the earliest
supported release.]
**Fixed in:** none as of this writing.
**Prior disclosure:** none found — no published GHSA; no issue/PR describing this. (Adjacent but
different: #3985 Windows Docker-sandbox path handling; nothing on the `startswith` guard.)
**CWE:** CWE-22 (Path Traversal) / CWE-706 (Incorrect Name Resolution); the specific flaw is the
classic *missing-trailing-separator prefix match*.
**Severity:** Medium — CVSS 3.1 **5.0** `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L` (see `cvss.md`;
rises toward ~7 High if sensitive data sits in a prefix-sibling directory, which the default
deployment layout makes true — see Impact).
**Reporter:** [your name / handle], [contact] · **Disclosure policy:** 90-day coordinated.

---

## Summary
The built-in file tools (`create_file`, `create_directory`, `read_file`, `list_directory`,
`delete_file`, `delete_directory`, `move_item`) each confine operations to a workspace directory
via a shared `_validate_path()`. The containment check is `abs_path.startswith(self.init_path)`
**without a trailing path separator**, so any absolute path whose string merely *begins with* the
workspace string passes — e.g. with the default workspace `/mnt/nexent`, a path like
`/mnt/nexent-data/...` or `/mnt/nexentX/...` is accepted. A model- or tool-supplied path
(reachable by indirect prompt injection driving a file tool) therefore escapes the declared
workspace to sibling directories that share the prefix, across read, write, delete (including
`shutil.rmtree`) and move.

## Affected code
`sdk/nexent/core/tools/create_file_tool.py`, `_validate_path()` (the identical guard appears in
all seven file tools):

```python
if os.path.isabs(file_path):
    abs_path = os.path.abspath(file_path)
else:
    abs_path = os.path.abspath(os.path.join(self.init_path, file_path))
abs_path = os.path.normpath(abs_path)
if not abs_path.startswith(self.init_path):          # init_path default "/mnt/nexent", NO trailing sep
    raise Exception("Permission denied: File operations are restricted to the workspace ...")
return abs_path
```

Each tool documents that "operations are restricted to the workspace directory", and
`_validate_path` is the enforcement. `init_path` defaults to `/mnt/nexent`
(`Field(..., default="/mnt/nexent")`); the backend wires `workspace_path` defaults of
`/mnt/nexent/workdir`.

**Reachability — which configurations hit the flawed branch.** `_validate_path` first checks
`self.workspace_mapping`; when that is set it delegates to `SandboxWorkspace.resolve_file()`,
which *is* correct (it uses `Path.resolve().relative_to(base)`). But `workspace_mapping` is wired
**only** for Docker bind-mount sandboxing — `nexent_agent.py:303` sets it only when
`sandbox_config.workspace_mode == "bind"` **and** `sandbox_config.level == DOCKER`, and in that
case `init_path` is additionally reset to `<host_root>/outputs`. In every other configuration
(no sandbox config, local sandbox level, or non-bind workspace mode) `workspace_mapping` is
`None`, so the vulnerable `startswith` branch is the active guard. This is a default/local-mode
bypass, not a Docker-bind-mode one.

## Root cause / tainted path
```
untrusted content in the agent's context (indirect prompt injection)
  -> model calls a file tool with an absolute `path` argument
  -> Tool.forward(path) -> self._validate_path(path)
  -> `abs_path.startswith(self.init_path)`  passes for a prefix-sibling absolute path
  -> open()/os.makedirs()/os.remove()/shutil.rmtree()/shutil.move()  OUTSIDE the workspace
```
`normpath` collapses `..`, so pure `../../etc/passwd`-style traversal is **blocked** (the result
is not prefixed); only absolute paths literally beginning with the `init_path` string pass. That
bounds the escape to prefix-siblings — which is why Attack Complexity is High — but does not make
it safe (see below).

## Proof of concept
Tested locally against a self-hosted checkout; benign canary only; no third-party systems
(`poc.py`, `run-transcript.txt` in this directory). The PoC reproduces `_validate_path` verbatim
(sha256 of the real `create_file_tool.py` = `393fafd…`). With workspace `/work/mnt/nexent`:

- `notes.txt` (intended) → accepted inside the workspace.
- `../../../etc/shadow` → **blocked** (normpath collapses `..`).
- `/work/mnt/nexent-secrets/stolen.txt` → **accepted and written outside** the workspace.
- `/work/mnt/nexentX/evil.txt` → accepted outside the workspace.

Escape confirmed: the validator accepted and a real write landed in a prefix-sibling directory
outside `/work/mnt/nexent`. Transcript in `run-transcript.txt`.

## Impact
Read, overwrite, move and delete (`os.remove`, `shutil.rmtree`) of files in directories that
share the workspace's string prefix, with the agent process's own filesystem authority — a
bypass of the documented workspace isolation. The default deployment layout makes this concrete:
the shipped compose files mount sibling paths under the shared prefix `/mnt/nexent`, including
**`/mnt/nexent-data/...`** (`skills`, `logs`, and `memory-provider-plugins`). `/mnt/nexent-data`
begins with `/mnt/nexent`, so it is reachable through this bypass. Writing into
`memory-provider-plugins` is a plausible escalation to code execution, because that directory is
loaded by `spec_from_file_location` + `exec_module` (`management/services/memory/providers/
plugins.py`) — though reaching that loader from a planted file needs the plugin path/trigger to
line up, so treat RCE-via-plugin as a conditional escalation to confirm, not a given.
Fully arbitrary-filesystem escape (beyond prefix-siblings) additionally requires a symlink inside
the workspace, since there is no `realpath`/`O_NOFOLLOW`.

## Suggested fix
Enforce a real directory boundary, not a string prefix. Any of:

```python
from pathlib import Path
base = Path(self.init_path).resolve()
resolved = Path(abs_path).resolve()               # realpath collapses symlinks too
if not resolved.is_relative_to(base):             # py3.9+: or compare os.path.commonpath
    raise Exception("Permission denied: outside workspace")
```

or minimally `abs_path == self.init_path or abs_path.startswith(self.init_path + os.sep)`. Apply
to the shared `_validate_path` so all seven tools are fixed at once; resolve symlinks
(`os.path.realpath`) before the check to also cover the symlink-escape case. (The in-repo
`SandboxWorkspace.resolve_file` already does this correctly — the non-mapped branch should match
it.)

## Disclosure timeline (template)
- [YYYY-MM-DD] Reported privately via GitHub Security → "Report a vulnerability" (private
  reporting is enabled), or `zhenggaoqi@huawei.com` per `SECURITY.md`.
- [YYYY-MM-DD] Maintainer acknowledged (SECURITY.md commits to 48h).
- [YYYY-MM-DD] Fix released in [version].
- [report date + 90d] Public disclosure (or earlier by mutual agreement).

## References
- `../verdicts.md` — batch-4 analysis, dedup, and bounded-impact honesty notes.
- `poc.py`, `run-transcript.txt`, `poc.pdf` — reproduction.
- `cvss.md` — scoring and the "rises toward High" conditions.
