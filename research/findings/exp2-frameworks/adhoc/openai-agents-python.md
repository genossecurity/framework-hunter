# Ad-hoc — openai/openai-agents-python (rank ~5; user-requested)

Commit `23e9996`, 1030 src files. Scan: 13 priority, **taint=0** (all helper). Scans local-only.

## Verdict: already-confined / clean. No net-new finding.

All 13 priority rows are inside the SDK's own tool sandbox (`src/agents/sandbox/`) — a robust,
defense-in-depth confinement:

- `_is_under(path, root) = path == root or root in path.parents` (`workspace_paths.py:549`) —
  correct (parents-based, not `startswith`), applied to `.resolve(strict=False)`'d paths
  (symlink-safe). No sibling-prefix bug.
- `resolve_workspace_path` (`entries/base.py`) rejects Windows/absolute paths, and when
  absolute-within-root is allowed does `.resolve().relative_to(host_root.resolve())` **plus** a
  lexical `relative_to` — double containment.
- `_resolved_host_path_and_grant` confines to root via `_is_under`; out-of-root access only via
  explicit `SandboxPathGrant`s (a deliberate mount allowlist), with read-only grant enforcement
  (`_raise_if_read_only_grant`).
- `_mount_security.py` is a hardened module: rclone argument-injection defense
  (`_rclone_extra_args_are_safe`; the `startswith("-")` checks are defenses), inline-authority URL
  blocking (`_url_contains_inline_authority`), and trusted mount-class allowlisting.
- `docker_removal.py` runs `[sys.executable, "-I", ...]` argv (no shell); `advanced_sqlite_session`
  PRAGMA uses an internal `messages_table` name.

The FIXPOINT-TIMEOUTs on `_mount_security.py` / `_contract_validation.py` / `_contract_surface.py`
are the Semgrep taint soundness gap on large security-logic functions — reviewed by hand; the
confinement is sound.
