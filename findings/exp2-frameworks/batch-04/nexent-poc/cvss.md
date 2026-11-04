# CVSS 3.1 — nexent workspace-confinement bypass (prefix match)

Self-assessed (not an official NVD/CNA score).

**Primary vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L`
**Base score: 5.0 (Medium)**

| metric | value | justification |
|---|---|---|
| AV Attack Vector | Network | Malicious path arrives via content the agent ingests (indirect prompt injection) that drives a file-tool argument. |
| AC Attack Complexity | High | Escape is bounded to absolute paths sharing the `init_path` string prefix (`/mnt/nexent*`); impact depends on sensitive data sitting beside the workspace, or a pre-existing workspace symlink for full escape — conditions outside the attacker's control. |
| PR Privileges Required | None | Attacker supplies the tool argument via injected content. |
| UI User Interaction | Required | Operator runs the agent task. |
| S Scope | Unchanged | Still the agent process's own FS authority (declared workspace boundary crossed, but same authority). |
| C/I/A | Low/Low/Low | Bounded read/write/delete (incl. `shutil.rmtree`) within prefix-sibling directories. |

**Sensitivity / honest notes**
- Rises toward **~7 (High)** if valuable data sits in a prefix-sibling dir (→ `I:H/A:H`, `rmtree`)
  or a workspace symlink enables arbitrary-FS escape.
- Pure `..` traversal to arbitrary paths is **blocked** (normpath), which is why AC is High and
  impact bounded — this is a boundary-prefix bug, not full path traversal.
