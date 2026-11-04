# Experiment 2 — Agent frameworks, batch 4 (ranks 61–70 of frameworks-top100.txt)

Same method/criterion as prior batches. Scans local-only; **nothing filed**. Work dir
`~/mcp-hunt-work/exp2`.

## Result: 1 confirmed finding (nexent workspace-confinement bypass, moderate; PoC + dedup done,
## NOT filed). Rest already-confined / by-design / FP / bundled-MCP-servers.

| repo | files | taint | priority | verdict |
|---|---|---|---|---|
| potpie-ai/potpie | 1109 | 0 | 23 | by-design code-graph file reads (not escalated) |
| Klavis-AI/klavis | 1187 | 7 | 182 | **bundled 3rd-party MCP servers** (exp1 territory): confined / by-design / FP |
| AgentOps-AI/agentops | 885 | 0 | 0 | clean (SDK/observability) |
| aiwaves-cn/agents | 83 | 0 | 0 | clean |
| ModelEngine-Group/nexent | 3971 | 19 | 123 | **FINDING: workspace-confinement bypass (prefix match) in 7 file tools** |
| microsoft/CUAWright | 112 | 0 | 0 | clean |
| browser-act/skills | 146 | 0 | 0 | clean |
| lavague-ai/LaVague | 117 | 0 | 0 | clean |
| crestalnetwork/intentkit | 956 | 7 | 7 | by-design (fixed-host crypto/data API wrappers) |
| genkit-ai/genkit | 1460 | 7 | 66 | **already-confined** (resolvePath: `rootDir + path.sep`, correct) |

---

## FINDING — ModelEngine-Group/nexent: workspace-confinement bypass via prefix match

**Status: PoC-confirmed (local, sandboxed, benign); deduped — no public report/GHSA; NOT filed.
Moderate severity (bounded escape).** HEAD today. PoC: `nexent-poc/` (`poc.py`, `run-transcript.txt`).

**Location:** `sdk/nexent/core/tools/{create_file,create_directory,delete_file,delete_directory,
move_item,read_file,list_directory}_tool.py` — each defines an identical `_validate_path()`:

```python
if os.path.isabs(file_path):
    abs_path = os.path.abspath(file_path)
else:
    abs_path = os.path.abspath(os.path.join(self.init_path, file_path))
abs_path = os.path.normpath(abs_path)
if not abs_path.startswith(self.init_path):          # init_path default "/mnt/nexent" — NO trailing sep
    raise Exception("Permission denied: ... restricted to the workspace directory ...")
return abs_path
```

**Claimed confinement:** each tool documents "operations are restricted to the workspace
directory"; `_validate_path` is the guard. These are smolagents-style `Tool`s whose `forward()`
takes an LLM-controlled path, reaching `open`/`os.makedirs`/`os.remove`/**`shutil.rmtree`**/
`shutil.move`.

**Bug (CWE-22 / CWE-706):** the guard uses `abs_path.startswith(self.init_path)` **without a
trailing separator**, so any absolute path whose string begins with `init_path` passes — e.g.
`/mnt/nexent-secrets/...`, `/mnt/nexentX/...`. A model/tool-supplied path escapes the workspace to
sibling directories sharing the prefix, across read/write/delete/move/rmtree.

**PoC (confirmed).** `nexent-poc/poc.py` reproduces `_validate_path` verbatim (sha256 of the real
`create_file_tool.py` = `393fafd…`) and runs under `tools/sandbox.sh`:
- intended `notes.txt` → accepted inside; `../../../etc/shadow` → **blocked** (normpath collapses
  `..`, result not prefixed);
- `/work/mnt/nexent-secrets/stolen.txt` → **accepted and written OUTSIDE** the workspace
  `/work/mnt/nexent`. Escape confirmed.

**Impact & honest bounds:** the escape is **not fully arbitrary** — `..` is normalized away, so only
absolute paths literally beginning with the `init_path` string are reachable (its prefix-siblings,
e.g. `/mnt/nexent*`). Full arbitrary-FS escape additionally needs a symlink inside the workspace
(no `realpath`/`O_NOFOLLOW`). So it is a genuine but bounded workspace-isolation bypass; real
impact depends on what sits beside the workspace. `rmtree`/`os.remove` on prefix-siblings make it
more than read-only.

**Dedup:** GHSA none; 31 issues/PRs scanned — none reports this (adjacent-but-different: #3238 JWT
verify, #4004 SSRF-guard). Appears non-public. (Before any disclosure, skim #1753/#3577/#3950,
which touch file tools, to be sure.)

**Fix:** compare with a separator / containment helper, as genkit does in this same batch:
`os.path.commonpath([abs_path, root]) == root`, or `Path(abs_path).resolve().is_relative_to(root)`
with `realpath` for symlinks; or `startswith(init_path + os.sep)` plus the `== init_path` case.

---

## Dismissed / other

- **genkit (Google):** filesystem middleware `resolvePath` (`js/plugins/middleware/src/filesystem.ts`)
  is **correct** — `rootDir = path.resolve(cfg.rootDirectory)`, `securePrefix = rootDir + path.sep`,
  `p = path.resolve(rootDir, requested)`, `if (!p.startsWith(securePrefix) && p !== rootDir) throw`.
  No sibling-prefix bug; `..` collapsed. (Minor: no symlink realpath, and the app must supply
  `rootDirectory` — by contract.) Already-confined.
- **Klavis-AI/klavis:** an MCP-integration platform that **bundles third-party MCP servers**
  (`mcp_servers/local/{filesystem,git,terminal}`, `mcp_servers/wordpress`). The taint hits are the
  known MCP-server patterns from exp1: the canonical filesystem server (`validPath` containment —
  confined), the git server (`repo_path`), a terminal server (declared command executor with its
  own allowlist — by-design), and WordPress.com API `client.get` (fixed host → `.get` SQL **FP**).
  Not the Klavis framework's own surface; exp1-style targets, confined/by-design/FP.
- **crestalnetwork/intentkit:** 7 SSRF rows are `_arun` tools calling **fixed** crypto/data APIs
  (pyth, allora, enso, firecrawl `api.firecrawl.dev`, github, x402) with host fixed and only path/
  id templated — API wrappers by design, no arbitrary-host SSRF.
- **potpie:** path-traversal in code-graph/repo-analysis file reads over a cloned repo; by-design,
  no bypassed confinement claim surfaced (not exhaustively line-verified).
- **agentops / aiwaves-cn/agents / CUAWright / browser-act/skills / LaVague:** 0 priority over the
  tool surface.
