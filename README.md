# mcp-hunt

Static taint-analysis toolkit for finding injection-to-impact bugs in MCP servers
(JavaScript/TypeScript and Python). It traces **MCP tool arguments** — attacker-controllable,
including via prompt injection of the calling agent — into dangerous sinks (shell, argv,
filesystem paths, outbound URLs, eval/deserialization, SQL), then ranks and helps you triage
the results for coordinated disclosure.

Built on Semgrep OSS, plus the glue it lacks: a cross-function reach walk, chunked re-scans to
beat Semgrep's silent fixpoint timeout, and a priority queue tuned to the shapes real MCP bugs
take.

## Pipeline

```
  discover.py / funnel            clone (atomic, checkpointed)
  top-N by npm downloads   ──►     $MCP_HUNT_WORK/scan/src/<slug>
  that build an MCP server
          │
          ▼
  ┌───────────────────────────────────────────────────────────┐
  │  scan.py  — per repo                                       │
  │                                                            │
  │   Semgrep taint (3 tiers)        run 2–3× and union        │
  │   ├ taint  : tool-handler params   (beats nondeterminism)  │
  │   ├ helper : any fn param          + chunk re-scan every   │
  │   └ audit  : any sink arg            tool reg / switch case │
  │                                      (beats fixpoint timeout)│
  │                                    + shadow .ts tree for    │
  │                                      .mts/.cts              │
  │              │                                             │
  │              ▼                                             │
  │   reach walk: name-based call graph, handler → helper →    │
  │   sink (≤5 hops, skips tests/generic names)                │
  │              │                                             │
  │              ▼                                             │
  │   context demotion (auto_notes): fixed host, path          │
  │   containment, shell escaping, identifier allowlist        │
  └───────────────────────────────────────────────────────────┘
          │
          ▼
  PRIORITY QUEUE  ──►  manual triage  ──►  dedup (GHSA/issues/PRs,
  (summary.md,         (is it reachable?    canonical+parent repo)
   findings.csv)        intended capability?         │
                        confinement bypass?)         ▼
                                              sandboxed PoC (bwrap,
                                              benign payload, local)
                                                     │
                                                     ▼
                                              coordinated disclosure
```

The scanner finds candidates; a human decides verdicts. Priority rank is a triage input, not a
bug count.

For a walkthrough of the whole pipeline, see [docs/pipeline.pdf](docs/pipeline.pdf).

## Layout

| path | holds |
|---|---|
| `scan.py`, `hunt.py`, `discover.py` | scanner, single-server front end, mid-tier target discovery |
| `tools/` | rule generator, funnel filter, batch runner, PoC sandbox |
| `rules/`, `rules-audit/`, `tests/` | generated Semgrep rules and their fixtures |
| `bench/` | CVE recall benchmark |
| `targets/` | target lists and `funnel.csv` |
| `findings/` | per-batch verdicts, notes, disclosure packages |
| `docs/` | pipeline PDF, disclosure template |

## Validation

| check | result |
|---|---|
| Rules (`make test`) | 21/21 against annotated positive/negative fixtures |
| Recall (`make recall`) | all 4 published CVEs re-found and ranked at their vulnerable versions: CVE-2025-54073 (mcp-package-docs), CVE-2025-53355 (mcp-server-kubernetes), CVE-2025-5277 (aws-mcp-server, 3-hop chain), CVE-2025-53967 (figma-developer-mcp, 4-hop chain through a generic-named method) |
| Patched versions | manual: all 4 repos at HEAD have zero command-injection priority hits |

Read **Known limits** before trusting a clean result.

## Setup

```
pip install semgrep          # 1.x, runs offline
```

Python 3.10+, git. `$MCP_HUNT_WORK` (default `~/mcp-hunt-work`) holds clones, checkpoints and
PoC trees — kept out of the repo.

## Use

**One server:**

```
./hunt.py ./path/to/mcp-server      # or: ./hunt.py owner/repo
```

Prints the priority queue with reach chains, what was demoted and why, scan health, and (for
GitHub repos) prior public advisories/PRs. Saves `report.md` under `$MCP_HUNT_WORK/hunt/<slug>`.

**A batch / funnel:**

```
make discover                                    # -> repos.txt (GitHub + npm, mid-tier)
python3 tools/filter_tools.py <list> \
    --src "$MCP_HUNT_WORK/scan/src" -o targets.txt --csv funnel.csv   # keep only real MCP servers w/ tools
tools/run_batches.sh 1 15                        # scan in resumable batches of 10
```

Then open `summary.md` / `findings.csv`, work the priority queue top-down, and for each
candidate run the **triage checklist** below. Record verdicts in `findings/batch-NN/verdicts.md`.

## The three tiers

Semgrep OSS taint is intraprocedural (it can't follow a call from a handler into a helper), so
the scan layers three source definitions and then reconnects them with the reach walk:

| tier | taint source | catches | noise |
|---|---|---|---|
| **taint** | registered tool-handler params (`server.tool`, `registerTool`, `addTool`, `setRequestHandler`, `@mcp.tool`, …) | bugs in the handler itself | low |
| **helper** | any function parameter | handler → helper → sink (all 4 recall CVEs; figma is a 4-hop chain) | medium, filtered by `reach_hint` |
| **audit** (`--audit`) | any non-literal sink argument | custom frameworks the others miss | high |

**Priority queue** = taint findings + helper findings inside a tool file or ≤4 hops from one,
minus context-demoted rows. Demoted rows stay in `findings.csv` — verify before discarding.

## Triage checklist

- [ ] The sink value really comes from a tool argument (follow `reach_hint` by hand).
- [ ] No validation between source and sink (allowlist, regex, `resolve`+`startsWith`, quoting).
- [ ] **Is this the tool's intended capability?** A `run_shell` tool running shell, or a file
      tool reading files, is a design choice — *unless* it claims a sandbox, allowlist, or
      read-only mode you can bypass, or escapes a configured root. That bypass is the bug.
- [ ] Threat model: stdio-local servers matter via prompt injection of the agent; HTTP/SSE
      without auth is directly reachable. State which.
- [ ] **Dedup first:** check GHSA, issues and PRs on the repo *and its parent/upstream* before
      building a PoC. Most real MCP bugs in popular servers are already public.
- [ ] PoC on your own clone only, benign payloads, in the sandbox (`tools/sandbox.sh`).

## Rules of engagement

- Clone and analyse **locally only** — never probe anyone's deployed instance.
- The scanner parses code; it never installs or runs it. PoCs go in bubblewrap/VM
  (`npm install` runs third-party scripts).
- Coordinated disclosure: private report, ~90 days, publish after a fix. Keep this repo
  **private** while `findings/` has unreported candidates.

## Outputs

- `summary.md` — counts, priority queue with GitHub permalinks, per-repo table.
- `findings.csv` — the dataset, one row per candidate. Auto columns (repo, commit, tier, rule,
  CWE, reach_hint, auto_notes, file:line, sink, permalink) plus triage columns you fill
  (`reachable`, `sanitized_or_contained`, `poc_confirmed`, `status`, `cve`, …).
- `repos.csv` — per-repo commit, tool count, findings per tier, scan health.
- `findings/` — per-batch verdicts and disclosure packages. See **`findings/SUMMARY.md`** for
  the 141-server run and its results.

## Methodology finding (Semgrep soundness gap)

Semgrep OSS's taint fixpoint has a per-function time budget with **no CLI knob**. When a large
`createServer()` or `switch(name)` body exceeds it, *every* taint finding in that function is
dropped silently — the "Fixpoint timeout" line shows only under `--debug` — and the result set
is **nondeterministic** near the budget. This toolkit measures and works around it: 2–3× unioned
runs, and a chunked re-scan of each tool registration / `switch` case as its own small file so
each handler fits inside one budget. Quantified by the `unstable_results`, `chunks` and
`chunk_only_findings` columns.

## Extending

Rules are generated from `tools/gen_rules.py`:

```
make rules && make test && make recall
```

Add a fixture (`// ruleid:` / `// ok:`) for every new sink or false-positive fix. When you
confirm a new bug, add its repo + vulnerable commit to `bench/recall.sh` so it becomes a
regression test.

## Known limits

- **Not a soundness guarantee** — a clean scan is not a clean server.
- Tool-handler shapes outside the known SDK patterns fall to the helper/audit tiers.
- `reach_hint` is name-based, not a real call graph: same-named functions create false links,
  dynamic dispatch (`handlers[name](args)`) breaks real ones.
- Containment/escaping is flagged (`auto_notes`), not modelled in the rules.
- Languages: JS/TS and Python only. Go/Rust/C#/Java MCP servers are out of scope.
