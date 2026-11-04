# framework-hunter

Static taint-analysis toolkit for finding injection-to-impact bugs in agent frameworks and MCP
servers (JavaScript/TypeScript and Python). It traces **tool arguments** — attacker-controllable,
including via prompt injection of the calling agent — into dangerous sinks (shell, argv,
filesystem paths, outbound URLs, eval/deserialization, SQL), then ranks and helps you triage
the results for coordinated disclosure.

Built on Semgrep OSS, plus the glue it lacks: a cross-function reach walk, chunked re-scans to
beat Semgrep's silent fixpoint timeout, and a priority queue tuned to the shapes real agent tool
bugs take.

## Experiments

| | Experiment 1: MCP servers | Experiment 2: agent frameworks |
|---|---|---|
| **Targets** | Top 200 npm packages by weekly downloads, filtered to 141 servers that register tools | 100 frameworks curated from GitHub topic searches, scanned least-used first |
| **Scanned** | 141 of 141 | 99 of 100 (`agent-native` skipped for size, `mastra` run alone) |
| **New findings** | 1: crewly, published as [GHSA-v7q6-5mpg-q47w](https://github.com/stevehuang0115/crewly/security/advisories/GHSA-v7q6-5mpg-q47w) (High, 8.8; CVE pending) | 3: validated and submitted to maintainers on 2026-11-04 (CVEs pending) |
| **Results** | [`SUMMARY.md`](research/findings/exp1-mcp/SUMMARY.md) | [`METHODOLOGY.md`, Part 2](research/METHODOLOGY.md) and [`exp2-frameworks/`](research/findings/exp2-frameworks/) |

The three experiment 2 findings are under embargo until a fix ships or 2027-02-02, whichever comes
first. Keep their details out of anything public until then.

### What experiment 2 changed in the scanner

Experiment 1 only recognised MCP tool registrations. Commit `e528437` extended the same pipeline:

- **Python taint sources:** `@tool`, `@function_tool`, `@kernel_function`, `.tool_plain`,
  `.agent_tool`, and the parameters of `_run`, `_arun` and `forward`.
- **JS/TS taint sources:** LangChain.js `tool(fn, {schema})`, `DynamicTool`,
  `DynamicStructuredTool` and `$F.from_function(...)`. Vercel AI, Mastra and genkit object tools
  already matched the existing patterns.
- **Tool detection:** the reach walk and chunked re-scans recognise these shapes too.
- **Scale handling:** generated code is excluded, along with files over 400 KB and files over
  150 KB with more than 4,000 lines. Semgrep uses all CPU cores.

These changes apply to every scan, so re-running experiment 1 today would not exactly reproduce the
original run.

## Pipeline

```
  target list                     clone (atomic, checkpointed)
  exp 1: npm funnel        ──►     <work>/src/<slug>
  exp 2: curated frameworks
          │
          ▼
  ┌────────────────────────────────────────────────────────────┐
  │  src/scan.py  — per repo                                   │
  │                                                            │
  │   Semgrep taint (3 tiers)        run 2–3× and union        │
  │   ├ taint  : tool-handler params   (beats nondeterminism)  │
  │   ├ helper : any fn param          + chunk re-scan every   │
  │   └ audit  : any sink arg            tool reg / switch case│
  │                                      (beats fixpoint       │
  │                                      timeout)              │
  │                                    + shadow .ts tree for   │
  │                                      .mts/.cts             │
  │              │                                             │
  │              ▼                                             │
  │   reach walk: name-based call graph, handler → helper →    │
  │   sink (≤5 hops, skips tests/generic names)                │
  │              │                                             │
  │              ▼                                             │
  │   context demotion (auto_notes): fixed host, path          │
  │   containment, shell escaping, identifier allowlist        │
  └────────────────────────────────────────────────────────────┘
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

For how each step decides what to surface, see [research/METHODOLOGY.md](research/METHODOLOGY.md).
[research/findings/exp1-mcp/pipeline.pdf](research/findings/exp1-mcp/pipeline.pdf) is a
plain-language walkthrough written for experiment 1, so it covers MCP servers only and uses the old
project name and paths.

## Layout

| path | holds |
|---|---|
| `src/` | the Python entry points, described below |
| `tools/` | rule generator, funnel filter, batch runner, PoC sandbox |
| `rules/`, `rules-audit/`, `tests/` | generated Semgrep rules and their fixtures |
| `bench/` | recall benchmark against published MCP bugs |
| `research/METHODOLOGY.md` | decision gates at each pipeline step, and the write-up of experiment 2's PoCs |
| `research/targets/` | experiment 1 lists and `funnel.csv`; experiment 2 `frameworks-*.txt` and `exp2_batch/` batch lists |
| `research/findings/exp1-mcp/` | experiment 1 `batch-NN/` verdicts and disclosure packages, plus `SUMMARY.md` and the pipeline PDF |
| `research/findings/exp2-frameworks/` | experiment 2 `batch-NN/` verdicts and PoCs, plus `adhoc/` notes |
| `docs/` | disclosure template |
| `architecture.drawio` | architecture diagram |

**`src/`**

- `src/scan.py`: clones targets, runs the tiered Semgrep scan with reach walk and context demotion, and writes `findings.csv`, `repos.csv` and `summary.md`.
- `src/hunt.py`: runs `scan.py` on one local directory or `owner/repo`, prints the priority queue and prior public reports, and saves `report.md`.
- `src/discover.py`: builds `repos.txt`, a target list of mid-tier MCP servers from GitHub and npm search.

## Validation

| check | result |
|---|---|
| Rules (`make test`) | 21/21 against annotated positive/negative fixtures, including the agent-framework shapes |
| Recall (`make recall`) | 5 published MCP bugs re-found and ranked at their vulnerable versions: CVE-2025-54073 (mcp-package-docs), CVE-2025-53355 (mcp-server-kubernetes), CVE-2025-5277 (aws-mcp-server, 3-hop chain), CVE-2025-53967 (figma-developer-mcp, 4-hop chain through a generic-named method), GHSA-v7q6-5mpg-q47w (crewly) |
| Patched versions | manual: the 4 CVE repos at HEAD have zero command-injection priority hits |

The recall benchmark contains only MCP servers, so agent-framework detection is covered by the
fixtures alone. Scanning crewly takes up most of its runtime, about 18 minutes on its own. Read **Known limits** before trusting a clean result.

## Setup

```
pip install semgrep pyyaml   # semgrep 1.x runs offline; pyyaml is only for `make rules`
```

Python 3.10+, git. Clones, checkpoints and scan output stay out of the repo by default:
`src/hunt.py` writes under `$FRAMEWORK_HUNTER_WORK/hunt/<slug>` (default `~/framework-hunter-work`),
`tools/batch.py` under `~/framework-hunter-work/scan`. `src/scan.py` on its own writes to
`./hunter-scan` (gitignored); change it with `--work`. Set `FRAMEWORK_HUNTER_VENV` if Semgrep lives
in a virtual environment.

## Use

Run these from the repo root.

**One target:**

```
python3 src/hunt.py ./path/to/target      # or: python3 src/hunt.py owner/repo
```

Prints the priority queue with reach chains, what was demoted and why, scan health, and (for
GitHub repos) prior public advisories/PRs. Saves `report.md` under
`$FRAMEWORK_HUNTER_WORK/hunt/<slug>`. For a framework, its "MCP server code: NOT detected" line is
expected.

**A batch of agent frameworks (experiment 2):**

```
python3 tools/batch.py 1 --list research/targets/frameworks-reversed.txt \
    --work ~/framework-hunter-work/exp2       # batch 1 = the 10 least-used frameworks
```

Check a repo's size before scanning it. No code enforces the scale limit: `agent-native` (about
20k files) was skipped by hand and `mastra` was run alone.

**A batch of MCP servers (experiment 1):**

```
python3 src/discover.py -o repos.txt             # GitHub + npm, mid-tier MCP servers
python3 tools/filter_tools.py <list> \
    --src ~/framework-hunter-work/scan/src -o targets.txt --csv funnel.csv   # keep only MCP servers with tools
tools/run_batches.sh 1 15                        # scan in resumable batches of 10
```

`src/discover.py` and `tools/filter_tools.py` are MCP-specific. `tools/batch.py` and
`tools/run_batches.sh` read `research/targets/repos-top200-downloads-tools.txt` unless you pass
`tools/batch.py --list`.

Then open `summary.md` / `findings.csv`, work the priority queue top-down, and for each
candidate run the **triage checklist** below. Record verdicts in
`research/findings/<experiment>/batch-NN/verdicts.md`.

## The three tiers

Semgrep OSS taint is intraprocedural (it can't follow a call from a handler into a helper), so
the scan layers three source definitions and then reconnects them with the reach walk:

| tier | taint source | catches | noise |
|---|---|---|---|
| **taint** | registered tool-handler params: MCP (`server.tool`, `registerTool`, `addTool`, `setRequestHandler`, `@mcp.tool`, …) and agent frameworks (`@tool`, `@function_tool`, `BaseTool._run`, `DynamicTool`, …) | bugs in the handler itself | low |
| **helper** | any function parameter | handler → helper → sink (all 4 CVE recall targets; figma is a 4-hop chain) | medium, filtered by `reach_hint` |
| **audit** (`--audit`) | any non-literal sink argument | custom tool registration the others miss | high |

**Priority queue** = taint findings + helper findings inside a tool file or ≤4 hops from one,
minus context-demoted rows. Demoted rows stay in `findings.csv` — verify before discarding.

## Triage checklist

- [ ] The sink value really comes from a tool argument or model output (follow `reach_hint` by hand).
- [ ] No validation between source and sink (allowlist, regex, `resolve`+`startsWith`, quoting).
- [ ] **Is this the tool's intended capability?** A `run_shell` tool running shell, or a file
      tool reading files, is a design choice — *unless* it claims a sandbox, allowlist, or
      read-only mode you can bypass, or escapes a configured root. That bypass is the bug.
- [ ] Threat model: stdio-local servers and framework tools matter via prompt injection of the
      agent; HTTP/SSE without auth is directly reachable. State which.
- [ ] **Dedup first:** check GHSA, issues and PRs on the repo *and its parent/upstream* before
      building a PoC. Most real bugs in popular targets are already public.
- [ ] PoC on your own clone only, benign payloads, in the sandbox (`tools/sandbox.sh`).

## Rules of engagement

- Clone and analyse **locally only** — never probe anyone's deployed instance.
- The scanner parses code; it never installs or runs it. PoCs go in bubblewrap/VM
  (`npm install` runs third-party scripts).
- Coordinated disclosure: private report, ~90 days, publish after a fix. Keep this repo
  **private** while `research/findings/` has unreported or embargoed findings.

## Outputs

- `summary.md` — counts, priority queue with GitHub permalinks, per-repo table.
- `findings.csv` — the dataset, one row per candidate. Auto columns (repo, commit, tier, rule,
  CWE, reach_hint, auto_notes, file:line, sink, permalink) plus triage columns you fill
  (`reachable`, `sanitized_or_contained`, `poc_confirmed`, `status`, `cve`, …).
- `repos.csv` — per-repo commit, tool count, findings per tier, scan health.
- `research/findings/` — per-batch verdicts and disclosure packages.

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

Add a fixture (`// ruleid:` / `// ok:`) for every new sink, tool shape or false-positive fix. When
you confirm a new bug, add its repo + vulnerable commit to `bench/recall.sh` so it becomes a
regression test, once the bug is public.

## Known limits

- **Not a soundness guarantee** — a clean scan is not a clean target.
- Tool shapes outside the known MCP and framework patterns fall to the helper/audit tiers.
- `reach_hint` is name-based, not a real call graph: same-named functions create false links,
  dynamic dispatch (`handlers[name](args)`) breaks real ones.
- Containment/escaping is flagged (`auto_notes`), not modelled in the rules.
- `_run`, `_arun` and `forward` match by method name, so they can flag methods outside tool classes.
- The large-file filter also drops hand-written files. Chunked re-scans still cover tool
  registrations, but a sink in a big helper file outside a registration can be missed.
- Most logic and classification bugs need manual review: the experiment 2 findings were an `eval`
  fallback, a missing path separator and a missing DuckDB flag.
- Languages: JS/TS and Python only. Go/Rust/C#/Java targets are out of scope.
