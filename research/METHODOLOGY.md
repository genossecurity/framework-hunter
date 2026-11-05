# framework-hunter — Methodology & decision gates

*Written for: engineers/reviewers new to this repo (and as the write-up behind the paper). It
explains how the scanner decides what to surface at each step, and — for the agent-framework run
(experiment 2) — what each confirmed PoC was looking for and what it found. Non-technical readers:
each stage in Part 1 opens with a plain-English summary.*

The scanner **finds candidates; a human decides verdicts.** Every automated step below is a *filter
or a ranking input*, never a bug count. The only step that declares a vulnerability is manual triage
against the **finding criterion** (§7).

---

## Part 0 — The whole pipeline as pseudocode

Every `GATE`/`DECISION` below is the actual logic in `src/scan.py` / `tools/gen_rules.py` /
`src/hunt.py`, with two exceptions applied by hand: target curation for exp 2 (gate 1) and the
scale check (gate 2).

```text
hunt(population):                                   # population = funnel (exp1) or curated list (exp2)
    candidates = []
    for target in population:
        # ---- GATE 1: target selection ----
        if not reachable(target):            drop  # 404 / private / deleted
        if not builds_tool_surface(target):  drop  # registers tools / ships tool defs (not a client)
        if language(target) not in {JS, TS, PY}: drop   # Go/Rust/C#/Java out of scope
        if is_list_or_tutorial_or_app(target):   drop

        repo = clone_shallow(target)               # --depth 1, atomic (*.partial→rename), 5-min cap
        # ---- GATE 2: scale ----
        if src_file_count(repo) ~>= 20_000:  skip_or_scope(repo)   # manual call, not in code

        rows = scan(repo)
        for r in rows:
            r.reach_hint = reach_walk(r.function, repo)            # step 4
            r.auto_notes = context_demotion(r)                    # step 5
        candidates += [r for r in rows if is_priority(r)]         # step 6

    for r in priority_queue(candidates):           # ranked: taint first, ERROR first
        verdict = triage(r)                        # step 7  — the ONLY vuln decision
        if verdict == FINDING and not already_public(r):   # step 8 dedup
            if poc_confirms(r):                    # step 9  — sandboxed, benign
                record(r, cvss(r)); disclose(r)    # step 10 — coordinated, repo stays private


scan(repo):                                        # ---- GATE 3: semgrep, 3 tiers + robustness ----
    files = [f for f in sources(repo)
             if f not in EXCLUDES                  # node_modules,dist,build,tests,examples,docs,.generated,*.bridge.ts,…
             and not non_reviewable(f)]            # minified_files(): avg_line>2KB OR size>400KB OR (size>150KB and lines>4000)
    results = []
    for run in 1..3:                               # 2–3× then UNION  → beats near-budget nondeterminism
        results |= semgrep(files, [taint, helper], timeout=120/file, jobs=nproc)
    results |= shadow_ts_scan(repo)                # .mts/.cts analyzed via a .ts shadow tree
    for reg in tool_registrations(repo):           # CHUNK re-scan: each handler/switch-case as its
        results |= semgrep(as_small_file(reg))     #   own file so it fits one taint budget
    return dedupe_by_sink(results)                 # keep strongest tier per (file,rule,sink)

# taint source  = a registered tool-handler param        (confidence: use directly)
# helper source = ANY function/method param              (confidence: must prove reachable → reach_walk)
# audit source  = ANY non-literal sink arg (opt-in, noisy)
# sinks: CWE-78 shell · 88 argv · 22 path · 918 ssrf · 94 eval/deser · 89 sql


reach_walk(fn, repo):                              # ---- GATE 4: name-based reverse call graph ----
    frontier = [(fn, [fn])]
    for hop in 1..5:                               # MAX_HOPS = 5
        for (f, chain) in frontier:
            for (callsite_file, caller) in callers_of(f):
                if f in GENERIC_NAMES and callsite is not (this.f|self.f): continue  # avoid false links
                if callsite_file is a TOOL_FILE:
                    hops = len(chain)
                    return "inside/called from tool file" if hops <= 4 else "distant path (N hops)"  # PRIORITY_HOPS=4
        frontier = next_hop(frontier)
    return "no path to tool code found"            # TOOL_FILE = MCP handler shapes OR agent-tool shapes


context_demotion(r):                               # ---- GATE 5: cheap "probably-mitigated" notes ----
    win = lines[idx-30 .. idx]                     # a note DEMOTES off the queue (row kept in csv)
    if r.cwe==SSRF  and fixed_host(near):      note "URL host fixed — path-only?"
    if r.cwe==PATH  and containment(win):      note "containment nearby — verify it is correct"   # ← nexent hid here
    if r.cwe==CMD   and shell_escape(win):     note "escaping nearby — verify coverage"
    if r.cwe==ARGV  and dashdash(near):        note "uses '--' separator"
    if r.cwe==SQL   and allowlist(win):        note "identifier allowlist/quoting — verify coverage"
    if r.cwe==SQL   and is_bind_get(line) and no_sql_context(win): note "non-SQL .get()/.all()/.run() — likely FP"
    return notes


is_priority(r):                                    # ---- GATE 6: the priority queue ----
    if r.auto_notes:                 return False  # demoted (still in findings.csv)
    return r.tier == "taint"
        or (r.tier == "helper" and r.reach_hint.startswith({"inside tool file","called from tool file"}))
    # NOTE: priority is a TRIAGE INPUT, not a bug count.


triage(r):                                         # ---- GATE 7: the finding criterion (human) ----
    if not sink_value_comes_from_tool_arg(r):      return FALSE_POSITIVE   # follow reach_hint by hand
    if sink is .execute/.command/.get/local-exec on a non-dangerous obj
       or parameterized_sql or fixed_host_url or dead/example/test code:  return FALSE_POSITIVE
    claim = confinement_claimed(r)                 # sandbox / read-only / allowlist / workspace-root / "no state change"
    if claim is None:                              return BY_DESIGN        # declared executor (python/Bash/CodeAct/text-to-SQL)
    if enforcement_of(claim) is correct:           return ALREADY_CONFINED # verify the "containment nearby" note by hand
    if llm_arg_can_escape(claim):                  return FINDING          # ← the bug: a claimed boundary a tool arg breaks
    return ALREADY_CONFINED

# FINDING also requires: no (bypassable-only) validation between source and sink;
#   a stated threat model (stdio→prompt-injection of the agent; HTTP/SSE no-auth→direct); dedup first.
```

---

## Part 1 — The pipeline, step by step (with the gate at each step)

```
 target selection → clone → semgrep (3 tiers) → reach walk → context demotion
   → PRIORITY QUEUE → manual triage → dedup → sandboxed PoC → CVSS → disclosure
```

### 1. Target selection (the funnel)
**In plain English:** We start with a list of widely used AI software projects and cross off anything
we can't meaningfully test: projects that no longer exist, are written in programming languages our
tool can't read, or are only tutorials or lists of links. What remains is software that lets an AI
take real actions, which is where the risk lies.

Pick the population, then keep only real, analyzable targets.

- **Exp 1 (MCP servers):** top-200 npm packages by weekly downloads.
- **Exp 2 (agent frameworks):** 100 frameworks curated from GitHub topic searches
  (`agent-framework`, `ai-agents`, `agentic-ai`, `llm-agents`, `multi-agent-*`) + known seeds,
  ordered by stars as a usage proxy (`frameworks-top100.txt`), scanned bottom-up (least-used first)
  in 10 batches of 10.

**Gates (a repo is dropped unless all hold):**
- repo is reachable (not 404 / private / deleted);
- it actually *builds an agent/tool surface* (registers tools / ships tool definitions), not just a
  client or a config package;
- it is in a language the rules read: **JS/TS or Python** (Go/Rust/C#/Java are out of scope);
- it is not an awesome-list / tutorial / prompt dump / end-user app masquerading as a library.

### 2. Clone
**In plain English:** We download a copy of each project's latest code to our own machine, so our
analysis never touches anyone's live system. If a project is too enormous to scan in a reasonable
time, we skip it or look only at its relevant parts, so that it doesn't hold up the rest.

Shallow (`git clone --depth 1 --no-tags`), atomic (clone to `*.partial`, rename on success so an
interrupted clone never looks finished), 5-min timeout, `GIT_TERMINAL_PROMPT=0` (never hang on auth).

**Scale gate (a monorepo guard, added in exp 2):** this is a manual decision; no code checks file
count. Before scanning, measure source-file count. A repo in the ~20k-file range (e.g. `BuilderIO/agent-native`) is an un-scannable product monorepo;
it is **skipped** (or scoped to its framework packages) rather than stalling a batch. `mastra`
(~8k effective) was deferred and run alone.

### 3. Semgrep — three source tiers
**In plain English:** 

An automated tool reads the code and flags places where information from an AI
could reach something dangerous, such as running a command, opening a file or querying a database.

It can search narrowly (more reliable) or broadly (catches more, but with more false alarms), and it
repeats the scan because a single pass can miss things. Everything it flags is only a lead to check,
not a confirmed problem.

The tool is Semgrep, a free, open-source code scanner. It works like a search that understands how
code is structured and can follow a piece of information as it moves through a program. It suits this
work for several reasons:

- It reads code without installing or running it, which is safer and practical across about 100
  unfamiliar projects.
- One rule format covers both programming languages we target.
- We can teach it the patterns specific to AI tools.
- It runs quickly and offline, and because it's free, others can repeat our work.

Semgrep also has limits. It loses track of information passed between separate parts of a program,
can silently give up on very complex code, and can mistake harmless code for something dangerous. The
repeat scans, later stages and final human review are there to make up for these gaps.

Semgrep OSS taint is **intraprocedural** (it can't follow a call from a handler into a helper), so
the scan layers three definitions of "where attacker input enters" and reconnects them in step 4.

| tier | taint source | catches | noise |
|---|---|---|---|
| **taint** | registered tool-handler params — MCP (`server.tool`, `@mcp.tool`, `setRequestHandler`…) **and agent-framework tool definitions** (see below) | bugs in the handler itself | low |
| **helper** | *any* function/method parameter | handler → helper → sink dispatch | medium (filtered by reach walk) |
| **audit** (`--audit`, opt-in) | *any* non-literal sink argument | custom frameworks the others miss | high |

**Agent-framework sources added for exp 2** (`tools/gen_rules.py`): Python `@tool` /
`@function_tool` / `@kernel_function` / `@agent.tool_plain`, and class tools `BaseTool._run/_arun`,
`Tool.forward`; JS/TS LangChain.js `tool(fn, {schema})` + `DynamicTool`/`DynamicStructuredTool`
(Vercel AI / Mastra / genkit object-tools were already matched by the MCP factory patterns).
Validated by `make test` (21/21 fixtures incl. 8 new agent-framework fixtures) and `make recall`
(all 4 published MCP CVEs still re-found).

**Sinks (the bug classes), per language:** 
CWE-78 command injection, 
CWE-88 argument injection,
CWE-22 path traversal, 
CWE-918 SSRF, 
CWE-94 code injection / unsafe deserialization, 
CWE-89 SQL.

**Gates / robustness inside this step:**
- **Per-file taint timeout** `--timeout 120 --timeout-threshold 0`. Semgrep's taint fixpoint has a
  per-function budget with *no CLI knob*; an over-budget function silently drops *all* its taint
  findings (notice only under `--debug`). Mitigations: run **2–3× and union** (beats the
  near-budget nondeterminism — quantified by `unstable_results`), and **chunk re-scan** each tool
  registration / `switch` case as its own small file so each handler fits one budget
  (`chunk_only_findings`). A `.ts` **shadow tree** lets `.mts/.cts` be analyzed.
- **Non-reviewable-file guard** (`minified_files()`): a file is excluded from semgrep when it is
  minified/bundled (avg line > 2 KB), **> 400 KB**, or big-and-generated (> 150 KB and > 4 000
  lines). This is the gate that stops a 32k-line generated `*.bridge.ts` from burning the taint
  budget for minutes and yielding nothing. Path/name excludes also drop `dist/`, `build/`,
  `node_modules/`, tests, examples, docs, vendored `repos/`, and `.generated`/`*.bridge.ts`.
  **Safety of the gate:** a big *hand-written* handler excluded here is still covered — its tool
  registrations are recovered by the chunk re-scan (step 3's chunking), which reads each
  registration as a small file.
- semgrep uses **all cores** (`--jobs nproc`).

### 4. Reach walk (reconnect helper-tier findings to tool code)
**In plain English:** Dangerous-looking code only matters if an AI can actually reach it. So we trace
backwards, asking "what uses this code, and what uses that?", for up to five steps to see whether the
trail leads to the part of the software an AI controls. The trace matches on names and can be wrong,
so its result is a hint for a person to follow, not proof.

A name-based reverse call walk: from the function holding a sink, find call sites of that name,
take *their* enclosing function, repeat until a **tool file** is reached.

**Gates:**
- **≤ 5 hops** total (`MAX_HOPS`); a chain **> 4 hops** (`PRIORITY_HOPS`) is reported but *not*
  prioritized ("distant path").
- **generic names** (`run`, `get`, `request`, `execute`, `handle`, …) are only followed through
  `this.`/`self.` calls, never bare or `obj.name(` — this is what stops `path.join`/`arr.map` from
  linking everything to everything.
- a **tool file** is one matching `TOOLFILE_RE` (MCP handler shapes *and* the agent-framework tool
  shapes added in exp 2). The result is a `reach_hint`: `inside tool handler` (taint),
  `inside tool file`, `called from tool file: a -> b -> sink`, `distant path (N hops)`, or
  `no path to tool code found`.

*Limitation (stated honestly):* the walk is name-based, not a real call graph — same-named
functions create false links; dynamic dispatch (`handlers[name](args)`) breaks real ones. So a
`reach_hint` is a **lead to follow by hand**, not proof of reachability.

### 5. Context demotion (`auto_notes`) — cheap "probably-mitigated" signals
**In plain English:** Some flagged code appears to have a safety measure right beside it. We attach a
note and move those leads down the list, but keep them on file, because a safety check that looks
fine can still be broken. One of our confirmed findings (nexent) was hiding behind exactly that kind
of faulty check.

Before ranking, each finding gets notes from a ±30-line window; a note **demotes it out of the
priority queue** (but the row is kept in `findings.csv` — demoted ≠ discarded).

**The six gates (`auto_notes`):**
- **SSRF** — the URL host looks *fixed* (`https://api.x/...`, only the path is templated) → "path-only?"
- **path-traversal** — a containment check (`resolve`/`realpath`/`relative_to`/`commonpath`/
  `startswith(root…)`) is nearby → "verify it is correct".
- **command-injection** — shell escaping (`shlex.quote`/`shellQuote`) nearby → "verify coverage".
- **argument-injection** — a `--` separator is used → noted.
- **SQL** — an identifier allowlist/quoting is nearby → "verify it covers every interpolation".
- **SQL false-positive** — the sink is a bind-method `.get()/.all()/.run()` with **no SQL context**
  in the window (an HTTP client `client.get('/path')`, `Map.get`, IndexedDB) → "likely not SQL".

These are *demotions to review*, not dismissals — the triager still verifies each is correct
(e.g. a "containment nearby" note is exactly where nexent's broken check hid).

### 6. The priority queue (`is_priority`)
**In plain English:** The most promising leads go onto a shortlist for human review: those clearly
connected to what an AI controls, with no sign of a safety measure. Being on the shortlist means
"worth a person's time", not "this is a bug", and most entries turn out to be harmless.

A finding is **priority** iff: it is **taint-tier**, *or* it is **helper-tier with a `reach_hint`
that starts `inside tool file` / `called from tool file`** — **and** it has **no `auto_notes`
demotion**. Everything else stays in `findings.csv` but off the queue.

> Priority rank is a **triage input, not a confirmed-bug count.** A 700-row repo and a 0-row repo
> get the same verdict process; most priority rows resolve to by-design or FP (see §7).

### 7. Manual triage — the only step that declares a vulnerability
**In plain English:** A person examines each lead and makes the call; nothing automated can declare a
vulnerability. The key test is whether the software promises a limit, such as "read-only" or "only
this folder", that an AI can get past. A tool openly built to run code is like a knife being sharp:
that's its purpose, not a defect. A lock that opens with a push is a defect.

For each priority candidate, the triager answers the **triage checklist**, but the decision turns
on one question — the **finding criterion**:

> **A tool doing what it is documented to do is not a bug — *unless* it claims a confinement
> (sandbox / read-only / allowlist / workspace root / "no state change") that an
> LLM-controllable tool argument can escape. That escape is the finding.**

So every candidate resolves into exactly one bucket:
- **Finding** — a *claimed* confinement is bypassed by a tool argument (reachable via direct call
  or **indirect prompt injection** of the agent).
- **By-design / declared executor** — the tool openly runs code/commands/SQL/files and claims no
  boundary (a `python` tool, a `Bash` tool, a CodeAct runner, a text-to-SQL engine). Not a bug.
- **Already-confined** — a confinement is claimed *and correctly enforced* (verify the `auto_notes`
  "containment nearby" by hand).
- **FP** — the sink is a name collision (`.execute`/`.command`/`.get`/`exec` on a non-dangerous
  object), parameterized SQL/ORM, a fixed-host URL, or dead/example/test code.

**The rest of the checklist (must also hold for a finding):**
1. the sink value really comes from a tool argument (follow `reach_hint` by hand — it can be a
   false link);
2. no validation between source and sink (and if there is, it is *bypassable*);
3. threat model stated — stdio-local servers matter via prompt injection of the agent; HTTP/SSE
   without auth is directly reachable;
4. **dedup first** (step 8) before building a PoC.

### 8. Dedup (before any PoC or disclosure)
**In plain English:** Before going further, we check whether someone has already reported or fixed
the problem by searching the project's public security notices, bug reports and change history. We
read the reports themselves, because a title can make two different problems look like the same one.

Check the repo *and its parent/upstream* for a prior report: GitHub Security Advisories (GHSA),
issues, PRs, and CHANGELOG — searching the specific vector, not just the file. Most real bugs in
popular projects are already public or fixed. **Read the actual issue/PR bodies**, not just titles
(hive looked like a dup from titles; reading them showed the known issues were a *different* vector).

### 9. Sandboxed PoC
**In plain English:** We prove the problem is real by safely triggering it. We do this only on our
own copy, inside a sealed-off environment with no internet access or real data, and the "attack" does
something harmless, such as creating a test file. This confirms the problem without putting anyone at
risk.

On **our own clone only**, never a deployed instance. Benign payload (a canary file, no real
secrets), inside bubblewrap (`tools/sandbox.sh`: network off, `$HOME` an empty tmpfs, `/`
read-only, env cleared). Where feasible the PoC runs the **real target code** (import the actual
module, stub only its heavy third-party imports, sha256-pin the file); otherwise it reproduces the
exact sink lines verbatim with a citation. The scanner never installs or runs target code — only
PoCs do, in the sandbox.

### 10. CVSS & coordinated disclosure
**In plain English:** We rate how serious the problem is on the industry-standard severity scale,
noting anything that could raise or lower the score. We then tell the project's maintainers
privately, usually allowing about 90 days for a fix, and publish only after the fix is out, so that
attackers can't use our findings in the meantime.

CVSS 3.1 base vector + honest sensitivity notes (config gates, `UI:N` vs `UI:R`, scope). Disclosure
is coordinated: private report, ~90 days, publish after a fix. **The repo stays private while
`research/findings/` holds unreported or embargoed candidates.**

---

## Part 2 — What each PoC was looking for, and what it found

Experiment 2 scanned 99 of 100 frameworks (agent-native skipped; mastra run separately). **3
confirmed net-new findings**, each with a sandboxed PoC, CVSS, and PDF under
`research/findings/exp2-frameworks/batch-NN/`. All 3 were validated on 2026-11-03 and submitted to
their maintainers on 2026-11-04; each is a pending CVE, not an assigned one.

### PoC 1 — youtu-agent (TencentCloudADP/youtu-agent) — batch 3
- **Hunting for:** CWE-94 code injection — an LLM-controllable value reaching `eval`/`exec`.
- **Where it came from:** the agent-framework taint sources (the ReAct model-output parser).
- **Found:** `ReactConverter._parse_react_output()` parses the model's `Action:` text with
  `json.loads`, and on failure falls back to **`eval(text_output)`** — *before* the
  `name`/`arguments` validation. The ReAct format emits single-quoted Python dicts (invalid JSON),
  so `eval` is the routine path. A prompt-injected action
  (`__import__('os').system(...) or {...}`) runs arbitrary Python in the agent host. Live via
  `runner: "react"` (`agent_config.py`). **PoC:** executed the *real* `react_converter.py`
  (sha256-pinned) under bwrap → canary created, parser returned normally (silent RCE).
- **Verdict:** **RCE, CVSS 3.1 = 8.8 High** (→9.8 if autonomous; gated on the `react` runner).
  Deduped non-public. Fix: `ast.literal_eval`, not `eval`.

### PoC 2 — nexent (ModelEngine-Group/nexent) — batch 4
- **Hunting for:** CWE-22 path traversal / workspace-sandbox bypass — a tool path argument escaping
  a *claimed* confinement (the `auto_notes` "containment nearby" gate pointed here).
- **Found:** 7 file tools (`create/read/delete file+dir`, `move`) share a `_validate_path()` whose
  guard is `abs_path.startswith(self.init_path)` — **no trailing separator** (`init_path` defaults
  to `/mnt/nexent`). A model path like `/mnt/nexent-secrets/x` shares the string prefix → passes,
  escaping the workspace (incl. `shutil.rmtree`). **PoC:** reproduced `_validate_path` verbatim
  (real file sha256-pinned) under bwrap → `../../../etc/shadow` correctly **blocked** (normpath),
  but `/work/mnt/nexent-secrets/…` **accepted and written** outside the workspace.
- **Verdict:** **workspace-confinement bypass, CVSS 3.1 = 5.0 Medium** (bounded to prefix-siblings;
  not full-FS unless a workspace symlink exists). Deduped non-public. Fix: `commonpath` /
  `is_relative_to` / `startswith(root + os.sep)` — exactly what genkit does correctly in the same
  batch.

### PoC 3 — hive (aden-hive/hive) — batch 6
- **Hunting for:** CWE-22/732 — a *claimed* read-only + path-sandboxed SQL tool whose confinement
  can be escaped (exp 1's "read-only SQL that can be bypassed" criterion).
- **Found:** `csv_sql` confines the CSV *path* to `~/.hive` (correct `resolve_safe_path`) and gates
  the query "SELECT-only for security reasons", but runs it on `duckdb.connect(":memory:")` with
  **no `enable_external_access=false`**. DuckDB's file-reading functions are not blocked, so an
  allowed `SELECT content FROM read_text('/home/user/.ssh/id_rsa')` reads **any** file — bypassing
  the path sandbox. **PoC:** installed duckdb, reproduced the exact guard, ran under the sandbox →
  the malicious SELECT passed the guard and returned a file outside `~/.hive`.
- **Verdict:** **arbitrary file read (read-only), CVSS 3.1 = 6.5 Medium** (→7.5 if autonomous).
  Dedup: the ~8 known csv_sql issues are all the *path-interpolation* vector (fixed by parameter
  binding); this **query-body file-read** vector appears distinct and unreported. Fix:
  `SET enable_external_access=false` (same root cause in `excel_sql`).

### Near-misses (recorded, not escalated)
- **FrontierAgent** (batch 2) — `write_file` `/tmp/agent-outputs` `startswith` traversal is real in
  code and PoC-confirmed, **but** the reachable sibling (sandbox/native) branch is already fixed
  (PR #59) and the surviving branch is only hit in a non-CLI no-sandbox config. Edge residual of an
  already-public fix.
- **agency-swarm** (batch 3) & **cognee** (batch 9) — `exec()` of datamodel-code-generator output
  from a schema; only reachable if the *schema* is attacker-controlled (developer-supplied in
  practice). Low-reach secondary.

### What the clean 90+ repos tell us
The same lesson as experiment 1: **the most-used, actively-maintained frameworks are already
well-hardened.** The net-new bugs were in *less-scrutinized* projects and were **logic/
classification gaps** (an `eval` fallback, a missing path separator, a missing DuckDB flag), not
patterns a signature would flag. Notably, of every framework shipping a file-path sandbox, **only
nexent implemented it incorrectly** (`startswith` without a separator); crewAI (`commonpath`),
openai-agents-python (`.parents`), ag2 / Upsonic (`relative_to`), genkit (`rootDir + sep`), hive
`resolve_safe_path` (`root + os.sep`), and open-multi-agent (symlink re-check) all got it right.
Most other priority rows were **declared executors** (CodeAct runners, `python`/`Bash`/code-mode
tools, text-to-SQL), **parameterized SQL/ORM**, **fixed-host API wrappers**, or **name-collision
FPs** (`.execute`/`.command`/`.get`/a local `exec` variable).
