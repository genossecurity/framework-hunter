# Exp 3 — CodeQL agent-framework hunt

Re-run your **Exp 2 corpus** (agent frameworks) with **CodeQL** instead of
Semgrep, and measure the **delta** — bugs CodeQL finds that your Semgrep pipeline
missed. CodeQL is natively interprocedural, so it catches the handler→helper→sink
chains your mcp-hunt needed hacks for and the ones it dropped on fixpoint
timeouts. The delta *is* the Exp-3 result: it quantifies that blind spot.

Runs on **your** machine (needs `codeql` + `git`). Driver + diff are stdlib
Python, no deps.

## 0. Install CodeQL (once)
```bash
# CLI (pick the latest release asset for your OS):
#   https://github.com/github/codeql-cli-binaries/releases
# unzip, put `codeql` on PATH, then confirm:
codeql --version
# Standard query libraries (so the built-in suite + your pack resolve):
git clone --depth 1 https://github.com/github/codeql ~/codeql-repo
export CODEQL_REPO=~/codeql-repo         # some setups: codeql pack install in ql/python
```

## 1. Build the repo list
`repos.txt`, one `owner/repo` per line — **your Exp 2 agent-framework repos**
(the same corpus mcp-hunt scanned, so the diff is apples-to-apples). `#` comments ok.
```
stevehuang0115/crewly
TencentCloudADP/youtu-agent
ModelEngine-Group/nexent
aden-hive/hive
# ...the rest of your Exp 2 list
```

## 2. Dry-run (verify the loop, no codeql)
```bash
python3 run_codeql_hunt.py --repos repos.txt --dry-run
```

## 3. Run for real
```bash
python3 run_codeql_hunt.py --repos repos.txt --work work --ql ql --batch-size 20
#   --resume     skip repos already in work/done.jsonl (safe to re-run after a stop)
#   --keep-db    keep CodeQL DBs (default: deleted per repo to save disk)
```
Per repo the terminal shows each stage and a rolling ETA; a **heartbeat** prints
every 15 s during DB build so it never looks hung:
```
[12/141] crewai/crewai
    [db:python] 45s elapsed...
    clone 2s | db:python 1m18s | analyze:python 34s
    OK · 3 findings · repo 1m54s | done 12/141 (9%) · avg 1m22s · elapsed 16m · ETA ~2h58m (129 left)
--- batch 1 done (20/141) · avg 1m20s · ETA ~2h41m for 121 remaining ---
```

## 4. The delta (Exp-3 result)
```bash
python3 diff_semgrep.py --sarif work/sarif --semgrep ~/mcp-hunt-work/scan/findings.csv
```
Prints overlap vs **CodeQL-only** (what Semgrep missed) + a miss-rate, and writes
`delta.csv`. That miss-rate is the number worth reporting — and each CodeQL-only
row is a candidate bug to triage (dedup vs issues/PRs/advisories before filing).

## What runs, and the honest caveats
- **Two query layers per repo:** (1) CodeQL's built-in `*-security-extended`
  suite — works out of the box, catches conventionally-sourced flows; (2) your
  **custom agent-tool-source pack** in `ql/python/` — the differentiator that
  treats tool-handler parameters as sources (the built-in suite does NOT).
- **The custom QL is a STARTER.** Validate before trusting it:
  `codeql query compile ql/python` — the dataflow API drifts between CodeQL
  versions, so expect to fix a predicate or two. Extend `isAgentToolHandler` in
  `AgentSources.qll` with each framework's registration pattern (crewly's
  registry, LangChain `Tool`, CrewAI decorators). Path/SSRF sinks: clone
  `agent_codeexec.ql` per the note at its bottom.
- **ETA realism:** CodeQL is heavier than Semgrep — DB build dominates and
  varies a lot by repo size (seconds to several minutes). The ETA is a rolling
  average, so it's rough for the first few repos then settles. Raise
  `--batch-size` only changes how often the summary prints, not speed.
- **Resumable:** stop anytime; `--resume` continues from `work/done.jsonl`.
- **Honest scope:** this is Exp-3 as a *measurement* (CodeQL vs Semgrep delta on
  your own corpus) plus a bug-finding pass. It's the same Tier-1 output lane —
  valuable as a controlled before/after on your pipeline, not a climb.
