#!/usr/bin/env python3
"""Scan one batch of the tool-only funnel and write a triage report for it.

    python3 tools/batch.py 2                       # repos 11-20 of the funnel
    python3 tools/batch.py 2 --size 10 --fresh     # ignore checkpoints

The report (<work>/batches/batch-NN/report.md) has one section per repo: attack surface,
scan health, priority queue with sinks, and prior public security reports. It is an input
to manual triage, not a verdict. Record verdicts in findings/batch-NN/verdicts.md, next to
any per-repo notes and PoCs.
"""
import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hunt import ensure_semgrep, github_repo, prior_reports, short_rule, surface  # noqa: E402
from scan import is_priority, parse_targets, slug_for  # noqa: E402

MAX_ROWS = 30


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("batch", type=int, help="batch number, from 1")
    ap.add_argument("--size", type=int, default=10)
    ap.add_argument("--list", default=str(ROOT / "repos-top200-downloads-tools.txt"))
    ap.add_argument("--work", default=str(Path.home() / "mcp-hunt-work" / "scan"))
    ap.add_argument("--fresh", action="store_true", help="re-run Semgrep instead of reusing checkpoints")
    ap.add_argument("--no-github", action="store_true", help="skip the prior-reports lookup")
    args = ap.parse_args()

    ensure_semgrep()
    targets = parse_targets(Path(args.list))
    chosen = targets[(args.batch - 1) * args.size:args.batch * args.size]
    if not chosen:
        sys.exit(f"batch {args.batch} is empty: the funnel has {len(targets)} repos")

    work = Path(args.work)
    out_dir = work / "batches" / f"batch-{args.batch:02d}"
    out_dir.mkdir(parents=True, exist_ok=True)
    list_file = out_dir / "repos.txt"
    list_file.write_text("\n".join(chosen) + "\n")
    cmd = [sys.executable, "-u", str(ROOT / "scan.py"), str(list_file), "--work", str(work), "--jobs", "8"]
    if not args.fresh:
        cmd.append("--resume")
    if subprocess.run(cmd).returncode != 0:
        return 1

    start = (args.batch - 1) * args.size + 1
    L = [f"# Batch {args.batch}: funnel repos {start}-{start + len(chosen) - 1} of {len(targets)}", ""]
    for n, target in enumerate(chosen):
        slug = slug_for(target)
        checkpoint = work / "results" / f"{slug}.json"
        L.append(f"## {start + n}. {target}\n")
        if not checkpoint.exists():
            L += ["**Scan failed: no results. Not clean.** See the scan log.", ""]
            continue
        cp = json.loads(checkpoint.read_text())
        stat, rows = cp["stat"], cp["rows"]
        surf = surface(work / "src" / slug)
        L.append(f"- `{stat.get('commit')}` `{stat.get('package_version') or '?'}`, {stat.get('files_scanned')} files; "
                 f"{len(surf['tool_names'])} tool names / {surf['tool_sites']} sites; "
                 f"transports: {', '.join(surf['transports'])}; SECURITY.md: {'yes' if surf['security_md'] else 'no'}")
        errs = [e for e in (stat.get("errors") or "").split("; ") if e]
        L.append(f"- health: unstable={stat.get('unstable_results', 0)}, chunk-only={stat.get('chunk_only_findings', 0)}"
                 + (f", {'; '.join(errs)[:220]}" if errs else ""))
        prio = sorted((r for r in rows if is_priority(r)),
                      key=lambda r: (r["tier"] != "taint", r["severity"] != "ERROR", r["file"], r["line"]))
        L.append(f"- findings: {len(rows)} total, **{len(prio)} priority**; "
                 + ", ".join(f"{k}={v}" for k, v in Counter(short_rule(r["rule"]) for r in prio).most_common()))
        L.append("")
        for r in prio[:MAX_ROWS]:
            who = r["tool_name"] or (r["function"] + "()" if r["function"] else "?")
            via = "" if r["reach_hint"] in ("inside tool handler", "inside tool file") else f" [{r['reach_hint'][:80]}]"
            L.append(f"  - {r['tier'][0]}/{r['severity'][:4]} {short_rule(r['rule'])} `{r['file']}:{r['line']}` "
                     f"{who}{via}: `{r['sink_code'][:100]}`")
        if len(prio) > MAX_ROWS:
            L.append(f"  - ...{len(prio) - MAX_ROWS} more in findings.csv")
        repo = github_repo(target, None)
        if repo and not args.no_github:
            terms = sorted({r["tool_name"] for r in prio if r["tool_name"]})[:2]
            L += ["", "  prior public reports:"] + [f"  - {x}" for x in prior_reports(repo, terms)]
            time.sleep(20)   # unauthenticated GitHub search allows 10 requests a minute
        L.append("")

    report = out_dir / "report.md"
    report.write_text("\n".join(L) + "\n")
    print(f"[batch] report: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
