#!/usr/bin/env python3
"""
Exp 3 result: diff CodeQL findings against your Semgrep (Exp 2) findings.

The delta — findings CodeQL reports that your Semgrep pipeline MISSED — is the
measurement: it quantifies your intraprocedural / fixpoint-timeout blind spot.

  python3 diff_semgrep.py --sarif work/sarif --semgrep ~/mcp-hunt-work/scan/findings.csv

--semgrep is OPTIONAL. Omit it (or point at a missing/empty file) when the
Semgrep baseline for this corpus was 0 — e.g. the MCP corpus, where Exp 1 found
nothing. With no baseline, every CodeQL finding is delta by definition, which is
exactly the measurement: did CodeQL see what Semgrep's intraprocedural pass could
not?

Semgrep CSV is read tolerantly: it looks for columns named (case-insensitive)
repo, file (or path), line (or a "file:line"/permalink field). Override with
--col-repo / --col-file / --col-line if your headers differ. Stdlib only.
"""
import argparse, csv, json, re
from pathlib import Path
from collections import defaultdict

def unslug(name):  # work/sarif/<owner>__<repo>.<lang>.sarif -> owner/repo
    base = re.sub(r"\.(python|javascript)\.sarif$", "", name)
    return base.replace("__", "/")

def norm_repo(s):
    s = (s or "").strip().lower()
    m = re.search(r"github\.com[:/]+([^/\s]+/[^/\s#]+)", s)
    if m: s = m.group(1)
    return s.removesuffix(".git").strip("/")

def load_codeql(sarif_dir):
    rows = []
    for f in Path(sarif_dir).glob("*.sarif"):
        repo = norm_repo(unslug(f.name))
        try: d = json.loads(f.read_text())
        except Exception: continue
        for run in d.get("runs", []):
            for r in run.get("results", []):
                rule = r.get("ruleId", "")
                for loc in r.get("locations", []) or [{}]:
                    pl = loc.get("physicalLocation", {})
                    uri = pl.get("artifactLocation", {}).get("uri", "")
                    line = pl.get("region", {}).get("startLine", 0)
                    rows.append(dict(repo=repo, file=Path(uri).name, path=uri,
                                     line=int(line or 0), rule=rule))
    return rows

def pick(headers, *names, override=None):
    if override: return override
    low = {h.lower(): h for h in headers}
    for n in names:
        if n in low: return low[n]
    return None

def load_semgrep(csv_path, a):
    rows = []
    if not csv_path or not Path(csv_path).exists():
        return rows  # no baseline (e.g. MCP corpus, Semgrep=0) -> all CodeQL hits are delta
    with open(csv_path, newline="") as fh:
        rd = csv.DictReader(fh)
        hs = rd.fieldnames or []
        c_repo = pick(hs, "repo", "repository", override=a.col_repo)
        c_file = pick(hs, "file", "path", "filename", override=a.col_file)
        c_line = pick(hs, "line", "start_line", "startline", override=a.col_line)
        c_fl   = pick(hs, "file:line", "location", "permalink", "link")
        for r in rd:
            repo = norm_repo(r.get(c_repo, "")) if c_repo else ""
            fname, line = "", 0
            if c_file and r.get(c_file):
                fname = Path(r[c_file]).name
                if c_line and r.get(c_line):
                    try: line = int(re.sub(r"\D", "", r[c_line]) or 0)
                    except Exception: line = 0
            elif c_fl and r.get(c_fl):  # parse "path/file.py:123" or a permalink #L123
                s = r[c_fl]
                m = re.search(r"([^/:#]+\.\w+)[:#L]+(\d+)", s)
                if m: fname, line = m.group(1), int(m.group(2))
                else: fname = Path(s.split(":")[0]).name
            rows.append(dict(repo=repo, file=fname, line=line))
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--semgrep", help="Semgrep findings CSV (Exp 2 baseline); omit if baseline is 0, e.g. MCP corpus")
    ap.add_argument("--tol", type=int, default=3, help="line match tolerance")
    ap.add_argument("--out", default="delta.csv")
    ap.add_argument("--col-repo"); ap.add_argument("--col-file"); ap.add_argument("--col-line")
    a = ap.parse_args()

    cq = load_codeql(a.sarif)
    sg = load_semgrep(a.semgrep, a)
    sg_idx = defaultdict(list)
    for s in sg: sg_idx[(s["repo"], s["file"])].append(s["line"])

    def in_semgrep(c):
        for ln in sg_idx.get((c["repo"], c["file"]), []):
            if ln == 0 or abs(ln - c["line"]) <= a.tol: return True
        return False

    delta = [c for c in cq if not in_semgrep(c)]       # CodeQL found, Semgrep missed
    overlap = len(cq) - len(delta)

    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["repo","file","line","rule","codeql_only"])
        for c in sorted(delta, key=lambda x:(x["repo"], x["file"], x["line"])):
            w.writerow([c["repo"], c["file"], c["line"], c["rule"], "yes"])

    nrepos = len({c["repo"] for c in cq})
    baseline = "none provided → treating Semgrep baseline as 0" if not a.semgrep else "Exp 2"
    print(f"CodeQL findings : {len(cq)}  across {nrepos} repos")
    print(f"Semgrep findings: {len(sg)} ({baseline})")
    print(f"overlap         : {overlap}")
    print(f"CodeQL-ONLY     : {len(delta)}   <-- the delta: what your Semgrep missed")
    if cq:
        print(f"miss rate       : {100*len(delta)/len(cq):.1f}% of CodeQL hits were invisible to Semgrep")
    byrule = defaultdict(int)
    for c in delta: byrule[c["rule"]] += 1
    if byrule:
        print("delta by rule:")
        for r,n in sorted(byrule.items(), key=lambda x:-x[1]): print(f"  {n:3d}  {r}")
    print(f"\nwrote {a.out} — triage these (dedup vs issues/PRs/advisories before filing).")

if __name__ == "__main__":
    main()
