#!/usr/bin/env python3
"""
Exp 3 result: diff CodeQL findings against your Semgrep (Exp 2) findings.

The delta — findings CodeQL reports that your Semgrep pipeline MISSED — is the
measurement: it quantifies your intraprocedural / fixpoint-timeout blind spot.

  python3 diff_semgrep.py --sarif work/sarif --semgrep ~/mcp-hunt-work/scan/findings.csv

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
    # mcp-hunt CSVs store repos as owner__repo; SARIF names unslug to owner/repo
    return s.removesuffix(".git").strip("/").replace("__", "/")

def cwe_of(s):
    """Extract a normalized CWE number ('cwe-078'/'CWE-78'/'external/cwe/cwe-022') -> '22'."""
    m = re.search(r"cwe[-_/]?0*(\d+)", (s or ""), re.I)
    return m.group(1) if m else ""

def norm_path(p):
    """Relative path, lowercased, leading slash stripped, backslashes normalized."""
    return (p or "").replace("\\", "/").lstrip("/").lower()

def load_codeql(sarif_dir):
    rows = []
    for f in Path(sarif_dir).glob("*.sarif"):
        repo = norm_repo(unslug(f.name))
        try: d = json.loads(f.read_text())
        except Exception: continue
        for run in d.get("runs", []):
            # rule_id -> cwe, from the tool driver + extensions rule metadata
            rule_cwe = {}
            for comp in [run.get("tool", {}).get("driver", {})] + run.get("tool", {}).get("extensions", []):
                for ru in comp.get("rules", []) or []:
                    tags = " ".join(ru.get("properties", {}).get("tags", []) or [])
                    rule_cwe[ru.get("id", "")] = cwe_of(tags) or cwe_of(ru.get("id", ""))
            for r in run.get("results", []):
                rule = r.get("ruleId", "")
                cwe = rule_cwe.get(rule, "") or cwe_of(rule)
                for loc in r.get("locations", []) or [{}]:
                    pl = loc.get("physicalLocation", {})
                    uri = pl.get("artifactLocation", {}).get("uri", "")
                    line = pl.get("region", {}).get("startLine", 0)
                    rows.append(dict(repo=repo, file=Path(uri).name, path=norm_path(uri),
                                     line=int(line or 0), rule=rule, cwe=cwe))
    return rows

def pick(headers, *names, override=None):
    if override: return override
    low = {h.lower(): h for h in headers}
    for n in names:
        if n in low: return low[n]
    return None

def load_semgrep(csv_path, a):
    rows = []
    with open(csv_path, newline="") as fh:
        rd = csv.DictReader(fh)
        hs = rd.fieldnames or []
        c_repo = pick(hs, "repo", "repository", override=a.col_repo)
        c_file = pick(hs, "file", "path", "filename", override=a.col_file)
        c_line = pick(hs, "line", "start_line", "startline", override=a.col_line)
        c_cwe  = pick(hs, "cwe", "cwe_id")
        c_fl   = pick(hs, "file:line", "location", "permalink", "link")
        for r in rd:
            repo = norm_repo(r.get(c_repo, "")) if c_repo else ""
            fname, path, line = "", "", 0
            if c_file and r.get(c_file):
                fname = Path(r[c_file]).name; path = norm_path(r[c_file])
                if c_line and r.get(c_line):
                    try: line = int(re.sub(r"\D", "", r[c_line]) or 0)
                    except Exception: line = 0
            elif c_fl and r.get(c_fl):  # parse "path/file.py:123" or a permalink #L123
                s = r[c_fl]
                m = re.search(r"([^\s:#]+\.\w+)[:#L]+(\d+)", s)
                if m: fname, path, line = Path(m.group(1)).name, norm_path(m.group(1)), int(m.group(2))
                else: fname = Path(s.split(":")[0]).name; path = norm_path(s.split(":")[0])
            rows.append(dict(repo=repo, file=fname, path=path, line=line,
                             cwe=cwe_of(r.get(c_cwe, "")) if c_cwe else ""))
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--tol", type=int, default=3, help="line match tolerance")
    ap.add_argument("--out", default="delta.csv")
    ap.add_argument("--col-repo"); ap.add_argument("--col-file"); ap.add_argument("--col-line")
    ap.add_argument("--fp-ledger", help="CSV repo,file,line,rule,verdict,reason of triaged "
                    "non-bugs (fp/by-design/trusted-input/known-public); subtracted from the delta. "
                    "line=* matches any line in that repo+file.")
    ap.add_argument("--match", choices=["basename", "path", "path-cwe"], default="path-cwe",
                    help="overlap key: basename (run-1 loose), path (full relative path), "
                    "path-cwe (full path AND same CWE class; strictest, default)")
    ap.add_argument("--skip-noise", action="store_true",
                    help="drop low-value rules (log-injection, stack-trace, clear-text-logging, "
                    "insecure-randomness, redos, file-system-race, temp-file, ...) before diffing")
    ap.add_argument("--keep-rule", action="append", default=[],
                    help="regex of rules to KEEP (repeatable); overrides --skip-noise for matches")
    a = ap.parse_args()

    NOISE = re.compile(r"(log-injection|stack-trace|clear-text-logging|clear-text-storage|"
                       r"insecure-randomness|biased-cryptographic|polynomial-redos|\bredos\b|"
                       r"file-system-race|insecure-temporary-file|missing-regexp-anchor|"
                       r"incomplete-hostname-regexp|incomplete-url-substring|bad-tag-filter|"
                       r"weak-sensitive-data-hashing|weak-cryptographic|bind-socket|"
                       r"request-without-cert|overly-permissive-file|overly-large-range|"
                       r"missing-origin-check|http-response-splitting|jinja2/autoescape|"
                       r"identity-replacement|empty-password|insufficient-password|"
                       r"cors-misconfiguration|file-access-to-http|http-to-file-access|"
                       r"functionality-from-untrusted|unvalidated-dynamic-method)", re.I)
    keep = [re.compile(k, re.I) for k in a.keep_rule]
    def is_noise(rule):
        if any(k.search(rule) for k in keep): return False
        return bool(NOISE.search(rule))

    # fp_ledger: {(repo,file,rule): set of lines, or {'*'} for whole-file}. repo/file normalized
    # like the CodeQL rows so a ledger entry and a SARIF hit meet on the same key.
    fp = defaultdict(set)
    if a.fp_ledger:
        with open(a.fp_ledger, newline="") as fh:
            for r in csv.DictReader((ln for ln in fh if not ln.lstrip().startswith("#"))):
                fp[(norm_repo(r["repo"]), Path(r["file"]).name, r["rule"])].add(r["line"].strip())
    def is_fp(c):
        lines = fp.get((c["repo"], c["file"], c["rule"]))
        return bool(lines) and ("*" in lines or str(c["line"]) in lines)

    cq = load_codeql(a.sarif)
    sg = load_semgrep(a.semgrep, a)
    cq_all = len(cq)
    if a.skip_noise:
        cq = [c for c in cq if not is_noise(c["rule"])]

    # overlap key per --match. key() returns the (repo, locator[, cwe]) a CodeQL hit and a
    # Semgrep hit must share; line is still compared with tolerance.
    def loc(x): return x["file"] if a.match == "basename" else x["path"]
    def key(x):
        k = (x["repo"], loc(x))
        return k + (x.get("cwe", ""),) if a.match == "path-cwe" else k
    sg_idx = defaultdict(list)
    for s in sg: sg_idx[key(s)].append(s["line"])

    def in_semgrep(c):
        if a.match == "path-cwe" and not c.get("cwe"):  # no CWE to match on -> treat as miss
            return False
        for ln in sg_idx.get(key(c), []):
            if ln == 0 or abs(ln - c["line"]) <= a.tol: return True
        return False

    delta = [c for c in cq if not in_semgrep(c)]       # CodeQL found, Semgrep missed
    overlap = len(cq) - len(delta)
    delta_fp = [c for c in delta if is_fp(c)]           # delta already triaged as non-bug
    net = [c for c in delta if not is_fp(c)]            # the honest delta: untriaged / real

    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["repo","file","line","rule","codeql_only","known_fp"])
        for c in sorted(delta, key=lambda x:(x["repo"], x["file"], x["line"])):
            w.writerow([c["repo"], c["file"], c["line"], c["rule"], "yes", "yes" if is_fp(c) else ""])

    nrepos = len({c["repo"] for c in cq})
    print(f"match mode      : {a.match}{'  (noise rules skipped)' if a.skip_noise else ''}")
    print(f"CodeQL findings : {len(cq)}  across {nrepos} repos"
          + (f"  ({cq_all-len(cq)} noise dropped)" if a.skip_noise else ""))
    print(f"Semgrep findings: {len(sg)} (Exp 2)")
    print(f"overlap         : {overlap}")
    print(f"CodeQL-ONLY     : {len(delta)}   <-- raw delta (line-match vs Semgrep)")
    if a.fp_ledger:
        print(f"  known non-bug : {len(delta_fp)}   (subtracted via {a.fp_ledger})")
        print(f"  NET delta     : {len(net)}   <-- untriaged / candidate real misses")
    if cq:
        print(f"raw miss rate   : {100*len(delta)/len(cq):.1f}% of CodeQL hits invisible to Semgrep")
        if a.fp_ledger:
            print(f"net miss rate   : {100*len(net)/len(cq):.1f}% after subtracting triaged non-bugs")
    byrule = defaultdict(int)
    for c in (net if a.fp_ledger else delta): byrule[c["rule"]] += 1
    if byrule:
        print(f"{'net ' if a.fp_ledger else ''}delta by rule:")
        for r,n in sorted(byrule.items(), key=lambda x:-x[1]): print(f"  {n:3d}  {r}")
    print(f"\nwrote {a.out} — triage the net delta (dedup vs issues/PRs/advisories before filing).")

if __name__ == "__main__":
    main()
