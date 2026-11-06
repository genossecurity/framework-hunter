#!/usr/bin/env python3
"""
Exp 3 — CodeQL agent-framework hunt, batch driver.

Runs, per repo: shallow clone -> CodeQL DB create -> analyze (security suite +
custom agent-tool-source queries) -> collect SARIF. Resumable, with live
terminal progress: per-stage timing, a heartbeat during slow stages so it never
looks hung, a rolling ETA, and a summary per batch.

Runs on YOUR machine (needs the `codeql` CLI on PATH and `git`). Stdlib only.

  python3 run_codeql_hunt.py --repos repos.txt --work work --ql ql --batch-size 20
  python3 run_codeql_hunt.py ... --resume          # skip repos already done
  python3 run_codeql_hunt.py ... --dry-run         # simulate, no codeql/git

See README.md for setup and for extending the agent-tool source patterns.
"""
import argparse, json, os, re, shutil, subprocess, sys, threading, time
from pathlib import Path

def fmt(s):
    s = int(s)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m{s%60:02d}s"
    return f"{s//3600}h{(s%3600)//60:02d}m"

def slug(repo): return repo.strip().replace("/", "__")

STEP_RE = re.compile(r"\[(\d+)/(\d+)[ \]]")  # CodeQL "[52/54 eval ...]" progress markers

def _last_progress(path):
    """Return (k, N, text) of the latest CodeQL '[k/N ...]' step line in a log file,
    so a long analyze/build shows steps-done and steps-remaining, not just elapsed."""
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except Exception:
        return None
    for ln in reversed(lines[-80:]):
        m = STEP_RE.search(ln)
        if m:
            return int(m.group(1)), int(m.group(2)), ln.strip()[:90]
    # no step marker yet (e.g. DB build extracting) — show the last non-empty line
    for ln in reversed(lines[-40:]):
        if ln.strip():
            return None, None, ln.strip()[:90]
    return None

class Heartbeat:
    """Every `every` s while a stage runs, print elapsed AND the live CodeQL step
    progress (k/N, remaining) tailed from the stage's log, so a long run on a giant
    repo visibly advances instead of looking frozen."""
    def __init__(self, stage, logfile=None, every=15):
        self.stage, self.every, self.logfile = stage, every, logfile
        self._stop = threading.Event(); self._t0 = time.time(); self._th = None
    def __enter__(self):
        def loop():
            while not self._stop.wait(self.every):
                el = fmt(time.time() - self._t0)
                prog = _last_progress(self.logfile) if self.logfile else None
                if prog and prog[0] is not None:
                    k, N, txt = prog
                    sys.stdout.write(f"    [{self.stage}] {el} · step {k}/{N} ({N-k} left) · {txt}\n")
                elif prog:
                    sys.stdout.write(f"    [{self.stage}] {el} · {prog[2]}\n")
                else:
                    sys.stdout.write(f"    [{self.stage}] {el} elapsed...\n")
                sys.stdout.flush()
        self._th = threading.Thread(target=loop, daemon=True); self._th.start(); return self
    def __exit__(self, *a):
        self._stop.set()
        if self._th: self._th.join(timeout=1)

def run(cmd, cwd=None, stage="", heartbeat=15, dry=False, dry_secs=0.0, logdir=None, timeout=None):
    """Run a subprocess with a progress-aware heartbeat; return (rc, seconds, tail).
    On timeout returns rc=124 so a stalling stage (e.g. a wide-net analyze on a giant
    repo) is marked and skipped instead of blocking the whole batch."""
    t0 = time.time()
    if dry:
        time.sleep(dry_secs); return 0, time.time()-t0, "(dry-run)"
    logf = None
    if logdir:
        logf = str(Path(logdir) / (stage.replace(":", "_") + ".log"))
        Path(logdir).mkdir(parents=True, exist_ok=True)
    try:
        if logf:
            with open(logf, "w") as fh, Heartbeat(stage, logf, heartbeat):
                p = subprocess.run(cmd, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT,
                                   text=True, timeout=timeout)
            tail = Path(logf).read_text(errors="replace")[-400:].strip()
            return p.returncode, time.time()-t0, tail
        with Heartbeat(stage, None, heartbeat):
            p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        tail = (p.stdout[-400:] + p.stderr[-400:]).strip()
        return p.returncode, time.time()-t0, tail
    except subprocess.TimeoutExpired:
        return 124, time.time()-t0, f"TIMEOUT after {fmt(timeout)} (stage {stage})"
    except FileNotFoundError as e:
        return 127, time.time()-t0, str(e)

def detect_langs(src: Path):
    langs = set()
    for p in src.rglob("*"):
        if p.is_dir(): continue
        s = p.suffix.lower()
        if s == ".py": langs.add("python")
        elif s in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cts", ".mts"): langs.add("javascript")
        if len(langs) == 2: break
    return langs or {"python"}

def count_sarif(path: Path):
    try:
        d = json.loads(path.read_text())
        return sum(len(r.get("results", [])) for r in d.get("runs", []))
    except Exception:
        return 0

def process_repo(repo, work: Path, ql: Path, args):
    src = work / "src" / slug(repo)
    logdir = work / "proglog" / slug(repo)   # per-repo stage logs for the progress heartbeat
    timings, findings, status, note = {}, 0, "ok", ""
    # clone
    if src.exists(): shutil.rmtree(src, ignore_errors=True)
    rc, dt, tail = run(
        ["git", "clone", "--depth", "1", f"https://github.com/{repo}", str(src)],
        stage="clone", heartbeat=20, dry=args.dry_run, dry_secs=1.5, logdir=logdir)
    timings["clone"] = dt
    if rc != 0:
        return dict(repo=repo, status="clone_failed", note=tail[:200], timings=timings, findings=0)
    if args.dry_run:
        (src).mkdir(parents=True, exist_ok=True); (src / "x.py").write_text("x=1\n")
    langs = detect_langs(src)
    # per language: db create + analyze
    for lang in sorted(langs):
        db = work / "db" / f"{slug(repo)}.{lang}"
        if db.exists(): shutil.rmtree(db, ignore_errors=True)
        rc, dt, tail = run(
            ["codeql", "database", "create", str(db), f"--language={lang}",
             f"--source-root={src}", "--overwrite"],
            stage=f"db:{lang}", heartbeat=15, dry=args.dry_run, dry_secs=4.0, logdir=logdir)
        timings[f"db:{lang}"] = dt
        if rc != 0:
            status, note = "db_failed", (note + f" [{lang}] " + tail[:160]); continue
        sarif = work / "sarif" / f"{slug(repo)}.{lang}.sarif"
        sarif.parent.mkdir(parents=True, exist_ok=True)
        # queries: the built-in security suite (works out of the box) +, if present,
        # your custom agent-source pack in ql/ (the differentiator — see README).
        suite = f"{lang}-security-extended.qls"
        queries = [suite]
        pack = ql / lang
        if (pack).exists(): queries.append(str(pack))
        rc, dt, tail = run(
            ["codeql", "database", "analyze", str(db), *queries,
             "--format=sarif-latest", f"--output={sarif}",
             f"--threads={args.threads}", f"--ram={args.ram}",
             "--rerun", f"--timeout={args.query_timeout}"],
            stage=f"analyze:{lang}", heartbeat=15, dry=args.dry_run, dry_secs=3.0,
            logdir=logdir, timeout=args.analyze_timeout)
        timings[f"analyze:{lang}"] = dt
        if rc == 124:  # whole-analyze wall timeout: nothing usable written
            status, note = "analyze_timeout", (note + f" [{lang}] " + tail[:160]); continue
        if rc == 33:   # CodeQL per-query timeout: partial SARIF (built-in kept, some agent queries skipped)
            status = "analyze_partial" if status == "ok" else status
            note = (note + f" [{lang}] query-timeout, partial results").strip()
            if args.dry_run:
                sarif.write_text(json.dumps({"runs":[{"results":[{}, {}]}]}))
            findings += count_sarif(sarif); continue
        if rc != 0:
            status, note = ("analyze_failed" if status == "ok" else status), (note + f" [{lang}] " + tail[:160]); continue
        if args.dry_run:
            sarif.write_text(json.dumps({"runs":[{"results":[{}, {}]}]}))  # 2 fake hits
        findings += count_sarif(sarif)
    if not args.keep_src:
        shutil.rmtree(src, ignore_errors=True)
    if not args.keep_db:
        for lang in langs: shutil.rmtree(work / "db" / f"{slug(repo)}.{lang}", ignore_errors=True)
    return dict(repo=repo, status=status, note=note.strip()[:200], timings=timings, findings=findings)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", required=True, help="file: one owner/repo per line")
    ap.add_argument("--work", default="work")
    ap.add_argument("--ql", default="ql", help="dir with custom QL packs (ql/python, ql/javascript)")
    ap.add_argument("--batch-size", type=int, default=20)
    ap.add_argument("--analyze-timeout", type=int, default=900,
                    help="per-language analyze timeout in seconds (default 900=15m); "
                    "a repo that exceeds it is marked analyze_timeout and skipped, to revisit later")
    ap.add_argument("--threads", type=int, default=0,
                    help="codeql analyze threads (0 = all cores)")
    ap.add_argument("--ram", type=int, default=2048,
                    help="total MB codeql may use for analyze (raises JVM heap; default was ~2.7G and OOM'd big JS repos)")
    ap.add_argument("--query-timeout", type=int, default=180,
                    help="CodeQL per-query evaluation timeout in seconds (default 180); a single "
                    "pathological query is skipped while the other queries on that repo still run")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--keep-src", action="store_true")
    ap.add_argument("--keep-db", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    (work/"sarif").mkdir(exist_ok=True); (work/"src").mkdir(exist_ok=True); (work/"db").mkdir(exist_ok=True)
    ckpt = work / "done.jsonl"
    done = {}
    if args.resume and ckpt.exists():
        for line in ckpt.read_text().splitlines():
            try: r = json.loads(line); done[r["repo"]] = r
            except Exception: pass

    repos = [l.strip() for l in Path(args.repos).read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    todo = [r for r in repos if r not in done]
    N = len(repos); started = time.time(); per_repo = []
    print(f"=== Exp 3: CodeQL agent-framework hunt ===")
    print(f"repos: {N} total | {len(done)} already done | {len(todo)} to run"
          f"{'  [DRY RUN]' if args.dry_run else ''}\n")

    ck = ckpt.open("a")
    for i, repo in enumerate(todo, 1):
        pos = len(done) + i
        print(f"[{pos}/{N}] {repo}")
        t0 = time.time()
        res = process_repo(repo, work, Path(args.ql), args)
        dur = time.time() - t0; per_repo.append(dur)
        res["seconds"] = round(dur, 1)
        stages = " | ".join(f"{k} {fmt(v)}" for k, v in res["timings"].items())
        mark = {"ok":"OK","clone_failed":"CLONE-FAIL","db_failed":"DB-FAIL","analyze_failed":"ANALYZE-FAIL"}.get(res["status"], res["status"])
        avg = sum(per_repo)/len(per_repo); left = len(todo) - i
        print(f"    {stages}")
        print(f"    {mark} · {res['findings']} findings · repo {fmt(dur)} | "
              f"done {pos}/{N} ({100*pos/N:.0f}%) · avg {fmt(avg)} · "
              f"elapsed {fmt(time.time()-started)} · ETA ~{fmt(avg*left)} ({left} left)")
        if res.get("note"): print(f"    note: {res['note']}")
        ck.write(json.dumps(res)+"\n"); ck.flush()
        if i % args.batch_size == 0 and left:
            b = i // args.batch_size
            print(f"\n--- batch {b} done ({i}/{len(todo)}) · avg {fmt(avg)} · "
                  f"ETA ~{fmt(avg*left)} for {left} remaining ---\n")
    ck.close()

    # final summary (reads the full checkpoint, incl. prior resumed runs)
    results = [json.loads(l) for l in ckpt.read_text().splitlines() if l.strip()]
    tot = sum(r.get("findings",0) for r in results)
    fails = [r for r in results if r.get("status") != "ok"]
    print(f"\n=== DONE === {len(results)}/{N} repos · {tot} total findings · "
          f"{len(fails)} with errors · wall {fmt(time.time()-started)}")
    hits = sorted([r for r in results if r.get("findings",0)], key=lambda r:-r["findings"])
    if hits:
        print("top repos by findings:")
        for r in hits[:15]: print(f"  {r['findings']:3d}  {r['repo']}")
    print(f"\nSARIF in {work/'sarif'} · next: python3 diff_semgrep.py "
          f"--sarif {work/'sarif'} --semgrep <your findings.csv>")

if __name__ == "__main__":
    main()
