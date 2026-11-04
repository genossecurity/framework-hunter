#!/usr/bin/env python3
"""Hunt one MCP server: scan it, print the triage queue, save a report.

  src/hunt.py ./path/to/server             # a directory you already have
  src/hunt.py owner/repo                   # clone from GitHub first
  src/hunt.py ./server --work ./out        # keep the outputs somewhere specific
  src/hunt.py ./server --audit             # add the noisy sink-only tier
  src/hunt.py ./server --no-github         # skip the prior-reports lookup

What you get, on the terminal and in <work>/report.md:
  - what the server exposes: tool names, registration files, transports, SECURITY.md
  - the priority queue (taint findings, and helper findings reached from tool code),
    each with its reach chain, so you can confirm the path by hand
  - what was demoted and why, and the lower-priority leftovers
  - scan health: unstable Semgrep results, fixpoint timeouts, findings only the
    chunked re-scan found
  - for GitHub repos: public issues/PRs and advisories that may already cover a finding

Semgrep only parses the target; nothing in it is installed or run. Outputs land under
$MCP_HUNT_WORK/hunt/<slug> (default ~/mcp-hunt-work), outside this repo.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from src.scan import Repo, is_priority, slug_for, tool_names, tool_sites, has_mcp_server, iter_sources, TEST_PATH_RE  # noqa: E402

TRANSPORT_RE = {
    "stdio": re.compile(r"StdioServerTransport|stdio_server\(|transport\s*=\s*['\"]stdio['\"]"),
    "streamable-http": re.compile(r"StreamableHTTP|streamable_http|streamable-http|createMcpHandler|mcp-handler"),
    "sse": re.compile(r"SSEServerTransport|SseServerTransport|sse_app\(|['\"]sse['\"]"),
    "http server": re.compile(r"express\(\)|http\.createServer|fastify\(|Hono\(|FastAPI\(|uvicorn|\.listen\("),
}
GITHUB_RE = re.compile(r"github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def ensure_semgrep() -> None:
    if shutil.which("semgrep"):
        return
    for venv in (os.environ.get("MCP_HUNT_VENV"), ROOT / ".venv", Path.home() / "mcp-hunt-work" / ".venv"):
        if venv and (Path(venv) / "bin" / "semgrep").exists():
            os.environ["PATH"] = f"{Path(venv) / 'bin'}{os.pathsep}{os.environ['PATH']}"
            return
    sys.exit("semgrep not found: pip install semgrep==1.183.0, or set MCP_HUNT_VENV to a venv that has it")


def github_repo(target: str, root: Path | None) -> str | None:
    if re.fullmatch(r"[\w.-]+/[\w.-]+", target):
        return target
    m = GITHUB_RE.search(target)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    if root:
        r = subprocess.run(["git", "-C", str(root), "remote", "get-url", "origin"], capture_output=True, text=True)
        m = GITHUB_RE.search(r.stdout.strip())
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    return None


def gh_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "mcp-hunt"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)


SECURITY_TITLE_RE = re.compile(r"secur|vuln|inject|travers|ssrf|\brce\b|exploit|cve-|ghsa|sanitiz|escap|unauthori|bypass|leak|"
                               r"arbitrary|unrestricted|confine|allowlist|whitelist|scope", re.I)


def prior_reports(repo: str, tool_terms: list[str]) -> list[str]:
    """Public advisories, security-titled issues/PRs, and anything mentioning the tools in
    the priority queue. Best effort: unauthenticated GitHub search is 10 requests/minute."""
    out, seen, notes = [], set(), []

    def add(items, tag=""):
        for i in items:
            if i["number"] in seen:
                continue
            seen.add(i["number"])
            kind = "PR" if "pull_request" in i else "issue"
            out.append(f"{kind} #{i['number']} {i['state']} {i['created_at'][:10]}: {i['title'][:90]}{tag}")

    def try_json(url):
        """One request, isolated: a failure (e.g. a 422 from a stale repo slug on the
        search endpoint) is recorded but never aborts the other lookups."""
        try:
            return gh_json(url)
        except Exception as e:  # noqa: BLE001
            notes.append(str(e)[:60])
            return None

    # GitHub's search endpoint 422s on a renamed/redirected slug (the repos API follows the
    # redirect, search does not). Resolve the canonical full_name once and search by that.
    meta = try_json(f"https://api.github.com/repos/{repo}")
    canon = meta.get("full_name") if isinstance(meta, dict) else None
    rs = canon or repo
    if canon and canon.lower() != repo.lower():
        out.append(f"(repo renamed: {repo} -> {canon})")
    # If this is a fork, also look at the upstream parent: a popular fork published to npm can
    # lag a fix that the parent already shipped, so a bug here may be a public dup upstream.
    parent = (meta.get("parent") or {}).get("full_name") if isinstance(meta, dict) else None
    if parent and parent.lower() != rs.lower():
        out.append(f"(fork of {parent} — also check upstream advisories/PRs)")
        padv = try_json(f"https://api.github.com/repos/{parent}/security-advisories?per_page=10")
        for a in padv if isinstance(padv, list) else []:
            out.append(f"UPSTREAM ADVISORY {a.get('ghsa_id')} {a.get('cve_id') or ''}: {a.get('summary','')[:80]}")

    adv = try_json(f"https://api.github.com/repos/{rs}/security-advisories?per_page=10")
    for a in adv if isinstance(adv, list) else []:
        out.append(f"ADVISORY {a.get('ghsa_id')} {a.get('cve_id') or ''}: {a.get('summary', '')[:90]}")
    q = urllib.parse.quote(f"repo:{rs} security OR vulnerability OR injection OR traversal OR SSRF OR RCE")
    hits = try_json(f"https://api.github.com/search/issues?q={q}&per_page=30")
    add([i for i in (hits or {}).get("items", []) if SECURITY_TITLE_RE.search(i["title"])])
    for term in tool_terms[:4]:
        q = urllib.parse.quote(f"repo:{rs} {term}")
        hits = try_json(f"https://api.github.com/search/issues?q={q}&per_page=10")
        add([i for i in (hits or {}).get("items", []) if SECURITY_TITLE_RE.search(i["title"]) or term in i["title"]],
            tag=f"  [mentions {term}]")
    if not out:
        out.append("nothing public with a security-looking title; search the tool names by hand too")
    if notes:
        out.append(f"({len(notes)} lookup(s) failed: {notes[0]}; by-hand check advised)")
    return out


def surface(root: Path) -> dict:
    transports = set()
    for p in iter_sources(root):
        if TEST_PATH_RE.search(str(p.relative_to(root))):
            continue
        try:
            t = p.read_text(errors="replace")
        except OSError:
            continue
        for name, rx in TRANSPORT_RE.items():
            if rx.search(t):
                transports.add(name)
    repo = Repo(root)
    return {
        "mcp_server": has_mcp_server(root),
        "tool_names": sorted(tool_names(root)),
        "tool_sites": tool_sites(root),
        "tool_files": sorted(str(p.relative_to(root)) for p in repo.tool_files),
        "transports": sorted(transports) or ["none detected"],
        "security_md": any((root / n).exists() for n in ("SECURITY.md", ".github/SECURITY.md", "SECURITY")),
    }


def short_rule(rule: str) -> str:
    return re.sub(r"^mcp-(js|py)-", "", re.sub(r"-(helper|audit)$", "", rule))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="local directory, owner/repo, or GitHub URL")
    ap.add_argument("--work", help="output dir (default $MCP_HUNT_WORK/hunt/<slug>)")
    ap.add_argument("--audit", action="store_true", help="also run the noisy sink-only audit tier")
    ap.add_argument("--no-helper", action="store_true", help="taint tier only")
    ap.add_argument("--no-github", action="store_true", help="skip the prior-reports lookup")
    ap.add_argument("--refresh", action="store_true", help="re-clone a GitHub target")
    args = ap.parse_args()

    ensure_semgrep()
    target = args.target
    local = os.path.isdir(target)
    slug = slug_for(target)
    work = Path(args.work) if args.work else Path(os.environ.get("MCP_HUNT_WORK", Path.home() / "mcp-hunt-work")) / "hunt" / slug
    work.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, "-u", str(HERE / "scan.py"), "--work", str(work)]
    cmd += ["--local", target] if local else [str(write_list(work, target))]
    cmd += ["--audit"] * args.audit + ["--no-helper"] * args.no_helper + ["--refresh"] * args.refresh
    print(f"[hunt] scanning {target} -> {work}", flush=True)
    if subprocess.run(cmd).returncode != 0:
        return 1

    root = Path(target).resolve() if local else work / "src" / slug
    stats = {r["repo"]: r for r in csv.DictReader((work / "repos.csv").open())}.get(slug, {})
    rows = [r for r in csv.DictReader((work / "findings.csv").open()) if r["repo"] == slug]
    if stats.get("status") != "ok":
        print(f"[hunt] scan status: {stats.get('status', 'unknown')} {stats.get('errors', '')}")
        return 1
    surf = surface(root)
    repo = github_repo(target, root if local else None)
    prio = sorted((r for r in rows if is_priority(r)),
                  key=lambda r: ({"ERROR": 0, "WARNING": 1}.get(r["severity"], 2), r["tier"], r["file"], int(r["line"])))
    demoted = [r for r in rows if r.get("auto_notes")]
    rest = [r for r in rows if not is_priority(r) and not r.get("auto_notes")]

    L = [f"# mcp-hunt report: {target}", ""]
    L += [f"- commit `{stats.get('commit')}`, package `{stats.get('package_version') or '?'}`, "
          f"{stats.get('files_scanned')} files scanned",
          f"- MCP server code: {'yes' if surf['mcp_server'] else 'NOT detected (client/SDK/other?)'}; "
          f"transports: {', '.join(surf['transports'])}; SECURITY.md: {'yes' if surf['security_md'] else 'no'}",
          f"- tools: {len(surf['tool_names'])} named ({surf['tool_sites']} registration sites) in "
          f"{len(surf['tool_files'])} tool file(s): {', '.join(surf['tool_files'][:6])}"
          + (" ..." if len(surf["tool_files"]) > 6 else "")]
    if surf["tool_names"]:
        L.append("  " + ", ".join(surf["tool_names"][:40]) + (" ..." if len(surf["tool_names"]) > 40 else ""))
    health = []
    if int(stats.get("unstable_results") or 0):
        health.append(f"{stats['unstable_results']} match(es) unstable across Semgrep runs (unioned)")
    if int(stats.get("chunk_only_findings") or 0):
        health.append(f"{stats['chunk_only_findings']} finding(s) only the chunked re-scan saw")
    fx = [e.replace("FIXPOINT-TIMEOUT ", "") for e in (stats.get("errors") or "").split("; ") if e.startswith("FIXPOINT")]
    if fx:
        health.append(f"taint fixpoint gave up in: {', '.join(fx[:6])} (chunked re-scan covers tool code there)")
    other = [e for e in (stats.get("errors") or "").split("; ") if e and not e.startswith("FIXPOINT")]
    if other:
        health.append("semgrep: " + "; ".join(other)[:200])
    L.append("- scan health: " + ("; ".join(health) if health else "stable, no timeouts"))
    L += ["", f"## Priority queue: {len(prio)} candidate(s)", ""]
    if not prio:
        L.append("None. Remember: zero candidates is not a clean bill. Check the tool list above is complete, "
                 "and audit authorization logic (scope / read-only guards) by hand; taint rules cannot see it.")
    else:
        L.append("| sev | tier | rule | where | tool / function | reach | sink |")
        L.append("|---|---|---|---|---|---|---|")
        for r in prio:
            who = r["tool_name"] or (r["function"] + "()" if r["function"] else "?")
            where = f"{r['file']}:{r['line']}" + (" (chunk)" if r.get("scan_path") == "chunk" else "")
            L.append(f"| {r['severity']} | {r['tier']} | {short_rule(r['rule'])} | {where} | {who} | "
                     f"{r['reach_hint'][:70]} | `{r['sink_code'][:90].replace('|', '\\|')}` |")
        L += ["", "Confirm each by hand: argument really reaches the sink; no allowlist/containment/quoting in "
                  "between; it is not the tool's advertised purpose. PoC only in `tools/sandbox.sh`."]
    if demoted:
        L += ["", f"## Demoted by a context check: {len(demoted)}", ""]
        for note, n in Counter(r["auto_notes"] for r in demoted).most_common():
            L.append(f"- {n} × {note}")
        L.append("These stay in findings.csv; a containment check can be wrong, so skim them.")
    if rest:
        L += ["", f"## Lower priority: {len(rest)} helper/audit row(s) not traced to tool code", ""]
        for (rule, reach), n in Counter((short_rule(r["rule"]), r["reach_hint"].split(":")[0]) for r in rest).most_common(8):
            L.append(f"- {n} × {rule} ({reach})")
    if repo and not args.no_github:
        terms = sorted({r["tool_name"] for r in prio if r["tool_name"]})
        L += ["", f"## Prior public reports for {repo}", ""] + [f"- {x}" for x in prior_reports(repo, terms)]
        L.append("Search `repo:" + repo + " <tool_name>` before building any PoC; both real findings so far were already public.")
    L += ["", f"Files: `{work / 'findings.csv'}` (dataset + triage columns), `{work / 'summary.md'}`, "
              f"raw Semgrep JSON in `{work / 'results'}`."]
    report = "\n".join(L) + "\n"
    (work / "report.md").write_text(report)
    print("\n" + report)
    return 0


def write_list(work: Path, target: str) -> Path:
    p = work / "target.txt"
    p.write_text(target + "\n")
    return p


if __name__ == "__main__":
    sys.exit(main())
