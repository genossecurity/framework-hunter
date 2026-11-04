#!/usr/bin/env python3
"""Build a target list (repos.txt) of mid-tier MCP servers for scan.py.

The sweet spot is servers with real users but little security attention:
some stars/downloads, recently maintained, small maintainer team, not one
of the big names everyone else is already auditing.

Sources:
  github  GitHub repo search (topics mcp-server / mcp / model-context-protocol,
          split into star bands so each query stays under GitHub's 1000-result cap)
  npm     npm registry search ("mcp server", keywords:mcp), mapped to GitHub
          repos, with last-week download counts

Usage:
  python3 src/discover.py -o repos.txt                       # both sources, defaults
  python3 src/discover.py --source npm --min-downloads 200 -o repos.txt
  python3 src/discover.py --min-stars 50 --max-stars 2000 --pushed-days 120 --limit 300
  python3 src/discover.py --exclude done.txt -o repos.txt    # skip repos already scanned

GitHub auth: set GITHUB_TOKEN, or be logged in with `gh` (its token is used).
Unauthenticated search is limited to 10 requests/minute.
Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "mcp-hunt-discover/1.0"
# Heavily-audited projects: findings there are unlikely and contested.
DEFAULT_SKIP = {
    "modelcontextprotocol/servers", "modelcontextprotocol/typescript-sdk",
    "modelcontextprotocol/python-sdk", "modelcontextprotocol/inspector",
    "ollama/ollama", "langchain-ai/langchain", "jlowin/fastmcp", "punkpeye/fastmcp",
    "punkpeye/awesome-mcp-servers", "wong2/awesome-mcp-servers", "appcypher/awesome-mcp-servers",
    "microsoft/playwright-mcp", "github/github-mcp-server", "geelen/mcp-remote",
}
AWESOME_RE = re.compile(r"awesome|list|directory|registry|collection|curated", re.I)


def http_json(url: str, headers: dict | None = None, retries: int = 2):
    h = {"User-Agent": UA, "Accept": "application/json", **(headers or {})}
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:200]
            if e.code in (403, 429) and "rate limit" in body.lower() and attempt < retries - 1:
                reset = e.headers.get("X-RateLimit-Reset")
                wait = max(5, int(reset) - int(time.time()) + 2) if reset else 60
                print(f"  [rate limited] sleeping {min(wait, 120)}s", file=sys.stderr)
                time.sleep(min(wait, 120))
                continue
            raise RuntimeError(f"HTTP {e.code} for {url}: {body}") from e
        except urllib.error.URLError as e:
            if attempt < retries - 1 and "refused" not in str(e.reason).lower():
                time.sleep(2)
                continue
            raise RuntimeError(f"network error for {url}: {e.reason}") from e
    raise RuntimeError(f"giving up on {url}")


def github_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        return tok
    if shutil.which("gh"):
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return ""


GH_REPO_RE = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$")


def to_owner_repo(url: str) -> str | None:
    m = GH_REPO_RE.search(url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


# ------------------------------------------------------------------- github ---

def star_bands(lo: int, hi: int) -> list[tuple[int, int]]:
    edges = [lo]
    for e in (25, 50, 100, 200, 400, 800, 1500, 3000, 6000, 12000):
        if lo < e < hi:
            edges.append(e)
    edges.append(hi)
    return [(edges[i] + (1 if i else 0), edges[i + 1]) for i in range(len(edges) - 1)]


def discover_github(args, fetch=http_json) -> dict[str, dict]:
    tok = github_token()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    else:
        print("  [github] no token: unauthenticated search is 10 req/min", file=sys.stderr)
    since = (dt.date.today() - dt.timedelta(days=args.pushed_days)).isoformat()
    out: dict[str, dict] = {}
    for topic in args.topics:
        for lang in args.languages:
            for lo, hi in star_bands(args.min_stars, args.max_stars):
                q = f"topic:{topic} stars:{lo}..{hi} pushed:>={since} archived:false fork:false"
                if lang:
                    q += f" language:{lang}"
                for page in range(1, 11):
                    url = ("https://api.github.com/search/repositories?" + urllib.parse.urlencode(
                        {"q": q, "sort": "updated", "order": "desc", "per_page": 100, "page": page}))
                    try:
                        data = fetch(url, headers)
                    except RuntimeError as e:
                        print(f"  [github] {e}", file=sys.stderr)
                        break
                    items = data.get("items", [])
                    for it in items:
                        name = it["full_name"]
                        if name.lower() in out:
                            continue
                        out[name.lower()] = {
                            "repo": name, "stars": it.get("stargazers_count", 0),
                            "lang": it.get("language") or "", "pushed": (it.get("pushed_at") or "")[:10],
                            "desc": (it.get("description") or "")[:80], "src": "github",
                        }
                    if len(items) < 100:
                        break
                    if not tok:
                        time.sleep(6)
                if not tok:
                    time.sleep(6)
        print(f"  [github] topic:{topic} -> {len(out)} unique so far", file=sys.stderr)
    return out


# ---------------------------------------------------------------------- npm ---

def discover_npm(args, fetch=http_json) -> dict[str, dict]:
    out: dict[str, dict] = {}
    pkgs: dict[str, str] = {}
    for text in args.npm_queries:
        for frm in range(0, args.npm_max, 250):
            url = "https://registry.npmjs.org/-/v1/search?" + urllib.parse.urlencode(
                {"text": text, "size": 250, "from": frm})
            try:
                data = fetch(url)
            except RuntimeError as e:
                print(f"  [npm] {e}", file=sys.stderr)
                break
            objs = data.get("objects", [])
            for o in objs:
                p = o.get("package", {})
                repo = to_owner_repo((p.get("links") or {}).get("repository", ""))
                if repo and p.get("name") and p["name"] not in pkgs:
                    pkgs[p["name"]] = repo
            if len(objs) < 250:
                break
    # last-week downloads, batched (scoped packages cannot be batched -> single calls).
    # If the downloads API is unreachable, stop after the first failure and keep
    # the packages with downloads unknown rather than stalling or dropping them.
    names = list(pkgs)
    downloads: dict[str, int] = {}
    dl_ok = True

    def dl(url):
        nonlocal dl_ok
        if not dl_ok:
            return None
        try:
            return fetch(url)
        except RuntimeError as e:
            dl_ok = False
            print(f"  [npm] downloads API unavailable ({str(e)[:80]}); "
                  "keeping packages with downloads unknown", file=sys.stderr)
            return None

    unscoped = [n for n in names if not n.startswith("@")]
    for i in range(0, len(unscoped), 128):
        chunk = unscoped[i:i + 128]
        data = dl("https://api.npmjs.org/downloads/point/last-week/" + ",".join(chunk))
        if data is None:
            break
        if len(chunk) == 1:
            data = {chunk[0]: data}
        for n, v in data.items():
            if isinstance(v, dict):
                downloads[n] = int(v.get("downloads") or 0)
    for n in [n for n in names if n.startswith("@")][: args.npm_scoped_limit]:
        data = dl("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(n, safe="@"))
        if data is None:
            break
        downloads[n] = int(data.get("downloads") or 0)
    for n, repo in pkgs.items():
        d = downloads.get(n)
        if d is None:
            if dl_ok:
                continue  # API worked but no data (e.g. scoped beyond limit) -> skip
        elif not (args.min_downloads <= d <= args.max_downloads):
            continue
        key = repo.lower()
        prev = out.get(key, {}).get("downloads")
        if key not in out or (d or 0) > (prev if isinstance(prev, int) else 0):
            out[key] = {"repo": repo, "downloads": d if d is not None else "?", "npm": n, "src": "npm"}
    print(f"  [npm] {len(pkgs)} packages with a GitHub repo -> {len(out)} in download range",
          file=sys.stderr)
    return out


# --------------------------------------------------------------------- main ---

def load_list(path: str) -> set[str]:
    s = set()
    with open(path) as f:
        for ln in f:
            t = ln.split("#", 1)[0].strip()
            r = to_owner_repo(t) or (t if re.fullmatch(r"[\w.-]+/[\w.-]+", t) else None)
            if r:
                s.add(r.lower())
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=["github", "npm", "all"], default="all")
    ap.add_argument("-o", "--out", default="repos.txt")
    ap.add_argument("--min-stars", type=int, default=20)
    ap.add_argument("--max-stars", type=int, default=3000)
    ap.add_argument("--pushed-days", type=int, default=180, help="pushed within N days (github)")
    ap.add_argument("--topics", nargs="+", default=["mcp-server", "mcp", "model-context-protocol"])
    ap.add_argument("--languages", nargs="+", default=["TypeScript", "JavaScript", "Python"],
                    help="github language filters (scan.py covers these)")
    ap.add_argument("--npm-queries", nargs="+", default=["mcp server", "keywords:mcp", "modelcontextprotocol"])
    ap.add_argument("--npm-max", type=int, default=1000, help="max search results per npm query")
    ap.add_argument("--npm-scoped-limit", type=int, default=300, help="max @scoped download lookups")
    ap.add_argument("--min-downloads", type=int, default=100, help="npm weekly downloads floor")
    ap.add_argument("--max-downloads", type=int, default=200000, help="npm weekly downloads ceiling")
    ap.add_argument("--exclude", action="append", default=[], help="file of repos to skip (repeatable)")
    ap.add_argument("--limit", type=int, default=0, help="cap the output list (0 = no cap)")
    args = ap.parse_args()

    found: dict[str, dict] = {}
    if args.source in ("github", "all"):
        found.update(discover_github(args))
    if args.source in ("npm", "all"):
        for k, v in discover_npm(args).items():
            if k in found:
                found[k].update({"downloads": v["downloads"], "npm": v["npm"], "src": "github+npm"})
            else:
                found[k] = v

    skip = {s.lower() for s in DEFAULT_SKIP}
    for f in args.exclude:
        skip |= load_list(f)
    rows = [v for k, v in found.items()
            if k not in skip and not AWESOME_RE.search(v["repo"].split("/")[1])]
    # rank: recently pushed + mid popularity first; unknown stars (npm-only) after
    def n(x):
        return x if isinstance(x, int) else 0
    rows.sort(key=lambda v: (-n(v.get("stars")), -n(v.get("downloads"))))
    if args.limit:
        rows = rows[: args.limit]

    with open(args.out, "w") as f:
        f.write(f"# generated by discover.py on {dt.date.today()} — {len(rows)} targets\n")
        f.write("# review before scanning; delete anything you should not be testing\n")
        for v in rows:
            meta = []
            for k in ("stars", "downloads", "lang", "pushed", "npm", "src"):
                if v.get(k) not in (None, ""):
                    meta.append(f"{k}={v[k]}")
            f.write(f"{v['repo']}  # {' '.join(meta)}\n")
    print(f"[+] wrote {len(rows)} targets to {args.out} "
          f"(skipped {len(found) - len(rows)} big/listing/excluded repos)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
