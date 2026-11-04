#!/usr/bin/env python3
"""mcp-hunt scanner: clone MCP server repos, run the taint rules, and build a
triage dataset (findings.csv) plus a human summary (summary.md).

Usage:
  python3 scan.py repos.txt                 # taint + helper tiers (default)
  python3 scan.py repos.txt --no-helper     # handler-taint tier only (fewest FPs)
  python3 scan.py repos.txt --audit         # + noisy sink-only audit tier
  python3 scan.py --local ./some-server     # scan a directory you already have
  python3 scan.py repos.txt --work ./run1 --jobs 6
  python3 scan.py repos.txt --resume        # reuse per-repo results from an interrupted run

repos.txt: one entry per line — owner/repo, a GitHub URL, or a local path.
Lines starting with # are ignored; text after # is a comment.

Re-running is safe: triage columns you filled in findings.csv (reachable,
poc_confirmed, status, cve, notes, ...) are preserved for findings that still
exist, keyed on repo + rule + file + the sink line's code.

Each finished repo is checkpointed to <work>/results/. --resume reuses a
checkpoint when the commit and rule files are unchanged.

Cloned code is treated as untrusted DATA: it is parsed by Semgrep, never
installed, built, or executed by this script.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
TAINT_RULES = HERE / "rules" / "mcp-taint.yaml"
HELPER_RULES = HERE / "rules" / "mcp-helper.yaml"
AUDIT_RULES = HERE / "rules-audit" / "mcp-sinks-audit.yaml"

EXCLUDES = ["node_modules", "dist", "build", "out", ".next", "vendor", "venv", ".venv",
            "__pycache__", "coverage", "site-packages", ".smithery",
            # build artifacts: a minified/bundled file is one pathological line that burns the
            # per-rule taint timeout (minutes/file) and yields nothing — not reviewable source
            "*.min.js", "*.min.mjs", "*.min.cjs", "*.bundle.js", "*.bundle.mjs", "*.bundle.cjs",
            "*-bundle.js", "*-bundle.mjs", "*.d.ts",
            # generated code artifacts (not hand-written source): e.g. Builder.io's
            # .generated/ trees and *.bridge.ts glue — huge and pathological for taint
            ".generated", "*.generated.ts", "*.generated.js", "*.generated.tsx",
            "*.generated.jsx", "*.bridge.ts", "*.gen.ts", "*.gen.js",
            # not shipped server code: findings here are not reachable from a tool
            "test", "tests", "__tests__", "spec", "specs", "e2e", "e2e-tests", "fixtures",
            "examples", "example", "explorations", ".spike-*", ".claude", ".cursor", ".github",
            "sample-apps", "samples", "sample", "demo", "demos", "probe",
            # vendored dependencies checked into the tree (e.g. foldkit's repos/effect/)
            "repos",
            "scripts", "bench", "benchmark", "benchmarks", "docs", "*.test.*", "*.spec.*",
            "*.spec-d.*", "*.smoke.*", "*.fixture.ts", "*.fixtures.ts",
            "test_*.py", "*_test.py", "conftest.py"]

# --timeout is per rule per file; the taint rules need well over the 5 s default on
# 3k-line handler files, and a timed-out rule silently drops its findings for that file.
# --timeout-threshold 0 stops Semgrep from skipping a file entirely after 3 timeouts.
# --debug (not --quiet) because only the debug log carries "Fixpoint timeout while
# performing taint analysis", the message that means a function's taint findings were dropped.
SEMGREP_FLAGS = ["--json", "--debug", "--metrics", "off", "--disable-version-check",
                 "--timeout", "120", "--timeout-threshold", "0",
                 "--jobs", str(os.cpu_count() or 8),   # use all cores
                 "--max-target-bytes", "2000000", "--no-git-ignore"]
FIXPOINT_RE = re.compile(r"Fixpoint timeout while performing taint analysis at (\S+?):\d+:\d+")

TRIAGE_COLS = ["reachable", "sanitized_or_contained", "requires_auth_or_approval",
               "poc_confirmed", "status", "disclosed_via", "advisory_id", "cve", "notes"]
AUTO_COLS = ["key", "repo", "commit", "package_version", "scanned_at", "tier", "rule",
             "severity", "cwe", "impact", "tool_name", "function", "reach_hint", "auto_notes",
             "file", "line", "sink_code", "url", "scan_path"]
ALL_COLS = AUTO_COLS + TRIAGE_COLS

# Tool-registration lines, used to (a) name the tool enclosing a finding and
# (b) count how many tools each server exposes (attack-surface size for the dataset).
JS_TOOL_RE = re.compile(
    r"""\.(?:tool|registerTool)\(\s*['"`]([\w\-.:/]+)['"`]"""
    r"""|\.addTool\(\s*\{[^}]*?name\s*:\s*['"`]([\w\-.:/]+)['"`]"""
    r"""|name\s*:\s*['"`]([\w\-.:/]+)['"`]\s*,\s*(?:description|inputSchema|parameters|annotations|title|outputSchema)"""
    r"""|\bannotations\s*:[^{}]*?\bname\s*:\s*['"`]([\w\-.:/]+)['"`]"""     # { annotations, description, name }
    r"""|\b(\w+)\s*:\s*(?:tool|defineTool|createTool|injectableTool|mcpTool)\(\s*\{"""     # run_it: tool({
    r"""|\b(\w+)\s*:\s*\{[^{}]*?\b(?:parameters|inputSchema)\s*:[^{}]{0,300}?\b(?:execute|handler)\s*:""",     # run_it: { parameters, execute }
    re.S)
JS_SWITCH_RE = re.compile(r"""case\s+['"`]([\w\-.:/]+)['"`]\s*:""")
PY_DECO_RE = re.compile(
    r"^\s*@(?:[\w.]+\.)?(?:tool|call_tool|function_tool|kernel_function|tool_plain|agent_tool)\b.*$")
PY_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")
SRC_EXT = {".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx", ".py"}


def log(msg: str) -> None:
    print(f"{dt.datetime.now():%H:%M:%S} {msg}", flush=True)


# ------------------------------------------------------------------ targets ---

def parse_targets(path: Path) -> list[str]:
    out = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def slug_for(target: str) -> str:
    t = target.rstrip("/")
    t = re.sub(r"^https?://(www\.)?github\.com/", "", t)
    t = re.sub(r"\.git$", "", t)
    if os.path.isdir(target):
        return "local__" + re.sub(r"[^\w.-]+", "_", Path(target).resolve().name)
    return re.sub(r"[^\w.-]+", "__", t)


def repo_url(target: str) -> str | None:
    if os.path.isdir(target):
        return None
    if target.startswith(("http://", "https://", "git@")):
        return target
    if re.fullmatch(r"[\w.-]+/[\w.-]+", target):
        return f"https://github.com/{target}"
    return None


def fetch(target: str, src_root: Path, refresh: bool) -> tuple[str, Path | None, str]:
    slug = slug_for(target)
    if os.path.isdir(target):
        return slug, Path(target).resolve(), "local"
    url = repo_url(target)
    if not url:
        return slug, None, f"unrecognized target: {target}"
    dest = src_root / slug
    # an empty or broken dir would otherwise scan as a clean repo
    if dest.exists() and (refresh or not git_commit(dest)):
        shutil.rmtree(dest)
    if not dest.exists():
        # clone beside dest and rename, so an interrupted clone never looks finished
        partial = src_root / (slug + ".partial")
        shutil.rmtree(partial, ignore_errors=True)
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")   # never hang on auth prompts
        try:
            r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", "--no-tags", url, str(partial)],
                               capture_output=True, text=True, env=env, timeout=300)
        except subprocess.TimeoutExpired:
            shutil.rmtree(partial, ignore_errors=True)
            return slug, None, "clone failed: timed out (5 min)"
        if r.returncode != 0:
            shutil.rmtree(partial, ignore_errors=True)
            return slug, None, "clone failed: " + (r.stderr.strip().splitlines() or ["?"])[-1]
        partial.rename(dest)
    return slug, dest, "ok"


def git_commit(d: Path) -> str:
    if not (d / ".git").exists():   # git -C would walk up into an enclosing repo
        return ""
    r = subprocess.run(["git", "-C", str(d), "rev-parse", "--short=12", "--verify", "--quiet", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def package_version(d: Path) -> str:
    pj = d / "package.json"
    if pj.is_file():
        try:
            j = json.loads(pj.read_text(errors="replace"))
            return f"{j.get('name', '?')}@{j.get('version', '?')}"
        except Exception:
            pass
    pp = d / "pyproject.toml"
    if pp.is_file():
        t = pp.read_text(errors="replace")
        n = re.search(r'^\s*name\s*=\s*["\']([^"\']+)', t, re.M)
        v = re.search(r'^\s*version\s*=\s*["\']([^"\']+)', t, re.M)
        if n or v:
            return f"{n.group(1) if n else '?'}=={v.group(1) if v else 'dynamic'}"
    return ""


def github_blob_url(target: str, commit: str, rel: str, line: int) -> str:
    url = repo_url(target)
    if not url or "github.com" not in url or not commit:
        return ""
    base = re.sub(r"\.git$", "", url.rstrip("/"))
    return f"{base}/blob/{commit}/{rel}#L{line}"


# ----------------------------------------------------------- tool surface ---

def iter_sources(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in SRC_EXT or not p.is_file():
            continue
        parts = set(p.relative_to(root).parts)
        if parts & {"node_modules", "dist", "build", "vendor", ".venv", "venv", "site-packages"}:
            continue
        if p.stat().st_size > 2_000_000:
            continue
        yield p


def count_tools(root: Path) -> int:
    return len(tool_names(root))


def tool_names(root: Path) -> set[str]:
    """Literal tool names registered in shipped source (heuristic)."""
    names = set()
    for p in iter_sources(root):
        if TEST_PATH_RE.search(str(p.relative_to(root))):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        if p.suffix == ".py":
            lines = text.splitlines()
            for i, ln in enumerate(lines):
                if PY_DECO_RE.match(ln):
                    for nxt in lines[i + 1:i + 6]:
                        m = PY_DEF_RE.match(nxt)
                        if m:
                            names.add(m.group(1))
                            break
        elif ("modelcontextprotocol" in text or "mcp" in text.lower() or ".tool(" in text
              or "inputSchema" in text):
            for m in JS_TOOL_RE.finditer(text):
                names.add(next(g for g in m.groups() if g))
    return names


def tool_sites(root: Path) -> int:
    """Tool registration sites in shipped source. Unlike count_tools this needs no
    literal name, so it sees server.tool(TOOL_NAMES.x, ...) and class-based tools."""
    sites = 0
    for p in iter_sources(root):
        if TEST_PATH_RE.search(str(p.relative_to(root))):
            continue
        try:
            sites += sum(1 for _ in TOOL_SITE_RE.finditer(p.read_text(errors="replace")))
        except OSError:
            continue
    return sites


def has_mcp_server(root: Path) -> bool:
    """True if shipped source builds an MCP server (not just a client or a config type)."""
    for p in iter_sources(root):
        if TEST_PATH_RE.search(str(p.relative_to(root))):
            continue
        try:
            if MCP_SERVER_RE.search(p.read_text(errors="replace")):
                return True
        except OSError:
            continue
    return False


# `(?:<[^>]*>)?` accepts type parameters: `function fetchWithRetry<T>(url: string)`
JS_FUNC_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*(?:<[^>]*>)?\s*\("""
    r"""|^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:<[^>]*>)?\s*(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>"""
    r"""|^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+|readonly\s+)*(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?::[^{]+)?\{\s*$"""
    r"""|^\s*(\w+)\s*:\s*(?:async\s*)?(?:<[^>]*>)?\s*\([^)]*\)\s*(?::[^=]+)?=>""")   # execute: async (args) =>
JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "constructor", "with",
               "import", "await", "super", "require", "typeof", "new"}
TOOLFILE_RE = re.compile(
    r"""CallToolRequestSchema|ReadResourceRequestSchema|GetPromptRequestSchema|fallbackRequestHandler"""
    r"""|setRequestHandler\(\s*['"](?:tools/call|resources/read|prompts/get)['"]"""
    r"""|\.(?:tool|registerTool|addTool)\("""
    r"""|\b(?:server|mcp|mcpServer)\.(?:resource|registerResource|prompt|registerPrompt)\("""
    r"""|(?<![.\w])(?:tool|defineTool|createTool|injectableTool|mcpTool)\(\s*\{"""
    r"""|\b(?:parameters|inputSchema)\s*:[\s\S]{0,3000}?\b(?:execute|handler)\s*:"""
    r"""|@[\w.]+\.(?:tool|call_tool|resource|read_resource|prompt|get_prompt)\b"""
    # agent-framework tool definitions (experiment 2)
    r"""|^\s*@(?:[\w.]+\.)?(?:tool|function_tool|kernel_function|tool_plain|agent_tool)\b"""
    r"""|\bclass\s+\w+\s*\([^)]*\b(?:BaseTool|StructuredTool)\b"""
    r"""|\b(?:FunctionTool|StructuredTool|DynamicStructuredTool|DynamicTool|Tool)\s*(?:\.from_\w+\s*)?\("""
    r"""|\bnew\s+(?:DynamicStructuredTool|DynamicTool)\b""", re.M)
TOOL_SITE_RE = re.compile(
    r"""\.(?:tool|registerTool|addTool)\("""
    r"""|setRequestHandler\(\s*(?:CallToolRequestSchema|ListToolsRequestSchema|['"]tools/(?:call|list)['"])"""
    r"""|fallbackRequestHandler"""
    r"""|(?<![.\w])(?:tool|defineTool|createTool|injectableTool|mcpTool)\(\s*[{'"`]"""
    r"""|\b(?:parameters|inputSchema)\s*:[^{}]{0,300}?\b(?:execute|handler)\s*:"""
    r"""|@[\w.]+\.(?:tool|call_tool)\b"""
    # agent-framework tool definitions (experiment 2)
    r"""|^\s*@(?:[\w.]+\.)?(?:tool|function_tool|kernel_function|tool_plain|agent_tool)\b"""
    r"""|\bclass\s+\w+\s*\([^)]*\b(?:BaseTool|StructuredTool)\b"""
    r"""|\bnew\s+(?:DynamicStructuredTool|DynamicTool)\b"""
    r"""|\b(?:FunctionTool|StructuredTool)\s*\.from_\w+\s*\(""", re.M)
# tool definition modules, registered elsewhere by reference:
#   export const getFigmaDataTool = { name: "get_figma_data", description, parameters, handler: getFigmaData }
#   export const metadata = { name: "nextjs_call", ... }; export async function handler(args) {...}
TOOL_MODULE_RES = [
    re.compile(r"""\bname\s*:\s*['"][\w\-.:/]+['"][\s\S]{0,1500}?\b(?:handler|execute)\s*:\s*[\w.]+\s*[,}\n]"""),
    re.compile(r"""export\s+const\s+metadata\s*=\s*\{[\s\S]{0,400}?\bname\s*:\s*['"](?=[\s\S]*export\s+(?:async\s+)?function\s+handler\b)"""),
]
STRINGS_RE = re.compile(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`|//.*$""")


def is_tool_file(text: str) -> bool:
    return bool(TOOLFILE_RE.search(text)) or any(r.search(text) for r in TOOL_MODULE_RES)


MCP_SERVER_RE = re.compile(
    r"""@modelcontextprotocol/(?:sdk/server|server)\b|new\s+McpServer\(|\bcreateMcpServer\(|\bcreateMcpHandler\("""
    r"""|\b(?:CallToolRequestSchema|ListToolsRequestSchema)\b"""
    r"""|['"](?:mcp-framework|mcp-handler|@vercel/mcp-adapter|fastmcp|@cyanheads/mcp-ts-core)['"]"""
    r"""|^\s*from\s+(?:mcp\.server|fastmcp)\b|^\s*import\s+fastmcp\b""", re.M)


def enclosing_function(lines: list[str], idx: int, is_py: bool) -> str:
    for i in range(idx, max(0, idx - 300) - 1, -1):
        ln = lines[i]
        if is_py:
            m = PY_DEF_RE.match(ln)
        else:
            m = JS_FUNC_RE.match(ln)
        if m:
            name = next((g for g in m.groups() if g), "")
            if name and name not in JS_KEYWORDS:
                return name
    return ""


TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?|examples?|sample-apps|samples?|"
                          r"demos?|scripts|bench|"
                          r"benchmarks?|docs)(/|$)"
                          r"|(^|/)test_[^/]*\.py$|_test\.py$|conftest\.py$|\.(test|spec)\.[cm]?[jt]sx?$")

# Names too common to link call sites by name alone (path.join, arr.map, ...).
GENERIC_NAMES = set("""join run get set remove delete clear main push pop map filter reduce read write
close open start stop init handle call apply bind then catch resolve reject parse stringify
toString add has update send log emit on off once execute exec create load save fetch request
query find list next default constructor render validate check process format wrap test it
describe setup teardown use build compile transform normalize merge copy move""".split())


# declarations, wasm-bindgen output and agent config can name functions but never call them
NAME_RE = re.compile(r"[\w$]+")
NOT_SERVER_CODE_RE = re.compile(r"\.d\.[cm]?ts$|(^|/)pkg/[^/]*\.js$|(^|/)\.(claude|cursor|github)/")


class Repo:
    """Per-repo source index used for the reachability hint.

    The hint is a name-based reverse call walk: from the function containing
    the sink, find call sites of that name, take *their* enclosing function,
    and repeat until a tool-registration file is reached (max 5 hops). It is a
    heuristic — same-named functions can create false links — but it turns
    'some helper has an exec' into 'tool file -> a -> b -> sink' for triage.
    """

    MAX_HOPS = 5          # walk depth
    PRIORITY_HOPS = 4     # chains longer than this are reported but not prioritized
    # 4 covers the common TS shape: tool handler -> service method -> this.request -> helper (CVE-2025-53967)

    def __init__(self, root: Path):
        self.root = root
        self.tool_files: set[Path] = set()
        self.lines: dict[Path, list[str]] = {}
        self.uses: dict[str, list[tuple[Path, int, str]]] = {}   # name -> code lines that mention it
        self.caller_cache: dict[str, list] = {}
        for p in iter_sources(root):
            rel = str(p.relative_to(root))
            if TEST_PATH_RE.search(rel) or NOT_SERVER_CODE_RE.search(rel):
                continue
            try:
                t = p.read_text(errors="replace")
            except OSError:
                continue
            self.lines[p] = t.splitlines()
            if is_tool_file(t):
                self.tool_files.add(p)
            self._index(p, self.lines[p])

    def _index(self, p: Path, lines: list[str]):
        in_import = False
        for i, ln in enumerate(lines):
            s = ln.strip()
            # names inside `import { a, b } from` blocks and export lists are not uses
            if s.startswith(("import ", "import{", "export {", "export type")):
                in_import = "from" not in s and not s.endswith(";") and not s.endswith("}")
                continue
            if in_import:
                if "from" in s or s.endswith(";") or s.startswith("}"):
                    in_import = False
                continue
            if s.startswith(("//", "*", "/*")):
                continue
            code = STRINGS_RE.sub('""', ln)   # a name inside a string or comment is not a use
            for name in set(NAME_RE.findall(code)):
                self.uses.setdefault(name, []).append((p, i, code))

    def _callers(self, func: str):
        if func not in self.caller_cache:
            self.caller_cache[func] = list(self._find_callers(func))
        return self.caller_cache[func]

    def _find_callers(self, func: str):
        # generic names (request, run, get...): only trust this./self. calls, never bare or obj.name(
        prefix = r"(?:this\.|self\.)" if func in GENERIC_NAMES else r"(?:this\.|self\.|\w+\.)?"
        # `(?:<[^>]*>)?` accepts explicit type arguments: fetchWithRetry<GetFileResponse>(url)
        call = re.compile(r"(?<![\w$.])" + prefix + re.escape(func) + r"\s*(?:<[^>]*>)?\s*\(")
        # in a tool file a bare mention counts too: handlers are passed by reference,
        # server.tool("get_figma_data", desc, params, getFigmaData)
        mention = re.compile(r"(?<![\w$.])" + re.escape(func) + r"\b(?!\s*:)")
        defn = re.compile(r"(?:function\s*\*?\s*|def\s+|const\s+|let\s+|var\s+)" + re.escape(func) + r"\b"
                          r"|^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*"
                          + re.escape(func) + r"\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?::[^{]+)?\{")
        for p, i, code in self.uses.get(func, ()):
            pats = (call, mention) if (p in self.tool_files and func not in GENERIC_NAMES) else (call,)
            if any(pat.search(code) for pat in pats) and not defn.search(code):
                yield p, enclosing_function(self.lines[p], i, p.suffix == ".py")

    def reach_hint(self, func: str, own_file: Path, tier: str) -> str:
        if tier == "taint":
            return "inside tool handler"
        if own_file in self.tool_files:
            return "inside tool file"
        if not func:
            return "unknown function"
        seen, frontier = {func}, [(func, [func])]
        weak = ""
        for _ in range(self.MAX_HOPS):
            nxt = []
            for f, chain in frontier:
                for p, caller in self._callers(f):
                    if p in self.tool_files:
                        hops = len(chain)
                        tag = "called from tool file" if hops <= self.PRIORITY_HOPS else \
                            f"distant path ({hops} hops) from tool file"
                        return f"{tag}: {p.name} -> " + " -> ".join(reversed(chain))
                    # a generic-named caller is followed, but only through this./self. calls (see _callers)
                    if caller and caller not in seen:
                        seen.add(caller)
                        nxt.append((caller, chain + [caller]))
                    elif not caller and not weak:
                        weak = f"called at module level in {p.name}"
            frontier = nxt
            if not frontier:
                break
        if weak:
            return weak
        return "no path to tool code found" if len(seen) > 1 else "no call sites found (outside tests)"


def enclosing_tool(lines: list[str], idx: int, is_py: bool) -> str:
    """Best-effort: walk upward from the sink to the nearest tool registration."""
    lo = max(0, idx - 200)
    for i in range(idx, lo - 1, -1):
        ln = lines[i]
        if is_py:
            m = PY_DEF_RE.match(ln)
            if m and i > 0 and any(PY_DECO_RE.match(lines[j]) for j in range(max(0, i - 4), i)):
                return m.group(1)
        else:
            # `name: 'x',` is often followed by the next key on the next line
            m = JS_TOOL_RE.search("\n".join(lines[i:i + 3])) or JS_SWITCH_RE.search(ln)
            if m:
                return next(g for g in m.groups() if g)
    return ""


# ------------------------------------------------------------------ semgrep ---

def result_key(r: dict) -> tuple:
    return (r["check_id"], r["path"], r["start"]["line"], r["start"]["col"],
            r.get("end", {}).get("line"), r.get("end", {}).get("col"))


def run_semgrep(target_dir: Path, configs: list[Path]) -> tuple[list[dict] | None, list[str], int, int]:
    """Run Semgrep at least twice and union the results.

    Semgrep's taint engine is not deterministic on large handler functions: identical
    runs on the same tree were seen to drop a taint match and report another in its
    place, with no error or timeout. Two runs catch most of that; a third is added when
    the first two disagree. Returns (results, errors, files scanned, unstable), where
    unstable is the number of matches that appeared in only some of the runs.
    """
    seen: dict[tuple, dict] = {}
    runs: list[set] = []
    errs, files = [], 0
    for _ in range(3):
        res, errs, files = semgrep_once(target_dir, configs)
        if res is None:
            return None, errs, 0, 0
        keys = {result_key(r) for r in res}
        runs.append(keys)
        for r in res:
            seen.setdefault(result_key(r), r)
        if len(runs) >= 2 and runs[-1] == runs[-2]:
            break
    unstable = len(set.union(*runs) - set.intersection(*runs))
    return list(seen.values()), errs, files, unstable


_MINIFIED_CACHE: dict[Path, list[str]] = {}


def minified_files(root: Path) -> list[str]:
    """Relative paths of minified/bundled files — one giant line of generated code. These
    are pathological for taint analysis (a single 1 MB line burns the per-rule timeout, minutes
    per file) and are never reviewable source. Detected by content (avg bytes/line), so
    hash-named build assets like `assets/index-CjrRzEm_.js` are caught, not just `*.min.js`."""
    if root in _MINIFIED_CACHE:
        return _MINIFIED_CACHE[root]
    out = []
    for p in root.rglob("*"):
        if p.suffix not in SRC_EXT or not p.is_file():
            continue
        if {"node_modules", ".git"} & set(p.relative_to(root).parts):
            continue
        try:
            sz = p.stat().st_size
            if sz < 50_000:
                continue
            with open(p, "rb") as f:
                blob = f.read(1_200_000)
            head = blob[:200_000]
            lines = blob.count(b"\n") or 1
            # minified/bundled: one giant line.  OR huge-but-short-line generated code
            # (e.g. a 1 MB, 32k-line generated bridge file) — also pathological for the
            # taint fixpoint and never hand-reviewed. Both are excluded from the scan.
            if (sz / (head.count(b"\n") or 1) > 2_000          # avg line > 2 KB
                    or sz > 400_000                            # >400 KB single file: data blob / mega-file
                    or (sz > 150_000 and lines > 4_000)):      # big generated code
                # A big hand-written handler file is still covered: scan.py re-scans each
                # tool registration as its own small chunk, so registrations aren't lost here.
                out.append(str(p.relative_to(root)))
        except OSError:
            continue
    _MINIFIED_CACHE[root] = out
    return out


def semgrep_once(target_dir: Path, configs: list[Path]) -> tuple[list[dict] | None, list[str], int]:
    """Returns (results, errors, files scanned); results is None if the scan itself failed."""
    cmd = ["semgrep", *SEMGREP_FLAGS]
    for c in configs:
        cmd += ["--config", str(c)]
    for e in EXCLUDES + minified_files(target_dir):
        cmd += ["--exclude", e]
    cmd.append(str(target_dir))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return None, ["semgrep timed out (30 min)"], 0
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None, [f"semgrep produced no JSON (exit {r.returncode}): {r.stderr.strip()[-300:]}"], 0
    errs = [f"{e.get('type', 'error')}: {str(e.get('message', ''))[:200]}"
            for e in data.get("errors", []) if e.get("level", "error") == "error"]
    # timeouts are reported as warnings, but they mean findings are missing for that file
    for e in data.get("errors", []):
        if "timeout" in str(e.get("type", "")).lower() and e.get("level") != "error":
            rules = e.get("rule_id") or ",".join(r.split(".")[-1] for r in e.get("rules", []) or [])
            errs.append(f"TIMEOUT {Path(str(e.get('path', '?'))).name}: {rules or str(e.get('message', ''))[:120]}")
    # a taint fixpoint that gives up drops every taint finding in that function, silently
    for f in sorted({Path(m).name for m in FIXPOINT_RE.findall(r.stderr or "")}):
        errs.append(f"FIXPOINT-TIMEOUT {f}")
    return data.get("results", []), errs, len(data.get("paths", {}).get("scanned", []))


# ------------------------------------------------------------------ chunking ---
# Semgrep's taint analysis runs a fixpoint per function with a fixed internal time
# budget (no CLI knob). A tool file whose registrations all sit inside one 3,000-line
# function, or one giant tools/call switch, exceeds it, and Semgrep then silently drops
# every taint finding in that function; the CLI never reports the "Fixpoint timeout".
# Re-scanning each registration as its own small file recovers those findings.
CHUNK_MAX_LINES = 1500        # longest single registration or case body worth isolating
CHUNK_START_RE = re.compile(
    r"^\s*(?:return\s+|export\s+(?:default\s+)?|(?:const|let|var)\s+\w+\s*=\s*|\w+\s*:\s*)?"
    r"(?:[\w.]+\.(?:tool|registerTool|addTool)\(|(?:tool|defineTool|createTool|injectableTool|mcpTool)\(\s*\{)")
# a dispatch switch over the tool name, in the tools/call handler or a helper it calls
SWITCH_RE = re.compile(r"^\s*switch\s*\(\s*(?:[\w.]+\.)?(?:name|toolName|tool_name|tool|method|action|command)\s*\)")
FUNC_HEADER_RE = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b|setRequestHandler\(|=>\s*\{\s*$"
                            r"|^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*\w+\s*\([^)]*\)\s*(?::[^{]+)?\{\s*$")
CASE_RE = re.compile(r"^(\s*)(?:case\s+['\"`][\w\-.:/ ]+['\"`]\s*:|default\s*:)")
OPENERS, CLOSERS = "([{", {"(": ")", "[": "]", "{": "}"}


def bracket_walk(lines: list[str], start: int = 0, limit: int | None = None) -> list[list[str]]:
    """Unclosed brackets after each line from `start`, skipping the contents of strings,
    block comments and template literals (which may span lines; their ${...} code is
    scanned). '${' on the stack marks an open template substitution."""
    stacks: list[list[str]] = []
    stack: list[str] = []
    mode: list[str] = []    # 'tpl' inside a template literal, 'comment' inside /* */
    end = len(lines) if limit is None else min(len(lines), start + limit)
    for i in range(start, end):
        text, j, n = lines[i], 0, len(lines[i])
        while j < n:
            c = text[j]
            if mode and mode[-1] == "comment":
                k = text.find("*/", j)
                if k < 0:
                    break
                mode.pop()
                j = k + 2
            elif mode and mode[-1] == "tpl":
                if c == "\\":
                    j += 2
                elif c == "`":
                    mode.pop()
                    j += 1
                elif text.startswith("${", j):
                    mode.pop()        # code until the matching '}' re-enters the template
                    stack.append("${")
                    j += 2
                else:
                    j += 1
            elif text.startswith("//", j):
                break
            elif text.startswith("/*", j):
                mode.append("comment")
                j += 2
            elif c in "'\"":
                k = j + 1
                while k < n and text[k] != c:
                    k += 2 if text[k] == "\\" else 1
                j = k + 1
            elif c == "`":
                mode.append("tpl")
                j += 1
            else:
                if c in OPENERS:
                    stack.append(c)
                elif c == "}" and stack and stack[-1] == "${":
                    stack.pop()
                    mode.append("tpl")
                elif c in ")]}" and stack and CLOSERS.get(stack[-1]) == c:
                    stack.pop()
                j += 1
        stacks.append(list(stack))
    return stacks


def block_end(lines: list[str], start: int, limit: int = CHUNK_MAX_LINES) -> int | None:
    """Index of the line where the bracket group opened on `start` closes."""
    opened = False
    for k, stack in enumerate(bracket_walk(lines, start, limit)):
        if stack:
            opened = True
        elif opened:
            return start + k
    return None


def closers_for(lines: list[str]) -> str:
    """Brackets that close everything `lines` leave open."""
    stack = bracket_walk(lines)[-1] if lines else []
    return "".join(CLOSERS.get(c, "}") for c in reversed(stack))


def js_chunks(lines: list[str]) -> list[tuple[list[int], list[str]]]:
    """(original line numbers, chunk lines) for each tool registration and each case
    of a tools/call switch handler. Chunks are closed with whatever brackets they leave open."""
    out = []
    taken = [False] * len(lines)
    for i, ln in enumerate(lines):
        if not CHUNK_START_RE.match(ln) or taken[i]:
            continue
        end = block_end(lines, i)
        if end is None or end - i < 3:
            continue
        for k in range(i, end + 1):
            taken[k] = True
        out.append((list(range(i + 1, end + 2)), lines[i:end + 1]))
    for sw, ln in enumerate(lines):
        if not SWITCH_RE.match(ln):
            continue
        end = block_end(lines, sw, limit=50_000)   # the switch itself may be thousands of lines
        head = next((k for k in range(sw - 1, max(-1, sw - 150), -1) if FUNC_HEADER_RE.search(lines[k])), None)
        if end is None or head is None:
            continue
        # the enclosing function's header and the statements before the switch (the
        # `const { name, arguments: args } = request.params` line) go into every chunk
        prefix, prefix_nos = lines[head:sw + 1], list(range(head + 1, sw + 2))
        cases = [k for k in range(sw + 1, end) if CASE_RE.match(lines[k])]
        for a, b in zip(cases, cases[1:] + [end]):
            if b - a < 3 or b - a > CHUNK_MAX_LINES or any(taken[a:b]):
                continue
            body = lines[a:b]
            out.append((prefix_nos + list(range(a + 1, b + 1)) + [b],
                        prefix + body + [closers_for(prefix + body) + ";"]))
    return out


def write_chunks(root: Path, chunk_root: Path) -> dict[Path, tuple[Path, list[int]]]:
    """Split big JS/TS tool files into one file per registration under chunk_root.
    Returns chunk path -> (original path, original line number of each chunk line)."""
    shutil.rmtree(chunk_root, ignore_errors=True)
    mapping: dict[Path, tuple[Path, list[int]]] = {}
    for p in iter_sources(root):
        rel = str(p.relative_to(root))
        if p.suffix == ".py" or TEST_PATH_RE.search(rel):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        lines = text.split("\n")
        if not TOOLFILE_RE.search(text):
            continue
        for idx, (nos, body) in enumerate(js_chunks(lines)):
            # the index keeps case chunks apart: they all start at the same prefix line
            cp = chunk_root / (re.sub(r"[^\w.-]+", "__", rel) + f"__c{idx:03d}_L{nos[-2]}"
                               + SHADOW_EXT.get(p.suffix, p.suffix))
            cp.parent.mkdir(parents=True, exist_ok=True)
            cp.write_text("\n".join(body) + "\n")
            mapping[cp.resolve()] = (p, nos)
    return mapping


def scan_chunks(root: Path, chunk_root: Path, configs: list[Path], seen: set) -> tuple[list[dict], int]:
    """Taint-scan the chunks and return results mapped back to the original files,
    minus any match the whole-file scan already produced. Also returns chunk count."""
    mapping = write_chunks(root, chunk_root)
    if not mapping:
        return [], 0
    res, _errs, _files = semgrep_once(chunk_root, configs)
    added = []
    for r in res or []:
        m = mapping.get(Path(r["path"]).resolve())
        if not m:
            continue
        orig, nos = m
        for pos in ("start", "end"):
            if pos in r and "line" in r[pos]:
                r[pos]["line"] = nos[min(max(r[pos]["line"], 1), len(nos)) - 1]
        r["path"] = str(orig)
        r["_chunk"] = True
        if result_key(r) not in seen:
            seen.add(result_key(r))
            added.append(r)
    return added, len(mapping)


# ------------------------------------------------------------------ .mts/.cts ---
# Semgrep 1.183 does not scan .mts/.cts files at all (not even with --include). Copy them
# into a shadow tree under .ts names, scan that, and map paths back to the originals.
SHADOW_EXT = {".mts": ".ts", ".cts": ".ts"}


def shadow_tree(root: Path, shadow_root: Path) -> dict[Path, Path]:
    shutil.rmtree(shadow_root, ignore_errors=True)
    mapping: dict[Path, Path] = {}
    for p in iter_sources(root):
        if p.suffix not in SHADOW_EXT:
            continue
        dest = (shadow_root / p.relative_to(root)).with_suffix(SHADOW_EXT[p.suffix])
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dest)
        mapping[dest.resolve()] = p
    return mapping


def scan_shadow(root: Path, shadow_root: Path, configs: list[Path], seen: set) -> tuple[list[dict], int]:
    """Scan the .mts/.cts files as .ts; returns results with original paths, and the file count."""
    mapping = shadow_tree(root, shadow_root)
    if not mapping:
        return [], 0
    res, _errs, _files, _unstable = run_semgrep(shadow_root, configs)
    added = []
    for r in res or []:
        orig = mapping.get(Path(r["path"]).resolve())
        if not orig:
            continue
        r["path"] = str(orig)
        if result_key(r) not in seen:
            seen.add(result_key(r))
            added.append(r)
    return added, len(mapping)


def rules_digest(configs: list[Path]) -> str:
    h = hashlib.sha256()
    for c in configs:
        h.update(c.read_bytes())
    return h.hexdigest()[:16]


def load_checkpoint(path: Path, commit: str, digest: str) -> dict | None:
    try:
        cp = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return cp if commit and cp.get("commit") == commit and cp.get("rules") == digest else None


TIER_RANK = {"taint": 0, "helper": 1, "audit": 2}

# Context checks that suggest a candidate is probably NOT exploitable. They do
# not delete anything: they write auto_notes and drop the row out of the
# priority queue. Always verify by hand — a containment check can be wrong.
FIXED_HOST_RE = re.compile(r"""[`'"]https?://[A-Za-z0-9.\-]+(?::\d+)?/""")
CONTAIN_RE = re.compile(r"startsWith\(|path\.relative\(|\brealpath|is_relative_to|commonpath|"
                        r"isPathInside|isSubPath|isWithin|allowedDir|allowed_dir|ALLOWED_(?:DIRS|PATHS)")
ESCAPE_RE = re.compile(r"shlex\.quote|shell-quote|shellQuote|shellEscape|escapeShellArg|shellescape|quote\(")
DASHDASH_RE = re.compile(r"""['"]--['"]""")
ALLOWLIST_RE = re.compile(r"hasOwnProperty\.call\(|validateTableName|validateColumn|quoteIdentifier|escapeIdentifier|"
                          r"escapeId\(|ALLOWED_(?:TABLES|COLUMNS|FIELDS)|allowedTables|allowedColumns|"
                          r"\b(?:allowlist|whitelist|VALID_\w+)\b|\.has\(\w+\)\)\s*(?:throw|return)|"
                          r"\]\.includes\(\w+\)")
# bind-method sink that frequently fires on non-SQL callers (HTTP get, Map.get, IndexedDB get)
NONSQL_GET_RE = re.compile(r"\.(?:get|all|run)\s*\(")
# genuine SQL context: a SQL verb, a prepared-statement build, or a db/sql-ish receiver nearby
SQL_CTX_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|FROM|WHERE|JOIN|UNION|PRAGMA)\b|"
                        r"\.prepare\(|\bsql\b|\bquery\b|\bstatement\b|\bdb\b|\bdatabase\b|knex|sequelize", re.I)


def auto_notes(rule: str, lines: list[str], idx: int) -> str:
    win = "\n".join(lines[max(0, idx - 30):idx + 1])
    near = "\n".join(lines[max(0, idx - 12):idx + 1])
    notes = []
    if "ssrf" in rule:
        m = FIXED_HOST_RE.search(near)
        if m:
            notes.append(f"URL host looks fixed ({m.group(0).strip(chr(96) + chr(39) + chr(34))}...) — path-only?")
    if "path-traversal" in rule and CONTAIN_RE.search(win):
        notes.append("containment check nearby — verify it is correct")
    if "command-injection" in rule and ESCAPE_RE.search(win):
        notes.append("shell escaping nearby — verify coverage")
    if "argument-injection" in rule and DASHDASH_RE.search(near):
        notes.append("uses '--' separator")
    if "sql-injection" in rule and ALLOWLIST_RE.search(win):
        notes.append("identifier allowlist/quoting nearby — verify it covers every interpolation")
    # the SQL bind-method sink (.get/.all/.run) also matches non-SQL callers: HTTP clients
    # (client.get('/path')), Map.get, IndexedDB objectStore.get(id). Demote when the line is a
    # bind-method call and no SQL keyword/receiver is anywhere in the window.
    if "sql-injection" in rule and NONSQL_GET_RE.search(lines[idx]) and not SQL_CTX_RE.search(win):
        notes.append("non-SQL '.get()/.all()/.run()' call (HTTP/Map/IndexedDB), no SQL context — likely not SQL injection")
    return "; ".join(notes)


def finding_rows(target: str, slug: str, root: Path, commit: str, version: str,
                 results: list[dict], now: str) -> list[dict]:
    rows, cache = [], {}
    repo = Repo(root)
    for r in results:
        abspath = Path(r["path"])
        try:
            rel = str(abspath.resolve().relative_to(root.resolve()))
        except ValueError:
            rel = r["path"]
        if abspath not in cache:
            try:
                cache[abspath] = abspath.read_text(errors="replace").splitlines()
            except OSError:
                cache[abspath] = []
        lines = cache[abspath]
        line = r["start"]["line"]
        end = r.get("end", {}).get("line", line)
        sink = " ".join(l.strip() for l in lines[line - 1:min(end, line + 2)])[:300] if lines else ""
        rule = r["check_id"].split(".")[-1]
        meta = r.get("extra", {}).get("metadata", {})
        tier = meta.get("tier") or ("audit" if rule.endswith("-audit") else
                                    "helper" if rule.endswith("-helper") else "taint")
        base_rule = re.sub(r"-(audit|helper)$", "", rule)
        key = "|".join([slug, base_rule, rel, re.sub(r"\s+", " ", sink)])
        is_py = abspath.suffix == ".py"
        tool = enclosing_tool(lines, line - 1, is_py) if lines else ""
        func = enclosing_function(lines, line - 1, is_py) if lines else ""
        rows.append({
            "key": key, "repo": slug, "commit": commit, "package_version": version,
            "scanned_at": now, "tier": tier, "rule": rule,
            "severity": r.get("extra", {}).get("severity", ""),
            "cwe": meta.get("cwe", ""), "impact": meta.get("impact", ""),
            "tool_name": tool if tier == "taint" else "",
            "function": func,
            "reach_hint": repo.reach_hint(func, abspath, tier),
            "auto_notes": auto_notes(rule, lines, line - 1) if lines else "",
            "file": rel, "line": line, "sink_code": sink,
            "url": github_blob_url(target, commit, rel, line),
            "scan_path": "chunk" if r.get("_chunk") else "file",
        })
    # one row per key: several tiers can hit the same sink; keep the strongest
    best: dict[str, dict] = {}
    for row in rows:
        k = row["key"]
        if k not in best or TIER_RANK[row["tier"]] < TIER_RANK[best[k]["tier"]]:
            best[k] = row
    return list(best.values())


# ------------------------------------------------------------------ outputs ---

def load_existing(csv_path: Path) -> dict[str, dict]:
    if not csv_path.exists():
        return {}
    with csv_path.open(newline="") as f:
        return {row["key"]: row for row in csv.DictReader(f) if row.get("key")}


def write_csv(csv_path: Path, rows: list[dict], existing: dict[str, dict],
              scanned_repos: set[str]) -> int:
    kept = 0
    for row in rows:
        old = existing.get(row["key"])
        for c in TRIAGE_COLS:
            row[c] = old.get(c, "") if old else ""
    # keep previously-triaged rows from repos NOT scanned this run
    carried = [r for k, r in existing.items() if r.get("repo") not in scanned_repos]
    kept = len(carried)
    sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    allrows = sorted(rows + carried, key=lambda r: (
        not is_priority(r), TIER_RANK.get(r.get("tier", ""), 3), sev_rank.get(r.get("severity", ""), 3), r["repo"], r["file"],
        int(r.get("line") or 0)))
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ALL_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(allrows)
    return kept


def write_repos_csv(path: Path, repo_stats: list[dict]) -> None:
    cols = ["repo", "status", "commit", "package_version", "files_scanned", "unstable_results",
            "chunks", "chunk_only_findings", "tools_exposed", "tool_sites", "taint_findings", "helper_findings", "audit_findings", "errors"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(repo_stats)


def is_priority(r: dict) -> bool:
    """Taint findings, or helper findings that trace back to tool code,
    minus anything a context check flagged as probably mitigated."""
    if r.get("auto_notes"):
        return False
    return r["tier"] == "taint" or (r["tier"] == "helper" and str(r.get("reach_hint", "")).startswith(
        ("inside tool file", "called from tool file")))


def write_summary(path: Path, rows: list[dict], repo_stats: list[dict], tiers: list[str]) -> None:
    ok = [s for s in repo_stats if s["status"] == "ok"]
    no_source = sum(s["status"] == "no-source" for s in repo_stats)
    failed = len(repo_stats) - len(ok) - no_source
    by_tier = Counter(r["tier"] for r in rows)
    prio = [r for r in rows if is_priority(r)]
    tools = sum(int(s.get("tools_exposed") or 0) for s in ok)
    sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    L = [f"# mcp-hunt scan summary — {dt.datetime.now():%Y-%m-%d %H:%M}\n",
         f"- Targets: {len(repo_stats)} ({len(ok)} scanned, {no_source} with no JS/TS/Python files "
         f"scanned, {failed} failed)",
         f"- Tiers run: {', '.join(tiers)}",
         f"- Tools exposed across scanned servers (heuristic count): {tools}"]
    for t in tiers:
        L.append(f"- {t} findings: {by_tier.get(t, 0)}")
    L.append(f"- **Priority queue** (taint, or helper reached from tool code): {len(prio)} "
             f"in {len({r['repo'] for r in prio})} repos")
    L.append("\nCandidates are not vulnerabilities. Each needs: reachable from a tool arg, "
             "no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.\n")

    L.append("## Priority findings by rule\n")
    L.append("| rule | count |\n|---|---|")
    for rule, n in Counter(re.sub(r"-(helper|audit)$", "", r["rule"]) for r in prio).most_common():
        L.append(f"| {rule} | {n} |")

    L.append("\n## Triage queue (priority findings, highest severity first)\n")
    L.append("| sev | tier | repo | tool / function | rule | reach | location |\n|---|---|---|---|---|---|---|")
    for r in sorted(prio, key=lambda r: (sev_rank.get(r["severity"], 3), r["tier"], r["repo"]))[:200]:
        loc = f"[{r['file']}:{r['line']}]({r['url']})" if r["url"] else f"{r['file']}:{r['line']}"
        who = r["tool_name"] or (r["function"] + "()" if r["function"] else "?")
        L.append(f"| {r['severity']} | {r['tier']} | {r['repo']} | {who} | "
                 f"{re.sub(r'-(helper|audit)$', '', r['rule'])} | {r['reach_hint']} | {loc} |")
    if len(prio) > 200:
        L.append(f"\n…{len(prio) - 200} more in findings.csv")
    rest = len(rows) - len(prio)
    if rest:
        demoted = sum(1 for r in rows if r.get("auto_notes"))
        L.append(f"\n{rest} lower-priority finding(s) are in findings.csv after the priority rows "
                 f"({demoted} demoted by a context check — see auto_notes; the rest are helper "
                 f"findings not traced to tool code, or audit tier).")

    L.append("\n## Per-repo\n")
    L.append("| repo | status | tools | taint | helper | audit | version |\n|---|---|---|---|---|---|---|")
    for s in sorted(repo_stats, key=lambda s: (-int(s.get("taint_findings") or 0),
                                                -int(s.get("helper_findings") or 0))):
        L.append(f"| {s['repo']} | {s['status']} | {s.get('tools_exposed', '')} | "
                 f"{s.get('taint_findings', '')} | {s.get('helper_findings', '')} | "
                 f"{s.get('audit_findings', '')} | {s.get('package_version', '')} |")
    path.write_text("\n".join(L) + "\n")


# --------------------------------------------------------------------- main ---

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="?", help="file with one target per line")
    ap.add_argument("--local", nargs="+", default=[], help="local directories to scan")
    ap.add_argument("--work", default="./mcp-scan", help="output/work dir (default ./mcp-scan)")
    ap.add_argument("--no-helper", action="store_true",
                    help="skip the helper tier (function-param sources); fewer FPs, misses handler->helper bugs")
    ap.add_argument("--audit", action="store_true", help="also run the noisy sink-only audit tier")
    ap.add_argument("--jobs", type=int, default=4, help="parallel clones (default 4)")
    ap.add_argument("--refresh", action="store_true", help="re-clone repos already on disk")
    ap.add_argument("--resume", action="store_true", help="reuse checkpoints in <work>/results/")
    ap.add_argument("--reprocess", action="store_true",
                    help="rebuild rows from saved raw Semgrep results (same commit and rules) without re-running "
                         "Semgrep; use after changing scan.py's post-processing")
    args = ap.parse_args()

    if not shutil.which("semgrep"):
        sys.exit("semgrep not found: pip install semgrep")
    if not shutil.which("git"):
        sys.exit("git not found")
    targets = (parse_targets(Path(args.repos)) if args.repos else []) + args.local
    if not targets:
        ap.error("give a repos file and/or --local DIR")

    work = Path(args.work)
    src_root = work / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    results_root = work / "results"
    results_root.mkdir(exist_ok=True)
    tiers = ["taint"] + ([] if args.no_helper else ["helper"]) + (["audit"] if args.audit else [])
    configs = [{"taint": TAINT_RULES, "helper": HELPER_RULES, "audit": AUDIT_RULES}[t] for t in tiers]
    digest = rules_digest(configs)
    now = dt.datetime.now().isoformat(timespec="seconds")

    log(f"[*] fetching {len(targets)} targets ({args.jobs} parallel)")
    fetched = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = {ex.submit(fetch, t, src_root, args.refresh): t for t in targets}
        for fut in cf.as_completed(futs):
            t = futs[fut]
            try:
                fetched[t] = fut.result()
            except Exception as e:  # noqa: BLE001
                fetched[t] = (slug_for(t), None, f"error: {e}")
            if fetched[t][2] not in ("ok", "local"):
                log(f"    [!] {t}: {fetched[t][2]}")
            else:
                log(f"[clone {len(fetched)}/{len(targets)}] {fetched[t][0]}")

    all_rows, stats, scanned = [], [], set()
    for i, t in enumerate(targets, 1):
        slug, d, status = fetched[t]
        if d is None:
            stats.append({"repo": slug, "status": status})
            continue
        commit, version = git_commit(d), package_version(d)
        checkpoint = results_root / f"{slug}.json"
        saved = load_checkpoint(checkpoint, commit, digest) if args.resume else None
        raw = load_checkpoint(results_root / f"{slug}.semgrep.json", commit, digest) if args.reprocess else None
        if saved:
            log(f"[{i}/{len(targets)}] {slug}: reused checkpoint")
            rows, stat = saved["rows"], saved["stat"]
        else:
            chunk_hits = chunks = unstable = 0
            if raw:
                log(f"[{i}/{len(targets)}] {slug}: reprocessing saved Semgrep results")
                results, errs, files = raw["results"], raw["errors"], raw["files_scanned"]
                old = load_checkpoint(checkpoint, commit, digest) or {}
                unstable = old.get("stat", {}).get("unstable_results", 0)
                chunks = old.get("stat", {}).get("chunks", 0)
                chunk_hits = sum(1 for r in results if r.get("_chunk"))
            else:
                log(f"[{i}/{len(targets)}] scanning {slug}")
                results, errs, files, unstable = run_semgrep(d, configs)
                if results is not None:
                    seen = {result_key(r) for r in results}
                    shadowed, shadow_files = scan_shadow(d, work / "shadow" / slug, configs, seen)
                    results += shadowed
                    files += shadow_files
                    added, chunks = scan_chunks(d, work / "chunks" / slug, configs, seen)
                    results += added
                    chunk_hits = len(added)
            if results is None:
                # not a clean result: leave it unscanned so it is retried and counted as failed
                log(f"    [!] {slug}: {errs[0]}")
                stats.append({"repo": slug, "status": "scan failed", "commit": commit,
                              "package_version": version, "errors": errs[0][:500]})
                continue
            if not raw:
                # raw Semgrep output, so post-processing can be re-run (--reprocess) or a dropped match investigated
                (results_root / f"{slug}.semgrep.json").write_text(json.dumps(
                    {"commit": commit, "rules": digest, "files_scanned": files, "errors": errs, "results": results}))
            try:
                rows = finding_rows(t, slug, d, commit, version, results, now)
            except Exception as e:  # noqa: BLE001
                log(f"    [!] {slug}: post-processing failed: {e}")
                stats.append({"repo": slug, "status": "scan failed", "commit": commit,
                              "package_version": version, "errors": f"post-processing: {e}"[:500]})
                continue
            c = Counter(r["tier"] for r in rows)
            stat = {"repo": slug, "status": "ok" if files else "no-source", "commit": commit,
                    "package_version": version, "files_scanned": files, "unstable_results": unstable,
                    "chunks": chunks, "chunk_only_findings": chunk_hits,
                    "tools_exposed": count_tools(d), "tool_sites": tool_sites(d), "taint_findings": c["taint"],
                    "helper_findings": c["helper"], "audit_findings": c["audit"],
                    "errors": "; ".join(errs)[:500]}
            checkpoint.write_text(json.dumps({"commit": commit, "rules": digest, "stat": stat, "rows": rows}))
            np = sum(is_priority(r) for r in rows)
            if rows:
                log(f"    -> {np} priority / {len(rows)} total finding(s)"
                    + (f"; {unstable} unstable across semgrep runs" if unstable else "")
                    + (f"; {chunk_hits} only found by chunked scan" if chunk_hits else ""))
            for e in errs[:3]:
                log(f"    [semgrep] {e}")
        all_rows += rows
        scanned.add(slug)
        stats.append(stat)

    csv_path = work / "findings.csv"
    carried = write_csv(csv_path, all_rows, load_existing(csv_path), scanned)
    write_repos_csv(work / "repos.csv", stats)
    write_summary(work / "summary.md", all_rows, stats, tiers)

    c = Counter(r["tier"] for r in all_rows)
    log(f"\n[+] {sum(is_priority(r) for r in all_rows)} priority finding(s) across {len(scanned)} "
        f"scanned repo(s); by tier: " + ", ".join(f"{t}={c.get(t, 0)}" for t in tiers))
    if carried:
        log(f"[+] kept {carried} row(s) from repos not scanned this run")
    log(f"[+] {csv_path}  (dataset + triage columns)")
    log(f"[+] {work / 'repos.csv'}  (per-repo stats)")
    log(f"[+] {work / 'summary.md'}  (triage queue)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
