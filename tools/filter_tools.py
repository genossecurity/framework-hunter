#!/usr/bin/env python3
"""Tool-only funnel: keep targets whose cloned source builds an MCP server that registers tools.

Reads clones already on disk (scan.py fetches them); order and comments are kept. Every
target lands in exactly one stage, so the funnel's numbers add up and can go in a paper:

    python3 tools/filter_tools.py repos-top200-downloads.txt \
        --src mcp-scan/src -o repos-top200-downloads-tools.txt --csv funnel.csv
"""
import argparse
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scan import TEST_PATH_RE, has_mcp_server, parse_targets, slug_for, tool_sites  # noqa: E402

STAGES = ["tools", "server, no tool sites", "server, unsupported language", "no MCP server", "not cloned"]
# SDK names, or the protocol's method name for hand-written servers (mockserver's McpRequestProcessor)
TOOLS_CALL = r"""|["']tools/call["']"""
OTHER_LANG = {
    ".go": re.compile(r"mark3labs/mcp-go|modelcontextprotocol/go-sdk|metoro-io/mcp-golang" + TOOLS_CALL),
    ".cs": re.compile(r"\bModelContextProtocol\b.*\bServer\b|\[McpServerTool" + TOOLS_CALL),
    ".java": re.compile(r"io\.modelcontextprotocol|McpServerFeatures|McpSyncServer|McpAsyncServer|@McpTool" + TOOLS_CALL),
    ".kt": re.compile(r"io\.modelcontextprotocol|McpServerFeatures" + TOOLS_CALL),
    ".rs": re.compile(r"\brmcp::|\bmcp_server\b|#\[tool_router\]" + TOOLS_CALL),
    ".c": re.compile(TOOLS_CALL.lstrip("|")),
    ".cpp": re.compile(TOOLS_CALL.lstrip("|")),
    ".rb": re.compile(TOOLS_CALL.lstrip("|")),
    ".php": re.compile(TOOLS_CALL.lstrip("|")),
    ".swift": re.compile(TOOLS_CALL.lstrip("|")),
}
MAX_FILE = 2_000_000


def other_language_server(root: Path) -> str:
    """The language of an MCP server the scanner cannot read, or ''."""
    for p in root.rglob("*"):
        rx = OTHER_LANG.get(p.suffix)
        if rx is None or not p.is_file() or ".git" in p.parts or "node_modules" in p.parts:
            continue
        rel = str(p.relative_to(root))
        if TEST_PATH_RE.search(rel) or re.search(r"(^|/)src/test/|Tests?(/|\.)", rel) or p.stat().st_size > MAX_FILE:
            continue
        try:
            if rx.search(p.read_text(errors="replace")):
                return p.suffix.lstrip(".")
        except OSError:
            continue
    return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos")
    ap.add_argument("--src", default="mcp-scan/src", help="directory holding the clones")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--csv", help="also write one row per target: repo, stage, tool_sites, language")
    args = ap.parse_args()

    src = Path(args.src)
    kept, counts, rows = {}, dict.fromkeys(STAGES, 0), []
    for target in parse_targets(Path(args.repos)):
        root = src / slug_for(target)
        sites, lang = 0, ""
        if not (root / ".git").exists():
            stage = "not cloned"
        elif has_mcp_server(root):
            sites = tool_sites(root)
            stage = "tools" if sites else "server, no tool sites"
        else:
            lang = other_language_server(root)
            stage = "server, unsupported language" if lang else "no MCP server"
        counts[stage] += 1
        rows.append({"repo": target, "stage": stage, "tool_sites": sites, "language": lang})
        print(f"{stage:29} {sites:5} {lang:5} {target}")
        if stage == "tools":
            kept[target] = sites

    lines = [f"# filtered from {args.repos}: repos whose source builds an MCP server with tools"]
    for raw in Path(args.repos).read_text().splitlines():
        target = raw.split("#", 1)[0].strip()
        if target in kept:
            lines.append(f"{raw.split('  tool_sites=')[0]}  tool_sites={kept[target]}")
    Path(args.output).write_text("\n".join(lines) + "\n")
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["repo", "stage", "tool_sites", "language"])
            w.writeheader()
            w.writerows(rows)

    print(f"\nFUNNEL  {len(rows)} targets")
    for stage in STAGES:
        print(f"  {counts[stage]:5}  {stage}")
    print(f"  -> {args.output}")


if __name__ == "__main__":
    main()
