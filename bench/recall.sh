#!/usr/bin/env bash
# Recall benchmark: scan three MCP servers at versions with published CVEs and
# check each known sink lands in the priority queue. Run after changing rules
# or the scanner:  make recall
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
W="${W:-$HERE/.recall}"; mkdir -p "$W"; cd "$W"
export GIT_TERMINAL_PROMPT=0
get() { [ -d "$2" ] || git clone --quiet "$1" "$2"; git -C "$2" checkout --quiet "$3"; }
get https://github.com/sammcj/mcp-package-docs     pkgdocs cb4ad49615275379fd6f2f1cf1ec4731eec56eb9^  # CVE-2025-54073
get https://github.com/Flux159/mcp-server-kubernetes k8s    v2.4.9                                     # CVE-2025-53355
get https://github.com/alexei-led/aws-mcp-server    awsmcp  2f42717^                                   # CVE-2025-5277
get https://github.com/GLips/Figma-Context-MCP      figma   v0.6.2                                     # CVE-2025-53967
rm -f run/findings.csv
python3 "$HERE/scan.py" --local "$W/pkgdocs" "$W/k8s" "$W/awsmcp" "$W/figma" --work "$W/run" | grep -E "priority"
cd "$HERE" && python3 - "$W/run/findings.csv" <<'PY'
import csv, sys
from scan import is_priority
rows = list(csv.DictReader(open(sys.argv[1])))
checks = {
    "CVE-2025-5277  aws-mcp-server        ": lambda r: r["file"].endswith("tools.py") and "command" in r["rule"],
    "CVE-2025-53355 mcp-server-kubernetes ": lambda r: r["file"].endswith("kubectl-describe.ts") and "command" in r["rule"],
    "CVE-2025-54073 mcp-package-docs      ": lambda r: r["repo"].endswith("pkgdocs") and "command" in r["rule"],
    # exec(curl ... "${url}") in a generic helper, 2 hops below the get_figma_data tool
    "CVE-2025-53967 figma-developer-mcp   ": lambda r: r["file"].endswith("fetch-with-retry.ts") and "command" in r["rule"],
}
fail = 0
for name, f in checks.items():
    hits = [r for r in rows if f(r) and is_priority(r)]
    print(name, "PASS" if hits else "FAIL", "|", hits[0]["reach_hint"] if hits else "")
    fail += not hits
sys.exit(fail)
PY
