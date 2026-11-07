"""Faithful repro of nexent sdk/nexent/core/tools/create_file_tool.py _validate_path()
(lines ~85-101, byte-identical below). Demonstrates the workspace-confinement bypass:
the guard `abs_path.startswith(self.init_path)` has NO trailing separator, so a sibling
path sharing the string prefix passes. Benign canary; runs under bwrap."""
import os
class Tool:
    def __init__(self, init_path): self.init_path = init_path
    def _validate_path(self, file_path):
        # ---- verbatim from create_file_tool.py ----
        if os.path.isabs(file_path):
            abs_path = os.path.abspath(file_path)
        else:
            abs_path = os.path.abspath(os.path.join(self.init_path, file_path))
        abs_path = os.path.normpath(abs_path)
        if not abs_path.startswith(self.init_path):
            raise Exception(f"Permission denied: outside workspace '{self.init_path}'")
        return abs_path

ws = "/work/mnt/nexent"                 # the claimed workspace root
os.makedirs(ws, exist_ok=True)
t = Tool(ws)
tests = [
    ("intended (inside)",        "notes.txt"),
    ("traversal to parent",      "../../../etc/shadow"),   # should be blocked (not prefixed)
    ("ATTACK: sibling prefix",   "/work/mnt/nexent-secrets/stolen.txt"),  # shares '/work/mnt/nexent'
    ("ATTACK: prefix no-sep",    "/work/mnt/nexentX/evil.txt"),
]
for label, fp in tests:
    try:
        rv = t._validate_path(fp)
        inside = rv == ws or rv.startswith(ws + os.sep)
        print(f"{label:26} input={fp!r}\n   -> ACCEPTED as {rv!r}   inside-workspace? {inside}")
    except Exception as e:
        print(f"{label:26} input={fp!r}\n   -> BLOCKED ({e})")
# prove a real write escapes to a sibling dir outside the workspace
esc = t._validate_path("/work/mnt/nexent-secrets/CANARY.txt")
os.makedirs(os.path.dirname(esc), exist_ok=True)
open(esc,"w").write("benign")
print("\nRESULT:", "ESCAPE CONFIRMED — validator accepted + wrote OUTSIDE the workspace:" if os.path.exists(esc) and not esc.startswith(ws+os.sep) else "no escape", esc)
