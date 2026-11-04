"""Faithful repro of ApodexAI/FrontierAgent plugins/tools/write_file.py no-sandbox
local fallback (HEAD cc32d88). Lines below are byte-identical to the repo:

  _LOCAL_OUTPUT_DIR = "/tmp/agent-outputs"                       # write_file.py:29
  if not path.startswith(_LOCAL_OUTPUT_DIR):                     # write_file.py:106
      path = os.path.join(_LOCAL_OUTPUT_DIR, os.path.basename(path))  # :107
  os.makedirs(os.path.dirname(path), exist_ok=True)             # :111
  with open(path, mode, encoding="utf-8") as f: f.write(content)# :112

Reached only in no-sandbox mode (sandbox_available() False). resolve_runtime_path()
returns a non-alias path UNCHANGED (_sandbox.py:'return path'); _authorized_local_path()
returns None for an unauthorized path -> this fallback runs. Benign canary only; no network.
"""
import os

_LOCAL_OUTPUT_DIR = "/tmp/agent-outputs"

def write_file_fallback(path: str, content: str) -> str:
    # --- verbatim fallback logic ---
    if not path.startswith(_LOCAL_OUTPUT_DIR):
        path = os.path.join(_LOCAL_OUTPUT_DIR, os.path.basename(path))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.realpath(path)

os.makedirs(_LOCAL_OUTPUT_DIR, exist_ok=True)
print("confinement claim: writes land under", _LOCAL_OUTPUT_DIR, "\n")

cases = [
    ("control: normal name",        "report.txt"),
    ("control: absolute elsewhere", "/tmp/other/x.txt"),
    ("ATTACK: dotdot traversal",    "/tmp/agent-outputs/../PWNED_OUTSIDE.txt"),
]
for label, p in cases:
    where = write_file_fallback(p, "benign-canary")
    inside = where == os.path.realpath(_LOCAL_OUTPUT_DIR) or where.startswith(os.path.realpath(_LOCAL_OUTPUT_DIR) + os.sep)
    print(f"{label}\n   input : {p}\n   wrote : {where}\n   inside confinement? {inside}\n")

esc = os.path.realpath("/tmp/agent-outputs/../PWNED_OUTSIDE.txt")
print("RESULT:", "ESCAPE CONFIRMED — file written outside /tmp/agent-outputs:" if os.path.exists(esc) and not esc.startswith(os.path.realpath(_LOCAL_OUTPUT_DIR)+os.sep) else "no escape", esc)
