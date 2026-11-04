#!/usr/bin/env python3
"""Generate rules/mcp-taint.yaml.

The MCP SDKs register tools in many syntactic shapes (typed / untyped,
async / sync, server.tool / registerTool / addTool / low-level handler,
@mcp.tool decorators). Writing every source variant by hand into every rule
is error-prone, so this script builds them once and shares them across all
bug-class rules. Edit here, then re-run:

    python3 tools/gen_rules.py && make test
"""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- sources ---
# Where attacker-controlled input enters: MCP tool handler parameters.

JS_CONTAINERS = [
    "$S.tool(..., {H})",
    "$S.registerTool(..., {H})",
    "$S.addTool({{..., execute: {H}, ...}})",   # fastmcp (punkpeye)
    # tool definitions as data: tool({ parameters, execute }) factories and
    # { execute_sql: { parameters, execute } } maps. Schema + handler keeps out
    # unrelated objects that merely have an execute key.
    "$F({{..., parameters: $SCHEMA, ..., execute: {H}, ...}})",
    "$F({{..., inputSchema: $SCHEMA, ..., execute: {H}, ...}})",
    "$F({{..., parameters: $SCHEMA, ..., handler: {H}, ...}})",
    "$F({{..., inputSchema: $SCHEMA, ..., handler: {H}, ...}})",
    "$V = {{..., parameters: $SCHEMA, ..., execute: {H}, ...}}",
    "$V = {{..., inputSchema: $SCHEMA, ..., execute: {H}, ...}}",
    "$V = {{..., parameters: $SCHEMA, ..., handler: {H}, ...}}",
    "$V = {{..., inputSchema: $SCHEMA, ..., handler: {H}, ...}}",
    "$KEY = {{..., $NAME: {{..., parameters: $SCHEMA, ..., execute: {H}, ...}}, ...}}",
    "$KEY = {{..., $NAME: {{..., inputSchema: $SCHEMA, ..., execute: {H}, ...}}, ...}}",
    "return {{..., $NAME: {{..., parameters: $SCHEMA, ..., execute: {H}, ...}}, ...}}",
    "return {{..., $NAME: {{..., inputSchema: $SCHEMA, ..., execute: {H}, ...}}, ...}}",
    # resources and prompts take client-supplied URIs and arguments too
    "$S.resource(..., {H})",
    "$S.registerResource(..., {H})",
    "$S.prompt(..., {H})",
    "$S.registerPrompt(..., {H})",
    # agent-framework tools (experiment 2). Vercel AI / Mastra / genkit / VoltAgent
    # `tool({{ parameters/inputSchema, execute }})` shapes are already covered by the
    # factory patterns above. These add LangChain.js, which is function-first:
    #   tool(async (input) => {{...}}, {{ name, schema }})     and the Dynamic*Tool classes
    "tool({H}, {{..., schema: $SCHEMA, ...}})",
    "tool({H}, {{..., name: $NAME, ...}})",
    "new DynamicStructuredTool({{..., func: {H}, ...}})",
    "new DynamicTool({{..., func: {H}, ...}})",
    "$F.from_function({H}, ...)",
]
# Low-level SDK handlers, by schema object or by method name (newer SDKs).
JS_REQUEST_METHODS = ["CallToolRequestSchema", '"tools/call"', "ReadResourceRequestSchema",
                      '"resources/read"', "GetPromptRequestSchema", '"prompts/get"']
# (handler form, how to select the tainted thing)
JS_HANDLERS_FOCUS = [  # untyped / typed-identifier params -> focus the param
    "async ($ARGS, ...) => {{...}}",
    "($ARGS, ...) => {{...}}",
    "async function ($ARGS, ...) {{...}}",
    "function ($ARGS, ...) {{...}}",
    "async ($ARGS: $T, ...) => {{...}}",
    "($ARGS: $T, ...) => {{...}}",
]
JS_HANDLERS_FIELD = [  # typed destructuring `({ cmd }: {cmd: string})` -> the field names
    "async ({{..., $K, ...}}: $T, ...) => {{...}}",
    "({{..., $K, ...}}: $T, ...) => {{...}}",
]


def js_sources():
    src = []
    for c in JS_CONTAINERS:
        for h in JS_HANDLERS_FOCUS:
            inside = c.format(H=h.format())
            src.append({"patterns": [{"pattern-inside": inside},
                                     {"focus-metavariable": "$ARGS"}]})
        for h in JS_HANDLERS_FIELD:
            inside = c.format(H=h.format())
            src.append({"patterns": [{"pattern-inside": inside},
                                     {"pattern": "$K"}]})
        # `const { k } = args as { k: string }`: Semgrep parses the type literal as an
        # object value and assigns k <- string, so the taint is lost. Name the bindings
        # destructured from the handler's args as sources directly, like the typed fields above.
        for h in JS_HANDLERS_FOCUS:
            inside = c.format(H=h.format())
            src.append({"patterns": [
                {"pattern-inside": inside},
                {"pattern-either": [{"pattern-inside": "const {..., $K, ...} = $ARGS as $T2;\n...\n"},
                                    {"pattern-inside": "let {..., $K, ...} = $ARGS as $T2;\n...\n"}]},
                {"pattern": "$K"}]})
    # the variables a resource handler receives after its URI: (uri, { id }) => ...
    for c in ("$S.resource(..., {H})", "$S.registerResource(..., {H})"):
        for h in ("async ($URI, $ARGS, ...) => {{...}}", "($URI, $ARGS, ...) => {{...}}"):
            src.append({"patterns": [{"pattern-inside": c.format(H=h.format())},
                                     {"focus-metavariable": "$ARGS"}]})
    # low-level SDK: server.setRequestHandler(CallToolRequestSchema, async (request) => request.params.arguments)
    for method in JS_REQUEST_METHODS:
        src.append({"patterns": [
            {"pattern-inside": f"$S.setRequestHandler({method}, ...)"},
            {"pattern": "$R.params"}]})
    src.append({"patterns": [
        {"pattern-inside": "$S.fallbackRequestHandler = $H"},
        {"pattern": "$R.params"}]})
    return src


def py_sources():
    either = []
    # MCP SDK decorators (mcp.tool / call_tool / resources / prompts).
    for deco in ("@$M.tool(...)", "@$M.tool", "@$M.call_tool(...)", "@$M.call_tool",
                 "@$M.resource(...)", "@$M.read_resource(...)", "@$M.prompt(...)", "@$M.get_prompt(...)"):
        for kw in ("def", "async def"):
            either.append({"pattern-inside": f"{deco}\n{kw} $F(..., $P, ...):\n  ...\n"})
    # Agent-framework tool decorators (experiment 2): the decorated function's
    # parameters are LLM-/prompt-controlled, like an MCP tool argument.
    #   langchain / crewai / smolagents  @tool            (bare or @mod.tool, covered above)
    #   openai-agents                    @function_tool
    #   semantic-kernel                  @kernel_function
    #   pydantic-ai                      @agent.tool_plain (@agent.tool covered above)
    #   google-adk / llama-index         @FunctionTool / wrappers (name-based, below)
    for deco in ("@tool(...)", "@tool", "@function_tool(...)", "@function_tool",
                 "@$M.function_tool(...)", "@$M.function_tool",
                 "@kernel_function(...)", "@kernel_function", "@$M.kernel_function(...)", "@$M.kernel_function",
                 "@$M.tool_plain(...)", "@$M.tool_plain", "@$M.agent_tool(...)", "@$M.agent_tool"):
        for kw in ("def", "async def"):
            either.append({"pattern-inside": f"{deco}\n{kw} $F(..., $P, ...):\n  ...\n"})
    # Class-based tools: langchain/crewai BaseTool define _run/_arun; smolagents
    # Tool defines forward. The execute method receives the tool call arguments.
    for meth in ("_run", "_arun", "forward"):
        for kw in ("def", "async def"):
            either.append({"pattern-inside": f"{kw} {meth}(self, ..., $P, ...):\n  ...\n"})
    return [{"patterns": [{"pattern-either": either},
                          {"metavariable-regex": {"metavariable": "$P", "regex": "^(?!self$|cls$)"}},
                          {"focus-metavariable": "$P"}]}]


# Helper tier: real servers dispatch from the tool handler into helper
# functions (this.handleX(args), kubectlDescribe(input), run_cmd(cmd)).
# Semgrep OSS taint is intraprocedural, so the handler-param sources above
# cannot follow that call. This tier treats ANY function/method parameter as a
# source; the scanner then checks whether the function is referenced from
# tool-registration code (reach_hint) to prioritize.
JS_HELPER_FOCUS = [
    "function $F(..., $P, ...) {...}", "async function $F(..., $P, ...) {...}",
    "$F(..., $P, ...) {...}", "async $F(..., $P, ...) {...}",
    "(..., $P, ...) => {...}", "async (..., $P, ...) => {...}",
    "function $F(..., $P: $T, ...) {...}", "async function $F(..., $P: $T, ...) {...}",
    "$F(..., $P: $T, ...) {...}", "async $F(..., $P: $T, ...) {...}",
    "(..., $P: $T, ...) => {...}", "async (..., $P: $T, ...) => {...}",
]
JS_HELPER_FIELD = [
    "function $F(..., {..., $K, ...}: $T, ...) {...}", "async function $F(..., {..., $K, ...}: $T, ...) {...}",
    "$F(..., {..., $K, ...}: $T, ...) {...}", "async $F(..., {..., $K, ...}: $T, ...) {...}",
    "(..., {..., $K, ...}: $T, ...) => {...}", "async (..., {..., $K, ...}: $T, ...) => {...}",
]


def js_helper_sources():
    src = [{"patterns": [{"pattern-inside": h}, {"focus-metavariable": "$P"}]} for h in JS_HELPER_FOCUS]
    src += [{"patterns": [{"pattern-inside": h}, {"pattern": "$K"}]} for h in JS_HELPER_FIELD]
    # bindings destructured from a cast parameter, see js_sources()
    src.append({"patterns": [
        {"pattern-either": [{"pattern-inside": "const {..., $K, ...} = $X as $T;\n...\n"},
                            {"pattern-inside": "let {..., $K, ...} = $X as $T;\n...\n"}]},
        {"pattern": "$K"}]})
    return src


def py_helper_sources():
    return [{"patterns": [
        {"pattern-either": [{"pattern-inside": "def $F(..., $P, ...):\n  ...\n"},
                            {"pattern-inside": "async def $F(..., $P, ...):\n  ...\n"}]},
        {"metavariable-regex": {"metavariable": "$P", "regex": "^(?!self$|cls$)"}},
        {"focus-metavariable": "$P"}]}]


# ------------------------------------------------------------------ sinks ---

def sink(patterns, focus, extra=None):
    body = [{"pattern-either": [{"pattern": p} for p in patterns]}]
    if extra:
        body += extra
    body.append({"focus-metavariable": focus})
    return {"patterns": body}


SQL_OBJ = r"(?i)(db|database|conn|connection|client|pool|knex|sql|sequelize|pg|mysql|sqlite|tx|trx|duckdb)"

CP = {"metavariable-regex": {"metavariable": "$CP",
                             "regex": r"^(child_process|childProcess|cp|proc|childproc)$"}}

# spawn(..., {shell: true}) is already reported as command injection.
NOT_SHELL = [{"pattern-not": "$FN(..., {..., shell: true, ...})"},
             {"pattern-not": "$O.$FN(..., {..., shell: true, ...})"}]

JS_RULES = [
    dict(id="mcp-js-command-injection", severity="ERROR", cwe="CWE-78", impact="RCE",
         message="MCP tool argument reaches a shell-command sink. Shell metacharacters "
                 "(; | $() `) in the argument execute arbitrary commands on the server host. "
                 "Fix: execFile/spawn with an args array and no shell.",
         sinks=[
             sink(["exec($C, ...)", "execSync($C, ...)", "execaCommand($C, ...)",
                   "execaCommandSync($C, ...)", "$EX.command($C, ...)"], "$C"),
             sink(["$CP.exec($C, ...)", "$CP.execSync($C, ...)"], "$C", [CP]),
             # promisify(exec) aliases: const execAsync = promisify(exec)
             sink(["$EA($C, ...)"], "$C", [{"metavariable-regex": {"metavariable": "$EA",
                 "regex": r"^(execAsync|execPromise|execPromisified|pExec|asyncExec|promiseExec|execP|exec_async|runShell|shellExec)$"}}]),
             sink(["spawn($C, ..., {..., shell: true, ...})",
                   "spawnSync($C, ..., {..., shell: true, ...})",
                   "$CP.spawn($C, ..., {..., shell: true, ...})",
                   "$CP.spawnSync($C, ..., {..., shell: true, ...})"], "$C"),
         ]),
    dict(id="mcp-js-argument-injection", severity="WARNING", cwe="CWE-88", impact="RCE/file-write (tool-dependent)",
         message="MCP tool argument flows into the argv of a spawned program (no shell). "
                 "If the program is attacker-chosen this is RCE; otherwise check for option "
                 "injection (e.g. git --upload-pack=, ssh -oProxyCommand=, curl -o, tar --checkpoint-action). "
                 "Fix: allowlist the binary, insert '--' before user args, reject leading '-'.",
         sinks=[
             sink(["execFile($C, ...)", "execFileSync($C, ...)", "spawn($C, ...)", "spawnSync($C, ...)",
                   "$CP.execFile($C, ...)", "$CP.execFileSync($C, ...)", "$CP.spawn($C, ...)",
                   "$CP.spawnSync($C, ...)", "execa($C, ...)", "execaSync($C, ...)"], "$C", NOT_SHELL),
             sink(["execFile($B, $C, ...)", "execFileSync($B, $C, ...)", "spawn($B, $C, ...)",
                   "spawnSync($B, $C, ...)", "$CP.execFile($B, $C, ...)", "$CP.spawn($B, $C, ...)",
                   "$CP.spawnSync($B, $C, ...)", "execa($B, $C, ...)", "execaSync($B, $C, ...)"], "$C", NOT_SHELL),
         ]),
    dict(id="mcp-js-path-traversal", severity="WARNING", cwe="CWE-22", impact="arbitrary file read/write",
         message="MCP tool argument is used as a filesystem path. Without resolving it and "
                 "checking it stays under an allowed base directory, '../' or an absolute path "
                 "reads/writes arbitrary files. Note: a path.resolve()+startsWith() containment "
                 "check is NOT modeled here — verify by hand before reporting.",
         sinks=[
             sink(["$FS.$M($P, ...)"], "$P", [
                 {"metavariable-regex": {"metavariable": "$FS",
                                         "regex": r"^(fs|fsp|fsPromises|promises|fs\.promises|fse|fsExtra)$"}},
                 {"metavariable-regex": {"metavariable": "$M",
                                         "regex": r"^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|readdir|readdirSync|mkdir|mkdirSync|copyFile|copyFileSync|rename|renameSync|open|openSync|stat|statSync|outputFile|remove|move|copy)$"}}]),
             sink(["readFile($P, ...)", "writeFile($P, ...)", "appendFile($P, ...)", "readdir($P, ...)",
                   "unlink($P, ...)", "rm($P, ...)", "readFileSync($P, ...)", "writeFileSync($P, ...)"], "$P"),
         ],
         sanitizers=["path.basename(...)", "basename(...)"]),
    dict(id="mcp-js-ssrf", severity="WARNING", cwe="CWE-918", impact="SSRF",
         message="MCP tool argument controls the URL of an outbound request. With no host "
                 "allowlist and no block on loopback/link-local/metadata ranges, the tool can "
                 "reach internal services or cloud metadata (169.254.169.254). Test only against "
                 "a canary listener you own.",
         sinks=[
             sink(["fetch($U, ...)", "axios($U, ...)", "axios.$M($U, ...)", "got($U, ...)",
                   "got.$M($U, ...)", "http.get($U, ...)", "https.get($U, ...)",
                   "http.request($U, ...)", "https.request($U, ...)", "undici.request($U, ...)",
                   "$PAGE.goto($U, ...)", "ky($U, ...)", "ky.$M($U, ...)", "superagent.$M($U, ...)"], "$U"),
         ]),
    dict(id="mcp-js-code-injection", severity="ERROR", cwe="CWE-94", impact="RCE",
         message="MCP tool argument is evaluated as code. This is direct code execution in the "
                 "server process. If this is an intentional 'run code' tool, check whether it "
                 "claims to be sandboxed — vm/vm2 are not security boundaries.",
         sinks=[
             sink(["eval($X)", "new Function(..., $X)", "Function(..., $X)",
                   "vm.runInThisContext($X, ...)", "vm.runInNewContext($X, ...)",
                   "vm.runInContext($X, ...)", "new vm.Script($X, ...)"], "$X"),
             # vm2-style sandboxes only; a bare .run( is usually a prepared statement or a job
             sink(["$VM.run($X, ...)", "$VM.runInContext($X, ...)"], "$X", [
                 {"metavariable-regex": {"metavariable": "$VM",
                                         "regex": r"^(vm|vm2|VM|nodeVm|nodeVM|sandbox|sandboxVm|isolate|jail|safeVm|ses)$"}}]),
         ]),
    dict(id="mcp-js-sql-injection", severity="WARNING", cwe="CWE-89", impact="SQL injection",
         message="MCP tool argument reaches a SQL query string. If it is concatenated/templated "
                 "into the query, that is SQL injection; use parameters. If the tool is meant to "
                 "run arbitrary SQL, check for a claimed read-only mode that can be bypassed "
                 "(stacked queries, ATTACH, COPY ... PROGRAM, writable CTEs).",
         sinks=[
             # methods whose first argument is always query text
             sink(["$DB.$M($Q, ...)"], "$Q", [
                 {"metavariable-regex": {"metavariable": "$DB", "regex": SQL_OBJ}},
                 {"metavariable-regex": {"metavariable": "$M",
                                         "regex": r"^(query|prepare|raw|unsafe|execute|exec)$"}}]),
             # methods that take query text on a db object but bound values on a prepared
             # statement: db.run(sql) is a sink, db.prepare(sql).run(v) and stmt.run(v) are not
             sink(["$DB.$M($Q, ...)"], "$Q", [
                 {"metavariable-regex": {"metavariable": "$DB", "regex": SQL_OBJ}},
                 {"metavariable-regex": {"metavariable": "$M", "regex": r"^(run|all|each|get)$"}},
                 {"pattern-not": "$X.prepare(...).$M($Q, ...)"},
                 {"pattern-not-inside": "const $DB = $X.prepare(...);\n...\n"},
                 {"pattern-not-inside": "let $DB = $X.prepare(...);\n...\n"},
                 {"pattern-not-inside": "$DB = $X.prepare(...);\n...\n"}]),
         ]),
]

PY_RULES = [
    dict(id="mcp-py-command-injection", severity="ERROR", cwe="CWE-78", impact="RCE",
         message="MCP tool argument reaches a shell-command sink. Shell metacharacters in the "
                 "argument execute arbitrary commands on the server host. Fix: pass an args "
                 "list without shell=True.",
         sinks=[
             sink(["subprocess.$F($C, ..., shell=True, ...)", "os.system($C)", "os.popen($C, ...)",
                   "subprocess.getoutput($C)", "subprocess.getstatusoutput($C)",
                   "asyncio.create_subprocess_shell($C, ...)", "commands.getoutput($C)"], "$C"),
         ],
         sanitizers=["shlex.quote(...)", "pipes.quote(...)"]),
    dict(id="mcp-py-argument-injection", severity="WARNING", cwe="CWE-88", impact="RCE/file-write (tool-dependent)",
         message="MCP tool argument flows into the argv of a spawned program (no shell). If the "
                 "program is attacker-chosen this is RCE; otherwise check for option injection "
                 "(git --upload-pack=, ssh -oProxyCommand=, curl -o, tar --checkpoint-action). "
                 "Fix: allowlist the binary, insert '--' before user args, reject leading '-'.",
         sinks=[
             {"patterns": [
                 {"pattern-either": [{"pattern": "subprocess.$F($C, ...)"}]},
                 {"pattern-not": "subprocess.$F($C, ..., shell=True, ...)"},
                 {"metavariable-regex": {"metavariable": "$F",
                                         "regex": "^(run|call|check_call|check_output|Popen)$"}},
                 {"focus-metavariable": "$C"}]},
             sink(["asyncio.create_subprocess_exec(..., $C, ...)", "os.execv($C, ...)",
                   "os.execvp($C, ...)", "os.spawnv($M, $C, ...)"], "$C"),
         ]),
    dict(id="mcp-py-path-traversal", severity="WARNING", cwe="CWE-22", impact="arbitrary file read/write",
         message="MCP tool argument is used as a filesystem path. Without resolving it "
                 "(os.path.realpath / Path.resolve) and checking it stays under an allowed base "
                 "directory, '../' or an absolute path reads/writes arbitrary files. Containment "
                 "checks are NOT modeled here — verify by hand before reporting.",
         sinks=[
             sink(["open($P, ...)", "io.open($P, ...)", "aiofiles.open($P, ...)", "Path(..., $P, ...)",
                   "pathlib.Path(..., $P, ...)", "os.remove($P)", "os.unlink($P)", "os.rmdir($P)",
                   "os.listdir($P)", "os.makedirs($P, ...)", "os.rename($P, ...)",
                   "shutil.rmtree($P, ...)", "shutil.copy($P, ...)", "shutil.copyfile($P, ...)",
                   "shutil.move($P, ...)", "send_file($P, ...)", "FileResponse($P, ...)"], "$P"),
         ],
         sanitizers=["os.path.basename(...)", "secure_filename(...)"]),
    dict(id="mcp-py-ssrf", severity="WARNING", cwe="CWE-918", impact="SSRF",
         message="MCP tool argument controls the URL of an outbound request. With no host "
                 "allowlist and no block on loopback/link-local/metadata ranges, the tool can "
                 "reach internal services or cloud metadata. Test only against a canary you own.",
         sinks=[
             sink(["requests.$M($U, ...)", "httpx.$M($U, ...)", "urllib.request.urlopen($U, ...)",
                   "urlopen($U, ...)", "urllib3.request($M, $U, ...)", "aiohttp.request($M, $U, ...)"], "$U"),
             {"patterns": [
                 {"pattern-either": [
                     {"pattern-inside": "with httpx.Client(...) as $CL:\n  ...\n"},
                     {"pattern-inside": "async with httpx.AsyncClient(...) as $CL:\n  ...\n"},
                     {"pattern-inside": "async with aiohttp.ClientSession(...) as $CL:\n  ...\n"},
                     {"pattern-inside": "with requests.Session(...) as $CL:\n  ...\n"},
                 ]},
                 {"pattern": "$CL.$M($U, ...)"},
                 {"metavariable-regex": {"metavariable": "$M",
                                         "regex": "^(get|post|put|delete|patch|head|request|stream)$"}},
                 {"focus-metavariable": "$U"}]},
         ]),
    dict(id="mcp-py-code-injection", severity="ERROR", cwe="CWE-94", impact="RCE",
         message="MCP tool argument is evaluated as code or deserialized unsafely "
                 "(eval/exec/pickle/marshal/unsafe yaml/torch.load without weights_only). This is "
                 "code execution in the server process.",
         sinks=[
             sink(["eval($X, ...)", "exec($X, ...)", "compile($X, ...)", "pickle.loads($X, ...)",
                   "pickle.load($X, ...)", "marshal.loads($X)", "dill.loads($X, ...)",
                   "dill.load($X, ...)", "joblib.load($X, ...)", "yaml.unsafe_load($X)",
                   "cloudpickle.loads($X, ...)"], "$X"),
             {"patterns": [
                 {"pattern": "yaml.load($X, ...)"},
                 {"pattern-not": "yaml.load($X, Loader=yaml.SafeLoader)"},
                 {"pattern-not": "yaml.load($X, Loader=SafeLoader)"},
                 {"pattern-not": "yaml.load($X, Loader=yaml.CSafeLoader)"},
                 {"focus-metavariable": "$X"}]},
             {"patterns": [
                 {"pattern": "torch.load($X, ...)"},
                 {"pattern-not": "torch.load($X, ..., weights_only=True, ...)"},
                 {"focus-metavariable": "$X"}]},
         ]),
    dict(id="mcp-py-sql-injection", severity="WARNING", cwe="CWE-89", impact="SQL injection",
         message="MCP tool argument reaches a SQL query string. If it is formatted/concatenated "
                 "into the query, that is SQL injection; use parameters. If the tool is meant to "
                 "run arbitrary SQL, check for a claimed read-only mode that can be bypassed.",
         sinks=[
             sink(["$CUR.execute($Q, ...)", "$CUR.executemany($Q, ...)", "$CUR.executescript($Q)",
                   "sqlalchemy.text($Q)", "text($Q)", "pd.read_sql($Q, ...)",
                   "pandas.read_sql($Q, ...)", "$CON.sql($Q, ...)"], "$Q"),
         ]),
]


def build(rule, languages, sources, tier="taint"):
    out = {
        "id": rule["id"] + ("-helper" if tier == "helper" else ""),
        "mode": "taint",
        "languages": languages,
        "severity": rule["severity"],
        "message": (rule["message"] if tier == "taint" else
                    "[helper tier] A function parameter reaches this sink. Confirm the function is "
                    "called with MCP tool input (see reach_hint in findings.csv). " + rule["message"]),
        "metadata": {
            "cwe": rule["cwe"],
            "impact": rule["impact"],
            "category": "security",
            "confidence": "MEDIUM" if tier == "taint" else "LOW",
            "tier": tier,
            "source": ("MCP tool handler parameter" if tier == "taint"
                       else "any function parameter (check the function is reachable from a tool)"),
            "references": ["https://modelcontextprotocol.io/specification"],
        },
        "pattern-sources": sources,
        "pattern-sinks": rule["sinks"],
    }
    san = rule.get("sanitizers")
    if san:
        out["pattern-sanitizers"] = [{"pattern": s} for s in san]
    return out


def audit_sink(s):
    """Turn a taint sink into a plain search clause: same match, minus the
    focus, and skipped when the focused argument is a string literal."""
    pats = [p for p in s["patterns"] if "focus-metavariable" not in p]
    mv = next(p["focus-metavariable"] for p in s["patterns"] if "focus-metavariable" in p)
    pats.append({"metavariable-pattern": {"metavariable": mv,
                                          "patterns": [{"pattern-not": '"..."'}]}})
    return {"patterns": pats}


def build_audit(rule, languages):
    return {
        "id": rule["id"] + "-audit",
        "languages": languages,
        "severity": "INFO",
        "message": "[audit, no taint tracking] Non-literal value reaches a dangerous sink. "
                   "Use for servers whose tool registration the taint rules do not recognize "
                   "(custom wrappers, class-based tools). Expect many false positives. "
                   + rule["message"],
        "metadata": {"cwe": rule["cwe"], "impact": rule["impact"], "category": "security",
                     "confidence": "LOW", "tier": "audit", "source": "none (sink-only)"},
        "pattern-either": [audit_sink(s) for s in rule["sinks"]],
    }


def dump(path, rules, header):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + yaml.safe_dump({"rules": rules}, sort_keys=False, width=110))
    print(f"wrote {path} ({len(rules)} rules)")


def main():
    js_src, py_src = js_sources(), py_sources()
    js, py = ["javascript", "typescript"], ["python"]
    gen = "# GENERATED by tools/gen_rules.py — edit the generator, not this file.\n"

    taint = [build(r, js, js_src) for r in JS_RULES] + [build(r, py, py_src) for r in PY_RULES]
    dump(ROOT / "rules" / "mcp-taint.yaml", taint,
         gen + "# Taint rules: MCP tool-handler parameters (sources) -> dangerous sinks.\n")

    helper = ([build(r, js, js_helper_sources(), "helper") for r in JS_RULES]
              + [build(r, py, py_helper_sources(), "helper") for r in PY_RULES])
    dump(ROOT / "rules" / "mcp-helper.yaml", helper,
         gen + "# Helper tier: any function parameter -> dangerous sink (covers handler->helper dispatch).\n")

    audit = [build_audit(r, js) for r in JS_RULES] + [build_audit(r, py) for r in PY_RULES]
    dump(ROOT / "rules-audit" / "mcp-sinks-audit.yaml", audit,
         gen + "# Audit tier (opt-in, noisy): sinks with any non-literal argument, no taint.\n")


if __name__ == "__main__":
    main()
