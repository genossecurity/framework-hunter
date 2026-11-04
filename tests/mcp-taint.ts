// Fixtures for rules/mcp-taint.yaml (JS/TS rules).
// A 'ruleid' annotation means the next line MUST be flagged by that rule;
// an 'ok' annotation means it must NOT be flagged.
// Run: semgrep --test --config rules/ tests/   (or: make test)
import { exec, execSync, execFile, spawn } from "child_process";
import * as child_process from "child_process";
import * as fs from "fs";
import { readFile } from "fs/promises";
import * as path from "path";
import axios from "axios";
import * as vm from "vm";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new McpServer({ name: "fixture", version: "0.0.0" });

// ---------------------------------------------------------------- command injection
server.tool("ping", { host: z.string() }, async ({ host }) => {
  // ruleid: mcp-js-command-injection
  exec(`ping -c 1 ${host}`);
  return { content: [] };
});

server.tool("git_log", "show log", { repo: z.string() }, async ({ repo }: { repo: string }) => {
  const cmd = "git -C " + repo + " log";
  // ruleid: mcp-js-command-injection
  const out = child_process.execSync(cmd);
  return { content: [{ type: "text", text: out.toString() }] };
});

server.tool("shell_spawn", { c: z.string() }, async (args) => {
  // ruleid: mcp-js-command-injection
  spawn(args.c, [], { shell: true });
  return { content: [] };
});

server.tool("static_cmd", { x: z.string() }, async ({ x }) => {
  // ok: mcp-js-command-injection
  exec("uptime");
  return { content: [{ type: "text", text: x }] };
});

// ---------------------------------------------------------------- argument injection
server.tool("git_clone", { url: z.string() }, async ({ url }) => {
  // ruleid: mcp-js-argument-injection
  execFile("git", ["clone", url]);
  return { content: [] };
});

server.tool("safe_spawn", { n: z.number() }, async ({ n }) => {
  // ok: mcp-js-argument-injection
  spawn("ls", ["-la"]);
  return { content: [{ type: "text", text: String(n) }] };
});

// ---------------------------------------------------------------- path traversal
server.registerTool("read_file", { inputSchema: { p: z.string() } }, async ({ p }) => {
  // ruleid: mcp-js-path-traversal
  const data = fs.readFileSync(p, "utf8");
  return { content: [{ type: "text", text: data }] };
});

server.tool("read_doc", { name: z.string() }, async ({ name }) => {
  const full = path.join("/srv/docs", name);
  // ruleid: mcp-js-path-traversal
  const data = await readFile(full, "utf8");
  return { content: [{ type: "text", text: data }] };
});

server.tool("read_basename", { name: z.string() }, async ({ name }) => {
  // ok: mcp-js-path-traversal
  const data = fs.readFileSync(path.join("/srv/docs", path.basename(name)), "utf8");
  return { content: [{ type: "text", text: data }] };
});

// ---------------------------------------------------------------- SSRF
server.addTool({
  name: "fetch_url",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    // ruleid: mcp-js-ssrf
    const r = await fetch(args.url);
    return await r.text();
  },
});

server.tool("get_json", { u: z.string() }, async ({ u }) => {
  // ruleid: mcp-js-ssrf
  const r = await axios.get(u);
  return { content: [{ type: "text", text: JSON.stringify(r.data) }] };
});

server.tool("fixed_fetch", { q: z.string() }, async ({ q }) => {
  // ok: mcp-js-ssrf
  const r = await fetch("https://api.example.com/status");
  return { content: [{ type: "text", text: q + (await r.text()) }] };
});

// ---------------------------------------------------------------- code injection
server.tool("calc", { expr: z.string() }, async ({ expr }) => {
  // ruleid: mcp-js-code-injection
  const v = eval(expr);
  return { content: [{ type: "text", text: String(v) }] };
});

server.tool("sandbox", { code: z.string() }, async ({ code }) => {
  // ruleid: mcp-js-code-injection
  const v = vm.runInNewContext(code, {});
  return { content: [{ type: "text", text: String(v) }] };
});

// ---------------------------------------------------------------- SQL injection
declare const db: any;
server.tool("lookup", { user: z.string() }, async ({ user }) => {
  // ruleid: mcp-js-sql-injection
  const rows = db.query(`SELECT * FROM users WHERE name = '${user}'`);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});

server.tool("lookup_safe", { user: z.string() }, async ({ user }) => {
  // ok: mcp-js-sql-injection
  const rows = db.query("SELECT * FROM users WHERE name = ?", [user]);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});

// ---------------------------------------------------------------- low-level SDK handler
server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  if (name === "run") {
    // ruleid: mcp-js-command-injection
    execSync("bash -c " + (args as any).script);
  }
  return { content: [] };
});

// ---------------------------------------------------------------- not a tool handler: no source
function helper(userInput: string) {
  // ok: mcp-js-command-injection
  exec(userInput);
}

// ---------------------------------------------------------------- tool definitions as data
const factoryTool = injectableTool({
  description: "factory",
  parameters: z.object({ host: z.string() }),
  execute: async ({ host }) => {
    // ruleid: mcp-js-command-injection
    exec(`ping ${host}`);
  },
});

const aiTool = tool({
  inputSchema: z.object({ file: z.string() }),
  handler: async (args) => {
    // ruleid: mcp-js-path-traversal
    return fs.readFileSync(args.file);
  },
});

const toolMap = {
  run_it: {
    description: "map entry",
    parameters: z.object({ cmd: z.string() }),
    execute: async ({ cmd }) => {
      // ruleid: mcp-js-command-injection
      exec(cmd);
    },
  },
};

function getTools() {
  return {
    fetch_it: {
      inputSchema: z.object({ url: z.string() }),
      execute: async ({ url }) => {
        // ruleid: mcp-js-ssrf
        return fetch(url);
      },
    },
  };
}

// a job runner, not a tool: an execute key with no schema beside it
const job = {
  name: "cleanup",
  execute: async (command) => {
    // ok: mcp-js-command-injection
    exec(command);
  },
};

// a client calling a tool is not a tool definition
async function clientSide(client, cmd) {
  // ok: mcp-js-command-injection
  exec("uptime");
  return client.callTool({ name: "x", arguments: { cmd } });
}

// ---------------------------------------------------------------- low-level handlers
server.setRequestHandler("tools/call", async (request) => {
  // ruleid: mcp-js-command-injection
  exec(request.params.arguments.cmd);
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  // ruleid: mcp-js-path-traversal
  return fs.readFileSync(request.params.uri);
});

server.setRequestHandler("resources/read", async (request) => {
  // ruleid: mcp-js-path-traversal
  return fs.readFileSync(request.params.uri);
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  // ruleid: mcp-js-command-injection
  exec(request.params.arguments.cmd);
});

server.setRequestHandler(ListToolsRequestSchema, async (request) => {
  // ok: mcp-js-command-injection
  exec(request.params.cursor);
});

server.fallbackRequestHandler = async (request) => {
  // ruleid: mcp-js-command-injection
  exec(request.params.arguments.cmd);
};

// ---------------------------------------------------------------- resources and prompts
server.resource("file", template, async (uri, { name }) => {
  // ruleid: mcp-js-path-traversal
  return fs.readFileSync(name);
});

server.registerResource("doc", template, {}, async (uri) => {
  // ruleid: mcp-js-path-traversal
  return fs.readFileSync(uri.pathname);
});

server.prompt("review", { cmd: z.string() }, async ({ cmd }) => {
  // ruleid: mcp-js-command-injection
  exec(cmd);
});

// ---------------------------------------------------------------- prepared statements and sandboxes
declare const VM: any;
server.tool("bound_params", { user: z.string() }, async ({ user }) => {
  const stmt = db.prepare("SELECT * FROM users WHERE name = ?");
  // ok: mcp-js-sql-injection
  const rows = stmt.all(user);
  // ok: mcp-js-code-injection
  stmt.run(user);
  // ok: mcp-js-sql-injection
  db.prepare("DELETE FROM users WHERE name = ?").run(user);
  const dbStmt = db.prepare("UPDATE users SET seen = 1 WHERE name = ?");
  // ok: mcp-js-sql-injection
  dbStmt.run(user);
  // ruleid: mcp-js-sql-injection
  db.prepare(`SELECT * FROM ${user}`).all();
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});

server.tool("vm2_run", { code: z.string() }, async ({ code }) => {
  const vm = new VM();
  // ruleid: mcp-js-code-injection
  vm.run(code);
  return { content: [] };
});

server.tool("chained_prepare", { table: z.string(), id: z.number() }, async ({ table, id }) => {
  // ruleid: mcp-js-sql-injection
  db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
  // ruleid: mcp-js-sql-injection
  db.run(`DELETE FROM ${table}`);
  return { content: [] };
});

// ---------------------------------------------------------------- destructuring from a cast (firecrawl shape)
declare const log: any;
server.addTool({
  name: "parse_file",
  parameters: z.object({ filePath: z.string() }),
  execute: async (args: unknown, { log: l }): Promise<any> => {
    const { filePath, contentType: ct, ...options } = args as { filePath: string; contentType?: string } & Record<string, unknown>;
    const absPath = path.resolve(filePath);
    // ruleid: mcp-js-path-traversal
    const buffer = await readFile(absPath);
    // ruleid: mcp-js-path-traversal
    fs.readFileSync(ct);
    const { HOME } = process.env as { HOME: string };
    // ok: mcp-js-path-traversal
    fs.readFileSync(HOME);
    return buffer;
  },
});

server.addTool({
  name: "typed_with_ctx",
  parameters: z.object({ filePath: z.string() }),
  execute: async ({ filePath }: { filePath: string }, { log: l }) => {
    // Known Semgrep miss: another handler in this file declares `const { filePath } =
    // args as ...`, and that makes this parameter's taint disappear (rename it and the
    // match returns). scan.py re-scans each registration alone, which recovers it.
    // todoruleid: mcp-js-path-traversal
    return readFile(filePath);
  },
});

// =================== agent-framework tool sources (experiment 2) ===================
// Vercel AI SDK / Mastra / genkit / VoltAgent: tool({ parameters, execute }) — the
// object-first factory shape already covered by the MCP factory patterns.
const runTool = aiTool({
  description: "run a shell command",
  parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }: { cmd: string }) => {
    // ruleid: mcp-js-command-injection
    return execSync(cmd).toString();
  },
});

// LangChain.js: function-first tool(fn, { name, schema })
const lcTool = tool(
  async (input: { cmd: string }) => {
    // ruleid: mcp-js-command-injection
    return execSync(input.cmd).toString();
  },
  { name: "run", schema: z.object({ cmd: z.string() }) }
);

// LangChain.js: DynamicTool({ func })
const dyn = new DynamicTool({
  name: "fetch",
  func: async (url: string) => {
    // ruleid: mcp-js-ssrf
    return (await axios.get(url)).data;
  },
});
