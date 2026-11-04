# Fixtures for rules/mcp-taint.yaml (Python rules).
# A 'ruleid' annotation means the next line MUST be flagged by that rule;
# an 'ok' annotation means it must NOT be flagged.
# Run: semgrep --test --config rules/ tests/   (or: make test)
import os
import pickle
import shlex
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

import httpx
import requests
import torch
import yaml
from mcp.server.fastmcp import FastMCP
from mcp.server import Server

mcp = FastMCP("fixture")
server = Server("fixture-lowlevel")


# ------------------------------------------------------------- command injection
@mcp.tool()
def run_command(command: str) -> str:
    # ruleid: mcp-py-command-injection
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool
async def ping(host: str) -> str:
    # ruleid: mcp-py-command-injection
    os.system(f"ping -c 1 {host}")
    return "ok"


@mcp.tool()
def ping_quoted(host: str) -> str:
    # ok: mcp-py-command-injection
    os.system("ping -c 1 " + shlex.quote(host))
    return "ok"


# ------------------------------------------------------------- argument injection
@mcp.tool()
def git_clone(url: str) -> str:
    # ruleid: mcp-py-argument-injection
    subprocess.run(["git", "clone", url], check=True)
    return "cloned"


@mcp.tool()
def static_ls(n: int) -> str:
    # ok: mcp-py-argument-injection
    return subprocess.run(["ls", "-la"], capture_output=True, text=True).stdout + str(n)


# ------------------------------------------------------------- path traversal
@mcp.tool()
def read_file(path: str) -> str:
    # ruleid: mcp-py-path-traversal
    with open(path) as f:
        return f.read()


@mcp.tool()
def read_note(name: str) -> str:
    # ruleid: mcp-py-path-traversal
    return Path("/srv/notes", name).read_text()


@mcp.tool()
def read_note_safe(name: str) -> str:
    # ok: mcp-py-path-traversal
    return open(os.path.join("/srv/notes", os.path.basename(name))).read()


# ------------------------------------------------------------- SSRF
@mcp.tool()
def fetch(url: str) -> str:
    # ruleid: mcp-py-ssrf
    return requests.get(url, timeout=5).text


@mcp.tool()
async def fetch_async(url: str) -> str:
    async with httpx.AsyncClient() as client:
        # ruleid: mcp-py-ssrf
        r = await client.get(url)
        return r.text


@mcp.tool()
def fetch_fixed(q: str) -> str:
    # ok: mcp-py-ssrf
    return requests.get("https://api.example.com/status", params={"q": q}).text


# ------------------------------------------------------------- code injection / deserialization
@mcp.tool()
def calc(expr: str) -> str:
    # ruleid: mcp-py-code-injection
    return str(eval(expr))


@mcp.tool()
def load_state(blob: bytes) -> str:
    # ruleid: mcp-py-code-injection
    return repr(pickle.loads(blob))


@mcp.tool()
def load_config(text: str) -> str:
    # ruleid: mcp-py-code-injection
    return repr(yaml.load(text, Loader=yaml.Loader))


@mcp.tool()
def load_config_safe(text: str) -> str:
    # ok: mcp-py-code-injection
    return repr(yaml.load(text, Loader=yaml.SafeLoader))


@mcp.tool()
def load_model(model_path: str) -> str:
    # ruleid: mcp-py-code-injection
    m = torch.load(model_path)
    return str(type(m))


@mcp.tool()
def load_weights_safe(model_path: str) -> str:
    # ok: mcp-py-code-injection
    m = torch.load(model_path, weights_only=True)
    return str(type(m))


# ------------------------------------------------------------- SQL injection
@mcp.tool()
def find_user(name: str) -> str:
    cur = sqlite3.connect("app.db").cursor()
    # ruleid: mcp-py-sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return repr(cur.fetchall())


@mcp.tool()
def find_user_safe(name: str) -> str:
    cur = sqlite3.connect("app.db").cursor()
    # ok: mcp-py-sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return repr(cur.fetchall())


# ------------------------------------------------------------- low-level server
@server.call_tool()
async def handle_call(name: str, arguments: dict):
    if name == "run":
        # ruleid: mcp-py-command-injection
        subprocess.Popen(arguments["cmd"], shell=True)
    return []


# ------------------------------------------------------------- not a tool: no source
def helper(user_input: str) -> None:
    # ok: mcp-py-command-injection
    os.system(user_input)


# ---------------------------------------------------------------- resources and prompts
@mcp.resource("file://{name}")
def read_resource_file(name: str):
    # ruleid: mcp-py-path-traversal
    return open(name).read()


@mcp.prompt()
def prompt_cmd(cmd: str):
    # ruleid: mcp-py-command-injection
    return subprocess.run(cmd, shell=True)


# =================== agent-framework tool sources (experiment 2) ===================
# Decorators/classes are undefined here on purpose: semgrep matches syntactically.
# langchain / crewai / smolagents: @tool
@tool
def lc_run(command: str) -> str:
    # ruleid: mcp-py-command-injection
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@tool("read_file", description="read a file")
def lc_read(path: str) -> str:
    # ruleid: mcp-py-path-traversal
    return open(path).read()


# a @tool with a static command must NOT flag (nothing flows from the param)
@tool
def lc_static(n: int) -> str:
    # ok: mcp-py-command-injection
    return subprocess.run(["ls", "-la"], capture_output=True, text=True).stdout + str(n)


# openai-agents: @function_tool
@function_tool
def oa_fetch(url: str) -> str:
    # ruleid: mcp-py-ssrf
    return requests.get(url, timeout=5).text


# semantic-kernel: @kernel_function
@kernel_function(name="calc")
def sk_calc(expr: str) -> str:
    # ruleid: mcp-py-code-injection
    return str(eval(expr))


# pydantic-ai: @agent.tool_plain
@agent.tool_plain
def pa_sql(name: str) -> str:
    cur = sqlite3.connect("app.db").cursor()
    # ruleid: mcp-py-sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return repr(cur.fetchall())


# langchain / crewai class tool: BaseTool._run
class ShellTool(BaseTool):
    def _run(self, command: str) -> str:
        # ruleid: mcp-py-command-injection
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


# smolagents class tool: Tool.forward
class FetchTool(Tool):
    def forward(self, url: str) -> str:
        # ruleid: mcp-py-ssrf
        return requests.get(url, timeout=5).text
