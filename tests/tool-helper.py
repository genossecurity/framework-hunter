# Fixtures for rules/tool-helper.yaml (Python helper tier).
# A 'ruleid' annotation means the next line MUST be flagged by that rule;
# an 'ok' annotation means it must NOT be flagged.
# Shapes mirror real MCP CVEs: the @mcp.tool handler calls a helper in another
# module, and the helper builds the shell command.
import asyncio
import os
import pickle
import subprocess

import requests


async def execute_pipe_command(pipe_command: str) -> str:
    # ruleid: tool-py-command-injection-helper
    proc = await asyncio.create_subprocess_shell(pipe_command, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()


class Executor:
    def run(self, cmd: str) -> int:
        # ruleid: tool-py-command-injection-helper
        return os.system(cmd)

    def version(self) -> int:
        # ok: tool-py-command-injection-helper
        return os.system("aws --version")

    def clone(self, url: str) -> None:
        # ruleid: tool-py-argument-injection-helper
        subprocess.run(["git", "clone", url], check=True)


def read_any(path: str) -> str:
    # ruleid: tool-py-path-traversal-helper
    with open(path) as f:
        return f.read()


def get_page(url: str) -> str:
    # ruleid: tool-py-ssrf-helper
    return requests.get(url, timeout=5).text


def restore(blob: bytes):
    # ruleid: tool-py-code-injection-helper
    return pickle.loads(blob)


def uses_self_only(self) -> int:
    # ok: tool-py-command-injection-helper
    return os.system("true")
