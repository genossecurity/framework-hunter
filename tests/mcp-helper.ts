// Fixtures for rules/mcp-helper.yaml (JS/TS helper tier).
// A 'ruleid' annotation means the next line MUST be flagged by that rule;
// an 'ok' annotation means it must NOT be flagged.
// Shapes mirror real MCP CVEs: handler dispatches into a helper/method that
// builds a shell command from its parameter.
import { exec, execSync, execFile } from "child_process";
import * as fs from "fs";
import { promisify } from "util";

const execAsync = promisify(exec);

// kubectl-style helper in its own module (handler calls kubectlDescribe(input))
export async function kubectlDescribe(k8s: unknown, input: { resourceType: string; name: string }) {
  const command = `kubectl describe ${input.resourceType} ${input.name}`;
  // ruleid: mcp-js-command-injection-helper
  return execSync(command, { encoding: "utf8" });
}

// class-method dispatch (handler calls this.describeGoPackage(request.params.arguments))
class DocsServer {
  async describeGoPackage(args: { package: string; symbol?: string }) {
    // ruleid: mcp-js-command-injection-helper
    const { stdout } = await execAsync(`go doc ${args.package}`);
    return stdout;
  }

  private async isInstalled({ command }: { command: string }) {
    // ruleid: mcp-js-command-injection-helper
    await exec(`which ${command}`);
  }

  async version() {
    // ok: mcp-js-command-injection-helper
    return execSync("go version");
  }

  readDoc(name: string) {
    // ruleid: mcp-js-path-traversal-helper
    return fs.readFileSync("/srv/docs/" + name, "utf8");
  }
}

// arrow helper
const cloneRepo = async (url: string) => {
  // ruleid: mcp-js-argument-injection-helper
  execFile("git", ["clone", url]);
};

const download = async (u: string) => {
  // ruleid: mcp-js-ssrf-helper
  return fetch(u);
};

export { DocsServer, cloneRepo, download };
