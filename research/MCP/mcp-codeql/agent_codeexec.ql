/**
 * @name Tool parameter flows to code execution (CWE-094)
 * @description A parameter of an agent-framework OR MCP tool handler reaches
 *              eval/exec/compile — the youtu-agent class.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id agent/code-injection
 * @tags security external/cwe/cwe-094
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import AgentSources

module AgentCodeExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof ToolParamSource }
  predicate isSink(DataFlow::Node n) { n = any(CodeExecution e).getCode() }
}

module AgentCodeExecFlow = TaintTracking::Global<AgentCodeExecConfig>;

import AgentCodeExecFlow::PathGraph

from AgentCodeExecFlow::PathNode source, AgentCodeExecFlow::PathNode sink
where AgentCodeExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tool-handler parameter flows to code execution (CWE-094)."

// For CWE-022 (path) and CWE-918 (SSRF): clone this file, swap the sink to
//   any(FileSystemAccess a).getAPathArgument()         // path traversal (nexent/hive, MCP @resource)
//   any(Http::Client::Request r).getAUrlPart()         // SSRF
// and keep the same ToolParamSource source.
