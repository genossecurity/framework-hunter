/**
 * @name Tool parameter flows to OS command (CWE-078)
 * @description A parameter of an agent-framework OR MCP tool handler reaches an
 *              OS-command execution — the crewly / nexent class.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id agent/cmd-injection
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import AgentSources

module AgentCmdiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof ToolParamSource }
  predicate isSink(DataFlow::Node n) { n = any(SystemCommandExecution e).getCommand() }
}

module AgentCmdiFlow = TaintTracking::Global<AgentCmdiConfig>;

import AgentCmdiFlow::PathGraph

from AgentCmdiFlow::PathNode source, AgentCmdiFlow::PathNode sink
where AgentCmdiFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tool-handler parameter flows to an OS command (CWE-078)."
