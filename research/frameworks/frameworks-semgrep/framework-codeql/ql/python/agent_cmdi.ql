/**
 * @name Agent source to OS command
 * @description Agent source (tool param / model output) reaches an OS command (run 2, wide net).
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
import AgentSinks
import AgentSteps

module AgentCmdiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSource }
  predicate isSink(DataFlow::Node n) { n instanceof CmdSink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { agentWideStep(a, b) }
}
module AgentCmdiFlow = TaintTracking::Global<AgentCmdiConfig>;
import AgentCmdiFlow::PathGraph

from AgentCmdiFlow::PathNode source, AgentCmdiFlow::PathNode sink
where AgentCmdiFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches an OS command (CWE-078)."
