/**
 * @name Agent source to filesystem path
 * @description Agent source (tool param / model output) reaches a filesystem path (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id agent/path-injection
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import AgentSources
import AgentSinks
import AgentSteps

module AgentPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSource }
  predicate isSink(DataFlow::Node n) { n instanceof PathSink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { agentWideStep(a, b) }
}
module AgentPathFlow = TaintTracking::Global<AgentPathConfig>;
import AgentPathFlow::PathGraph

from AgentPathFlow::PathNode source, AgentPathFlow::PathNode sink
where AgentPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches a filesystem path (CWE-022)."
