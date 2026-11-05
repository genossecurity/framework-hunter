/**
 * @name Agent source to code exec
 * @description Agent source (tool param / model output) reaches code execution (run 2, wide net).
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
import AgentSinks
import AgentSteps

module AgentCodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSource }
  predicate isSink(DataFlow::Node n) { n instanceof CodeSink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { agentWideStep(a, b) }
}
module AgentCodeFlow = TaintTracking::Global<AgentCodeConfig>;
import AgentCodeFlow::PathGraph

from AgentCodeFlow::PathNode source, AgentCodeFlow::PathNode sink
where AgentCodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches code execution (CWE-094)."
