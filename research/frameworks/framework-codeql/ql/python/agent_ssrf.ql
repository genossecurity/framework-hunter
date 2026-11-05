/**
 * @name Agent source to request URL
 * @description Agent source (tool param / model output) reaches an outbound URL (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @id agent/ssrf
 * @tags security external/cwe/cwe-918
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import AgentSources
import AgentSinks
import AgentSteps

module AgentSsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSource }
  predicate isSink(DataFlow::Node n) { n instanceof SsrfSink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { agentWideStep(a, b) }
}
module AgentSsrfFlow = TaintTracking::Global<AgentSsrfConfig>;
import AgentSsrfFlow::PathGraph

from AgentSsrfFlow::PathNode source, AgentSsrfFlow::PathNode sink
where AgentSsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches an outbound URL (CWE-918)."
