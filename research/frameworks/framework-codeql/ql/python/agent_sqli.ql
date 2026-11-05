/**
 * @name Agent source to SQL execution
 * @description Agent source (tool param / model output) reaches SQL execution (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id agent/sql-injection
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import AgentSources
import AgentSinks
import AgentSteps

module AgentSqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSource }
  predicate isSink(DataFlow::Node n) { n instanceof SqlSink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { agentWideStep(a, b) }
}
module AgentSqlFlow = TaintTracking::Global<AgentSqlConfig>;
import AgentSqlFlow::PathGraph

from AgentSqlFlow::PathNode source, AgentSqlFlow::PathNode sink
where AgentSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches SQL execution (CWE-089)."
