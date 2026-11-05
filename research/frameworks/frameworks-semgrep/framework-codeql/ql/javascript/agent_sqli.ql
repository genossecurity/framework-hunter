/**
 * @name Agent to SQL (JS)
 * @description Agent source (tool param / model output) reaches SQL execution (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id agent/sql-injection-js
 * @tags security external/cwe/cwe-089
 */
import javascript
import semmle.javascript.security.dataflow.SqlInjectionCustomizations
import AgentSourcesJs

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSourceJs }
  predicate isSink(DataFlow::Node n) { n instanceof SqlInjection::Sink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    b.(DataFlow::PropRead).getBase() = a
    or
    exists(DataFlow::MethodCallNode m | a = m.getReceiver() and b = m)
  }
}
module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches SQL execution (CWE-089)."
