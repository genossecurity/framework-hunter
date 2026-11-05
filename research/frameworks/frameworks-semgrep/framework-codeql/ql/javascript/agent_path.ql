/**
 * @name Agent to fs path (JS)
 * @description Agent source (tool param / model output) reaches a filesystem path (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id agent/path-injection-js
 * @tags security external/cwe/cwe-022
 */
import javascript
import semmle.javascript.security.dataflow.TaintedPathCustomizations
import AgentSourcesJs

module TaintedPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSourceJs }
  predicate isSink(DataFlow::Node n) { n instanceof TaintedPath::Sink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    b.(DataFlow::PropRead).getBase() = a
    or
    exists(DataFlow::MethodCallNode m | a = m.getReceiver() and b = m)
  }
}
module TaintedPathFlow = TaintTracking::Global<TaintedPathConfig>;
import TaintedPathFlow::PathGraph

from TaintedPathFlow::PathNode source, TaintedPathFlow::PathNode sink
where TaintedPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches a filesystem path (CWE-022)."
