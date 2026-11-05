/**
 * @name Agent to request URL (JS)
 * @description Agent source (tool param / model output) reaches an outbound URL (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @id agent/ssrf-js
 * @tags security external/cwe/cwe-918
 */
import javascript
import semmle.javascript.security.dataflow.RequestForgeryCustomizations
import AgentSourcesJs

module RequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSourceJs }
  predicate isSink(DataFlow::Node n) { n instanceof RequestForgery::Sink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    b.(DataFlow::PropRead).getBase() = a
    or
    exists(DataFlow::MethodCallNode m | a = m.getReceiver() and b = m)
  }
}
module RequestForgeryFlow = TaintTracking::Global<RequestForgeryConfig>;
import RequestForgeryFlow::PathGraph

from RequestForgeryFlow::PathNode source, RequestForgeryFlow::PathNode sink
where RequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches an outbound URL (CWE-918)."
