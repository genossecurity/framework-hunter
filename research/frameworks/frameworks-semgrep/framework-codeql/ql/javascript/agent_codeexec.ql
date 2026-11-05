/**
 * @name Agent to code exec (JS)
 * @description Agent source (tool param / model output) reaches code execution (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id agent/code-injection-js
 * @tags security external/cwe/cwe-094
 */
import javascript
import semmle.javascript.security.dataflow.CodeInjectionCustomizations
import AgentSourcesJs

module CodeInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSourceJs }
  predicate isSink(DataFlow::Node n) { n instanceof CodeInjection::Sink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    b.(DataFlow::PropRead).getBase() = a
    or
    exists(DataFlow::MethodCallNode m | a = m.getReceiver() and b = m)
  }
}
module CodeInjectionFlow = TaintTracking::Global<CodeInjectionConfig>;
import CodeInjectionFlow::PathGraph

from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
where CodeInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches code execution (CWE-094)."
