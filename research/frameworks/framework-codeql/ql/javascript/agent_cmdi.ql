/**
 * @name Agent to OS command (JS)
 * @description Agent source (tool param / model output) reaches an OS command (run 2, wide net).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id agent/cmd-injection-js
 * @tags security external/cwe/cwe-078
 */
import javascript
import semmle.javascript.security.dataflow.CommandInjectionCustomizations
import AgentSourcesJs

module CommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof AgentSourceJs }
  predicate isSink(DataFlow::Node n) { n instanceof CommandInjection::Sink }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    b.(DataFlow::PropRead).getBase() = a
    or
    exists(DataFlow::MethodCallNode m | a = m.getReceiver() and b = m)
  }
}
module CommandInjectionFlow = TaintTracking::Global<CommandInjectionConfig>;
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Agent source reaches an OS command (CWE-078)."
