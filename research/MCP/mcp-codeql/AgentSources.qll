/**
 * Models TOOL-HANDLER PARAMETERS as taint sources — for BOTH corpora:
 *   - agent frameworks (Exp 2): crewly registry, LangChain Tool, CrewAI decorators…
 *   - MCP servers      (Exp 1): FastMCP @mcp.tool, low-level @server.call_tool
 *
 * This is the one thing the built-in security suite misses: it knows HTTP/Flask/
 * Django inputs, but not "this user function is a tool whose arguments the model
 * controls." Queries should use `ToolParamSource` (the union) so one pack scans
 * either corpus; the two subclasses stay separate so you can report which shape
 * fired.
 *
 * STARTER — validate on your CodeQL version with:  codeql query compile ql/python
 */
import python
import semmle.python.dataflow.new.DataFlow

/** Best-effort name of a decorator expression (`@tool`, `@mcp.tool`, `@x.tool()`). */
string decoratorName(Expr dec) {
  result = dec.(Name).getId()
  or
  result = dec.(Attribute).getName()
  or
  result = dec.(Call).getFunc().(Name).getId()
  or
  result = dec.(Call).getFunc().(Attribute).getName()
}

/** A non-self/non-injected parameter of `f` = an attacker-influenced source node.
 *  `ctx`/`context` are excluded: FastMCP injects a Context object, not model data. */
private DataFlow::Node toolParam(Function f) {
  exists(Parameter p |
    p = f.getArg(_) and
    not p.getName() in ["self", "cls", "ctx", "context"] and
    result = DataFlow::parameterNode(p)
  )
}

// ---------------------------------------------------------------------------
// Agent-framework handlers (Exp 2). EXTEND PER FRAMEWORK.
// ---------------------------------------------------------------------------

/** Heuristic: does `f` look like an agent-framework tool handler? */
predicate isAgentToolHandler(Function f) {
  // 1. Decorator-based: @tool, @app.tool, @register_tool, @function_tool
  exists(Expr dec |
    dec = f.getADecorator() and
    decoratorName(dec).regexpMatch("(?i)(^tool$|register_?tool|function_tool|agent_?tool)")
  )
  or
  // 2. Tool-subclass method pattern (smolagents / LangChain-style classes)
  f.getName() in ["forward", "execute", "_run", "run", "_arun", "call", "__call__"] and
  exists(Class c | c = f.getScope() and c.getName().regexpMatch("(?i).*tool.*"))
}

/** A parameter of an agent-framework tool handler. */
class AgentToolParamSource extends DataFlow::Node {
  AgentToolParamSource() { exists(Function f | isAgentToolHandler(f) and this = toolParam(f)) }
}

// ---------------------------------------------------------------------------
// MCP server handlers (Exp 1). This is the addition that makes the MCP-corpus
// run actually produce sources instead of a false "clean".
// ---------------------------------------------------------------------------

/** Heuristic: does `f` look like an MCP server tool/resource/prompt handler?
 *  Covers FastMCP (@mcp.tool/@mcp.resource/@mcp.prompt) AND the low-level SDK
 *  dispatcher (@server.call_tool, or a call_tool/handle_call_tool fn taking an
 *  `arguments` dict — the dominant server shape and the one most likely to hide
 *  an interprocedural sink). */
predicate isMcpToolHandler(Function f) {
  // 1. FastMCP + low-level decorators: @mcp.tool(), @server.call_tool(), @mcp.resource(), @mcp.prompt()
  exists(Expr dec |
    dec = f.getADecorator() and
    decoratorName(dec).regexpMatch("(?i)(mcp_?tool|call_tool|handle_call_tool|resource|prompt)")
  )
  or
  // 2. Low-level dispatcher that isn't decorated in a shape we catch: name + an
  //    `arguments`/`args` param is the untrusted tool-call payload.
  f.getName().regexpMatch("(?i)(call_tool|handle_call_tool)") and
  exists(Parameter p | p = f.getArg(_) and p.getName() in ["arguments", "args"])
}

/** A parameter of an MCP server tool/resource/prompt handler. */
class McpToolParamSource extends DataFlow::Node {
  McpToolParamSource() { exists(Function f | isMcpToolHandler(f) and this = toolParam(f)) }
}

// ---------------------------------------------------------------------------
// Union — point queries at this so one pack scans either corpus.
// ---------------------------------------------------------------------------

/** Any tool-handler parameter, agent-framework or MCP. */
class ToolParamSource extends DataFlow::Node {
  ToolParamSource() { this instanceof AgentToolParamSource or this instanceof McpToolParamSource }
}
