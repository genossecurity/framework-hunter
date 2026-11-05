/**
 * Agent-framework taint SOURCES for Python (run 2 — wide net).
 *
 * Run 1 modeled only tool-handler PARAMETERS and missed two confirmed bugs:
 *   - youtu-agent: eval() of MODEL OUTPUT (not a tool param)       -> ModelOutputSource
 *   - hive csv_sql: tool `query` param -> DuckDB execute (no SQL q) -> AgentSinks sqli
 *
 * Run 2 `AgentSource` is the UNION of:
 *   1. AgentToolParamSource    - params of a function that looks like an agent tool handler
 *   2. ModelOutputSource       - the result of an LLM-generation call
 *   3. ModelOutParamSource     - a param named like model output on any function
 *                                (catches parser chains: model text -> _parse(text) -> eval)
 * Wide by design: recall over precision. False positives are expected and are tracked in
 * fp_ledger.csv, not suppressed here.
 *
 * STARTER — validate on your CodeQL version with:  codeql query compile ql/python
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

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

/** Heuristic: does `f` look like an agent tool handler? Broadened per framework in run 2. */
predicate isAgentToolHandler(Function f) {
  // 1. Decorator-based registration across frameworks
  exists(Expr dec |
    dec = f.getADecorator() and
    decoratorName(dec)
        .regexpMatch("(?i)(tool|mcp_?tool|call_tool|register_?tool|function_tool|tool_call|" +
            "agent|action|command|skill|capability|ability|op|operation|handler|kernel_function|" +
            "ai_function|openai_function|langchain_tool|crew|task)")
  )
  or
  // 2. Tool/agent-subclass method pattern (smolagents / LangChain / CrewAI style)
  f.getName() in [
      "forward", "execute", "_run", "run", "_arun", "arun", "call", "__call__", "_call",
      "invoke", "ainvoke", "handle", "on_call", "perform", "act", "step"
    ] and
  exists(Class c |
    c = f.getScope() and
    c.getName().regexpMatch("(?i).*(tool|agent|action|skill|command|executor|handler|capability).*")
  )
  or
  // 3. Free function whose own name screams tool and takes args (registry-registered tools)
  f.getName().regexpMatch("(?i)(run|exec|execute|call|handle|do|perform)_?(tool|command|cmd|action|query|code|shell|sql)") and
  exists(f.getArg(_))
}

/**
 * MCP server tool/resource/prompt handler (Exp-1 corpus). Covers FastMCP
 * (@mcp.tool/@mcp.resource/@mcp.prompt) and the low-level SDK dispatcher
 * (@server.call_tool, or a call_tool/handle_call_tool fn taking an `arguments`
 * dict — the dominant server shape and the one most likely to hide an
 * interprocedural sink). The MCP SDK does NOT look like an HTTP source, so the
 * built-in suite misses these entirely.
 */
predicate isMcpToolHandler(Function f) {
  exists(Expr dec |
    dec = f.getADecorator() and
    decoratorName(dec).regexpMatch("(?i)(mcp_?tool|call_tool|handle_call_tool|resource|prompt)")
  )
  or
  f.getName().regexpMatch("(?i)(call_tool|handle_call_tool)") and
  exists(Parameter p | p = f.getArg(_) and p.getName() in ["arguments", "args"])
}

/** A non-self parameter of an agent OR MCP tool handler = an attacker-influenced source. */
class AgentToolParamSource extends DataFlow::Node {
  AgentToolParamSource() {
    exists(Function f, Parameter p |
      (isAgentToolHandler(f) or isMcpToolHandler(f)) and
      p = f.getArg(_) and
      not p.getName() = "self" and
      not p.getName() = "cls" and
      this = DataFlow::parameterNode(p)
    )
  }
}

/** An attribute/method name that denotes LLM generation. */
bindingset[s]
predicate isModelGenName(string s) {
  s.regexpMatch("(?i)(chat_?completion|completions?|create_?completion|generate|generation|" +
      "invoke|ainvoke|predict|apredict|complete|acomplete|chat|achat|run|arun|respond|" +
      "get_response|aget_response|create|acreate|call_model|query_?llm|ask|send_?message|stream)")
}

/** An identifier (receiver/var) that denotes an LLM/model/client object. */
bindingset[s]
predicate isModelReceiverName(string s) {
  s.regexpMatch("(?i).*(llm|model|client|agent|chat|openai|anthropic|claude|gpt|gemini|" +
      "completion|generat|assistant|oracle|brain).*")
}

/** The result of a call that looks like an LLM-generation call = model output. */
class ModelOutputSource extends DataFlow::Node {
  ModelOutputSource() {
    exists(Call c, Attribute a |
      a = c.getFunc() and
      this.asExpr() = c and
      isModelGenName(a.getName()) and
      // constrain the receiver so plain `.create()`/`.run()` everywhere isn't a source
      (
        isModelReceiverName(a.getObject().(Name).getId())
        or
        isModelReceiverName(a.getObject().(Attribute).getName())
        or
        // generation-specific names are allowed on any receiver
        a.getName()
            .regexpMatch("(?i)(chat_?completion|completions?|generate|generation|predict|" +
                "get_response|call_model|query_?llm|complete)")
      )
    )
  }
}

/**
 * A parameter named SPECIFICALLY like model output, on any function (parser-chain
 * catcher for model-text -> _parse(text) -> eval). Deliberately NOT generic names
 * like `response`/`content`/`message`/`output`/`result`: those match nearly every
 * function in a framework, which floods the source set and makes the taint steps
 * explode (PocketFlow hung for minutes). Kept names cover the confirmed cases
 * (youtu-agent `text_output`, SuperAGI `assistant_reply`).
 */
class ModelOutParamSource extends DataFlow::Node {
  ModelOutParamSource() {
    exists(Function f, Parameter p |
      p = f.getArg(_) and
      p.getName()
          .regexpMatch("(?i)(text_?output|model_?output|llm_?output|raw_?output|model_?response|" +
              "llm_?response|assistant_?reply|assistant_?message|react_?output|action_?text|" +
              "generated_?(text|code|output)|completion_?text|tool_?call_?text)") and
      this = DataFlow::parameterNode(p)
    )
  }
}

/** The run-2 agent source: tool params + model output + model-output params. */
class AgentSource extends DataFlow::Node {
  AgentSource() {
    this instanceof AgentToolParamSource or
    this instanceof ModelOutputSource or
    this instanceof ModelOutParamSource
  }
}
