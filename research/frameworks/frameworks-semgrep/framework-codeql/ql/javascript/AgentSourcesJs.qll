/**
 * Agent-framework taint SOURCES for JavaScript/TypeScript (run 2 — wide net).
 *
 * JS run 1 had no custom pack at all (built-in suite only), so tool-handler params and
 * model output were never treated as sources. Run 2 adds:
 *   1. AgentToolParamJs  - params of a callback passed to a tool-registration call
 *                          (server.tool(name, schema, (args) => ...), registerTool, addTool, ...)
 *   2. ModelOutputJs     - the result (and its property reads) of an LLM-generation call
 * Wide by design; FPs tracked in fp_ledger.csv.
 */
import javascript

/**
 * Param of a callback handed to an MCP/agent TOOL-registration call. Tightened for
 * the MCP corpus: matches tool-registration shapes ONLY, not generic `command`/
 * `action`/`handler`. Those matched commander.js `.command()/.action()` CLI
 * callbacks (operator args, not MCP payloads) and flooded the delta with ~137
 * CLI false positives in batch 1.
 *
 * Kept shapes: server.tool(...), registerTool/addTool/setTool/defineTool(...),
 * FastMCP-TS tool(...), and setRequestHandler(CallToolRequestSchema, (req)=>...).
 */
class AgentToolParamJs extends DataFlow::ParameterNode {
  AgentToolParamJs() {
    exists(DataFlow::CallNode call |
      call.getCalleeName()
          .regexpMatch("(?i)^(tool|register_?tool|add_?tool|set_?tool|define_?tool|" +
              "register_?tools|tool_?handler|setrequesthandler)$") and
      this = call.getABoundCallbackParameter(_, _)
    )
  }
}

/** Name of a method that denotes LLM generation. */
bindingset[s]
predicate isGenNameJs(string s) {
  s.regexpMatch("(?i)(generatetext|generatecontent|generateobject|createmessage|createcompletion|" +
      "chatcompletion|completions?|complete|generate|invoke|ainvoke|predict|chat|respond|run|" +
      "stream|streamtext|getresponse|callmodel|createresponse|messages)")
}

/** Identifier denoting an LLM/model/client object. */
bindingset[s]
predicate isModelRecvJs(string s) {
  s.regexpMatch("(?i).*(llm|model|client|agent|chat|openai|anthropic|claude|gpt|gemini|" +
      "completion|generat|assistant|ai|bedrock|vertex).*")
}

/** Result of a call that looks like LLM generation (and reads off it). */
class ModelOutputJs extends DataFlow::Node {
  ModelOutputJs() {
    exists(DataFlow::CallNode c |
      isGenNameJs(c.getCalleeName()) and
      (
        // generation-specific names on any receiver
        c.getCalleeName()
            .regexpMatch("(?i)(generatetext|generatecontent|generateobject|createmessage|" +
                "createcompletion|chatcompletion|generate|getresponse|callmodel|createresponse)")
        or
        // generic names only when the receiver looks like a model/client
        exists(DataFlow::SourceNode base |
          base = c.getReceiver().getALocalSource() and
          isModelRecvJs(base.toString())
        )
      ) and
      (this = c or this = c.getAPropertyRead())
    )
  }
}

/**
 * Run-2 JS agent source = TOOL-HANDLER PARAMETERS only.
 *
 * ModelOutputJs is deliberately EXCLUDED: on the MCP corpus it matched every
 * `.run()/.create()/.invoke()` on a model/client/agent-ish receiver (cline alone:
 * 543 sources), flooding `agent/path-injection-js` with ~460 CLI-file FPs. JS
 * model-output never caught a confirmed bug (the eval-of-model-output catches —
 * youtu-agent, SuperAGI — were all Python, where ModelOutputSource is kept). For
 * MCP servers the attack surface is the tool-call arguments, not model output.
 */
class AgentSourceJs extends DataFlow::Node {
  AgentSourceJs() { this instanceof AgentToolParamJs }
}
