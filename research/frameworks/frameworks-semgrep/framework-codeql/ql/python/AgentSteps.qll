/**
 * Wide additional taint steps for run 2 (recall over precision).
 *
 * Default TaintTracking can drop taint across parser-style string surgery like
 * `text.split(x)[1].strip()` (the youtu-agent chain). These steps propagate taint
 * through:
 *   - STRING-OP method calls on a tainted receiver (split/strip/replace/... only)
 *   - any subscript of a tainted value        (x[i]        tainted if x tainted)
 *   - f-strings / str concatenation / .format / .join with a tainted part
 *
 * NOTE: run-2 tuning. An "any method call" step (and an "any attribute read" step)
 * made analyze explode — PocketFlow hung >5m on an agent query, and big repos stalled.
 * Restricting the method step to string transforms keeps the parser chains (youtu-agent
 * split()[1].strip()) while cutting the global taint blowup. FPs tracked in fp_ledger.csv.
 */
import python
import semmle.python.dataflow.new.DataFlow

predicate agentWideStep(DataFlow::Node pred, DataFlow::Node succ) {
  // STRING-op method call on a tainted receiver: receiver -> call result
  exists(DataFlow::MethodCallNode m |
    m.getMethodName() in [
        // PURE string transforms only. Do NOT add dict/IO methods like get/pop/read/
        // loads/group: they are ubiquitous (e.g. PocketFlow's shared.get(...)) and make
        // taint flow through the whole program, exploding analyze.
        "split", "rsplit", "splitlines", "strip", "lstrip", "rstrip", "replace",
        "format", "format_map", "join", "lower", "upper", "title", "capitalize",
        "encode", "decode", "removeprefix", "removesuffix", "partition", "rpartition",
        "expandtabs", "swapcase", "casefold", "ljust", "rjust", "center", "zfill"
      ] and
    pred = m.getObject() and succ = m
  )
  or
  // subscript x[i] : x -> x[i]
  exists(Subscript s |
    pred.asExpr() = s.getObject() and succ.asExpr() = s
  )
  or
  // f-string / concat / format components flow to the whole expression
  exists(BinaryExpr b |
    (pred.asExpr() = b.getLeft() or pred.asExpr() = b.getRight()) and succ.asExpr() = b
  )
  or
  exists(Fstring f |
    pred.asExpr() = f.getAValue() and succ.asExpr() = f
  )
}
