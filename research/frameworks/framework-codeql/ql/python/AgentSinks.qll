/**
 * Agent-framework taint SINKS for Python (run 2).
 *
 * Built-in Concepts cover the common cases (SystemCommandExecution, CodeExecution,
 * FileSystemAccess, Http::Client::Request). Run 2 adds a widened SQL/exec sink so the
 * hive `csv_sql` class is reachable: DuckDB/sqlite/generic `.execute(query)` where the
 * query argument is not a constant. Wide net: recall over precision.
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts
import semmle.python.ApiGraphs

/** Command-execution sink (built-in). */
class CmdSink extends DataFlow::Node {
  CmdSink() { this = any(SystemCommandExecution e).getCommand() }
}

/** Code-execution sink (eval/exec/compile, built-in). */
class CodeSink extends DataFlow::Node {
  CodeSink() { this = any(CodeExecution e).getCode() }
}

/** Filesystem path sink (built-in). */
class PathSink extends DataFlow::Node {
  PathSink() { this = any(FileSystemAccess a).getAPathArgument() }
}

/** Outbound-request URL sink (built-in). */
class SsrfSink extends DataFlow::Node {
  SsrfSink() { this = any(Http::Client::Request r).getAUrlPart() }
}

/**
 * SQL-ish execute sink, widened. Built-in SqlExecution, PLUS any `*.execute(arg)` /
 * `*.executescript(arg)` / `*.sql(arg)` / `*.query(arg)` call — covers DuckDB, sqlite,
 * SQLAlchemy raw, and ORM raw paths the built-in SqlConstruction/SqlExecution miss.
 */
class SqlSink extends DataFlow::Node {
  SqlSink() {
    this = any(SqlExecution e).getSql()
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() in [
          "execute", "executescript", "executemany", "exec", "sql", "query", "raw", "from_query"
        ] and
      this = call.getArg(0)
    )
  }
}
