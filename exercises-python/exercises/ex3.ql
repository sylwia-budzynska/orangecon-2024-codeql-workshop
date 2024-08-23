import python
import semmle.python.ApiGraphs

from DataFlow::CallCfgNode call
where call = API::moduleImport("os").getMember("system").getACall() and
call.getLocation().getFile().getRelativePath().regexpMatch("test-app/.*")
select call // TODO: fill me in. Type a dot `.` right after `call` and press `Ctrl/Cmd+Space` to see available predicates.
