import python
import semmle.python.ApiGraphs

class OsSystemSink extends DataFlow::CallCfgNode {
	OsSystemSink() {
		//TODO: fill me in
	}
}

from DataFlow::CallCfgNode call
where // TODO: fill me in
and call.getLocation().getFile().getRelativePath().regexpMatch("test-app/.*")
select call.getArg(0), "Call to os.system"
