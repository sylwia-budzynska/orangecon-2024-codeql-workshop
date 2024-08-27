
// This query finds all command execution sinks, that are modeled in CodeQL.

import python
import semmle.python.Concepts

from SystemCommandExecution cmd
where cmd.getLocation().getFile().getRelativePath().regexpMatch("2/challenge-1/.*")
select cmd, "Command Execution sink"
