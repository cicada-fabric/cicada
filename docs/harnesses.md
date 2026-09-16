# Harness boundary

`Worker.harness` is persisted independently from the worker process. The
Control scheduler checks the requested harness against a Machine's
`capabilities.harnesses` profile, and the executor boundary can therefore grow
without changing Goal or Monitor data.

The current 0.3.0 development line supports the official Codex CLI and an
explicit `shell` harness. A Goal or additional Worker may state
`"harness":"codex"` or `"harness":"shell"`; an uninstalled harness is
rejected before any workspace or worker is created. This explicit failure is
safer than silently running a different agent.

The Shell harness accepts only `resources.argv`, a bounded string array. It
executes the program directly without a shell, captures at most 512 KiB of
combined stdout/stderr as evidence, and strips relay/API/connector secrets from
the child environment. The `shell.execute` permission can deny the executable
before launch. Claude, OpenCode, Happy Agent, and browser adapters can be added
behind the same boundary in later branches.
