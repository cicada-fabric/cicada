# Harness boundary

`Worker.harness` is persisted independently from the worker process. The
Control scheduler checks the requested harness against a Machine's
`capabilities.harnesses` profile, and the executor boundary can therefore grow
without changing Goal or Monitor data.

The current 0.3.0 development line installs and runs the official Codex CLI
only. A Goal or additional Worker may state `"harness":"codex"`; an
uninstalled harness is rejected before any workspace or worker is created.
This explicit failure is safer than
silently running a different agent. Claude, OpenCode, and other adapters can
be added behind the same boundary in a later branch.
