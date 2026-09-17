# Harness boundary

`Worker.harness` is persisted independently from the worker process. The
Control scheduler checks the requested harness against a Machine's
`capabilities.harnesses` profile, and the executor boundary can therefore grow
without changing Goal or Monitor data.

The current 0.4.0 development line supports the official Codex CLI, an
explicit `shell` harness, and bounded adapters for Claude Code, OpenCode, and
Happy Agent. A Goal or additional Worker may state `"harness":"codex"`,
`"harness":"shell"`, `"harness":"claude-code"`, `"harness":"opencode"`,
or `"harness":"happy-agent"`. Aliases such as `claude`, `open-code`, and
`happy` are normalized when persisted. The scheduler only assigns an optional
adapter to a Machine that advertises the corresponding installed binary.
Unknown harness names are rejected before any workspace or worker is created.

The Shell harness accepts only `resources.argv`, a bounded string array. It
executes the program directly without a shell, captures at most 512 KiB of
combined stdout/stderr as evidence, and strips relay/API/connector secrets from
the child environment. The `shell.execute` permission can deny the executable
before launch. Both Codex and the optional adapters can execute through a
remote [`machine agent`](remote-execution.md); remote workers keep Control and
connector tokens out of their child environment. Browser capabilities use the
separate [`external agent`](external-actions.md) protocol; they are
intentionally not exposed as a general-purpose Worker harness.

Optional adapters are direct child processes with prompt text on stdin and a
bounded combined stdout/stderr stream. They do not invoke a shell, accept
untrusted command-line arguments, or receive Cicada bearer, relay, webhook,
connector, or bot tokens. Operators can point the adapters at local binaries
and replace their default argv through runtime-only environment variables:

| Harness | Binary variable | Args variable | Default argv |
| --- | --- | --- | --- |
| Claude Code | `CICADA_CLAUDE_CODE_BIN` | `CICADA_CLAUDE_CODE_ARGS_JSON` | `['--print','--output-format','json']` |
| OpenCode | `CICADA_OPENCODE_BIN` | `CICADA_OPENCODE_ARGS_JSON` | `['run','--format','json']` |
| Happy Agent | `CICADA_HAPPY_AGENT_BIN` | `CICADA_HAPPY_AGENT_ARGS_JSON` | `[]` |

The args variables must contain a JSON string array with at most 64 entries;
each entry is capped at 4 KiB. Adapter output may include JSON Lines fields
`thread_id`, `session_id`, `conversation_id`, `id`, and one of `summary`,
`last_message`, `message`, `text`, or `content`; the first matching session
identifier and summary become the durable Worker evidence. A vendor-specific
session can be resumed only when that vendor CLI and its configured argv
implement the corresponding continuation semantics.
