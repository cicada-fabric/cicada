# Native writer recovery boundary

The Node Agent serializes writes to one physical Codex Thread through a private
file lock under its configured StateRoot. In multi-Hub mode, `--state-root` is
shared by the Hub contexts and each Hub keeps its own origin, Node ID, bearer
credential, session binding, inbox, and journal under
`<StateRoot>/hubs/<hash-of-Hub-ID-and-canonical-origin>/`. In single-Hub mode,
the configured `--state-dir` is also the writer root. Native queueing requires a
nonempty pinned Hub ID and exact binding; an unpinned Agent fails closed.

The common registry is `<StateRoot>/.native-writers/`. The lock filename is a
hash of `uid:<local OS UID>`, harness (`codex`), and exact native Session ID,
separated by NUL bytes. The corresponding `.lock.epoch` file records the
monotonic writer epoch, and `.lock.operations/` contains private operation
records. The UID is a local storage and serialization scope, **not** proof of
an authenticated Codex account. The lock coordinates processes only when they
use the same configured StateRoot. Different StateRoots do not provide a
cross-process mutual-exclusion guarantee.

An operation record identifies the Hub, Node, Endpoint, binding ID and epoch,
message ID, and payload digest. The Hub Relay attempt ID is stored as evidence
but is not part of the stable deduplication key. A changed attempt cannot
reinject an unresolved operation; a changed binding or digest conflicts with
the prior record instead of reusing its result. A previous writer cannot call
`FinishNativeOperation` after releasing its lock or losing its epoch.

The writer durably records `INJECTING` before starting `codex queue`. It holds
the lock through outcome persistence for a started command; a command that
cannot start is recorded as `FAILED_BEFORE_START`. A successful CLI exit is
`QUEUE_ACCEPTED` only after that result is durable. A started CLI that exits
nonzero, times out, or cannot durably record success is uncertain. If the
process crashes after
`INJECTING`, the next writer records `INJECTION_UNCERTAIN` and refuses a blind
retry. The same conservative result can follow a context timeout between
recording `INJECTING` and actually starting the CLI. `FAILED_BEFORE_START` is
the only recorded state that can be attempted again after fresh authorization.

A `QUEUE_ACCEPTED` record can support a receipt for a currently authorized
Relay attempt without running the CLI again. A Relay journal's
`QueueAccepted` flag alone cannot authorize a `CODEX_QUEUE_ACCEPTED` receipt;
the Node first requires the matching durable writer outcome. The Hub still
checks the current binding and attempt. `QUEUE_ACCEPTED` means only that the
official queue command returned successfully; it does not prove model
consumption, native Thread resume, business completion, or exactly-once
application behavior.
There is no automatic mechanism that resolves an uncertain native queue result
or safely retries it.

Each native writer scope is limited to 4096 operation records. At capacity,
new injection is refused; there is no automatic garbage collection, including
for uncertain records or deduplication records. Do not delete or edit a ledger
entry merely to force a retry after a crash. Preserve the private StateRoot and
Hub-specific state for offline investigation before considering any recovery
action. This version provides no CLI command that certifies an uncertain queue
result or performs a safe ledger repair.

Operational evidence should use bounded metadata such as Hub, Node, Endpoint,
binding epoch, message ID, attempt ID, writer epoch, and state. The queue
adapter discards native command output; prompts, message bodies, ciphertext,
bearer credentials, and private keys do not belong in logs or recovery notes.
