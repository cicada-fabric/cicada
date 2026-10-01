# Node backup and shared WriterRoot recovery

`cicada machine backup` format v2 archives one selected Node subtree together
with the bounded shared state that fences work across Hub contexts using the
same WriterRoot. It includes the provider-admission SQLite ledger and intent
rows, the metadata-only native-context history ledger, durable native-writer
epochs and operation records under `.native-writers/`, and durable physical
resource execution records under `nodes/.locks/`. SQLite is checkpointed and
verified. Live flock files are not archived: they do not carry durable
ownership and must not be restored as if a process still held a lock.

The archive does not include the whole WriterRoot, another Hub's Node subtree,
cryptographic keys stored outside the selected Node subtree, arbitrary MCP or
native-runtime state, or conversation bodies. Restoring a second Node archive
can reuse a shared fence bundle only when its digest exactly matches the
already restored bundle. Existing foreign Node subtrees remain untouched.

The WriterRoot must be a real owner-private directory with mode `0700`; its
covered subdirectories must also be private, and covered files must not grant
group or other access. The Agent and backup/restore commands reject permissive
roots rather than changing permissions silently. Before repairing an existing
root, stop all Hub Agents and Node writers that use it, verify the canonical
path is not a symlink and that its owner is the service account, and inspect
the contents and modes. An operator who confirms that ownership and access
scope are correct may tighten directory modes explicitly; otherwise create a
new private root and perform a separately reviewed state migration. Do not
split Hub contexts across different WriterRoots: native-writer exclusion and
known native-scope history are only shared within the same root.

Agents hold a shared WriterRoot lock for their lifetime, so several Hub Agents
can run together. Provider admission, native-context checks, native writer
operations, resource execution, workspace handling, and local peer bridges
inside those Agents are covered by that lifetime lock. The standalone native
writer lock still serializes a single native session; the WriterRoot lock
additionally excludes backup across all sessions and Hub contexts. The
node-control operator also takes the shared WriterRoot lock. Mutating operator
actions acquire the selected Node's Agent-ownership lock and are rejected while
that Node Agent is running. Backup and restore first take the selected Node's
exclusive maintenance lock and then attempt a nonblocking exclusive WriterRoot
lock. They return busy while any Agent or other shared WriterRoot user is
active; they do not wait indefinitely or stop a running process. To back up
multiple Node subtrees from one WriterRoot consistently, stop every Agent and
writer sharing that root, then back up each selected Node before restarting
them.

In the current code, `runMachineAgentWithContext` acquires the shared lock
before opening the provider ledger, native-context registry, or resource
manager and holds it until shutdown. Its native Fabric/approval handlers and
`machineAgentJoinBridge.recordLocalNativeContext` run under that Agent
context. `runMachineNodeControlOperator` separately takes the WriterRoot
shared lock; state-changing operator actions also acquire the Node ownership
lock. `BackupWithWriterRoot`, `RestoreWithWriterRoot`, and
`InspectWithWriterRoot` are the corresponding offline/read-only entrypoints.
Direct package-level ledger calls in tests use isolated temporary roots and do
not represent an exposed production CLI or remote API.

Restore is a recovery operation, not rollback support. A v2 restore writes a
durable pending marker before installing any shared file. All Agents using
that WriterRoot remain blocked until an operator has reconciled the restored
state; the current implementation has no command that clears this marker.
Repeated restore is accepted only for the same bundle while every installed
fence file still matches it. Missing, changed, conflicting, or newer shared
state is never overwritten. In particular, provider attempts, native writer
epochs, resource fencing epochs, key material, and replay counters must not be
reset or inferred from a Node subtree.

A legacy v1 archive contains no shared WriterRoot bundle. Restoring it with a
WriterRoot records `shared_fences_missing` and blocks every Agent using that
root. A later v2 archive does not automatically clear this hold: the old
attempt, epoch, or native-scope history cannot be reconstructed from the Node
subtree. Keep the original records and reconcile through a separately
authorized recovery procedure. `recovery inspect` is read-only and reports
whether the bundle matches; it does not prove that a native Runtime stopped,
that a provider action did not occur, or that external replay state is current.

Package tests also call the ledgers and resource/native writer APIs directly
using disposable private roots; those are controlled fixtures outside the
Agent lifecycle, not additional production entrypoints. The synthetic tests
cover shared Agent lock coexistence, immediate refusal of offline backup
while a shared lock is held, v1 fail-closed restore, v2 exact bundle restore,
changed-fence refusal, preserved foreign Node files, and provider/resource
generation non-rollback. They are not a production StateDir, physical Node,
or native Runtime restore rehearsal.
