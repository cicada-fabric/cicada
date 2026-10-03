# Disposable Node restore/recovery validation

This gate exercises the production `cicada machine backup`, `verify`, `restore`
and authenticated `recovery query` commands. A narrowly scoped command-package
test binary initializes synthetic Owner/device/Node identities through the
existing pairing services and serves the production Hub HTTP handler and Store.
It seeds real encrypted ordinary RPC receipts through that handler. Fault controls
exist only in the test binary. No production route, protocol or contract changes.

Run with an existing complete offline module cache and the locally pinned Go
1.27.1 Bookworm image. The driver refuses to pull an image or fetch dependencies:

```sh
python3 -m unittest discover -s scripts -p test_node_restore_recovery.py
python3 scripts/test-node-restore-recovery.py \
  --module-cache /path/to/offline/gomodcache \
  --evidence .cicada-data/restore-validation/new-owned-run
```

The image ID is fixed in the driver. Build and initialization containers use
`--network none --pull never`, read-only source/module-cache mounts and task-local
build output. Each case creates two separate runtime containers: the real Hub
handler and a Node container executing the production CLI. Their labelled internal
Docker network has no egress or published ports. Synthetic HTTP uses a disposable
Docker `.localhost` alias; this is application encrypted authentication over a
private test transport, **not public HTTPS acceptance**. Mounts contain only the
new fixture tree and task-built binaries. Owned labels are verified before cleanup.

Cases cover `COMPLETE`, `NOT_RECORDED`, `UNCERTAIN`, stale current Hub binding
epoch, corrupt accepted highwater, conflicting recorded packet digest, current
revocation, archive tampering, missing shared fence, read-only advisory lock mode
and changed external restore registration. Each fault has a separate disposable
tree. Synthetic SQL faults never repair or roll back a recovered Node. Queries
must remain bounded metadata, return no private payload/key/bearer material and
leave Node bytes and raw modes plus authoritative Hub recovery tables unchanged.
The Hub service and Node container restart before the second query; each query
runs in a fresh production CLI process. This does not prove a running Node Agent
crash window.

Restored fixtures contain an existing Owner trust row and Endpoint private key,
local crypto sequence 9, replay sequence 11 and an `INJECTION_UNCERTAIN` delivery
with its uncertain attempt. Read and restart checks preserve them exactly.
Production Agent startup, operator reconciliation and Owner trust/revocation
attempts must reject quarantine. All checked paths reject existing quarantine
before preparing locks or opening writable state, then retain their checks under
the relevant locks. The driver inventories every advisory lock and requires zero
byte or raw mode delta. These prechecks do not claim atomic zero-I/O rejection
for arbitrary concurrent host modifications; the locked rechecks prevent writable
state from opening after a serialized restore. MCP Group key
publication uses its existing authenticated whoami and independently checks the
selected Node and explicit common WriterRoot under maintenance locks; focused
Go tests verify no private key creation or candidate publication.

The query now checks the exact external registration and in-tree marker and
verifies v2 shared fences while holding both exclusive locks. A pending shared
marker does not substitute for checking its bundle. A shared marker may belong
to the first Node restored with the identical bundle; each later Node must retain
its own exact lineage. Legacy v1 reads can authenticate only a matching
`shared_fences_missing` hold and remain quarantined. Offline inspection reports
shared bundle mismatch separately from its held quarantine; its report is not
the authenticated query's final lineage check.

Repeated restore reuses only a complete exact shared bundle. A missing fence
after a prior pending marker is indistinguishable from lost forward state,
including after an interrupted first install. The command keeps quarantine and
requires manual recovery rather than recreating the file from an old archive.

`NOT_RECORDED` means receipt absence, possibly after rollback or pruning, and
never proves non-execution. `COMPLETE` is durable metadata rather than accepted
business output. `UNCERTAIN` remains unresolved. No status authorizes clearing
quarantine, resetting counters or replay windows, forcing keys, retrying uncertain
work, releasing resource fences or inferring that an old process stopped.

Evidence includes exact commands and exits, image/binary hashes, complete source
hashes and raw modes before/after, bounded result summaries, explicit advisory
lock deltas, fixture cleanup and separate skips. Captured command outputs are
hashed and secret-scanned bounded initial/restart query reports are retained;
private fixture trees are deleted. This is deterministic synthetic TCP
and storage evidence. Android, real native Runtime, physical device, provider,
production StateDir and public HTTPS results remain `NOT_RUN`; a utility fixture
test skipped outside its explicit mode is not a passed runtime case. Final gate
records are attributed to their complete dirty source inventory, not HEAD alone.
