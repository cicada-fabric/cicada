# Hub restore with a current-source forward checkpoint

This maintenance path supports a planned, offline handover of one continuously
current Hub to a designated directory in the same parent-local filesystem
namespace. An older verified backup B establishes restore lineage. A complete
current capsule C carries the actual identities, keys, replay and response
reservations, current authorization and revocation state, and operation
outcomes. The target receives C in its entirety before activation. An archive
signature, new nonce, operator click, or counter maximum cannot prove freshness.

Candidate03 passed the supervising task's focused normal/race checks, vet,
formatting, builds, Python checks, and three-case disposable TCP gate. The exact
tested source and exclusions are recorded below. Historical quarantine and
earlier audit-only results do not validate this candidate. Android, real native
Runtime, models and providers, physical devices, public HTTPS, production
StateDir recovery, and source-loss disaster activation remain separate
**NOT_RUN** results.

The source must already have an independent established-deployment trust pin.
It records the exact original source directory's canonical coordinate,
filesystem device/inode, registration nonce, Hub ID, three public identity
fingerprints, schema fingerprint, and an independent deployment reference
digest. Its expected file digest must be established outside this command.
Production CLI does not create such a pin; independent deployment pin provisioning
is not yet a product workflow. This planned handover does not complete ordinary
user disaster recovery and cannot bootstrap trust from a backup. Capturing a pin from an arbitrary
copy or restored archive does not establish a current source. Missing evidence
returns `AUTHORITY_UNPROVEN` and preserves hold. The synthetic initializer in
the test binary is solely a disposable validation fixture.

The authority lives under the source's private parent-local
`.hub-restore-authority` directory. Paths are explicit, directories are 0700,
files are 0600, and owner, symlink, coordinate, and incarnation checks fail
closed. Mounting a target without its independent authority does not authorize
startup. The original restore marker and its paired registration remain after
activation; external receipts and the single-use authority permit are never
portable archive payloads.

Loss of any single authority record, locator, or marker fails closed while the
remaining evidence still identifies the registered lineage. If every local
sentinel and every independent anchor is deliberately destroyed together, all
proof of that lineage has disappeared. The remaining ordinary payload alone
cannot reveal the prior registration; this slice does not claim to detect that
complete destruction of its evidence.

Stop source writers before executing this sequence. Every command must exit
successfully before continuing. Failures retain existing holds and apply the
durable fencing described below. There is no force, reset, key rotation, or
quarantine-clear option.

```sh
# The pin and expected digest already exist from original deployment registration.
cicada migration recovery register --source /private/source \
  --trust-file /private/established-pin.json --trust-sha256 "$ESTABLISHED_PIN_SHA256"

# B may precede later legitimate authorization and replay state advancement.
cicada migration backup --state-dir /private/source --output /private/B

# After legitimate source advancement and stopping every writer, seal current C.
cicada migration recovery prepare --source /private/source --backup /private/B \
  --capsule /private/C --state-dir /private/T
cicada migration restore --backup /private/B --state-dir /private/T
cicada migration recovery status --source /private/source --state-dir /private/T
cicada migration recovery reconcile --source /private/source --state-dir /private/T
cicada migration recovery activate --source /private/source --state-dir /private/T
```

`register` consumes the independent original-source pin; it is not a fallback
in `prepare` or `status`. `prepare` fences and durably retires SOURCE and creates
C under its existing exclusive maintenance lease. SOURCE cannot restart after
retirement, even if its internal marker is lost. `status` only inspects existing
evidence. `reconcile` checks complete B-to-C scope and UNKNOWN continuity and
publishes C by one atomic directory exchange. The older restored B payload is
retained in the reported parked directory, with its original holds. An
unsupported filesystem cannot fall back to remove or a two-rename replacement.

`activate` rechecks the final published target incarnation, original paired
holds, complete C inventory, and execution quiescence while exclusively leased.
It durably records a receipt and consumes one authority epoch by CAS. Receipt
without committed authority, authority without receipt, missing authority,
wrong target, copied receipt, or a later restore at the same pathname remains
held. Normal Full and Fabric-only startup continue through the existing guard.
A subsequent legitimate state update and restart use the active incarnation
and lineage; they need not match C's initial database hash forever.

If synchronization fails after an authority rename, a durably persisted latch
or a durable rollback normally keeps the transition held. The combined failure
where both persistence mechanisms fail has a narrower guarantee: strong
references to the exclusive leases keep this process fenced while it remains
alive. After process death, the disk state in that combined fault is
**UNKNOWN**. It is not a proven crash-safe hold and must not be marked **PASS**
without a separate durable mechanism and actual fault evidence.

The execution gate refuses recoverable pending Workers, Client intents,
processing requests, redispatchable relay/peer deliveries, and unresolved
resource or external writer ownership. This slice rejects every
`resource_v2_leases` row, including a `RELEASED` lease paired with an `AVAILABLE`
resource or operator Boolean evidence. It has no strong executor-stop proof.
An expired advisory lease or an operator Boolean is not proof that an executor
stopped. Original UNKNOWN operation identities, reservations and tombstones
must survive unchanged.
Their old packets yield cached sealed responses or `OUTCOME_UNCERTAIN`, never
a new business attempt. Unknown schemas, tables or uncovered scopes fail
closed. There is no native/provider execution-recovery claim in this slice.

The disposable gate uses actual production backup, restore, register, prepare,
status, reconcile and activate commands. Its test-only fixture creates visibly
synthetic keys and Client grants before B, advances real encrypted metadata
requests after B, revokes a second device, preserves an original UNKNOWN and
burned response reservation, and probes the activated target across restart.
It starts separate original-source and target Hub processes in an owned
internal Docker network; compilation is separate from TCP acceptance. The
loss-of-UNKNOWN and processing-request fixtures must refuse activation. A
copied restored directory must not register using the original source pin.

Build both binaries from the same frozen candidate through the supervisor's
pinned offline Go overlay, then run the gate explicitly:

```sh
python3 scripts/test-hub-restore-activation.py \
  --binary /absolute/frozen/cicada \
  --fixture-binary /absolute/frozen/hub-forward.test \
  --build-manifest /absolute/frozen/effective-source-manifest.json \
  --image sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 \
  --evidence "$PWD/.cicada-data/restore-validation/hub-forward-gate-new"
python3 -m unittest discover -s scripts -p test_hub_restore_activation.py
```

The fixture selector is `^TestHubRestoreForwardDisposableFixture$`. All paths
are explicitly mounted under `/synthetic`, with no host credentials or real
Node state. Evidence records exact commands/exits, output hashes, binary and
image identities, source raw modes and hashes before/after, original B
preservation, and exact owner-checked cleanup. Private fixture material is
removed only after owned processes are removed. A timeout has unknown exit
and fails the gate; a skip is never a pass. Software/Git revision, dirty source
fingerprint, schema, protocol and image digest remain distinct.

## Candidate03 validation record — 2026-10-04

The effective source was the read-only Main baseline
`d7bbbf5e4074cb846267896b89f58880e97290a3` plus 15 exact owned Go overlays.
All 923 effective-source inventory hashes and raw modes matched before and
after validation. The inventory includes non-Go and other files not directly
compiled; it does not establish that all 923 files were compiled. The worktree
checkout revision `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c`
is a checkout coordinate, not an attribution of these binaries to a clean
build of that revision. The pinned image was
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`.
The [build manifest](/home/zyf/CICADA_restore_validation/.cicada-data/restore-validation/hub-forward-implementation-20261004/build-manifest.json)
records the effective source, toolchain, build commands and binary hashes;
its SHA-256 is
`5c6fb03a1b0fe36a60650fe42345969d5d5e0790964c3fe6c72c27a065a1d21b`.

| Check | Actual result |
| --- | --- |
| Focused normal03, three Go packages | Exit 0; 46.7607 seconds |
| Focused race01, same three packages | Exit 0; 760.6319 seconds |
| vet01 and gofmt02 | PASS |
| Linux production and fixture binaries | PASS |
| Darwin/amd64 and Windows/amd64 product compile smoke | PASS; compilation only |
| Python syntax and seven driver tests | PASS; frozen driver hash unchanged |

Each Go run recorded 40 PASS top-level entries and 40 PASS subtests: 38
meaningful top-level scenarios plus two inactive fixture helpers reported as
PASS. The helpers do not count as scenarios. A separate old dual-binding
fixture recorded one explicit **SKIP**, giving 41 total top-level entries;
that skip is not a pass. The earlier normal01 fixture-0700 failure
is retained in full. Normal02 and normal03 passed after the repair; the failed
run has not been overwritten or reclassified.

The actual [TCP gate summary](/home/zyf/CICADA_restore_validation/.cicada-data/restore-validation/hub-forward-tcp-gate-20261004-01/summary.json)
records **PASS** for `happy`, `lost-unknown`, and `pending`, with 129 exact
commands. The happy case verified current replay floor advancement and
revocation, original UNKNOWN refusal to dispatch, cached sealed uncertainty
responses across restart, original identity bytes, B and hold preservation,
and Full/Fabric-only startup boundaries. The two fault cases passed by refusing
the unsafe transition. Source inventories matched before and after. Synthetic
model/provider calls were zero; model/provider execution was `NOT_TOUCHED`.

The supervisor independently verified cleanup of 20 exact owned Docker
references, their owner labels, and the private fixture path. Its
[cleanup record](/home/zyf/CICADA_restore_validation/.cicada-data/restore-validation/hub-forward-implementation-20261004/parent-tcp-cleanup-verification.json)
is **PASS**, SHA-256
`9de6e0d497db84374afe6d299a8c5f3467ca8716897003464e71129e9385b6ab`.
The command logs and source records belong to the external Core validation tree
`/home/zyf/CICADA_restore_validation/.cicada-data/restore-validation/hub-forward-implementation-20261004` and
`/home/zyf/CICADA_restore_validation/.cicada-data/restore-validation/hub-forward-tcp-gate-20261004-01`;
they were not copied into Main.

These results do not mark the combined persistence failure followed by process
death as PASS; its disk state remains **UNKNOWN** as described above. They also
do not establish detection after deliberate destruction of all sentinels and
independent anchors, or upgrade any prior audit-only conclusion to executed
evidence. Android, real native Runtime, physical-device, public HTTPS,
production StateDir, and source-loss disaster activation remain **NOT_RUN**.
These receipts validate the historical candidate source described above, independent
of its later Git integration; validation performed no push or deployment.
