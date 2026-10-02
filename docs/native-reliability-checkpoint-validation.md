# N1 same-Group native delivery admission and recovery

2026-10-02. This checkpoint changes the Node's sealed same-Group delivery admission. It does not establish actual Codex wake, model consumption, foreground input protection, or exactly-once business effects.

## Source and ownership

The isolated detached worktree `/home/zyf/CICADA_native_reliability_n1` follows `dev` commit `e8a029d79bbdddb75ea376afa76e62a5c8444f59`. Its starting source includes the exact Task14 owned patch `88a24bd16af82fc6d6acbe3659c9738556f98dd82ccd7065699b32548101fc47`, applied after a successful check. The starting combined source manifest is `e4f3d784a95069a84c4ed8dc1026f5a8c7ef0a914ea3a9457bfaa831bf51e85d`, 992 files. The private baseline Git tree is `b88f2f806d9ddf578ee49f04855d703e4a37b2fa`; N1 changes must be compared to that tree, not attributed to HEAD alone.

The original Task14 worktree and evidence remain unchanged at source manifest `b58ffaccd2467f773cc2b8c84771e2445602cc27e4e124e5865488341bfb2f96`. N1 changes only these five paths:

- `cicada-go/cmd/cicada/machine_native_delivery.go`: private writer-held runner and per-call lifecycle dependencies.
- `cicada-go/cmd/cicada/machine_native_delivery_test.go`: offline process, Guard, fault and transport tests.
- `cicada-go/cmd/cicada/machine_fabric.go`: native execution wrapper and its required imports only.
- `cicada-go/cmd/cicada/cross_node_group_bridge.go`: `drainMachineCrossNodeGroupRelayClaim` only.
- This validation document.

No Hub schema, Client, PQ/certificates, lease authority, Control/NodeControl admission, nodelock/nodeinbox state/reset API, global configuration, or dependency changes are included. There are no commits, pushes, deployments or provider/model calls.

## Implemented behavior

The existing `executeMachineNativeCodex` interface delegates to a private runner. It acquires the exact physical native writer once. For same-Group delivery, the held writer surrounds a new real HTTP request for the exact remote attempt's current Hub Guard. The response must match every previously cryptographically verified field. Existing signed route, key grants, digest, replay and plaintext checks remain in place.

The order is: verify ciphertext and durable inbox → acquire physical writer → fetch and compare current same-Group Guard → validate current local native context, cancellation and command preparation → persist inbox injection intent → persist native operation intent → actual queue `Start`/`Wait` → durable native outcome → close writer → inbox/reconciliation/Hub receipts. Receipt helpers reacquire the writer; closing it first prevents a nested-lock deadlock.

Before a successful `BeginInjection`, writer busy, cancellation, command unavailability, and temporary authority/history errors leave the inbox `NODE_RECEIVED` and preserve the original journal. `AbandonClaim` releases only the still-CLAIMED attempt. Its separate two-second local cleanup context preserves values and removes parent cancellation; it is never passed to Hub Guard, queue execution, or unknown injection cleanup. Cleanup errors are returned, and the inbox API independently refuses to abandon INJECTING/uncertain rows.

Known current authorization denial and a stable native operation identity conflict are permanently rejected before injection intent. A native `QUEUE_ACCEPTED` result is reused only for the exact immutable Hub/Node/Endpoint/binding/epoch/message/digest identity; changing the remote attempt cannot clear an uncertain result. Existing accepted results need no command lookup, while current scope/preflight checks still apply.

After `Start`, a nonzero exit, cancellation, or outcome commit failure remains uncertain. A successful `Wait` alone cannot produce a queue receipt. A failed writer close after durable acceptance is classified as uncertain so it cannot turn accepted work into a retry or discard its journal. If the parent is cancelled after Start, inbox acknowledgement may itself fail: the local row stays INJECTING until production reopen converts it to `INJECTION_UNCERTAIN`. The durable native uncertain record independently blocks another queue.

An inbox admission that committed but returned an error is also conservatively retained as unknown. The implementation does not reset that row just because the native intent or command has not started.

## Existing recovery boundary

`reconcileMachineRelayJournal` is unchanged. It reads the exact durable native outcome after startup inbox recovery. Native uncertainty yields `INJECTION_UNCERTAIN`; native durable acceptance permits the existing `CODEX_QUEUE_ACCEPTED` and `CONSUMPTION_UNCONFIRMED` receipt path, without another queue call.

That recovery path uses the existing authoritative receipt checks: current owner-bound Node credential, exact Endpoint/binding/Node/epoch/live lease, exact remote attempt/prior NODE_RECEIVED, and Store membership/enrollment fences. It does **not** rerun the complete injection Guard, candidate/group-key grants, local native context, or Task tuple validation. Recovering an existing outcome is distinct from authorizing new native admission. A binding change that denies the new success receipt leaves native acceptance, local consumption-unconfirmed state and the recovery journal intact; the error is returned and queue count does not increase.

Plain Relay, sealed Link, Network-direct, old Local Group and Monitor notification callers retain their existing admission order. The wrapper's fallible preflight now precedes its own native intent, but these five routes have not gained same-Group's before-inbox writer admission/current-Guard change. Their busy and authority-wait windows remain separate work. A writer lock fences only CICADA writers sharing that account/session/root, not external TUI input, later model consumption, or arbitrary application effects.

## Deterministic tests and evidence

All fixtures are visibly synthetic. The queue helper is a child of the Go test executable, not installed Codex. It durably appends one acceptance counter and exits zero. The adapter uses the real `exec.Cmd.Start` and `Wait`. Per-call private command/observer dependencies supply barriers; there is no public fault API, production environment fault switch or global mutable hook.

| Test | Evidence and assertion |
|---|---|
| `BusyPreservesClaimAndJournal` | Another process holds the writer; an expired parent deadline releases only the CLAIMED inbox attempt, creates no native intent, preserves journal, then accepts the same message once after release. Slash, quote, backtick and newline peer content remains one literal message argument. |
| `AuthorityChangesDuringWriterWait` | Production Fabric HTTP Guard checks after waiting reject membership revocation, binding epoch change, actual lease expiry and Node credential revocation. A temporary 503 retains retry eligibility and succeeds once authority returns. |
| `CrashAfterSuccessfulWaitBeforeOutcome` (C) | Actual helper acceptance → actual Wait nil → pre-Finish barrier; parent SIGKILLs adapter. Raw native record is INJECTING before kill. Production reopen/reconcile retains uncertainty, no success receipt, count 1; original and new remote attempts cannot queue again. |
| `CrashAfterDurableOutcomeBeforeReceipt` (D) | Actual helper acceptance → actual Wait nil → fsynced QUEUE_ACCEPTED → writer.Close → pre-receipt barrier; parent SIGKILLs adapter. Production reopen/reconcile returns queue acceptance/consumption unconfirmed, count 1. |
| `PreflightNeverPersistsIntent` / `CleanupCannotReleaseInjecting` | Wrong scope, cancellation and missing helper precede intent; cancelled local cleanup cannot clear an injecting row. |
| `StartedFailureAndCommitFailureStayUncertain` | Actual accepted helper with nonzero exit and a post-Wait outcome-file fault both preserve uncertainty, journal and count 1. |
| `AcceptedReplayUsesExactDurableIdentity` / `ConflictingDurableIdentityIsFenced` | Missing CLI does not discard accepted history. Wrong Hub/binding/epoch/digest cannot transplant success. A genuine prior queued conflicting digest is rejected permanently by actual same-Group drain without another queue. |
| `DurableReceiptDeniedRetainsRecovery` | Actual D crash followed by real binding fencing causes production receipt rejection, preserving durable local evidence/journal/count 1. |
| `AmbiguousInboxAdmissionStaysUnknown` | Actual local BeginInjection commit followed by a lost acknowledgement cannot be abandoned; production reopen/reconcile retains uncertainty with queue count 0. |
| `StartedCancellationRecoversUnknown` | A pipe barrier proves helper acceptance before parent cancellation; native becomes uncertain, cancelled inbox receipt leaves INJECTING until reopen, count remains 1. |
| `Transport` | Production MCP → owner Unix socket → actual loopback TCP Fabric-only Hub → authenticated sealed ingress → receiver subprocess → exact queue/consumption-unconfirmed receipts. Management returns 503 with no Control business service. |

The filename prefix for the table's tests is `TestMachineNativeDelivery`. There are 12 asserted normal N1 top-level tests, one separately selected Transport test, and one helper entry. The helper's inert top-level PASS is not a capability assertion. Normal/race select only the 12 asserted tests:

```sh
go test ./cmd/cicada -run '^TestMachineNativeDelivery(Busy|Authority|Crash|Preflight|Cleanup|Started|Accepted|Durable|Conflicting|Ambiguous)' -count=1 -v
go test -race ./cmd/cicada -run '^TestMachineNativeDelivery(Busy|Authority|Crash|Preflight|Cleanup|Started|Accepted|Durable|Conflicting|Ambiguous)' -count=1 -v
```

The separate disposable transport selector is:

```sh
go test ./cmd/cicada -run '^TestMachineNativeDeliveryTransport$' -count=1 -v
```

This is one Docker container with loopback TCP and real receiver subprocesses. It is not a multi-container Node topology or real native wake. Supervisor compatibility selectors may also retain the previously recorded native writer/outcome/inbox/queue/Guard baseline tests, without broad Store/full-suite testing.

Run with pinned offline `golang:1.27.1-bookworm` image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, source mounted read-only, `/tmp:exec`, network disabled, read-only `/home/zyf/CICADA/.cicada-data/m1-gomodcache`, and `/tmp/cicada-go-lts-buildcache`. The new worktree's ignored `.cicada-data/native-reliability-n1-20261002/record_gate.py` records exact argv, source manifests, logs and exit codes for every attempt.

Developer attempt 01 failed two test fixtures (missing trusted scope in C's replay check; nonprivate standalone inbox parent). Attempt 02 passed the then-existing focused tests and retained actual C/D JSON audits; its source fingerprint is `649c6ccca74d72a55f127a2a78e8657ba605aa0133c46e329c8281c381a10239`. The subsequent two added boundary tests passed separately in attempt 03, source fingerprint `9a06f771433ce039fbbd4951e8d75a64b8bc73038ab7390a5737e9de6faa44c5`. The final audit format additionally retains raw ledger/argv JSON text including newlines so original hashes can be recomputed directly. All attempts retain their own source attribution; they are not retrospective final-source passes. Independent final normal/race/vet/build/transport outcomes belong in the ignored final report after code/document freeze, with their exact final fingerprint. No unrun independent gate is claimed here.

C/D emit `N1_PROCESS_AUDIT` JSON containing actual synthetic witness/counter/argv, their hashes, bounded native records before kill and after recovery, actual SIGKILL signal 9/child exit -1, restored inbox state, HTTP receipt layers, and the test-helper binary SHA-256. Parent Go test exit 0 is recorded independently of the killed child. Optional test-only `CICADA_N1_TEST_EVIDENCE_DIR=/evidence/<unique-attempt>` exports those records as mode 0600 JSON before TempDir cleanup (directory created 0700). Export contains no fixture credential configuration, keys or crypto database. Supervisor should mount only the new ignored evidence directory for that export. Helper binary and separately built product binary IDs must remain distinct.

Actual Codex/provider/model turns, adopted idle/busy/approval-waiting behavior, Android, physical dual Nodes, public HTTPS and NativeDirect are **NOT_RUN** for N1. The historical native evidence and four old Monitor baseline failures retain their original attribution. This checkpoint supplies synthetic process and transport evidence only.
