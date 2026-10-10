# G4 durable crash-window process validation

This note defines a narrow deterministic process test and its relation to the
separate real-CLI queue crash fixture. Neither result alone is a full G4 pass.
The adopted demonstration requires failures before send, after Relay commit,
after Node durable receive, and after native injection, followed by restart and
checks of state, correlation, receipt identity, lease and uncertainty
(`CICADA.md` §39.5).

## Deterministic process selector

`TestG4CrashWindowsAtDurableBoundaries` in
`cicada-go/cmd/cicada/g4_crash_window_process_test.go` uses disposable synthetic
Store/Node state and subprocesses of the test binary. Its sender case kills the
child after durable outbox attempt preparation but before HTTP; this helper does
not invoke a send operation. A separate process reopens the outbox and proves
the same operation ID/input digest remain deduplicated without advancing the
attempt. The Relay case kills the real
production Fabric handler after the ASK transaction commits but before the HTTP
acknowledgment, then restarts it and checks that the original message/request,
sealed envelope, request state and acceptance receipt survive an identical
retry. The Node case kills the process after local inbox/journal persistence but
before `NODE_RECEIVED`, then restarts Hub and Node and verifies one exact
receipt, the original attempt/message/request/digest/binding epoch, and
unchanged SessionBinding lease fences. Wrong-epoch and wrong-digest receipts
remain rejected.

The focused command is:

```sh
go test -p 2 -mod=readonly ./cmd/cicada \
  -run '^TestG4CrashWindowsAtDurableBoundaries$' -count=1 -timeout=120s -v
```

This selector is **synthetic process-boundary evidence**: it does not start an
official Codex CLI, a Native Runtime or a model, and does not prove native
injection. It must not be reported as the fourth window or as full G4.

## Recorded process-window QA

Root's 2026-10-10 `qa-a5` run passed the normal and race phases. Each phase
reported 40 tests run and passed, 0 skipped or failed, across 2 packages; the
combined run exited 0 in 243.629 seconds. The selector also included the G5
permission test and three existing MCP guard tests. Its source was the dirty,
test-only overlay on HEAD `2594343b84ed0ec17a5cf349607631d831773cc3`, with the
G4 process test SHA256
`611313cbf3244ed6c63d782415ff90baf8d478d8bef08a9ac1cbf36ac38fc614` and the
G5 test SHA256
`f76b1137346eed1dbf885b1fbf72e51f91783b6578e30cb831b4c7f0bb9369af`. The
Root run receipt is
`.cicada-data/v01-next-gates-20261010/qa-a5/ROOT-RUN.NONAUTH.json`
(SHA256 `e390f3fb2baa45daa851eba15b058150eadd5bfc907c47d6696c5b47f8fec3af`);
the count receipt is `ROOT-COUNTS.NONAUTH.json` (SHA256
`cb64ffe3b756113fb4595a16b21bcaa17f7d2d8f39c6b3fb80d73fd21015aaa9`). The
normal and race JSONL hashes are respectively
`eac03b67e6ff58678fb4c7067735d4a941d2da9cc97566a6395aee8c61c3d250` and
`ffa694723816edc2c30426990f53acc5698c63f7dc0a2a8354fe6851d4659e58`.

This is a scoped synthetic process/HTTP result. It used no model and does not
cover the real CLI injection window or a physical device/runtime stop proof.

## Native queue / injection window

The existing opt-in `TestMachineNativeRealQueueCrashAcceptance` is the only
native boundary in this set. It exercises the actual official CLI 0.162.1
queue operation and crashes the adapter after one queue submission but before
the injection ledger finishes. Its exact fixture contract and command are in
[`native-queue-crash-acceptance.md`](native-queue-crash-acceptance.md#invocation-and-assertions):
the owner supplies a private synthetic-profile receipt and its checked hash,
the official CLI hash/version and Runtime image are pinned, provider egress is
disabled, and maximum model turns/provider POSTs are zero. The documented
command is:

```sh
CICADA_NATIVE_QUEUE_CRASH_ACCEPTANCE=1 \
CICADA_NATIVE_QUEUE_CRASH_FIXTURE=/absolute/path/to/private-fixture.json \
CICADA_NATIVE_QUEUE_CRASH_FIXTURE_SHA256=OWNER_CHECKED_RECEIPT_SHA256 \
go test -p 2 -mod=readonly ./cmd/cicada \
  -run '^TestMachineNativeRealQueueCrashAcceptance$' -count=1 -timeout=120s -v
```

### Recorded current-CLI injection result

Root's 2026-10-10 A3 execution passed this real queue window in 20.146 seconds:
`PASS_INJECTED_BEFORE_LEDGER_REAL_QUEUE_ONLY`, test exit 0. The run used official
CLI 0.162.1 (SHA256
`628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1`), Runtime
image `sha256:7d5c8ef4288772fae4f43eafef1cfdd5c0644d2fe29b9b94d1c025d6837ae45e`,
and executor image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`.
The source was a dirty test overlay on HEAD
`2594343b84ed0ec17a5cf349607631d831773cc3`, inventory SHA256
`aebb30d7331945e15f399d15c80a68160e558ef11679d5b5cfbec30769fdf057`; its
native fixture test source SHA256 was
`b28cae8d017d9ec148223c603a85d5934e4800e50f4543414368d533d7cbbb17`. The
result is
`.cicada-data/v01-next-gates-20261010/native-g4-preparation/runtime-output-003/result.NONAUTH.json`
(SHA256 `95f35a4040c2a3588e87434596f04e1dadbbdcb9e169632b6e514a0ddb8c0eac`);
Root's closeout receipt is `ROOT-RUNTIME-A3.NONAUTH.json` (SHA256
`f03796a1c53ca2ae74690ecaf189a4049bf7a35d2401e01e08bc1d0d09d37dd6`).

The official CLI operated on an independent copy of the saved synthetic
history. Readback matched the saved thread identity and full history hash
`fb618036edbb35cef3db4931fd47d0f4b5914b51dbd65038565580f901b0e414`, including
2 completed turns and 10 items; the thread was `notLoaded` and the queue was
terminal and empty. The injected crash occurred after the real queue
operation and before the Node ledger finished. The result records
`ZERO_TURN_STARTED_NOTIFICATIONS` with provider egress disabled (`NETWORK_NONE`);
the provider-request counter was not instrumented. Cleanup was confirmed, both
owned container IDs/names and the fixture root were absent, the six protected
residents were unchanged, and the compiled workspace inventory was unchanged.
This proves the named real-queue crash window only; it does not prove model
consumption, exactly-once execution, physical stop, or device behavior.

### Preserved failed attempts

Earlier attempts remain failures in their original records. A1 failed after
3.05 seconds with `UNIX_SOCKET_PATH_TOO_LONG` before native injection (result SHA256
`4e1dc144f10cecbe5c09f636aa11085c38844d504b7742c1aed42649d43c3eec`). A2
failed after 15.388 seconds. It performed the read-only CLI history readback,
but the Go fixture decoder
rejected its disposable-root path because the basename lacked the required
`cicada-native-queue-crash-` prefix; native injection was not attempted. A2's
result remains FAIL with test exit 1 (SHA256
`8311ce5f1d39e7061ce8b3dc410eaa9c190568622be605b66dc3a8186b7a4cf7`), and its
cleanup was confirmed. A3 is a distinct corrected-path result; it does not
rewrite either earlier failure.

## Current process-test assertion correction

The retained a4 normal/race QA result is **FAIL**: its Hub/Node case stopped in
the test helper when it used `GetFabricRequestV2` to read a sealed Link ASK.
That reader intentionally exposes only plaintext Relay requests, so the
`ErrRelayRequestNotFound` was a test-reader mismatch, not evidence that the
committed sealed request was missing. The helper now reads lifecycle metadata
through the authenticated `NodeSealedLinkRequestStatus` path and checks the
exact request/message/digest, sender and receiver endpoint/principal/group,
both binding IDs and epochs, Link scope, open state and reply fields alongside
the existing receipt-chain assertions. No production code changed. The a4
failure remains attributed to its original run. The corrected selector passed
in the later a5 normal/race run recorded above; this does not relabel a4.

## Acceptance boundary

Keep these evidence scopes separate: a5 is the synthetic process/HTTP result,
and A3 is the current-CLI real-queue injection result on its recorded dirty
source inventory. Together they are scoped evidence for the named checks, not
a blanket full-G4 acceptance or proof of model execution. Physical stop
verification, physical device behavior and public HTTPS remain outside these
results and are `NOT_RUN` here.
