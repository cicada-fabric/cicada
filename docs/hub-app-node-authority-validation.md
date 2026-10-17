# N3 Hub authority validation

## Explicit Hub Nodes runtime checkpoint

2026-10-17, phase HUB_NODES_ONLY. Tested dirty input based on integrated App/Store
predecessor `8df8ae5034f819ff3d839b6574f02c3c887af253`; this is not a build or test
attributed solely to that HEAD. The same immutable Go 1.27.2 Docker image and
private no-network/read-only-root/uid-1000 controls recorded below were used.
Only disposable synthetic state and loopback TCP were exercised.

Evidence directory:
`/home/zyf/Cicada/.local/evidence/n3-hub/runtime/`.
Normal manifest `checkpoint-normal-source.json` SHA-256:
`418549428c0a43c9bfc48b36c20f94c32dacaff0fa2d04833f6056fef36bec23`.
Race manifest `checkpoint-race-source.json` SHA-256:
`fbe62878bb7eb6881f2358eee6373778e00c7a95b7241919d3f3b953cb812197`.
Both runs verified their listed inputs remained unchanged. After those checks,
only this validation section and delivery-guide prose/commands were updated:
fresh Node files now share one configurable NodeRoot with bin/state and an
optional unexecuted user-service template. The Hub writer also removed only its
own README navigation delta, returning that file to QA ownership. Shell snippets
were syntax-checked separately; Go was not rerun for these doc-only changes.

| Lane | Result |
| --- | --- |
| Six-package focused normal | PASS: 40 events, zero failures/skips |
| Same focused race | PASS: 40 events, zero failures/skips |
| Eight-package vet | PASS |
| N3/N2 metadata; diff whitespace | PASS |
| Delivery-guide shell snippets | PASS: syntax only, commands not executed |
| Independent App/Hub adversarial/process-fault acceptance | NOT_RUN by this Hub checkpoint; QA-owned next gate |
| Standard disposable Docker product interop and broad N2/native regression | NOT_RUN by this checkpoint; integrated Root-owned gates |
| Actual Ubuntu Node/user service, native Windows UI/vault, public HTTPS, strict PQ TLS, actual Runtime | NOT_RUN |

Normal/race tested `./internal/server`, `./cmd/cicada`, `./internal/store`,
`./internal/control`, `./internal/hubauth` and `./internal/hubaccountwire`, with
`-count=1` and this selection:
`^TestN3HubNodes\|^TestServeHubNodes\|^TestN3StoreBoundHeartbeat\|^TestBoundNodeHeartbeatPreservesStatusUnlessExplicit$\|^TestNodeDeviceCodeOwnerConfirmation\|^TestStartNodeDeviceBinding\|^TestAppNode`.
Vet additionally covered the new `./internal/nodebinding` and
`./internal/hubnodes` packages.

The real TCP test uses the actual N2 Root KEM/signature activation and password
login, followed by an independently generated Node's real pairing proof. It
then exercises N3 discovery, exact full-key Owner preview/grant, atomic Client
confirmation and identical receipt retry; actual Node PQ binding-status and
identical retry; Worker RPC refusal; accepted empty heartbeat; self-cancel and
new READ_EXISTING; historical confirmation reconciliation; READ_EXPIRED for an
unadmitted read; and rejection of a late read as new authority. It verifies that
binding alone is UNKNOWN and an accepted heartbeat becomes CONNECTED while the
persisted Worker status remains offline. This shared-wire test does not claim
native App controller/UI execution against the new runtime.

The CLI subprocess executes the actual `serve --hub-nodes-only` entry point,
checks bounded discovery, unavailable old business APIs and graceful shutdown,
and verifies retained identities, no Control workspace/snapshot store and no
local Machine. Missing identity loading refuses without regeneration. Mixed
serve modes and a configured strict Node PQ listener refuse rather than
downgrading. The relay-only instruction now directs the user to Cicada App,
retaining the Device code marker, protocol VerificationURI validation and old
full-mode message. It is not a production installation or physical Node run.

The first TCP attempt reached confirmation but failed liveness: the existing
bound heartbeat writer used whole-second Store time, which truncated a newly
accepted heartbeat before a same-second RFC3339Nano approval. The RED log remains
`tcp-attempt2.jsonl`. Both accepted bound heartbeat writers now capture local
RFC3339Nano time after their binding/Owner guards; global Store `now()` and
strict pre-approval/future checks remain unchanged. A deterministic actual-Store
test approves at fractional `.123456789`, accepts a heartbeat ten nanoseconds
later in that same second, exercises both writers, and verifies CONNECTED with
Worker status unchanged. No sleep or time tolerance masks the failure.

The full compile-only attempt is recorded separately and claims no runtime
acceptance. Earlier compile failures (test Seal argument order and missing time
import) and the liveness RED are retained. `happy-attempt4` passed six initial
integration/CLI/heartbeat events; final 40-event lanes include the shared-wire
and existing Node code compatibility regression as well. The guide
[Hub Nodes mode and Ubuntu delivery](hub-nodes-only.md) keeps the ordinary-user,
single-root installation and optional unit distinct from unrun physical,
systemd, HTTPS and Runtime acceptance. No resident service, real keys, grants or
deployment was modified.

## Store checkpoint

2026-10-17, phase STORE_ONLY. Predecessor shared-helper commit:
`5f509befa6065ac41abeb23451ef8d41cc2c76aa`. Schema 63 adds private head,
proposal/grant, exact receipt/fence, confirmation provenance, rolling read-cache
and renewable diagnostic-rate tables. Wire version remains 1 and contract
revision remains app-node-authority-v1. No N3 HTTP endpoint or
`--hub-nodes-only` executable composition is enabled by this checkpoint.

Evidence is private and synthetic at
`/home/zyf/Cicada/.local/evidence/n3-hub/store/`. Final normal input manifest
`checkpoint-final-normal-source.json` has SHA-256
`d1311ce9730ffbbc4ca03c7958d7d2700647a5d5fcaccdfbfdaee878ae521517`;
final race input manifest `checkpoint-final-race-source.json` has SHA-256
`19a98429ef1f611f1eac0f42a5881eb66ca374ae37f49bbda512d95a68fdda4f`.
These identify dirty input based on the predecessor; all listed input hashes
remained unchanged during each run. This validation section was added afterward.
The same immutable Go 1.27.2 image and isolated container controls described
below were used. Containers used neither production credentials nor a resident
Hub. N2 enrollment and Node proof rows are explicitly synthetic Store guard
fixtures; N3 Owner signatures and N3/Client envelopes are real cryptography.

| Lane | Result and exact scope |
| --- | --- |
| Final normal | PASS: 31 events, zero failures/skips; `^TestN3Store\|^TestNodeControlOwnerConfirmationAndCredentialDigestRemainExact$` |
| Final race | PASS: the same 31 events, zero failures/skips, `-race`; 279.718 seconds |
| N3 within both final lanes | PASS: 30 events, zero failures/skips, including schema-63 after-apply rollback/restart |
| Final Store vet | PASS: `go vet ./internal/store` |
| Prior broader normal regression | 111 passed events, zero failures; one separately recorded physical-bind fixture skip, before the final LoginRequired correction |
| Prior broader race | NOT_COMPLETED: intentionally stopped with exit 143 to fix the known LoginRequired semantic issue; 12 events had passed, no pass claimed for the full lane |
| N3/N2 metadata and diff check | PASS |
| HTTP, CLI composition, integrated Docker product interop | NOT_RUN: remaining implementation/integrated acceptance |
| Real Ubuntu Node, native Windows, public HTTPS, strict PQ TLS, real Runtime | NOT_RUN |

The broader normal command used
`^TestN3Store\|^TestN2\|^TestNodeControl\|^TestV2Migration\|^TestHubRestore\|^TestHubForward`
in `./internal/store`, with `-count=1`. Its input manifest SHA-256 was
`75402a6bb788b4121af4e44920ea05290c42de7f1e75b7c7c757704aa51c5776`.
The skipped test was
`TestHubForwardPrepareRejectsPhysicalBindCapsuleBeforeFence`: two disposable
bind mounts were not supplied. That skip is not a pass. The final correction
changed only current-login projection/terminal assertions; final N3 normal/race
and Store vet cover it. Older migration and legacy Node transaction regressions
remain attributed to the earlier tested input, not silently relabelled.

Verified Store behavior includes one concurrent preview winner; head CAS;
separate PREPARED and published authority; exact N2 completion/public-key/epoch
source; no authority for inactive or wrong-kind humans; exact bound account
session; INITIAL and explicit READ_EXISTING; refusal of early same-session
refresh; self-cancel preserving confirmation provenance; and explicit new INITIAL
only for terminal unconfirmed history. Confirm uses the existing shared Node
confirmation transaction helper. Its Node effect, budget, Client request and
response slots, provenance and exact sealed receipt commit together. A seal
failure rolls them all back. Lost-response/restart retries return identical
ciphertext and consume no additional slot. Fences block late originals;
gapped/changed-epoch slots stay unresolved rather than skipping/resetting counters.

Status/reconcile read projections do not write grant transitions or Client
counters. More than 128 ordinary polls remain usable while read-cache storage
stays bounded. Expired uncached reads receive READ_EXPIRED. Permanent target
fences remain recoverable after the outer diagnostic cache ages out. A still
valid matching bound login returns LoginRequired=false even for EXPIRED or
CANCELLED authority; terminal state, empty operations and nil Node independently
deny business. Wrong/new/expired bound login remains LoginRequired=true.

Node observation verifies exact successful confirmation provenance and the
unchanged current binding/key/credential tuple. Accepted relay heartbeat time
can be CONNECTED while Worker status remains offline. Stale, future,
pre-approval and malformed heartbeat cases remain distinguishable; unsuitable
heartbeat data produces UNKNOWN. Restore preserves Owner/account/credential,
keys, Client counters and permanent history while fencing pending/active N3
authority. Restore coverage protects head floors, immutable claims/receipts and
provenance, and explicitly permits eviction of the two non-authority read/rate
tables. Legacy admission/recovery refuses tagged N3 packets, preserving the
single atomic entry point and permanent N2 restrictions.

Earlier failing attempts are retained: fixture credential digest was initially
noncanonical, candidate expiry initially exceeded the existing fifteen-minute
pairing bound, and a replacement fixture code initially had thirteen characters.
Those fixture errors were corrected before the final lanes; no failure or
interrupted lane was counted as pass.

## Shared-helper checkpoint (historical)

2026-10-17 shared-helper checkpoint, scoped to synthetic local tests.
Contract: [app-node-authority-v1](hub-app-node-authority-contract.md).
The contract-only predecessor is
`a545988ac6c038da180413d4f29ffbf740c402d4`. This checkpoint implements shared
proof and framing helpers; it does not enable N3 HTTP routes, a Store state
machine or `--hub-nodes-only`.

## Tested input and execution

Tests used dirty input based on that predecessor, with exact file hashes in
`/home/zyf/Cicada/.local/evidence/n3-hub/shared-helpers/source-attempt4.json`.
Its SHA-256 is
`482bd1832366f9b9a01bc5d131e26cfb9d7b1569fa33401e8fb085c673abe419`.
The validation document was added after the tested code input was fixed.
Do not attribute that dirty test run solely to its HEAD.

The disposable Docker image was Go 1.27.2,
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`.
Containers ran as uid/gid 1000, with no network, read-only root/repository/module
cache, dropped capabilities, no new privileges, an executable private tmpfs,
and a private writable Go build cache. No shared Hub or deployment state was
used. All identities were newly generated synthetic test fixtures.

Normal and race commands both tested `./internal/e2ee`,
`./internal/clientwire`, `./internal/hubaccountwire`, and `./internal/nodewire`
with `-count=1`; race added `-race`. `go vet` covered those four packages.
Metadata checks were `scripts/app-node-authority-contract.py check` and
`scripts/owner-activation-contract.py check`; `git diff --check` passed.

| Lane | Result |
| --- | --- |
| Four-package normal | PASS: 295 test events, zero failures; one separately recorded skip |
| Four-package race | PASS: 295 test events, zero failures; one separately recorded skip |
| N3-focused tests within each lane | PASS: 32 events, zero failures/skips |
| Four-package vet | PASS |
| N3 and N2 metadata checks | PASS |
| Independent OpenSSL 3.5.9 Owner-signature interop | SKIP: no explicit verified `CICADA_TEST_OWNER_OPENSSL` executable supplied; never counted as pass |
| Store/service/HTTP/composition/relay-only integration | NOT_RUN: not implemented in this helper checkpoint |
| Integrated disposable Docker product interop | NOT_RUN for this checkpoint; reserved for the integrated server implementation |
| Windows native, real Ubuntu Node, public HTTPS, strict PQ TLS, real Runtime | NOT_RUN |

Logs and their earlier attempts remain in the same private evidence directory.
`normal-attempt1/2` precede the final semantic guards; `attempt3` precedes the
final liveness/provenance guards. They are not evidence for those later changes.

## Verified behavior and retained failure

Real ML-DSA Owner signatures cover distinct preview/grant domains, exact
retained keys, canonical claims, deadlines and immutable scope. Real PQ account
envelopes round-trip INITIAL and READ_EXISTING prepare/complete. Incorrect
keys, changed signed targets, wrong domains, noncanonical proof bytes and
expired completion proofs fail. The READ_EXISTING helper cannot seal a confirm.

The confirmation adapter consumes the actual frozen Store public binding DTO;
it verifies the original tagged operation instance, durable expected response
sequence, approved request/version/digest and complete public-key tuple. A
delayed packet cannot borrow a newer grant. The App imports no Store package.

Genuinely Hub-signed invalid responses fail: READ_EXPIRED carrying Node data,
operations or a remaining budget; inconsistent ACTIVE head/latest instance,
session/deadline/counters/profile; CONNECTED with a future heartbeat or revoked
binding. `ValidateAppNodeLiveResult` additionally requires nonzero current time,
the exact locally retained grant scope/epochs/instance/lease/target, and the
exact READ_EXISTING confirmation provenance. Historical receipt recovery does
not confer current authority.

The full maximum opaque 128 KiB nested receipt carrier originally failed with
175161 bytes of plaintext because its encoded inner packet exceeded 256 KiB.
The original RED log is retained as
`contract-draft/nested-transport-red.log`. The reviewed correction gives only
the five N3 account operations an explicit 384 KiB inner bound; the outer bound
stays 384 KiB, body 192 KiB and original/receipt 128 KiB. The complete PQ outer
seal/open now passes at that carrier maximum. Default Client/N2 APIs and a
packet relabelled as N2 still reject that enlarged inner frame. Oversized outer
and receipt inputs fail. Opaque carrier bytes test transport capacity, not a
claim that arbitrary bytes are a valid business receipt.

Earlier contract-container setup failures (unwritable borrowed cache and
non-executable tmpfs) remain separately recorded. They were corrected with the
private cache and executable tmpfs; no failed attempt was relabelled as pass.

## App helper handoff

Use `e2ee.SignOwnerAppNodePreview/Grant` and
`e2ee.VerifyOwnerAppNodePreview/Grant` with the retained Owner identity.
`hubaccountwire.AppNodeSession` constructors produce typed prepare, complete,
status, cancel and reconciliation requests; existing `SealClientRequest` and
`OpenClientResponse` support those types. `OpenAppNodeResponse` dispatches a
prepare challenge or its common rejection result. Reconciliation must also
pass `ValidateAppNodeReconcileTarget` against the exact persisted original.

Use `SealAppNodeConfirmation` and `OpenAppNodeConfirmationResponse` for the one
allowed Client RPC. The response helper takes value
`e2ee.OwnerAppNodeGrantClaims` and the expected durable response sequence,
returning `AppNodeConfirmationResponse` with RequestID, OperationID, OK, Error
and `*e2ee.OwnerAppNodeBinding`. It permits historical receipt verification;
current action/UI gates remain separate.

After opening a fresh COMPLETED/ACTIVE status, call
`ValidateAppNodeLiveResult(result, retainedGrant, hub, now)` before adopting it.
Zero time is rejected by this live helper. Generic envelope authentication
cannot recover the complete private original scope from outbound ciphertext.
READ_EXPIRED closes only the exact read and provides no live Node authority.
The App must still persist bytes before every POST and apply local deadline,
freshness and counter-recovery gates. All mutations require the remaining Store
implementation's atomic current guards; helpers alone never authorize effects.
