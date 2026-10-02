# Client final integration gate preparation — historical planning record

## Superseding acceptance record

Clean Core `144e079` and its immutable images were subsequently delivered.
The independent checks, final APK pair, live outcomes and remaining blocks are
recorded in [current validation](client-hub-v1.6.1-144e079-validation.md). The
preparation below retains its original status and is not an acceptance claim.

## Original scope and status

This preparation follows Client milestone
`65d6a399122055e1bd38dfb70fa93686806bee36` on `dev/react-native`.
It prepares bounded integration tests against a separately delivered clean
Core shipping candidate. It does not accept that candidate, change the current
contract pins, build an APK, start a Hub or emulator, or claim native execution.

The current accepted integration **target**, as distinct from runtime
acceptance, remains Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`,
`client-hub-v1.6.1`, catalog
`6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b`,
Hub image
`sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`.
The clean `06d0a58` intermediate source check is source-only evidence;
it supplies neither a new fixed image nor shipping acceptance.

## Required final delivery

Before changing pins or building the integration APK pair, independently check:

1. Complete clean Core commit and source metadata containing the input
   inventory, unchanged v4 fingerprint, helper identity and catalog digest.
2. Immutable full Hub and interop image IDs, their source/build labels and
   source metadata. A mutable tag or a current dirty Core checkout is not a pin.
3. Protocol archive SHA-256, its manifest and source revision, catalog digest,
   and unchanged request/result schemas for every reused operation.
4. The matching disposable Core fixture producer, public fixture v2 and
   external synthetic Owner enrollment/signing tools.

The independent inventory tooling is described in
[Hub input inventory verification](hub-input-inventory-verification.md).
The final provenance check must use the final complete revision. Its
intermediate source-only result must not be reassigned to a shipping image.

After these checks, update the imported contract snapshot and the runner,
carrier and role-oracle pins together. Build the app/test APK pair once from
those exact inputs; record source fingerprint, both APK hashes, build commands
and exit codes. The corrected role assertions and new live selectors need that
new test APK. The preceding APK pair remains historical compiled evidence.

## Reusable harness and constraints

| Component | Reuse | Conditions |
|---|---|---|
| `v16-android-deterministic.py` | Owned offline emulator, Kotlin selectors and UI checks | Exact app/test SHA-256; network `none`; owned evidence; final pins |
| `v16-public-device.py` | Android public device export | Same strict run ID and selected profile; no private key export |
| `v16-stage-fixture.py` | Public Hub pin and selected primary/foreign Owner Grant staging | Matching Core fixture v2; Grant binds exact Hub, Owner and Android device |
| `v16-host-stdio-carrier.py` | Five public Client-Control routes; opaque packet relay | Exact clean owned Hub and APK identities; temporary ADB reverse |
| `ClientHubV16ResponseLossTest` | Enrollment 201 loss and completed RPC 200 loss | Current encrypted capabilities and exact persisted request recovery |
| `v16-role-oracle.py` | Independent catalog/implementation/role intersection | Final snapshot; 39 implemented, 16 closed; manager 39, external 31 |

Use one identical `v16-deterministic-v161-…` run ID throughout the emulator,
public-device, staging and instrumentation commands. The broader `v16-*`
validators accept this strict form; they do not make arbitrary run IDs valid.
For a second Owner, activate its separately enrolled profile and stage with
`--owner foreign` plus the Core-produced `owner-device-grant-foreign.json`.
This is a public Android test projection of the validated Core fixture. Its
reciprocal `foreign_*` references point to the original primary Owner/Network;
it neither edits the Core fixture nor grants access to the other Owner.

The carrier's RPC response-loss selector defaults to `status.snapshot`.
For Link status, `--fault rpc --rpc-drop-operation link.review_policy_status`
targets the public packet route while leaving the preceding encrypted Link
list intact. The proxy does not decrypt or persist business bodies. A lost
response after HTTP 200 is a completed-request test; it does not establish an
interrupted reservation or a crash.

Older `two-owner-android.py`, `monitor-recovery-faults.py` and
`ClientHubV15RecoveryFaultTest` contain different version/image/catalog pins.
Their prior results and selectors cannot establish current acceptance.
The older activity-recovery script also lacks the final owned-emulator and
exact-APK controls, so it is excluded from this final gate.

## Link status gate

Use the dedicated `ClientHubSession.linkReviewPolicyStatus` flow after a fresh
encrypted `link.list`. Check exact Link ID/version, authenticated Owner,
device/session and source/target side. The generic RPC entry must refuse this
operation before transport. The positive default NONE case is unconfigured
metadata; it is not bilateral approval or permission to send messages.

Required live cases are a real Owner-visible Link, both distinct Owner views
with opposite `my_side`, unknown and foreign Link refusal, stale selected
version, and original status-packet response recovery. A foreign Owner is
outside **both** Link sides. The other consenting side is not a foreign Owner.
An absent optional Link ID proves only refusal of an unverified reference in
the authenticated Owner list. It cannot establish that a real foreign Link
exists or that the Hub's status Guard rejected another Owner. Those results
need independently bound foreign-Link/Owner evidence.

A configured-policy result requires a genuine external Owner-proof fixture.
The Client does not enable policy preview/grant or sign an Owner proof to
prepare this read test. Device revocation, missing server capabilities and
Hub switching need their own real fixtures or clearly separated local tests.
Missing fixtures remain `BLOCKED` or `NOT_RUN`; they are not synthesized
capability or policy acceptance. Synthetic Endpoints may establish protocol
authorization only; they do not establish a native Thread or model run.

### Pinned configured-policy producer gap

A read-only audit of Core `fe565b4` found an inconsistent grant version
check. In `cicada-go/internal/server/client_rpc_v2.go`, lines 295–305,
the RPC rejects `expected_policy_version <= 0` and requires the proof version
to equal that value. In
`cicada-go/internal/store/communication_link_review_policy_v2.go`,
lines 289–331, the Store accepts a base version of zero and requires proof
version `expected_policy_version + 1`. Preview returns base zero/next one
for an unconfigured Link. The pinned OpenAPI grant minimum is one.
Therefore the first configured policy cannot be created through that pinned
RPC. Store-only tests do not establish the public RPC path.

The pinned `cmd/cicada` tree also has no `link-review-policy-sign` command;
the signing library is not a fixture CLI. These findings belong to the
immutable historical pin, not the pending shipping source. Core has been
given the exact request/version conflict. Until the final delivery supplies a
consistent public producer and genuine external proofs, configured-policy
acceptance is `BLOCKED`; the Client must not bypass RPC Guards or enable policy
writes to manufacture a passing read test.

Core subsequently confirmed the conflict in its current Main source and is
preparing a production-entry correction with real encrypted HTTP tests. That
work has not yet been delivered as a clean fixed image/package. Keep the
Client grant path closed; do not import the mutable working tree or transfer
Core's pre-fix test results to its eventual corrected shipping candidate.

## Interrupted-request recovery gate

Core identifies `cmd/client-recovery-fixture` as the isolated producer:

```text
client-recovery-fixture --db PATH --mode processing|uncertain|legacy
```

The original signed encrypted packet is supplied on stdin. The Core tool
requires a dedicated temporary database, its disposable marker and a fresh
request. Only Core's fixture tool may access that isolated database; the
Client must not read or alter it directly. Its binary must come from the final
fixed interop image. Reading its source is preparation, not execution evidence.

Capture a pending packet before the Hub accepts it. A completed HTTP 200
response-loss packet is not fresh and must not be reused as reservation input.
Core explicitly authorizes the driver to create the mode-0600 disposable
marker only after checking the owned temporary fixture, real paths, exact
image/state mounts and absence of shared resident state. The network fixture
uses `--rm`: stop it and confirm its removal, run the Core helper in the final
fixed interop image with `--network none` and the same UID, then recreate the
Hub using the producer's original parameters and the same owned state.
The image's supported command is `go run ./cmd/client-recovery-fixture`;
offline availability must be verified after final image delivery. Distinguish a controlled
processing reservation from an actual crash. A reserved uncertain request must
be fenced by the real restart; the fixture must not substitute a synthetic
terminal response.

Each scenario needs its own enrolled session. Assert actual 409
`STILL_PROCESSING`, signed encrypted `OUTCOME_UNCERTAIN`, and 409
`RECOVERY_UNAVAILABLE`, respectively. Verify exact operation ID, sequence,
packet hash and pending/fence handling, refusal to issue replacement work, and
subsequent permitted authoritative reads. Do not guess response counters or
clear unresolved write fences. Incompatible producer/fixture inputs block that
case without weakening the protocol.

## Execution order and reporting

| Gate | Preparation state | Final acceptance |
|---|---|---|
| Inventory data/Git verifier | Offline synthetic and intermediate source checks recorded separately | `NOT_RUN` for final candidate |
| Directory role assertion | Corrected in source; exact catalog role vectors | `NOT_RUN` in corrected APK |
| Link live status/negative/recovery selectors | Bounded harness under preparation | `NOT_RUN` |
| Three interrupted-request recovery scenarios | Matching Core producer identified; harness under preparation | `NOT_RUN` |
| Encrypted runtime contract/catalog and directory reads | Existing harness reusable after coordinated pin update | `NOT_RUN` for final candidate |
| Android native Node/Worker/approval/result or Monitor flow | Requires explicit current native identity and memberships | `BLOCKED` pending fixture/authorization |
| Physical Android | Separate device and lifecycle gate | `NOT_RUN` |
| Public HTTPS | Separate trusted deployment and transport gate | `NOT_RUN` |

The preparation source check passed in an offline Docker container, exit 0:
exact pinned catalog vectors, manager/external intersections 39/31, all 16
closed operations, syntax of both modified carrier files, carrier CLI help,
and rejection of a Link-drop selector without RPC fault mode. Inputs were
unchanged before/after. This is `PASS_STATIC_ONLY`, not instrumentation or
transport acceptance. Exact command, source hashes and log are recorded in
`/gpu1-share/data/cicada-client/client-final-gate-prep-20261002/source-check-001.receipt.json`,
SHA-256 `0e7b694bae5caf63713f854459c15a186499caaca709540b874eb5f4629926b2`.
The intentionally invalid CLI invocation exited 2 and was rejected before any
fixture or Docker operation; the enclosing check exited 0.

The selected-Owner staging regression check passed five synthetic cases in
offline Docker, exit 0: unchanged default primary projection, reciprocal
foreign projection, crossed Grant refusal before staging, wrong Hub and wrong
device fingerprint. Source SHA-256 before/after was
`79284103378fdb48eeda1afb61f63254da53b739fdce1bb5a8dd1c1a1ffdb693`.
This is `PASS_SYNTHETIC_STAGE_ONLY`; the carrier/ADB boundaries were stubbed,
identities were public synthetic bytes and Grant signatures were unverified
synthetic bytes. Trust verification, Grant cryptography, Hub and Android runtime
were `NOT_RUN`.

The final receipt is `stage-check-owner-regression-attempt4.receipt.json` under
the preparation evidence root, SHA-256
`c46101328867732f6f689a2e3ecd8610929a91186e60e497059b78d2a0a45086`;
it includes the exact command, image, exit and adjacent retained log.
Attempts 1 and 2 failed because the harness supplied the foreign Grant to the
default-primary case; the stage correctly refused it. Attempt 3's Docker
checks passed, exit 0, but its outer wrapper compared hashes for different
files and recorded FAIL. That original receipt is retained. Its separate
`stage-check-owner-regression-attempt3-correction.receipt.json`, SHA-256
`9a64d868e9399df064320c872066a788fe3098b4f3cbd842dc51873146a378f9`,
is a receipt interpretation correction, not a new test run. All four attempts
and their logs remain available; no failure was overwritten.

Run offline vectors and UI checks on the one newly built APK pair, then the
owned fixed-image encrypted gates. Keep physical-device, public HTTPS and
native-runtime results separate. Record each exact command, exit code, artifact
hash, observed result and private redacted evidence path. No fixture readiness,
HTTP acceptance or old-version result becomes a new PASS.

The carrier must stop its child relay/proxy and remove its exact ADB reverse.
The emulator must be stopped through its ownership-checked driver and its
absence confirmed. Core fixtures use their producer's ownership-checked
cleanup. Remove temporary packet/signing material; retain redacted evidence
outside Git under `/gpu1-share/data/cicada-client`. Do not touch resident
containers, production deployment, credentials or global Docker settings.

Combine implementation, corrected tests, independent provenance and final
acceptance records at the next complete milestone. Inherit the server's
effective global Git identity for both author and committer. No standalone
tooling commit, push or merge is part of this preparation.
