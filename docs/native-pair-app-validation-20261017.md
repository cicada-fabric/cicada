# Native Pair App consumer validation — 2026-10-17

Result: **APP_CONSUMER_SCOPED_PASS** for the
[App implementation](native-pair-app-implementation.md). This is a consumer
checkpoint with scripted HTTP crypto actors, not real Pair Store/Guard,
Runtime, Windows desktop or deployment acceptance. The Hub A2 preparation
checkpoint keeps `available=false`; the App emits no new Owner proof in that
case. This executable has not replaced the earlier delivered login artifact.

## Tested source and environment

The tested worktree was `task/n2-app`, based on
`17da3936e87ca07222bb416f0cacec57df2e1daa` **with uncommitted App changes**.
Results belong to the exact manifest, not that base commit alone. All 1,196 Go
and module files were unchanged before and after the final checks:

`663db4df91ecea8d369ae95d722995343111ef07a2db4a75889a45701e3e0558`

Manifest paths are relative to `cicada-go`. Implementation/validation prose was
completed after the code checks; no Go or module file changed during the gates.

The disposable builder was
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`
with Go 1.27.2, source/modules mounted read-only, networking disabled, three CPUs
and 6 GiB memory. Tests used the existing visibly synthetic OpenSSL Owner fixture
read-only, so the App-key compatibility cases did not skip. No fixture key or
vault was used to initialize a deployment.

Evidence directory:

`/home/zyf/Cicada/.local/evidence/n3-same-node-dialogue/run-20261017T122249Z-cb9b7d/app/final-01`

Its `validation.json` SHA-256 is:

`13966e3441d3320a74185b06313e67197dd0e9f4d512844e79207736e4fddfda`

## Actual checks

| Gate | Result |
|---|---|
| All owned packages: appcore, appkeys, appvault, appui/native, cicada-app | 319 passed, 0 failed, 0 skipped; exit 0 |
| Core `TestPair\|TestOwnerPublic` with race detector | 25 passed, 0 failed, 0 skipped; exit 0 |
| Complete appui/native tests with race detector | 153 passed, 0 failed, 0 skipped; exit 0 |
| Linux vet and Windows amd64 vet for the owned packages | Both exit 0 |
| Windows production dependency listing | Exit 0; no nodekeys or modernc dependency |
| Windows amd64 GUI cross-build | Exit 0 |

Counts include named subtests. The race lane deliberately covers the modified
Pair/export controller paths and the full portable UI suite; it is not a claim
that all existing real-HTTP account tests ran with the race detector.

The controller actors use real shared PQ envelopes and Owner proofs, verify
their typed targets, and inspect the actual encrypted vault before accepting
each POST. Coverage includes separate A/B consent; first-consent waiting and
second-consent projected memberships; preservation of recorded consent when
reviewing the unchanged plan; exact-slot rejection and explicit revocation;
unknown responses, exact retries and detached reconcile; response-CAS/reopen
boundaries; expired diagnostic renewal and late-response rejection; wrong
Pair ID/digest; dedicated no-effect fences for all five known mutation kinds;
contradictory outer/nested recovery results; and expired historical recovery
without live administrative permission.

Capability HTTP 404 and a valid `available=false` document both produce zero
Owner-proof POSTs and no new pending operation. Pure UI tests cover login
privacy, the public-export entry, complete slot review metadata and separate
consent. Public export matches the original local identity's three public JSON
fields, preserves existing files and rejects expired sessions. Its fingerprint
matches the existing Node API, including malformed-public-key rejection; that
Node package is only a test dependency.

The 640 KiB response-record test is explicitly a storage-size probe. Its bytes
are not an authenticated receipt, and the controller rejects them as authority.

## Development executable and limits

The final development cross-build is 13,781,504 bytes, SHA-256:

`b93faa83ebb5ebaba9e6b082046994e7152a66e7418a207f29b23ffc96e61c69`

Flags: `CGO_ENABLED=0 GOOS=windows GOARCH=amd64`, `-trimpath`,
`-ldflags='-s -w -H=windowsgui'`. This proves compilation only. An earlier
unstripped development build is retained separately and must not be compared
to stripped delivery sizes. The earlier delivered login executable remains
SHA-256 `27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`.

Native Pair production Store/Guard integration and a disposable Docker
interop gate for this final App source are **NOT_RUN in this App lane**.
Hub preparation evidence has separate source attribution. Real Codex threads,
model/queue activity, Windows Save dialog/DPAPI/ACL/desktop execution, physical
devices and public HTTPS are also **NOT_RUN**. The user-reported Windows text
rendering failure remains unaddressed in this scope. No Node/MCP source,
resident service, deployment, original identity or real key was changed by
that App-consumer checkpoint.

Earlier development attempts, including fixture/build failures and their
corrected reruns, remain under the same App evidence parent. They are not
substitutes for the final frozen-source result.

## Later independent Node-local checkpoint

The subsequent Node-local work is based on
`209b2081085d41dbccf0516f8379b9d40d98be2e` **with uncommitted Node changes**.
Its scope is schema-5-to-6 migration, durable local trust/policy, original
candidate publication bytes, bounded reservations/recovery and unwired Node
helpers. It is not production Pair MCP dispatch or end-to-end acceptance.

The complete frozen manifest contains 1,254 inputs: all 1,250 files under
`cicada-go` plus the two existing native-pair gate/evidence scripts, contract
and App plan. Of these inputs, 1,206 are Go source or `go.mod`/`go.sum` files;
that subset count is not the full manifest count. The full manifest is:

`10478416e0df121923e72ef8259397d0c3aa47901b64268a92e5e0aa3ce472cb`

The original local producer used the same pinned Go 1.27.2 builder as above,
three CPUs and 3 GiB memory, read-only source/modules, offline dependencies and
no network. Its source-before/source-after manifests match exactly. Disposable
SQLite, fresh synthetic keys and fabricated native-context records stay in
private test directories; no real Runtime, SID, queue or deployment is used.

Evidence directory:

`/home/zyf/Cicada/.local/evidence/n3-same-node-dialogue/run-20261017T122249Z-cb9b7d/node/resume-01`

The original `producer-receipt.json` SHA-256 remains:

`611d848576319b267205aa09ac93e95eadd96b488b19449c5243a23858bcb8e3`

| Local gate | Result |
|---|---|
| Complete `internal/nodekeys`, no `-run` filter | 112 passed, 0 failed, 0 skipped; exit 0 |
| `cmd/cicada`: NativePair helpers plus existing cache/restart cases | 10 passed, 0 failed, 0 skipped; exit 0 |
| `TestNativePair` in nodekeys and cmd with race detector | 15 passed, 0 failed, 0 skipped; exit 0 |

Counts include named subtests. The receipts retain exact selectors and package
results. Tests cover atomic trust/version/policy persistence, independent Owner
pin revocation, required-Group evidence rejection, missing/corrupt original
keys, lost candidate acknowledgement, original SID/context checks, budgets
across independent SQLite handles, cancellation without refunds, and recovery
of an accepted policy after JoinUntil without extending its peer deadline.
The legacy MCP restart cases retain their fixture-only scope.

The first development attempt compiled but could not execute test binaries
because its container tmpfs was noexec. That environment failure remains in
`dev-unit.jsonl`; the corrected reruns did not change production code to bypass
it. The original local producer did not retain actual test executable hashes.
Its test results retain that evidence limitation; subsequent executable-identity
evidence is additive and does not replace this original receipt.

QA independently matched every frozen input and recounted the original logs.
Its producer-review SHA-256 is
`16d2fc47b8e6b5f7d6bea195d2d158a0442bd4eb854e09535a99d470d01bbf49`.
The separate read-only `cleanup.json` SHA-256 is
`90d41f1555e495396f5247a8989cf33fa59ff72bf0b736da004fc2287cdd2b92`;
both exact run containers were observed absent. No Hub or named volume was
created, and shared caches were retained.

### Executable-identity supplement

An explicitly authorized rerun retained the actual executables through a
run-local Go `-exec` wrapper. It used the identical test names/selectors and
unchanged 1,254-input manifest above. For each execution the wrapper copied the
first argument into a separate lane artifact directory, checked SHA-256 of the
original against the copy, recorded the actual path/argv/hashes, then executed
the original binary with the remaining arguments. The wrapper is evidence
tooling outside the product repository and adds no dependencies.

The successful supplement is under the same Node evidence parent at
`binary-identity-02/producer-receipt.json`, SHA-256:

`dd7994e53bbb1650515fadb51ad78c81ceda6bdaaec82d05ff6f036b1b2bf898`

Its wrapper SHA-256 is
`82d1ac534f58e6319b81b6708a52c59711fc0314cfcfe750806201d32bb050f9`.
The wrapper restores the inherited umask before execution. Normal nodekeys,
scoped cmd and scoped race again passed 112/0/0, 10/0/0 and 15/0/0 respectively,
all exit 0. Every test name matches the corresponding original local gate;
source-before/source-after also match the original frozen manifest.

| Actual executed test binary | SHA-256 of original and retained copy |
|---|---|
| Normal nodekeys | `31496a77912e70b7d7b3967c27ccbe932cf77e8b477694138fe8f23e258decc0` |
| Scoped cmd | `2acbb6b787137d79f9716f92492f534b51713ab90ea43422be9a74031146e78c` |
| Race nodekeys | `dd917858675eef8411f99240199e01ebad14386e07307dc9f60eda852eb5cfd4` |
| Race cmd | `8f9c6a30560c59165c4079a556264098b2f8d5d59976ae7f6d59b7427f356284` |

The first supplement remains at `binary-identity-01/producer-receipt.json`,
SHA-256 `eb9b1b5a42014ca25ef0d588b1d758de2fd510ee1cd2815d371b5622e83d1f99`.
Its wrapper imposed umask 077 on the test executable. Two existing insecure-mode
fixtures were consequently created with private permissions; those subtests
and their parent failed, producing 109/3/0 in normal nodekeys. Scoped cmd and
race passed 10/0/0 and 15/0/0. The failure, original wrapper and four binaries
are retained. The corrected supplement used identical binary hashes and
unchanged Go inputs. Neither supplement replaces the original local receipt or
its results. Both exact supplemental containers were observed absent; no Hub,
named volume, real SID, provider or queue was created.

### Unclosed production boundaries

Current carrier validation, production Node Join receipt application, same-epoch
native/access lease renewal up to the peer ceiling, real MCP Pair dispatch,
real native Runtime/SID/queue consumption, Windows desktop/DPAPI/ACL, disposable
Hub interop and public HTTPS are **NOT_RUN** in this local checkpoint.

An existing reservation lookup does not authorize send or queue admission.
Fresh work still needs current peer evidence and independent Owner trust,
including checks after acquiring the original writer. Only matching
authenticated receipts settle admission or cancellation. Production recovery
must apply the original Join receipt before a new Describe/Join; an expired
lease cannot silently regain permission. Ordinary Network renewal rotates its
access epoch and cannot substitute for the still-unaccepted same-identity Pair
lease path. The endpoint helper is currently unwired; omitted receiver SID in
the legacy peer-key projection must be checked through actual Current data,
never copied from the signed plan.

## Node/MCP consumer local validation, 2026-10-18

This follow-up uses `f279093d9e8e09d6576ac319f18b9cedf1d670bf` plus
uncommitted Node consumer changes. It does not change the attribution of the
earlier App or Node-local checkpoints. The implementation and validation prose
are outside the executable input manifest. No Windows package or deployment
was produced by these checks.

Evidence is under
`/home/zyf/Cicada/.local/evidence/n3-same-node-dialogue/run-20261017T122249Z-cb9b7d/node/`.
Both `consumer-local-01` and `consumer-local-02` retain complete 1,284-input
before/after manifests, actual test executable copies made by `go test -exec`,
their original/copy hashes, NUL-delimited executed argv and inherited umask
`0022`. The wrapper restores that umask before executing the original binary.
Each source manifest is unchanged across its run. All three named disposable
containers were observed absent after each run. The pinned image remains
`golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`.
These two local runs use `TMPDIR=/tmp` on container tmpfs. They establish local
component persistence/reopen behavior, not persistence on a host-backed disk
or recovery after power loss. The later cross-component disk gate must retain
its separate mount and database attribution.

### First frozen run: retain the fixture failure

`consumer-local-01/producer-receipt.json` is **FAIL**, SHA-256
`a75a70a6a4d04c28043b97555d9a92666bc4043383c7b442edf0bf8d5ff74ca8`.
Its input manifest is
`94cb1a1636e4b7bbaa7860085eba0a87168ae001147c5d25ec45d5600e16f32d`.
Its 20 then-current changed source files are additionally retained in
`source-changes.tar.gz`.

| Executed lane | Pass/fail/skip | Exit |
|---|---|---|
| Full nodekeys | 112/1/0 | 1 |
| Scoped cmd: Pair, MCP, native delivery, same-Node Relay, local Join, Node-Control | 92/0/0 | 0 |
| Scoped race: nodekeys | 9/1/0 | 1 for combined race command |
| Scoped race: cmd | 23/0/0 | Same combined command |

The sole failure was the new local Current test constructing `State: ACTIVE`;
the closed contract requires `CURRENT`. That fixture was rejected before its
positive check. This run is not an overall pass.

The cmd results include the actual production drain caller after a real
synthetic queue subprocess produced ACCEPTED or UNCERTAIN. Six cases cover
each outcome with an early HTTP 403, a fresh HTTP 403 after acquiring the
writer, or independent Node-local Owner-pin revocation. Each retains the
original writer ledger bytes, inbox and journal, queue count one and only the
original Node-received receipt. No failure/cancellation or consumption success
is fabricated. This uses the existing legacy Group fixture, not a fabricated
Native Pair ACTIVE row. These six cases passed normally and with race on
this run's source; their result is not relabeled as executed on the next source.

### Corrected, scoped follow-up

`consumer-local-02/producer-receipt.json` is **SCOPED_PASS**, SHA-256
`f9ae27576490398eb01d31d866e7a986e66e87a4e53f1b9f2604576e28660c3e`.
Its input manifest is
`4063c78ddd2bf10c705557fe2ff613233431f499a366dc4d321b069756146522`.
Exactly three executable inputs differ from the first run: the Current test
fixture, the Node Join bridge's first/reused result labeling, and the matching
consumer test assertions. Other executable input hashes are unchanged.

| Executed lane | Pass/fail/skip | Exit |
|---|---|---|
| Full nodekeys | 117/0/0 | 0 |
| Four Join consumer cases | 4/0/0 | 0 |
| Scoped race: Current verifier plus four Join consumer cases | 9/0/0 | 0 |

The four Join cases traverse actual MCP dispatch, the owner-only local socket
and production encrypted Node-Control outbox code against a scripted PQ actor.
They check durable exact packet/body before POST; two lost Join responses
followed by detached reconciliation without another effect; recovery of a
historical initial lease through current same-binding whoami/heartbeat; a
lost candidate acknowledgement followed by client reopen using the same key
and attestation; capability absence emitting no new business packet; and an
unsigned diagnostic 403 preserving the original across reopen, including when
availability subsequently becomes false. Full Node proofs and the internal
session token do not cross the public MCP result.

| Actual executed binary in corrected run | SHA-256 |
|---|---|
| Normal nodekeys | `7a7535520eefb90a0f1e9f475ea8ef5cd644de7edd0fb6b6434270dab8d14354` |
| Scoped cmd | `cd79a948cc49786c159353014059661e7f6d55cbbf281b4506e3c71a33217739` |
| Race nodekeys | `9c87f8ea81315d8a0edec182092c44e8ad0058a8f6618f352ee174e10b29c9a9` |
| Race cmd | `d0bb2890444bb35736a7d305495e77b7bd8f73568b00ede89aee249b31764511` |

Unfrozen development iterations remain in `consumer-dev-01`, including the
initial synthetic Node-token precondition failure, an undefined test constant
compile failure, and a capabilities fixture emitting a forbidden canonical-JSON
newline. They are not promoted into frozen-source acceptance results or hidden
by the corrected run.

Actual Hub dual consent to production Node/MCP peer interoperability remains
**NOT_RUN** here, as do real Codex Runtime/model/native consumption, Windows
DPAPI/ACL/GUI, physical-device and public HTTPS/deployment acceptance. The
scripted actor's zero-Join response is not proof of real Hub ACTIVE authority.
No real SID, provider, queue, resident service or production key was touched.

## Committed-Hub consumer integration, 2026-10-18

The later final local integration source is
`3814439bbbe68e7e7d2c881439420f2b9bf8b1aa` plus the 26-file App/Node consumer
worktree change. Its complete 1,303-input manifest is
`578637a985a91ba51d8141681fad4d7e9016e3b574527fa7f68328de47261bfa`.
Before/after source files match exactly. This is a dirty-source validation,
not a claim that its executables were built from clean HEAD alone.

Under the same evidence parent, `consumer-integrated-01/producer-receipt.json`
is **SCOPED_PASS**, SHA-256
`25b029c1fa77ad4fa70cb4fd5cf324758b06106169105659c1bf0a783063a23c`.
Normal and race execute the same test-name maps:

| Required lane, including subtests | Normal pass/fail/skip | Race pass/fail/skip |
|---|---|---|
| Node/MCP consumer and real TCP cases | 21/0/0 | 21/0/0 |
| App Pair controller cases, including delayed clicks | 17/0/0 | 17/0/0 |

Both commands exit 0. `run.sh`, actual executed binaries, original/copy hashes,
NUL-delimited argv and restored inherited umask `0022` are retained. No old broad
suite is represented as rerun here. Earlier nodekeys, legacy writer and App
checks retain their separate tested source and receipt.

| Actual executable | SHA-256 |
|---|---|
| Normal cmd | `1d8913c4edaba36630099609fd198c2ca515ccc26da084f7a7bcb6fb90da55af` |
| Normal appcore | `e34ded674b1249ef063025372ef2fc433b62056043f55ca8519e25aedffb8590` |
| Race cmd | `3c1067941676385ae32bb031d17eb5b72ad71657988eb10e0cba1a9c619cc83a` |
| Race appcore | `7a72e548ec56e16656eb7dddc51348c90628f3d6022eccdd6d77280b5cc260df` |

The actual TCP fixture initializes an owned production Hub/SQLite composition
without Control inference, completes real N2/N3 and explicit Owner proofs, and
uses the reviewed development Node RPC probe to obtain original reserved-slot
Join receipts. Production MCP dispatch and its private socket recover those
receipts and publish the original local candidate attestations. Lost Join and
candidate acknowledgements preserve the exact original operation, SID, binding,
key and proof. The first consent retains zero peer permission; the compatible
second consent activates the real Store grants atomically.

Production MCP ASK and correlated REPLY then traverse the actual sealed Relay,
inbox and physical writer, ending at two synthetic queue subprocesses. The
highest recorded native completion is **CONSUMPTION_UNCONFIRMED**. The helper
is the retained test executable, never installed Codex or a provider.

Effective caller negatives separately cover missing evidence/Current and changed
actual SID, access epoch, generation, attempt, Network/member revisions and
lease owner; a matching existing reservation plus revoked independent local
Owner pin sends no new ASK POST or native queue; and a changed final Current
after writer wait denies before injection intent. An actual adapter subprocess
is killed after synthetic queue acceptance while its original writer remains
INJECTING. A new writer retains that historical operation as UNCERTAIN despite
local Owner revocation, with queue count one and no fabricated FAILED/NO_EFFECT.

The generation case has C occupy A's g1, the original A receive a permanent
authenticated no-effect fence, and the Owner reject C. The first real MCP fence
report persists its consumed marker without a new request; the next explicit
call reaches discovery and is still blocked by capability=false. A separately
identified fresh development probe sees actual g2 and joins the same original
A. MCP recovers its unique Endpoint and original key; B's original binding and
the late g1 packet's exact fence remain unchanged. Scripted immediate and
pending/reopen cases separately prove the fresh positive MCP control flow.

Actual TCP Hub databases, Node keys/state, inbox and writer use the owned host
bind at `/s`, with `TMPDIR=/s`. Only compilation scratch uses tmpfs via
`GOTMPDIR=/tmp`. `race-container.json` records the actual mounts, command,
immutable image and user. The older scripted Node helper still uses `/tmp`
tmpfs and keeps its component-only attribution. Both owned containers were
observed absent and the host state directory empty after fixture cleanup.
This is process recovery evidence, not a host power-loss test.

### Failures and intermediate sources remain retained

On `1c4a59d774c530a0cf5823bf81f585192650ea10` plus its then-current WIP,
`consumer-tcp-dev-01` first failed because the new test used `body` instead of
the existing `cicada_ask` argument `question`. Correcting that test exposed a
real producer gap: Pair Join returned no existing `sealed_v1` Endpoint
capability, so actual MCP correctly refused its first ASK. `consumer-tcp-dev-02`
retains all three failures; `consumer-tcp-dev-03` confirms the safe diagnostic
`source is missing the required sealed_v1 peer-delivery capability`.
Each retains its own unchanged full source manifest, actual executable,
argv, exit 1, source copies and cleanup. Receipt hashes are respectively:

- `8f2bad8c4640a045ae975c23cb897438e2fa80052d78e2770d98732a364b394b`
- `c228283a7f438a2de18ea7469c4452639b436a6c445482442d74daa84e346abb`
- `87def7a4328176694663a52833d9c7a43c31ad3cb6f08effa94322d6d99d7703`

The separate Hub producer correction is committed in `3814439`; this consumer
does not fabricate the capability or change public availability.

`consumer-fence-dev-01` first validated the scripted fence control flow and
actual g1/g2 development probe on its earlier source, 4/0/0 normal only, exit 0;
receipt `8de8e00729e80cc884cb265dd86d691394c4318bafcbd984d3354a7788a5c389`.
That intermediate result is not attributed to the final source.

`app-delay-red-01` is a retained new-test compile failure, not a product result.
After fixing those two test types, `app-delay-red-02` reproduced the App defect:
a delayed click signed its Group key proof with the click time instead of the
reviewed manifest issue time. Its actual App controller/scripted PQ actor test
failed, exit 1, with receipt
`2edd5cb916d6b760c67181d6022f1960310d35d76856992cd32186cd119e51e1`.
The final one-line production fix signs the exact manifest lifetime and keeps
the new Owner intent's click time fresh; both delayed A/B clicks pass normally
and with race. This does not establish an actual production App Pair actor or
Windows GUI acceptance.

Fresh positive public MCP/App discovery remains **UNAVAILABLE / NOT_ACCEPTED**
because public capability is still false. No availability shim was used in
the actual TCP fixture. Real native Runtime/model/consumption, native Windows
GUI/DPAPI/ACL, physical-device, public HTTPS and deployment acceptance remain
**NOT_RUN**. The tests did not touch resident services or real keys.
