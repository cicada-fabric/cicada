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
