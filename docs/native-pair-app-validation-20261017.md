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
resident service, deployment, original identity or real key was changed.

Earlier development attempts, including fixture/build failures and their
corrected reruns, remain under the same App evidence parent. They are not
substitutes for the final frozen-source result.
