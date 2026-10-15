# Native Cicada App

`cicada-app` is the native Go/Gio desktop entry point. It opens the local
`appcore` controller and renders only its sanitized snapshot. Hub health, an
account session, Owner proof, Root activation, and Manager authorization remain
separate states. The App has no authorized topology read path; the canvas
therefore stays empty unless a future authorized provider supplies objects.
“Local preview” is a separate, explicitly labeled fixture view and never creates
Hub status or sends a request.

The UI dispatches one typed action at a time on a worker goroutine. The window
event loop does not perform network or KDF work and does not poll for updates.
Closing the window cancels the controller context, waits for the in-flight
action to return, closes its local handles, and exits the process. Gio's
platform main loop remains the final call on the process main goroutine.
Passwords and activation codes are never included in UI status or logs. Existing
Owner PEM import uses native Windows file selection and the shared strict parser;
this checkpoint accepts unencrypted PKCS#8 only.

On startup the App discovers up to 64 existing vaults in its protected local
directory. Filenames and public headers are locators only: current-user DPAPI
unlock, authenticated decryption and agreement with the encrypted connection
scope must succeed before a saved connection is displayed. Discovery sends no
network traffic. A single authenticated profile resumes automatically; multiple
profiles require an explicit selection. Reopening verifies the full Hub pin
again and never needs an expired installer code. The existing N1 vault path is
retained without moving keys or creating replacement identities.

Recovery sends the exact persisted pending packet first. Unsigned HTTP errors
leave that packet pending. Saved session/inspection receipts never establish a
fresh account session; the App sends a new encrypted inspection before reporting
session readiness. Account readiness still grants no Manager authorization.
The native UI presents connection, local keys, account and recovery steps in
English and Chinese with a shared card and button style. Actual Windows visuals,
DPAPI and ACL execution require a Windows acceptance run.

The 2026-10-15 local-profile checkpoint passed focused Linux tests (49 passed,
one optional OpenSSL-fixture skip), race tests (40 passed, the same skip), Linux
vet, Windows vet and Windows amd64 cross-build using the pinned Go 1.27.1
builder. The `appkeys` package was then rerun against new, explicitly synthetic
OpenSSL 3.5.9 PEMs: normal and race each passed all nine cases without a skip.
The initial Docker interop attempt failed its source-stability fence while
tests were still being added; final integrated Docker interop belongs to the
integration owner. Native Windows execution, GUI appearance, DPAPI/ACL and
public HTTPS remain NOT_RUN. Source manifests, logs and the exact cross-build
are retained under `~/Cicada/.local/evidence/n2-app/local-profile-20261015-7KGOjS`;
the source was dirty relative to `c1b6a30` during validation.

The GUI dependency is pinned to `gioui.org v0.10.3` (Go module tag
`v0.10.3`, released in September 2026). Gio is dual-licensed under
`Unlicense OR MIT`; see its upstream [license](https://github.com/gioui/gio/blob/v0.10.3/LICENSE)
and [release notes](https://gioui.org/news/2026-09). Gio's official Windows
install documentation states that its Windows target does not require CGo or an
additional compiler toolchain: [Windows installation](https://gioui.org/doc/install/windows).
The Go module's pinned transitive graph is recorded in `go.mod` and `go.sum`.

This is a source/build foundation, not a released installer. Windows cross-build
and native Windows execution are tracked separately; a cross-build is not a
native GUI, DPAPI, keyboard, display, or file-picker acceptance result. No
application package size or runtime-performance claim is made here.

## Build and current authority scope

From `cicada-go`, a Windows amd64 executable can be built with:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -mod=readonly -trimpath \
  -ldflags='-s -w -H=windowsgui' -o cicada-app.exe ./cmd/cicada-app
```

This produces an unsigned executable, not an installer or deployment. The N1
controller has no Manager-authorized topology reader; management and live
canvas data remain unavailable even when the account session is active. Do not
use this build to operate Hub management or treat account login as Root or
Manager authorization.

## N2 finite activation and recovery

The main flow now presents one user decision at a time: connect with locally
issued activation material, create or import Owner keys, confirm this App's
limited access, and log in. Prepare/complete challenges, both Owner private-key
proofs and the separate Owner-signed device grant run inside the Go controller.
Legacy continuation imports the exact existing Owner keys and preserves account,
Owner and key IDs, credentials and older devices. Encrypted PKCS#8 input remains
unsupported and receives an explicit native error; the App never rekeys or asks
the user to run an external decrypt/signing command as a workaround.

The confirmation explains the fixed, nonrenewable 15-minute lease and its exact
`nodes.list` / `session.capabilities` scope. Ordinary account login follows Root
proof. The App confirms finite access only after independent fresh encrypted
session inspection and activation status; general Manager access remains
unavailable. Snapshot and native redraw deadlines remove readiness when the
session or lease expires, without a network poll or renewal. Connection details
are available separately from the English/Chinese guided steps.

Every business request, recovery query and authenticated receipt is committed
to the scoped encrypted vault before network progress is reported. Recovery
first retries exact bytes. Unsigned HTTP failures never settle the business
packet; an authenticated target-bound receipt or durable rejection fence does.
`ABSENT` keeps it uncertain. A rejected wrong-password completion can reuse its
still-valid registered-device challenge with corrected credentials. Current
account/device epoch observations prevent historical session receipts from
reviving a fenced session. Status observations are refreshed with a new request
after exact-cache recovery, even when the cached observation is very recent.

N2 App checkpoint validation used the fixed Go 1.27.2 image
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`
and the stable module closure supplied by the integration owner. Focused normal
tests passed **94 cases with zero skips**, including production Hub/SQLite/PQC
HTTP without Control: initial prepare/complete response loss and App/Hub
restarts, imported legacy identity/credential/device preservation, wrong-password
correction, expired-session re-login, Root revocation and account/device epoch
faults. Linux vet, Windows vet and Windows amd64 cross-build passed. **Race tests
were still running when this checkpoint was committed**; their final result is
reported separately to the integration owner. Native Windows GUI/DPAPI/ACL,
Android, physical devices, public HTTPS and PQTLS remain NOT_RUN. Final integrated
Docker interoperability and independent acceptance belong to the integration
owner. Evidence is retained under
`~/Cicada/.local/evidence/n2-app/n2-full-20261015-TDvq4Q`; tests ran on the dirty
`570c12f` source plus the recorded App changes, not that HEAD alone.

## Recovery correction checkpoint

An explicitly cancelled or refused setup can now accept new operator-issued
material for the same complete Hub/origin/account/Owner scope and purpose,
without changing Owner/App keys or device ID. An unused setup can also accept
replacement material. Epoch rollback, unknown pending requests and established
or revoked Root remain blocked. Sent operations require authenticated terminal
evidence; an accepted old challenge alone cannot reopen its authority. One prior
authenticated disposition receipt is retained in the vault. The native flow
offers replacement only when this evidence permits it, and an optional local
replacement view can return to activation without a request or state deletion.

Registered-device account login is independent of Root/runtime-lease status.
Current account login and session inspection may succeed after a restore or
Root revocation while the finite lease remains revoked and unconfirmed. A
device ID or prepare challenge alone never advertises login: registration is
established only by authenticated claim/completion/session evidence. Previous
N1/N2 profiles recover that fact without new keys or a new activation code.

This correction passed **101 normal tests and 53 App/UI race tests, zero skips
or failures**, plus Linux vet, Windows vet and Windows amd64 cross-build on the
same fixed Go 1.27.2 builder. Real Hub tests include original-packet settlement,
authenticated cancellation before replacement, unchanged reserved keys/IDs,
unused-code replacement, epoch/scope rollback rejection, established/revoked
Root refusal, and ordinary account re-login without regranting the lease.
Evidence and before/after source manifests are retained at
`~/Cicada/.local/evidence/n2-app/n2-recovery-20261015-Tj3El8`; Go/module manifest
SHA-256 is `e2d7704d933ce5347575334edd04935d785ff6522ccb15d8e9853898042f7c6d`.
The tested source was dirty relative to `070137c`; the final README facts were
added after the unchanged code completed its checks. Independent process
acceptance is rerun by its owner after integration. Native Windows runtime,
DPAPI/ACL, Android, physical devices, public HTTPS and PQTLS remain NOT_RUN.
