# Native Cicada App

`cicada-app` is the native Go/Gio desktop entry point. It opens the local
`appcore` controller and renders only its sanitized snapshot. Hub health, an
account session, Owner proof, Root activation, and Manager authorization remain
separate states. The N1 core has no authorized topology read path; the canvas
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
