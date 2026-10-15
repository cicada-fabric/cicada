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
