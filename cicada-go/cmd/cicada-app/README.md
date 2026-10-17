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

## Finite Node connection in the same App profile

N3 uses the existing vaulted Owner and enrolled App device. Connect and sign in
with the saved Hub profile, enter the code shown by the Ubuntu Node, and review
its exact identity and complete Node/Hub Node-Control key fingerprints. Explicit
consent signs one finite authorization for that Node and one exact INITIAL
confirmation. Private keys stay in the existing local vault; setup needs no
private-key export, browser, OpenSSL or replacement Owner.

The App first checks the Hub's separate Node availability document. Older or
unsupported Hubs receive no new N3 secret POST or pending packet. N3 requires
completed N2 enrollment history; it does not extend the original N2 lease.
Only `nodes.confirm` uses Client RPC. Node-only observation and diagnostic
recovery use `app-node-authority-v1` HTTP; no broad Node list, general status
snapshot, capability RPC, Worker/Goal operation or live canvas is called.

The Node permission has a fixed prepare-plus-15-minute deadline and ends sooner
if its bound account session ends. A new login cannot adopt it. For a previously
confirmed Node, "Authorize status again" prepares a new status-only review for
the exact saved binding and confirmation provenance. Approval permits reads
only; it never pairs again or spends another confirmation. "End this App's
Node access" ends only the App permission and preserves the Node binding.
An expired or cancelled unconfirmed review can return to a new code only after
authenticated terminal evidence, with a new grant/head and unchanged identities.

Binding approval, recent Node heartbeat and Runtime readiness are separate.
The card shows the authenticated observation time and last heartbeat. Its
connected label expires at the signed heartbeat `fresh_until`; polling cannot
extend an old heartbeat. This contract reports UNKNOWN, CONNECTED and STALE,
without inferring physical disconnection or Runtime readiness. A failed read or
expired permission keeps current status unknown.

Exact Node packets, signed receipts and applied markers are encrypted before
progress. A saved-but-unapplied response is completed idempotently at startup;
Client counters cannot advance twice. Separate encrypted records retain the
INITIAL confirmation and large diagnostic exchanges. Unsigned errors preserve
the original packet. `READ_EXPIRED` settles only its exact side-effect-free read;
mutations require an authenticated original receipt or durable rejection fence.
Node recovery remains accessible after logout or session expiry. This change
keeps the existing vault location and secure-storage backend.
Windows resumes the inherited N1 location
`%LOCALAPPDATA%\CICADA\vaults\CICADA\vaults\<scope-hash>.vault` when opened
as the same Windows user with the same environment. The nested path is retained;
this checkpoint does not migrate it or require a launch-environment override.

App-focused validation for this checkpoint is recorded with its exact dirty
source, scoped actor tests and Windows cross-build below. Independent Hub/Node
process, Windows native security/GUI and physical Ubuntu results remain separate
and are not established by the App crypto actor.

The final 2026-10-17 App check passed **41 Node-focused normal test events and
41 race test events, zero failures/skips**, Linux vet, Windows vet and Windows
amd64 cross-build. The actual controller regression advances time after preview
and reads Snapshot without publishing or sending traffic: expired consent is
removed while diagnostic refresh remains reachable. Other cases cover exact
receipt restart, confirmation/proof persistence boundaries, counter idempotency,
old-Hub preflight, session-ended diagnostics, status-only reauthorization and
full-binding substitution refusal. These are scripted crypto actors using real
shared PQ packets and disposable encrypted vaults, not production Hub Guard or
Hub/Node process-crash acceptance.

Final checks used the fixed Go 1.27.2 builder above, a task-exclusive build cache
and the read-only stable module closure. The tested source was dirty relative to
Store checkpoint `e078c58`; before/after Go/module manifests both hash to
`4cf16ff9726c774dfe18f437f7fd6f89b51b358b02a29805ae6968a42d150935`.
Receipts and the unsigned Windows build are retained at
`~/Cicada/.local/evidence/n3-app/controller-final-20261017-j7l2o3eb`.
The executable SHA-256 is
`d48745afe24b22dc91fdd469e24e4d71d7dc9be8828f9a1cbca398a479094ab2`.
An earlier broader App normal run passed 93 events on dirty `5f509be` source;
its race run was interrupted before the idle-expiry correction and is explicitly
**not a pass**. That separate evidence is retained at
`~/Cicada/.local/evidence/n3-app/controller-20261017-_tbmz785`.
The integration owner runs the complete native/disposable interoperability gate
after integration. Native Windows execution, GUI/DPAPI/ACL, physical Ubuntu Node,
native Runtime, Android, public HTTPS and PQTLS remain NOT_RUN for this App check.

The 2026-10-17 UI guidance correction distinguishes an expired INITIAL
connection review from an expired status-only review. Status-only instructions
keep the user on explicit status authorization. Known unfinished-connection
authorization outcomes are displayed even before a binding exists, so a
revoked permission does not send an already signed-in user back to login.
These messages preserve the controller's actions, recovery priority and consent.

This UI-only checkpoint passed **42 App UI/native normal events and 42 race
events, zero failures/skips**, both platform vet checks and Windows amd64 build
on the same fixed Go 1.27.2 builder. Before/after Go/module manifests both hash to
`4c51097dc46609fb6fef5633cd5129ee962bd255e6301ae9901884da7df8862d`;
the source was dirty relative to `ec72bf2`. Evidence is retained at
`~/Cicada/.local/evidence/n3-app/ux-guidance-20261017-sicleufn`.
Native Windows rendering/high-DPI/GUI/security and full process acceptance
remain separate NOT_RUN scopes for this UI check.

The idle-redraw correction retains a deadline that passes between reading the
controller Snapshot and scheduling the native frame. The renderer schedules one
earliest redraw; a still-live projection whose deadline has just passed requests
an immediate resample. Ended permissions and stale historical timestamps do not
create an idle redraw loop. No network polling or automatic authorization was
added. Status is fetched on demand; an out-of-date cached observation does not
establish whether the Hub has since received a newer Node heartbeat.

The saved Node card stays visible through account login, expiry and recovery.
It separates the saved connection, current observation and this App's finite
status access, with account login or saved-packet recovery taking priority.
Observation timestamps are hidden without current access. "Continue viewing
status" still opens the exact status-only review and requires explicit consent.
Status-access expiry does not revoke the saved Node binding or request a new
Node code. The UI presents an expired status record as a prompt to check for an
update, rather than an inferred Node disconnection.

This combined correction passed **95 App UI/native events plus one controller
clock event in both normal and race runs, zero failures/skips**, Linux/Windows
vet and Windows amd64 cross-build. The actual production scheduler is exercised
through portable Gio Router/Frame processing: substituting the previous helper
with Go's source overlay produces the retained RED (11 failed, six passed),
while all 17 scheduler events pass with the correction. A real-PQ controller
case separately checks Snapshot at heartbeat deadline minus one nanosecond,
exactly at the deadline and plus one nanosecond, without network or durable
state changes. These checks do not execute a Win32 window or establish a physical
Windows fix. Native idle rendering and physical-device follow-up remain NOT_RUN.
Final source was dirty relative to `e42640d`; its before/after Go/module manifest
is `685bdf3a81dafed9ec2a754a954520b1be298e81e9a6ffd5c29569f9918eded1`.
The fixed Go 1.27.2 builder, private cache, read-only module closure, RED/GREEN
logs and unsigned build are recorded at
`~/Cicada/.local/evidence/n3-app/native-status-20261017-fu0fc8pv`.

The automatic observation checkpoint reads only the selected saved Node every
30 seconds after completion, while its exact current finite grant and bound
account session remain valid. Foreground controls are processed first; an
in-flight read is briefly busy with HTTP capped at ten seconds or the earlier
effective expiry. Minimizing pauses future ticks; closing cancels the worker.
Core checks the full expected scope, grant, confirmed binding and authenticated
observation under its action lock before any new packet or vault write. Every
read still persists its exact encrypted packet and authenticated receipt.
Uncertain errors pause automation for explicit recovery; authenticated terminal
outcomes settle normally, and late receipts never become fresh permission.
Normal background reads use a quiet progress indication without overlaying old
authority or extending heartbeat freshness. No Owner proof, pairing, grant
renewal, Client counter or confirmation-budget operation is automatic. Normal
and race each passed **104 UI/native plus 35 core events, zero failures/skips**;
Linux/Windows vet and Windows amd64 build passed with the fixed Go 1.27.2
builder. Before/after Go/module manifests both hash to
`8700f5d8cc629b64ab71a251ceccbc0acf5ae890df1e46547fce8a033a01e7de`,
on dirty `530f5d5` source. Evidence is retained at
`~/Cicada/.local/evidence/n3-app/auto-observation-20261017-z_8hgpqy`.
These are real-PQ core actor and portable scheduler results; Win32 execution,
physical Ubuntu and independent process/interoperability gates remain separate.
