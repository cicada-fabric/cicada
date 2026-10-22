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

On startup the App discovers up to 64 existing vaults across the selected
directory and its fixed retained locations. Filenames and public headers are
locators only: current-user DPAPI
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

At that checkpoint, the saved Node card remained visible through account login,
expiry and recovery. The login privacy checkpoint below supersedes that display
choice. Within a signed-in account, the card separates the saved connection,
current observation and this App's finite status access.
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

The login privacy checkpoint shows a narrow, centered sign-in form before a
current trusted account session is confirmed. It hides Hub/account/Owner/Node
identity, saved binding details, status dates, connection health, key-storage
hints and canvas/preview controls. Saved profiles use numbered labels. Cached
usernames never prefill the editor; a manually entered username survives a
failed attempt, while passwords still clear on submission. Trusted scope changes
and sign-in transitions clear inputs, expanded details, preview/selection,
scroll positions and finite-consent checkboxes. Valid restored sessions can
continue after authenticated inspection; Owner-proof-pending sessions still
reach their existing flow without requiring Root to be active.

First connection, Owner initialization and finite activation keep their existing
steps. Generic recovery remains available before sign-in using the original
controller action. Hiding information does not alter the vault, saved binding,
available actions or exact pending packet. A fresh login reveals the same binding
even if status access has ended. The account screen pauses future automatic Node
reads and starts a fresh interval when eligible again; it cannot bypass an
uncertain request's explicit recovery. Normal in-flight Node observations do not
hide information for an otherwise valid account.

The final dirty source relative to `5fee32c` passed **141 UI/native events in each
normal and race run, zero failures/skips**, Linux/Windows vet and Windows amd64
cross-build in the fixed Go 1.27.2 builder. Before/after Go/module manifests are
`b9f78ea9e5b5c132d5afdc178e35c0a38825021b8e075baf159ced71a20060f7`.
Commands, individual results, private-cache mounts, manifest and unsigned artifact
hash are retained at
`~/Cicada/.local/evidence/n3-login-gate/run-20261017T112228Z-187b47/app/final`.
The parent App receipt is an earlier source and is not this checkpoint's receipt.
Win32 rendering/interaction/high-DPI, Windows DPAPI/ACL, physical devices, native
Runtime, Android and public HTTPS remain NOT_RUN for this change. Independent
Docker process/interoperability acceptance belongs to the integration owner.

Native startup now keeps first setup blocked until local profile discovery
finishes successfully. A profile already open in another Cicada process has a
distinct, neutral message and a retry button. Discovery, unlock, restored-state
and Hub-verification failures cannot fall back to a new device code or Owner-key
import/generation. Core rejects those actions too; this is not only a hidden
button. Discovery publishes its profile list only after every candidate is
authenticated, retaining earlier trusted locators if a later scan fails. A
successful empty scan still allows genuine first setup. Explicit headless core
callers without discovery retain their original connection-card retry after a
busy lock is released.
The reset snapshot publishes restricted recovery actions under the same lock,
including during slow discovery/unlock, so an intermediate frame cannot offer
first setup. Regression checks include concurrent frames across 1,000 resets.

Reopening recorded identity IDs is read-only, so detecting an invalid saved
session does not first rewrite that vault. Actual legacy key-ID completion and
new-device identity creation still persist, and the real-PQ request fixture
checks that both identity IDs and the exact request precede every POST.

The regression includes an actual second Linux OS process contending for the
encrypted synthetic fixture vault while the first keeps an uncertain request.
After the first closes, retry preserves the same Owner/App keys and resends the
original packet. This is a core/process result; it does not run two Win32 GUI
windows or validate Windows DPAPI/ACL, Chinese font rendering or visual style.
Those native checks remain separate; fonts and styling are deferred.

Final validation used dirty `a14ad28` source in the fixed Go 1.27.2 builder:
**290 normal events, 21 scoped core race events and 149 complete UI/native race
events, zero failures/skips**. The core selector covers every new profile
regression, including the second OS process, slow callbacks, concurrent reset,
legacy key-ID completion and the real-PQ persistence-before-POST barrier. The
normal run covers appcore, appui/native, appkeys and appvault. Linux/Windows vet
and the Windows amd64 cross-build passed. The existing synthetic OpenSSL Owner
fixture was mounted read-only; it is never deployment initialization material.

Original, resume and final Go/module manifests (1,151 entries) all match
`748629b4dd2e3c5adcefdcac58962beefa79e5636f349958c0848d7455755cf9`.
Commands, exit codes, source manifests, fixture/artifact hashes and the final
receipt are retained at
`~/Cicada/.local/evidence/n3-app/profile-recovery-20261017-1vxt9vq5/atomic-final`.
The broad legacy N2 race sweep was interrupted and is **not a pass**; its log and
reason remain beside the scoped race receipts. Earlier candidates retain their
own interrupted records, including the `final` directory's normal RED of
279 passed, two failed events (parent plus invalid-session case) and one
unconfigured optional-fixture skip. Those results do not transfer to this source.
Standard disposable interop and Windows two-window GUI acceptance remain
separate integration/native scopes.

## Workspace navigation and CJK source checkpoint (2026-10-20)

The native window now separates Overview, Devices, Sessions & communication,
Identity & access, and Settings. The account display boundary remains
`PresentScreen`: signed-out and expired sessions have no device/session
navigation or protected content. Pending operations show a persistent link to
their original recovery controls, without forcing the selected page. Account
steps stay on Identity; Node and Pair controls stay on their respective pages.
Overview shows names, current status and the next review step. Full identifiers
remain selectable/copyable in details. Exact Node and Pair approval targets,
permissions and expiry remain directly visible during consent; no renderer
creates authority or treats registration as communication permission.

The window uses a light palette, existing Gio dp/sp sizing, and startup-only
bounded loading of Windows' own `Fonts/msyh.ttc` or `Fonts/simsun.ttc` through
`opentype.ParseCollection`. The default family is selected explicitly only from
a successfully parsed CJK face. Missing, changed, oversized or invalid files
leave Gio's system fallback in place; no font is bundled or downloaded. The
prior implementation only relied on implicit system font discovery. This is
an explicit loading change, not a proven diagnosis of every reported glyph
failure. Actual Windows font loading, missing-font fallback, Chinese glyphs,
DPI, clipboard and GUI behavior are still **NOT_RUN** for this source.

Scoped evidence is retained at
`/home/zyf/.cicada/acceptance/app-ui-checks/run-20261020T135022Z/`.
`source-before.json` attributes the first source to dirty
`9866cf3ad6c0513539f67bde292368f1b344bca7` plus the ten frozen earlier WIP inputs
and this UI change. The actual retained UI binaries produced **133/0/0** in
normal and race runs, and scoped vet exited **0**. Initial Windows compilation
failed on an unused import; that source and failure remain under
`first-tested-ui/` and `first-result.json`. Removing that import closed both
Windows compile lanes (`ui-validation.json`). The subsequent Windows-only CJK
change was checked by compiling the native UI test package and GUI executable,
both exit **0**; its exact source inventory and artifacts are recorded in
`ui-cjk-compile-validation.json` and `source-cjk-before.json`. The earlier
normal/race executions are not reattributed to that later source.

All checks used the pinned Go 1.27.3 builder with external networking disabled.
This scoped UI checkpoint does not execute a real Hub, native Runtime, model,
queue or physical Windows App. Disposable protocol interop belongs to the
subsequent clean integration gate. The HTML information-architecture prototype
is a design artifact and is not a Gio or Windows runtime acceptance result.
User-file root selection, Owner directory access and automatic Codex context
binding remain separate checkpoints; this change does not migrate any vault.

## Selected user root and original-state recovery (2026-10-20)

New App vaults default to `~/.cicada/app/vaults`. `~` is the current user's
home on the target platform; the development workspace `~/Cicada` is not a
product default. `cicada-app.exe --user-root "D:\CicadaData"` selects a custom
root, ahead of `CICADA_USER_ROOT`. The selection must be an absolute canonical
path with protected existing ancestors. Invalid paths, links/reparse points,
Win32 aliases and untrusted write access fail closed. The resolver creates no
files. Current-user DPAPI, the original vault's authenticated scope, private
ACLs and atomic vault persistence remain the custody mechanisms.

This entry point does not install a shortcut or remember the launch flag.
Repeat `--user-root` or retain `CICADA_USER_ROOT` when opening that custom
installation. The existing component installer accepts omitted `--prefix`
using the same user-root default, or an explicit prefix. It installs files;
it does not migrate existing component data or change existing launch settings.

The App also checks the published nested legacy vault location
`%LOCALAPPDATA%/CICADA/vaults/CICADA/vaults` and the home-default App vaults.
It authenticates every discovered profile before publishing a complete
scope-to-source association. Selecting an empty custom root cannot hide an old
Owner or create a replacement identity. Duplicate scopes, corrupt or busy
vaults, renamed filename aliases and missing previously known sources require
recovery. Known profiles always reopen their original location; nothing is
copied, moved or rekeyed. Explicit creation of a genuinely new profile first
rechecks the fixed locations. Settings shows the selected root and the actual
authenticated vault source only after account sign-in, with full selectable
paths and a retained-location explanation in English and Chinese.

New implicit Node and MCP state defaults are `<root>/state` and
`<root>/mcp/sessions.json`. Existing component-specific state overrides retain
priority. A single populated legacy MCP location remains the source;
multiple populated locations require an explicit original state directory.
Outbox main databases and their SQLite side files count as retained state.
Orphan side files without a main database require recovery before SQLite can
open or create anything. Exact known Node state markers under the former
implicit `/state` require selecting the original `--state-dir` or component
environment override. Empty unrelated directories do not block new setup.
Invalid defaults stop before lock, identity or current-directory state creation.
These changes do not relocate managed workspaces, caches or existing Node data.

The recovery regression creates an encrypted synthetic profile with an
uncertain activation packet, closes its controller, selects an empty custom
root, rediscovers the original vault, and resumes the same Owner/App keys and
exact encrypted packet. This uses the real Core/PQ actor fixture, not a live
production Hub. Additional cases cover duplicate/corrupt/busy/missing sources,
explicit-only creation, filename aliases, retained outboxes and invalid path
side effects. Private production keys and payloads are not evidence inputs.

Scoped checks and retained test binaries are under
`/home/zyf/.cicada/acceptance/app-path-checks/run-20261020T151357Z/`.
These checks used dirty `bb0644b68627579af470ead52035d42618372c75` plus
the recorded paths changes, with the earlier ten WIP files already archived
and absent. Each following count includes test/subtest events, with zero
failures or skips in that listed successful lane:

| Checked source manifest | Normal / race checks |
| --- | --- |
| `source-final-before.json` (`1508bc08…`) | apppaths **3 / 3**, scoped appcore **27 / 27**, appui **134 / 134** |
| `source-corrected-before.json` (`6187bae1…`) | componentinstall **32 / 32**, scoped CLI **10 / 10** |
| `source-sideguard-before.json` (`1e0e5e65…`) | final CLI recovery/default guards **24 / 24** |

The initial Windows builds failed because pinned `x/sys/windows` does not
export `FILE_DELETE_CHILD`; the corrected source uses its documented WinNT.h
value. Initial installer test execution failed because fixture subprocesses
could not find Go in the test process PATH. Correcting only that process's
PATH let the same retained installer binaries pass. Earlier preflight fixture
failures and the evidence driver's filename/inventory errors are preserved,
not overwritten or counted as passes. The final orphan-side-file cases reject
opening a missing main database; intermediate presence-only behavior is not
the delivered behavior.

The corrected source passed scoped Linux/Windows vet, Windows amd64 App and
core/path test compilation, and Linux CLI build. The subsequent CLI-only
guards passed their own vet/build and normal/race runs. Before/after source
inventories and retained binary hashes are checked in the corresponding
`first-formal-review.json`, `corrected-gate-receipt.json` and
`sideguard-gate-receipt.json`; results are not transferred between manifests.
The Go 1.27.3 executable was extracted from the pinned official builder and
hash-verified; dependency resolution used the stable module cache with
`-mod=readonly`, `GOPROXY=off` and `GOSUMDB=off`. These were host
synthetic/local-TCP checks, not Docker-isolation
results. Disposable integrated interop belongs to the integration owner.
Native Windows DPAPI/ACL/GUI/CJK/DPI, physical devices, public HTTPS, Android,
live model/queue and product Hook integration remain **NOT_RUN** here.

After Root fast-forwarded the backend base to
`d3acd4bfe6f3f10867db6a5e3ae432f8477d9748`, all 29 local checkpoint
inputs were preserved. The affected Core storage selector passed **8/0/0**
normal events, and the Windows amd64 App cross-build exited **0**.
`post-d3-gate-receipt.json` binds these checks to the unchanged 1,308-entry
before/after manifest
`a5c81131f8f6aab005c63b24efdf0dca9ff706d7ea4730e31c1c00112d1608f4`.
The older normal/race matrices above retain their original sources. This paths
checkpoint does not yet consume the new Owner directory operation.

## Owner Thread directory and retained unknown reads (2026-10-20)

Sessions & communication now offers a native, explicit read of the original
approved Node's own Threads. The Core first verifies the bounded availability
document at `GET /v2/owner/endpoints/read`; an old/disabled/wrong-Hub response
creates no new directory proof, durable request or secret POST. Each page then
uses the current authenticated account and the existing vaulted Owner key to
sign the separate `owner.endpoints.read` purpose. The native read/next-page
gesture binds the exact original Node, current local session, cursor and limit.
There is no manual signing, browser or external crypto-tool step.

The old N2 operation TTL is not renewed or expanded. General management and live
canvas remain unavailable. Returned rows are always `SNAPSHOT_ONLY`, with an
explicit capture time; a recent lease does not establish current Thread
consumption or communication permission. Names and complete selectable workspace
paths are primary, with IDs in details. Both English and Chinese are available.
Account expiry, logout, unverified restored login and known Root/epoch mismatch
hide directory metadata and signing controls.

The original Node outbox holds the exact request and its typed signed context,
inside the existing encrypted vault, before POST. Response bytes are verified
against that original packet and persisted before application. Recovery retries
the original bytes even when public availability subsequently disappears.
Unsigned HTTP errors and a validly encrypted foreign-target response cannot
settle or replace it. Authenticated historical receipts remain snapshots.

If the original account session has also expired, the current wire does not
provide a new reconciliation purpose for that old packet. Its unsigned failure
remains unknown. After the original read proof expires, an explicit native
“Retain the unconfirmed read and continue” gesture can instead retain its full
original packet/proof/response as local **UNKNOWN** and release the active slot.
One existing Node-state CAS performs both changes; a failed CAS preserves the
previous pending request and history. This is local retention, not a Hub
settlement, and it is unavailable for authorization, Join, Leave or other
mutations. The gesture binds the current packet digest, proof and request ID;
an old click cannot dispose of a later read.

Unknown history permits at most four records and 384 KiB, also respecting the
existing complete Node-record limit. Capacity is checked before a new directory request
is persisted/sent; unknown records are neither evicted nor replayed
automatically. Full history blocks further directory reads while independent
Node operations remain available. New reads still require current login and a
new exact Owner gesture/proof. Before login, the UI shows the account step
without historical counts, Nodes or cards. A pure clock projection plus the
existing Gio deadline scheduler exposes the local retention option at proof
expiry, without a network poll or vault write.

Evidence is retained at
`/home/zyf/.cicada/acceptance/owner-read-checks/run-20261020T160425Z/`.
The initial dirty `73d6f9ad13c26ad7cf203e2924adcc7a46104213` source
(`source-final-before.json`, `8ccf68b3…`) passed scoped Core **26/26**,
complete appui **135/135** and portable native **28/28** normal/race events,
with zero failures/skips, Linux/Windows vet and Windows native-test/App
cross-compilation. These results precede local UNKNOWN retention and retain
their own source. All 19 WIP source paths are preserved under
`pre-park-passed-sources/`.

After Root's dependency fast-forward, the final dirty
`794de08590c015ed68ad641eac01f695b3bf34ec` source passed the narrow
Core **13/13**, UI/privacy/catalog **4/4**, and native deadline **1/1**
normal/race events, all zero failures/skips. Scoped Linux/Windows vet, Windows
native test compilation and App cross-build passed. Its before/after 1,323-input
manifest is
`a02b6b64ce0f078991a0d7d935e0f0ca6c82fa03fad491936248617a492e1060`;
`park-gate-receipt.json` records commands, exits and retained binary hashes.
Checks include a real failed vault CAS, unchanged originals across restart,
old/changed gesture rejection, live-proof and mutating-operation refusal,
bounded retention, restored original epochs and clock-only expiry.

The initial preflight's **10 passed / 1 failed** remains recorded. Its restart
assertion incorrectly expected visible rows after an unpersisted synthetic
account session had disappeared; diagnostics confirmed LOGIN_REQUIRED while
the authenticated original receipt was restored. The corrected test checks
receipt persistence and the login boundary, without manufacturing a login.
All fixtures are visibly synthetic Core/PQ actors; logical-clock tests are not
wall-clock Hub or Windows acceptance. The pinned Go 1.27.3 toolchain and offline
module resolution were reused. Independent actual Hub/process acceptance is
QA-owned; native Windows GUI/DPAPI/ACL/CJK/DPI, physical devices, public HTTPS,
Android, real model/queue and product Hook integration remain **NOT_RUN** here.

### 2026-10-20 managed Codex consumer checkpoint

The existing single Cicada plugin now selects `cicada mcp --codex-context`
through the portable `mcp.json` and compatibility `.mcp.json`, with one shared
Hook definition and the existing `$cicada-network` skill. Literal current-Thread
messages (`cicada join`, `cicada peers`, `cicada connect`, `cicada leave`,
`cicada help`) use the Node's
already reviewed local operator contract. Standard skill/plugin invocations
remain ordinary model workflows. Registration has zero communication rights;
repeat registration of a left Thread does not revive it. A saved Pair Join does
not claim either Owner consent or current communication authority. The native
Settings page also retains the explicit local fixture preview, using no live
management snapshot.

Managed MCP startup does not restore an ambient or parent SID. Every tool schema
requires its connection nonce; the trusted PreToolUse Hook replaces the complete
context with a fresh Node ticket bound to the actual record, workspace, tool
and business arguments. MCP consumes that ticket before scope restoration or
business work. Missing, changed, replayed or unsupported proof fails closed.
This is the existing same-user local Runtime trust boundary, not a new native
human attestation or a public Hub authorization mechanism. Hook configuration
or a public capability alone grants no business permission.

A valid switch cancels and waits for the previous immutable heartbeat worker
before installing another actor. Renewal uses only its frozen origin, context,
credential, Group, Endpoint, principal and binding epoch; a late denial cannot
clear a replacement actor or delete the original persisted scope. Idle renewal
is lease evidence. The separate named-connect cold-start Node lease work is
Hub-owned and is not established by this consumer checkpoint.

The existing scoped operator journal persists the original request before IPC.
A complete Join credential is saved in the existing private MCP scope before
output and acknowledgment. Cache or output failure retains the original result
for exact recovery. Leave retains that cache for the Hub Guard to reject stale
credentials; this consumer does not claim a cross-process cache deletion CAS.
Unknown results and unauthenticated errors do not settle the original command.
Human-visible Hook output is supplied through `systemMessage` as well as the
literal command's block response; actual installed-plugin display remains an
independent QA gate.

Evidence is retained in
`/home/zyf/.cicada/acceptance/codex-context-checks/run-20261020T173400Z/`.
The tested source was dirty `4cf544e8d3ad60c341581480aa09e45e7eed2bb5`,
not that commit alone. Before/after 2,374-input manifests both hash to
`ddf566c6585a1dc7e4604d467848dac3af26b865838f90d5329c7336dcd8e25f`.
Related MCP normal tests recorded **171 PASS, 0 FAIL, 7 SKIP**; the seven
explicit opt-in Runtime/Android/multi-Hub gates were not run. Affected-context,
main-entry, session/scope and outbox race tests recorded **85 PASS, 0 FAIL,
0 SKIP**, using the retained race binary before/after hash
`c984d7d450d56a44311ab574a36922d6622e79d3a4b814b279f6b84aacb369ac`.
The new consumer/main-entry subset recorded 21 passing events in each mode.
Portable UI **136/136** and native **29/29** passed normal/race with no failures
or skips. Scoped Linux/Windows vet, CLI build, Windows native-test compilation
and unsigned App cross-build passed. CLI stdio smoke exposed 71 tools and
rejected a missing ticket despite a synthetic ambient parent SID, without
writing its private HOME.

Initial synthetic Join fixture setup failures (missing workspace and private
root permissions) are retained under the earlier run's `preflight-failures/`.
Earlier runner failures remain separate: wrong package working directory and
umask caused the first normal run's 15 failures; both broad race attempts
exceeded their 300-second limits. An initial focused race run also rejected a
group-writable evidence ancestor used as TMPDIR; the corrected run used an
owned private temporary root, removed afterward. None was fixed by relaxing
product validation, and none is reported as an aggregate pass. The final
receipt records selectors, exact exits, source and artifact hashes; this README
was updated afterward with a documentation-only delta. No new protocol,
dependency, deployment or real identity was introduced. Own disposable Docker
interop, actual installed-plugin/native Runtime, Windows GUI/DPAPI/ACL/CJK/DPI,
physical device, Android and public HTTPS acceptance remain **NOT_RUN** here.


### 2026-10-20 installed-plugin asset correction

Independent QA's original `18868ba` installed-plugin run confirmed that
`plugin marketplace add /repo` succeeded, while `plugin add cicada@cicada-repo`
failed because the manifest's `./cicada` source resolved to missing `/repo/cicada`.
The original result remains at
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261020T175718Z-eBSGNY/result.json`
(SHA-256 `d7e21d89b81033656cb29b08e20e52902cfa4faa02132427e215e04ef054b1d6`).
This was a product asset failure before the actual Host environment/tool gate.
The existing marketplace now selects `./.agents/plugins/cicada` from the
repository root. The single bundle, identity, version and portable launch command
are retained.

Official `rust-v0.163.0` source resolves to
`83086188ae0614bd882818ff1aa23f3194962012`.
Its [marketplace resolver](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core-plugins/src/marketplace.rs#L677)
uses that repository-root layout. Its
[Codex MCP overlay](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core-plugins/src/agent_plugin_mcp_overlay.rs#L58)
adds local `env_vars` from the same-name compatibility stdio server after loading
the portable server, preserving the portable command and arguments. The local
launcher clears inherited variables and builds a bounded environment; its Unix
default list does not include Cicada configuration.

The compatibility `.mcp.json` therefore adds 17 explicit configuration names:
Hub origin, Node selection, selected user/Node roots, original MCP session and
outbox file/directory aliases, PQTLS configuration path, the existing advanced
Network directories, and the retained XDG state location. It supplies no values,
interpolation, caller SID, Endpoint/Group identity, credentials, key or proof
contents. The portable `mcp.json` and Hook definition are unchanged. The config
check independently resolves the marketplace source to the existing bundle and
checks the complete allowlist and shared transport. Existing scope and server
Guard validation remain authoritative. The opt-in per-call context schema from
`18868ba` is a local MCP schema change; this correction changes no Hub wire.

Source and validation evidence live under
`/home/zyf/.cicada/acceptance/codex-context-checks/env-review-20261020T174600Z/`.
The original read-only review, official tag/source hashes, pre-marketplace
26/26 normal/race result and a local marketplace regression **FAIL** are retained.
Final affected config/context/state/outbox tests recorded **26 PASS, 0 FAIL,
0 SKIP** in each mode; scoped vet also passed. The tested source was dirty
`18868bade057d5da97afe3e8139cc3cafb104afe`, with 2,374 inputs unchanged
across the before/after manifests
`74101ba420af1a97514cec53260864e55a319cf21530b950d9662b3012f8065c`.
`asset-gate-receipt.json` retains selectors, commands and binary hashes. This
README is a later documentation-only delta. Actual installed-plugin loading,
configuration forwarding, human-visible feedback and managed `whoami` remain
independent QA gates. No new Windows Runtime, GUI, Docker, Android, physical
device or public HTTPS result is claimed by these asset checks.


### 2026-10-20 Codex 0.163 supported Hook package

The next independent actual Host run on `c3a1517` installed and enabled
`cicada@cicada-repo` successfully, with the expected source and version 0.0.5.
Its `hooks/list` response nevertheless contained no hooks, errors or warnings.
The original **FAIL** remains at
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261020T180658Z-HsgwHR/result.json`
(SHA-256 `6faa7704b61d22a074181dd7510e33a70ebbca5c80701fa8ee35643d5f2028fc`).
That run stopped before TUI feedback or a managed tool call. It does not establish
configuration forwarding or successful business admission.

Official `rust-v0.163.0`, source commit
`83086188ae0614bd882818ff1aa23f3194962012`, explains this behavior.
The [manifest selector](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/utils/plugins/src/plugin_namespace.rs#L43)
prefers a schema-declared root `plugin.json`. The
[manifest cache](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core-plugins/src/manifest/manifest_cache.rs#L60)
classifies that selected root as `AgentPlugin`. The
[loader](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core-plugins/src/loader.rs#L966)
explicitly returns empty Hook sources and warnings for that format; it loads
bundled hooks for the supported legacy format instead. This target-version
implementation result takes precedence over assuming a feature flag can enable
portable hooks.

The current single Cicada bundle therefore uses `.codex-plugin/plugin.json`
and `.mcp.json` directly. The shadowing portable root `plugin.json` and unused
root `mcp.json` are removed; their previous contents remain in Git history.
The plugin identity, version, shared Hook/skill, marketplace source, managed
command/arguments and 17-name configuration-only environment list are retained.
The existing config check rejects a shadowing portable entry and verifies the
single supported manifest/server. Version checks and the public Go metadata
collector now require the selected legacy manifest alongside the existing
VERSION and wire/OpenAPI metadata. Other metadata, mount and privacy checks
remain in place. This is a package compatibility correction; shipping Go
behavior, Hub wire, Owner identities and stored requests are unchanged.

Evidence is retained at `/home/zyf/.cicada/acceptance/codex-context-checks/hook-format-checks/run-20261020T181310Z`.
Config and version checks each passed **1/1** in normal and race modes, with
zero failures/skips; three related Python metadata/envelope tests, two Python
AST checks, scoped vet and skill validation passed. The source was dirty
`c3a1517c7b47864a5d9d9a20c6de9ee444799622`; 2,372 existing inputs and the
two explicit deletions remained stable across the gate. Before/after manifests
both hash to `c185f03d32a9329f7a2d6a39d0fb89e6c9b91e89a9fcc1905438abbcc85f81a2`.
The later README edit is a documentation-only delta. Earlier portable-package
and asset results retain their original source attribution. Actual installed
legacy Hook discovery/trust, human-visible literal feedback and a verified
managed tool call remain independent QA gates; Windows Runtime and other
physical/public acceptance results are not added by these checks.


### 2026-10-20 local Hook feedback presentation

Actual Codex 0.163 TUI feedback on the earlier source displayed the complete
literal result twice: `systemMessage` and the identical blocking `reason` were
rendered separately. Local operator responses now keep the complete bilingual
result in `systemMessage`, while `reason` is the short neutral explanation that
Cicada handled the input locally. That statement covers help, refusal and
unconfirmed outcomes; it does not claim that a Hub operation or authorization
succeeded. `decision:block` remains. The SDK still labels this status
`Blocked by hook`; this correction does not claim a native success widget.

Command parsing, transport, original-intent persistence, credential handoff,
output-before-ACK order and per-call tool tickets retain their existing behavior.
The existing entry/framing test checks the complete help result, unverified
command feedback and ordinary skill pass-through. Focused normal/race checks also exercise literal Join save and
output failure recovery, the CLI dispatcher and existing PreTool replacement.

Evidence is retained at `/home/zyf/.cicada/acceptance/codex-context-checks/feedback-checks-20261020T191729Z/final/`.
Both modes recorded **13 PASS, 0 FAIL, 0 SKIP**; scoped vet, Linux CLI build and
actual CLI help/unverified-input smoke passed, with no private-HOME writes.
The tested source was dirty `29c3997b9f1850466ba5dfc5b5c1fd3a3be983dc`,
with 2,378 inputs stable across the before/after manifests
`85f88e6227df4fea5d69cf15a65b1680eef73cc3268efdee19235d6ca8126108`.
Earlier pre-review evidence remains separately retained in the parent directory.
This README is a later documentation-only delta. New installed-plugin TUI
presentation and Host acceptance remain QA-owned; no new Windows Runtime,
Docker, Android, physical-device or public HTTPS result is added here.

### 2026-10-22 formal plugin material installation

The existing file-only component installer accepts optional
`--codex-plugin-assets ABS --codex-plugin-sha256 HEX` with Linux `node`
(including a combined `hub,node` selection). `ABS` selects the downloaded
package root containing the one authoritative `.agents/plugins` bundle.
Both flags are required together. The installer checks the original bytes of
exactly these five ASCII-sorted paths:

1. `.agents/plugins/cicada/.codex-plugin/plugin.json`
2. `.agents/plugins/cicada/.mcp.json`
3. `.agents/plugins/cicada/hooks/hooks.json`
4. `.agents/plugins/cicada/skills/cicada-network/SKILL.md`
5. `.agents/plugins/marketplace.json`

The independently checked package digest is SHA-256 of compact UTF-8 JSON
`{"files":[["path","lowercase original-bytes SHA256"],...],"format":"cicada.codex-plugin-assets.v1"}`.
Object keys appear in `files,format` order, file rows in ASCII path order,
with no spaces or trailing newline. This digest excludes the installation
root; the installer records the original inventory and digest separately from
the hashes of installed material in `INSTALL-MANIFEST.json`.

Materials live under `<selected-root>/components/node/share/codex/.agents/plugins`.
The MCP launch uses the absolute installed Node executable and
`mcp --codex-context --user-root <selected-root>`, without `env_vars`.
Both Hook commands use that executable and selected root, with POSIX shell
quoting. The other three source files retain their original bytes. There is
no second maintained plugin source. Fresh installation and identical repeats
are supported; changing the binary, assets or selected-root record refuses
replacement. Adding assets to an existing older installation also refuses
an in-place upgrade. Removal retains unowned files and original state.

This is stage one, preparing component files. It never executes Codex or Node,
starts a service, initializes an account, or migrates existing Node state.
The user separately starts their Node with its original configuration, then
uses the normal Codex marketplace/plugin commands for stage three. The
repository marketplace remains a developer/legacy explicit-configuration
entry; the formal installed marketplace root is
`<selected-root>/components/node/share/codex`. Changing the root of an already
registered `cicada-repo` marketplace requires normal marketplace removal,
addition of the new root, then `codex plugin add cicada@cicada-repo` and normal
Host trust. This checkpoint alone does not claim a working discovery consumer
or actual Codex acceptance.

Scoped component-installer verification used pinned Go 1.27.3 on dirty
`25cca3a9764cf485da2242efc03d92f594a465ae`, with all four implementation/test
inputs stable before and after. Normal and race each recorded **54 PASS,
0 FAIL, 0 SKIP**; scoped vet passed. The suite uses visibly synthetic binaries
which panic if executed, and checks quoted paths containing spaces, an
apostrophe and shell expansion syntax, paired flags, original asset hashes,
changed-install refusal, unsafe inputs, material/manifest tampering and
preservation of unowned files. An initial run failed the existing directory
ownership fixture under host umask `002`; that failure is retained separately.
The reported runs used subprocess umask `077`, without changing product code
or existing directory permissions. Evidence is retained at
`/home/zyf/.cicada/acceptance/codex-context-checks/formal-assets-20261022T145844Z/`,
with result SHA-256
`3b84bb88a26c85599e9af1e4e59267a19c10f458169fbbab369599027b435d3e`.
This README is a later documentation delta. Docker interop, actual installed
Codex/Node integration, Windows Runtime, Android, physical devices and public
HTTPS are **NOT_RUN** for this checkpoint.

### 2026-10-22 installed local Node consumer

The three independent stages now have a consumer implementation. Stage one is
the existing file-only `components install` with the optional reviewed plugin
assets above. Stage two is the user's manual start of the original Node daemon:
add `--user-root ABS` to the existing `machine agent` configuration, retaining
its original state and account. A single-Hub daemon also explicitly declares
its original `--mcp-session-state-file ABS` and `--mcp-outbox-state-file ABS`;
these paths can differ. This declares existing locations rather than migrating
them. Multi-Hub publication uses its existing per-Hub paths. Neither installing
files nor installing the plugin starts a Node or creates a second Node identity.

Stage three installs the materialized marketplace using normal Codex commands.
For the default selected root, first remove an already registered old source
with `codex plugin marketplace remove cicada-repo`, then run:

```sh
codex plugin marketplace add "$HOME/.cicada/components/node/share/codex"
codex plugin add cicada@cicada-repo
```

For a custom selected root, use that installation's `components/node/share/codex`
directory. Complete normal Host trust for the installed MCP and changed Hooks.
The source repository's bare-command entry remains a developer/legacy mode.
The installed entry uses absolute executable/root arguments, with no terminal
PATH or Cicada deployment environment required in an already running Codex
daemon. The formal mode selects an already running standard-profile Node,
checks its original binding, and fixes independent cache/outbox/socket paths.
It does not infer strict-PQTLS configuration from absent environment variables.

Offline/ambiguous/unready discovery produces bounded bilingual guidance and
never guesses a different Node. Each tool and frozen heartbeat rechecks its
complete original pin; a same-binding daemon restart may change instance ID.
MCP session and operator-intent records persist that pin while keeping the
original scope hash. Old unpinned caches/pending commands return
`LOCAL_NODE_CONFIG_REQUIRED` and remain untouched. A new pinned session cannot
adopt an old outbox-only namespace: the original SQLite database requires its
own immutable pin metadata. New databases commit this metadata before WAL or
business rows; absent DBs with residual WAL/SHM/journal, empty interrupted DBs,
and existing unpinned DBs require original configuration recovery. Changed pins
cannot replace an uncertain request, cache or outbox. New managed acceptance
Threads use explicitly new scopes; no migration of existing Threads is claimed.
Current legacy code refuses pinned state; older published binaries do not
understand this forward-only schema and must not open that new pinned state.
Root-mode Network invitation/session and Monitor broadcast configuration are
not selected by this contract and return CONFIG_REQUIRED; original explicit
legacy flows remain separate. Registration still grants no communication rights.

Pinned Go 1.27.3 normal/race checks on dirty
`2fc293c80dda9ed2aa983a277fb346dd97d21847` each recorded **70 PASS, 0 FAIL,
0 SKIP**. Scoped CLI vet and Linux CGO-disabled build passed. Evidence is at
`/home/zyf/.cicada/acceptance/codex-context-checks/formal-consumer-20261022T152239Z/`,
result SHA-256
`fe4cb9a34d172dd3ea50727d38d2106fb296e3da32d99c336a8e3021b8630b6b`.
The before/after source manifest records all Go/C/header/module inputs and five
authoritative plugin assets, stable throughout these runs. The retained initial
failed run found an in-process environment-poison fixture issue, a private-fixture
umask issue, and an empty 307 heartbeat response previously treated as success;
the final source corrects all three. The HTTP test verifies no redirect target
receives credentials. Synthetic local descriptions and the real local bridge
fixture remain scoped tests, not actual Codex/Hub authorization acceptance.
This README and contract are later documentation deltas. Docker interop, actual
installed Codex/shared-daemon/native Runtime, Windows GUI, Android, physical
devices and public HTTPS are **NOT_RUN** in this checkpoint and remain separate
QA evidence.

### 2026-10-22 local Hook diagnostic stages

Hook refusals now distinguish native coordinates, native record verification,
missing tool input, missing call context, an invalid connection marker, invalid
business arguments, argument encoding failure and an unconfirmed Node ticket.
Each has a stable local support code and a short bilingual cause with an action
such as retrying in the original Thread, normal `/hooks` enable/review, checking
the Node in the App, or providing the code to support. No tool argument values,
native IDs, record paths, nonces, tickets or arbitrary Node error text are echoed.
These stages identify local processing failures; they do not turn them into a
Hub authorization refusal. Local record errors use `errors.As` with the reviewed
`LocalCodexContextError`: ROOT, PATH, OWNERSHIP, PERMISSION, INODE, METADATA,
SOURCE, SESSION and WORKSPACE have fixed messages. Unknown stages and wrapped
error text fall back to the bounded generic record stage. Node-side IPC errors
retain the Node-ticket stage; their text is not parsed for local record claims.
The shared native record validator and IPC shape are unchanged by this consumer
checkpoint.

Literal matched commands retain their blocking result and neutral short reason;
the SDK's `Blocked by hook` heading does not identify a business failure. Failed
PreToolUse still denies the invocation before any business action. Diagnostics
do not change permissions, recreate native identity, borrow a prior Thread or
claim that a preparation/repair command exists. The separate default local
collaboration flow awaits its shared DTOs and implementation, and is not
implemented or accepted by these diagnostic changes.

Pinned Go 1.27.3 normal and race checks each recorded **16 PASS, 0 FAIL,
0 SKIP** with the Hook/PreTool/real CLI-dispatch selector; scoped CLI vet passed.
The suite verifies stage selection, private-field redaction, refusal before Node
issue for invalid calls, bounded typed-stage handling, and unchanged bytes/mode
of an unsafe synthetic native record. Evidence is retained at
`/home/zyf/.cicada/acceptance/codex-context-checks/hook-diagnostics-typed-20261022T172936Z/`,
result SHA-256
`41e9cdc5fd0ac8032ed3eddd05a0ec520893f7eae97677b3e63067bb4fddcfe5`.
The tested source is dirty `5c1dd5a144817e6d6fcf399fd648258531520571`;
all source inputs remained stable across the retained before/after manifests.
The earlier generic-stage checks on dirty `96dcbe0` remain separately retained
under `hook-diagnostics-20261022T172150Z` and are not attributed to the final
typed-stage source. This README is a later documentation delta.
Actual installed Host, Docker, Windows GUI, Android, physical devices and public
HTTPS are **NOT_RUN** for this checkpoint.

### 2026-10-22 local collaboration App client

The default Devices workflow now consumes `native-local-domain-v1` using the
existing vaulted Owner and App keys. After account login and Node selection,
Core reads every authenticated policy-history page for that exact Node before
offering setup. An empty local cache never means the Hub is unconfigured.
An older Hub, malformed availability document or `available:false` permits no
new domain request; explicit refresh can rediscover an upgraded/recovered Hub.
Public availability itself supplies no caller authorization.

The native English/Chinese card prepares a named private Network and dedicated
Group. Friendly defaults are editable; the default policy lasts until revoke,
with optional 24-hour, seven-day and thirty-day choices. No raw UID, Network ID
or policy ID entry is required. The actual Node's signed fresh user report fixes
the OS user. Explicit approval validates the exact retained prepare packet,
challenge, report and lifetime before the local Owner signs the entire policy.
Core exposes enabled state only after a fresh authenticated Node-policy read.
App close, logout and account expiry do not revoke the domain. Account expiry
removes administrative actions without changing the policy's independent life.
The Overview links to this workflow and registered Threads; the previous Pair
workflow remains under the Sessions advanced disclosure, with its own pending
recovery prompt and unchanged authority model.

Each original request and authenticated response is encrypted in the scoped
vault before transmission or progress. Unauthenticated HTTP errors, redirects,
invalid responses and response loss retain the uncertain original. Domain
recovery retains one exact encrypted reconcile request containing the original
packet, validates its operation/request/digest and reopens the exact nested
receipt. Retried recovery uses identical bytes across restart, including after
account expiry. Historical mutation receipts remain saved outcomes until a
fresh authorized read. A still-live original prepare review can offer another
explicit approval only after independent revalidation. No Owner replacement,
private-key export, external signing tool, browser or new local database is used.

Five bounded domain namespaces coexist with the existing base, Node and Pair
records within the unchanged sixteen-record, 4 MiB vault limits. Raw encrypted
packet frames avoid nested base64 duplication; prepare review and its exact
response share one atomic state record. Metadata, response and target validation
precede restoration. The client test actor uses actual local Owner signatures,
shared PQ envelopes and disposable encrypted vaults; it is not Hub Store/Guard,
Node IPC or real Thread authorization acceptance. Source-specific checks are
recorded in [native App validation](../../../docs/native-app-validation.md).
Actual domain backend/Node/Host interoperability and physical Windows execution
remain separate gates. This checkpoint changes no public protocol or service.

Pinned Go 1.27.3 verification used dirty
`7ff12e8d506a0206a961d2ef9659cbd7811e55ec` plus the retained App sources.
Full Core/UI normal tests recorded **361 PASS, 0 FAIL, 0 SKIP** in
`/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-client-20261022T183316Z/`.
Its full Go/C/header/module manifest remained stable at
`92112adad38e9a90a0e04e2f381be86791a15fc77ee4de9f2c829dacbc8d44ca`.
The broader historical race matrix was deliberately interrupted, exit 1; its
partial events are not a PASS. The exact original receipt is retained with
SHA-256 `d522f46fa02594e52f4032a20950c8d0bc0a12a8a4ab064393da64b83fad28f1`.

The final renderer-only delta adds native review/policy deadline wakeups and
clears local-collaboration inputs when switching presentation scope. Core
production/test bytes remain identical to the full normal run. Final UI/native
normal tests recorded **170 PASS, 0 FAIL, 0 SKIP**; the scoped
`LocalCollaboration` Core/UI/native race run recorded **20 PASS, 0 FAIL, 0 SKIP**.
Linux vet, Windows vet and Windows amd64 GUI cross-build all exited 0. Evidence
is retained at
`/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-client-final-20261022T184131Z/`,
receipt SHA-256 `38b27598cd4a71ed799f2abcb51d06cfabf6d4582ca2836f91db96da1d058479`.
The before/after source manifest is stable at
`2a7e57430d4e6211ff66f52c31d963e01d081d3cd75ae192c76d7b68728a8d24`;
the unsigned executable SHA-256 is
`da9d1c5107958a8ea9c522dfc94cba5eebfd9b091ca729397169254983a347d2`.
The real encrypted-vault coexistence test holds all sixteen base/Node/Pair/domain
namespaces, a byte-bounded PQ page and detached recovery across two reopens and
two hours of account expiry: 2,164,336 opaque payload bytes, 2,910,450 vault file
bytes, 173,101 sealed-page bytes and 427,784 nested recovery-response bytes.
No vault limit is widened. This README is a later documentation delta. Docker
interop, actual Hub/Node/Host domain execution, physical Windows GUI/DPAPI/ACL,
Android, physical devices and public HTTPS are **NOT_RUN** here; Root/QA own
those separate acceptance gates.
### 2026-10-22 local-domain Hook and MCP consumer

The installed consumer accepts the private Node's consumed one-use context as
the native writer boundary. Empty or `LEGACY_STRICT` profiles require zero
domain fields. Only explicit `LOCAL_DOMAIN`, domain version 1 and a complete
policy ID/epoch/digest select the domain lane. Unknown or partial profiles fail
before reading cached credentials or sending business requests. Existing Pair
Join accepts only strict context; it cannot borrow a domain ticket.

Literal commands now use Node issue then consume, without a client-side strict
record precheck. Only the five exact
`codex.operator.{endpoint_register,endpoint_leave,endpoint_directory,native_pair_available,native_pair_join_named}`
purposes are allowed; help remains local. A new random event nonce and parsed
command digest bind each call to its original SID/workspace. Missing native
turn/tool-use IDs stay empty; the producer permits the double-empty form only
for those operator purposes. MCP retains its real event IDs. Operator tickets
cannot be used for MCP. The Node selects the verification profile; callers
supply no permission-relaxation switch.

An enabled-domain registration is saved only after the Node returns the
Registration, Join and domain key result together with accepted native scope.
The consumer checks the consumed policy digest, version/epoch, complete member,
manifest and Join scope, original native coordinates and pinned Node-Control
tuple. App Hub and Node-Control Hub fingerprints remain separate. The Node
uses its existing independent Owner trust pin to verify delegation before
registration and the full candidate chain before ACTIVE. The plugin neither
reads the Node's private database nor treats a policy's embedded Owner key as
an independent trust pin. Subsequent tools and heartbeat still require current
Hub Guard; a saved result is not evidence of model consumption or a reply.

A private operator intent is committed before IPC. Response loss and output or
cache-save failure retain its original request and selector. A newly selected
policy cannot replace an uncertain request. Historical completion under a
different current selector is acknowledged as history without restoring its
old session. Only confirmed explicit Leave clears the current scope cache;
original native records and historical outbox rows remain intact.

New domain caches use disk version 2; legacy/Pair caches keep version 1.
Version 1 with domain markers, malformed version 2 or mixed scopes fail without
rewriting the file. This prevents an old JSON reader from ignoring domain
fields. No native identity, scope hash, Node pin or cache path changes.
The existing SQLite outbox adds one bounded binding column; old rows retain
the empty legacy value. New domain rows bind policy version/selection and
original native BindingID/epoch. Reads and SQL updates reject changed policy
or admission before modifying an old row, so a new Join cannot lend its token
to an older uncertain operation. Frozen heartbeat includes the same domain
selection and cannot clear another policy after a late response. This adds no
database or background daemon.

The two authoritative plugin description/skill sources now explain the default
Owner-enabled local workflow and keep Pair advanced. The skill was updated
under `skill-creator` and passed its validator; no installed files or resident
processes were changed. The five original source assets have package digest
`24c9d1f0b5381811c11f7fc7947d58afc2fddea63d672500d846c7120d2798e8`.

Pinned Go 1.27.3 normal and race checks each recorded **123 PASS, 0 FAIL,
0 SKIP** on dirty `273965416adfd08a118e287e653c7184619bcc2d` plus this consumer source.
Scoped CLI vet, Linux and Windows CLI cross-build, and skill validation exited
0. Evidence: `/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-consumer-final-20261022T193030Z/`;
receipt SHA-256 `f39baf4346cb49b2c20950f3c28fcb2d48163000e5e4a9fe0165f098cfa8e867`.
The full Go/C/header/module/five-asset manifests match before and after at
`e63a80e926c5af6552f04dc47c6288613c91879c2dff19b741f8c074b8e7db0f`.
These tests use real private sockets, one-use HMAC contexts, local cache/SQLite
persistence and existing PQ Pair client regression. The domain projection
fixture explicitly uses synthetic verified-evidence markers; it does not
substitute for Node Owner/candidate verification. The first retained run at
`local-domain-consumer-20261022T192548Z` passed normal 123/0/0 but race failed
122/1/0 because its scripted socket callbacks shared an unsynchronized test
variable. Its original receipt
`60136e4f835618f8233fd817766626c31417be2d062df4852e3bee47cf6bf14a`
is retained. The final source uses an immutable atomic pointer and includes
the domain-only v2 cache correction. This README is a later documentation
delta. Actual Node domain profile/022 verification, Hub/Node Owner/candidate
admission, installed Host/model communication, Docker interop, native Windows,
Android, physical devices and public HTTPS remain **NOT_RUN** here.

### 2026-10-22 consumer binding-version compatibility correction

Read-only comparison with the Hub implementation found a real version mismatch:
the consumer compared `policy.NodeControlBindingVersion` with the discovered
`LocalNodeBinding.BindingVersion`. The former is the Node-Control key row
revision; the latter is the Owner binding version, carried by
`policy.Node.BindingVersion`. The original fixture set both to 1 and hid the
difference. The consumer now compares the Owner binding version with its
independent Node connection pin. The full policy digest and Node verification
continue to cover the separate Control-key row revision.

A regression explicitly sets Owner binding version **1** and Control-key row
revision **7**. It first fails against the original comparison, then passes
after the fix. A pin incorrectly using 7 as its Owner binding version and a
different Owner binding ID are rejected. Scoped normal and race checks each
recorded **17 PASS, 0 FAIL, 0 SKIP**, and CLI vet exited 0, using pinned Go 1.27.3
on dirty `a4b15e5c61783234109619d5bebe46f28eaae1a3` plus the two recorded source changes.
The affected code/test/module manifest is stable before and after at
`f311599b8bef538cd9f9a74b7add16d1338186e9da55f48d386e0d9e8b8da878`.
The red regression and final logs are retained at
`/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-binding-version-20261022T194648Z/`;
final receipt SHA-256 `17d5120d80c117dc8dc9b486951ebceadca3660dd84f6d56c4d9899f18483d18`.
This is a narrow consumer projection/persistence regression; it does not rerun
the earlier 123-event group or establish actual domain service acceptance.

The skill's Leave sentence now distinguishes a new explicit domain admission
under the current policy from reviving an old member/binding or reassigning an
unresolved original packet. Legacy/Pair behavior, native IDs and protocol
structures are unchanged. The five original plugin source assets now have
digest `89502bd0ddc39971591940a7273e7ebdca848e4a1a60e4653ac650114d32c7eb`; the earlier
`24c9d1f0b5381811c11f7fc7947d58afc2fddea63d672500d846c7120d2798e8`
remains attributed to its tested producer source. This README and skill sentence
are later documentation deltas. No executable was rebuilt or delivered for this
correction. Actual Node/Hub/Host acceptance remains separate; the final Windows
App must be rebuilt from clean combined source after backend and QA acceptance.

### 2026-10-22 profile resume with an unresolved local-domain activation

The actual process gate on clean `2458552c78a69daba386ec9c1721568f30d49e51`
retained an activation accepted by Hub, lost its response, and restarted both
App and Hub. Reopening the same encrypted profile then failed before the
safe checkpoint. QA's separate diagnostic run classified the failure as
`UNLOCK_AND_RESUME_PROFILE` returning an error with no snapshot error code.
Those two failed runs remain failed evidence; this Core correction does not
retroactively establish actual service acceptance.

The restored account session was present, so `resumeProfile` called
`inspectSession` after loading the unresolved domain packet. The shared
`canBeginOperation` guard correctly refused a new request while that original
was pending. Profile unlock now completes with the retained pending operation
and the session still requiring independent inspection. Explicit domain
recovery remains available. No generic guard is relaxed, and cached outcomes
still cannot establish current management authorization.

The new regression stores a visibly synthetic Hub-signed, device-encrypted
login receipt in the real local vault, loses an accepted activation response,
and reopens the same profile. It covers both live and expired account sessions,
then loses the reconciliation response and reopens again. Assertions retain
the original Owner/App keys and exact activation/reconciliation packets,
prevent fresh account POSTs during recovery, and restore the historical ACTIVE
outcome with `Current=false`. The live-session case first fails against the
original Core; the expired-session control passes. This closes the previous
RAM-only actor session coverage gap without claiming real account login or
Hub/Node service coverage.

Pinned Go 1.27.3 scoped normal tests recorded **46 PASS, 0 FAIL, 0 SKIP**
for local collaboration and profile discovery/recovery. The new two-case
regression under race recorded **3 PASS, 0 FAIL, 0 SKIP** including its
parent test; App Core vet exited 0. The tested source is dirty
`2458552c78a69daba386ec9c1721568f30d49e51` plus the recorded Core and test edits,
not HEAD alone. The Go/C/header/module manifest matches before and after at
`747ca821780ae892aeff6c0501d4e6d1b9b12126cff787eb0b1d958a7270c17c`.
Evidence: `/home/zyf/.cicada/acceptance/codex-context-checks/local-domain-profile-recovery-20261022T212140Z/`;
red receipt SHA-256 `abb7c7f83c319beddf7b8683efb9a3cb73539a18a2f98296f45771a75aef1306`;
final receipt SHA-256 `89b1253acfe5ec6e45be34346d54e7cfb235777d4d853152baa64f8623ec8009`.
This README is a later documentation delta. The original actual process FAIL
and QA diagnostic FAIL are retained separately. A fresh actual Hub/Node/App
process gate, Docker interop, installed Host/model communication, native
Windows Runtime, Android, physical devices and public HTTPS are **NOT_RUN**
for this correction. No executable was rebuilt or delivered here.

### 2026-10-22 exact pending domain Join recovery before current context

An accepted literal domain Join could become impossible to reconcile after its
response was lost and the policy was revoked: the Hook requested a new context
before reading its persisted operator intent, and the Node's current-policy
issuer could then select the strict profile and refuse the native record.

The Hook now probes an existing private intent before that issuer gate, only
for a pinned, saved version-1 domain `endpoint_register`. It compares the
current native SID/workspace, parsed operation and all parameters, Node ID,
origin and entire saved connection pin before using the complete original
request. Request ID, timestamp, policy selector and digest stay unchanged.
An absent original creates no alternate intent directory, lock or request.
Unknown IPC outcomes retain the pending original; historical completion and
refusal keep the existing output/acknowledgment rules.

Historical Join tokens enter the current cache only after an additional fresh,
matching Node-issued and consumed context, with the connection pin revalidated.
Without it, output confirms historical completion, restores no communication
permission and saves no token. The scope is deliberately limited: legacy,
Pair, directory, Leave and unpinned commands retain their original verification
order. Directory intents do not contain the complete native tuple, and this
change does not infer or add it. New literal commands and MCP business calls
still require their current context. No Node, public wire or shared native
verifier changes are included.

A real private-socket consumer regression first fails against the original
Hook. Its scripted Node uses the real HMAC issue/consume authority and pinned
local discovery, loses the original response, then refuses context issuance
with no current policy and an `022` native record. Exact replay can still
receive UNKNOWN without changing the original file, then recover completion
through another output loss. The saved result is acknowledged only after
successful historical output; the token never enters the cache or output.
Changed name, cwd and pin fail before issuer/business IPC. A different SID
still needs a fresh ticket and creates no replacement scope state on refusal.
This tests consumer ordering, not the Node's sealed-packet or Owner chain.

Pinned Go 1.27.3 scoped normal checks recorded **84 PASS, 0 FAIL, 0 SKIP**
for the affected Hook/operator/context/domain/pin paths. The new recovery test
under race recorded **5 PASS, 0 FAIL, 0 SKIP** including its four subtests;
CLI vet exited 0. This source is dirty `bd0d90120c042735aba0f627bd01a1b0a0546055`
plus the two consumer edits and new regression, with a stable Go/C/header/module
manifest `83d4f96a5d6bd7d0bf24a7556a33da96bcad3fd0a61a173f272915611ddcfa28`.
Evidence: `/home/zyf/.cicada/acceptance/codex-context-checks/operator-domain-historical-recovery-20261022T220016Z/`;
behavioral red receipt SHA-256 `d1267c538cafae0a0e2755d5abf257529b67a55d2dcbdf3ffe3852834057f064`;
final receipt SHA-256 `6e8099d115111379234e6809aa1ba8cf2c8ebf8b0594cab39d80af0d458da575`.
Earlier fixture compilation and the pre-SID-assertion passing run are retained
separately in that directory. This README is a later documentation delta.
Actual Hub/Node IPC loss/revocation, installed Host/model communication,
Docker interop, Windows Runtime and public HTTPS are **NOT_RUN** here and keep
their separate backend/QA attribution. No EXE was built or delivered.

### 2026-10-22 domain delivery scope and control projection correction

A real Hook/MCP/Relay producer gate reached ASK with a correctly saved domain
outbox operation, then failed with a different-authorized-session-context
error before Node dispatch. `currentMCPOutboxScope` already retained the policy
selection and original native binding, but `currentMCPDeliveryRequest` rebuilt
that scope without its `codexOutboxBinding`, so its strict comparison rejected
every matching domain operation.

Delivery now snapshots `sessionDomain` and the cached native binding ID/epoch
under the same existing session read lock and carries them into that comparison.
Empty legacy/Pair binding semantics and exact equality remain unchanged. The
receive, same-Group request status/cancel, and sealed RPC status/cancel temporary
operation projections also carry the existing scope binding unchanged. No SQL,
historical outbox rows, Node, protocol or authorization checks are changed.
The constructor audit included the common outbox, delivery, local receive and
control paths. Network uses its separate Network session scope; Monitor,
Space and Task behavior is outside these domain rights and is not extended.

A regression executes real MCP SEND/ASK/REPLY dispatch, SQLite persistence,
fresh HTTP session/card probes and private Node sockets with scripted cards
and receipts. It first fails against the old delivery comparison. Corrected
matching operations reach Node IPC and persist SENT; receive, status/cancel
and sealed control projections also pass. Changed domain version, policy ID,
epoch, digest, legacy profile, native binding ID or native epoch all fail
before HTTP, with the original outbox row unchanged. The tests retain the
current Group and native tuple and reject plaintext HTTP fallback. These are
consumer dispatch/projection checks, not Hub Guard, Relay cryptography or
real native callback acceptance.

Pinned Go 1.27.3 scoped normal checks recorded **48 PASS, 0 FAIL, 0 SKIP**,
including the affected domain/outbox and legacy immutable-route regressions.
The new dispatch/mismatch tests under race recorded **17 PASS, 0 FAIL, 0 SKIP**
including subtests; CLI vet exited 0. Tested source is dirty
`cdc056162a032922e3e3e1fe4ead0ee362fb68d9` plus the four consumer files and new test,
with a stable Go/C/header/module manifest
`d2f75de8408a1afb718ce01d24c38293575c938b64cb48aaf537f68a78b12786`.
Evidence: `/home/zyf/.cicada/acceptance/codex-context-checks/domain-delivery-binding-20261022T222152Z/`;
behavioral red receipt SHA-256 `36c4e5cd80a1a5ee9e27f2327553342c744a67979fe5019d1f45a474764fb0ea`;
final receipt SHA-256 `dfd324db751d9c3310595ebc4a703fd346ed0a848832fa4d3aa3418ccfb25d61`.
This README is a later documentation delta. The actual Hook/MCP/Relay/native
callback gate, Docker interop, real Windows Runtime and public HTTPS remain
**NOT_RUN** for this producer checkpoint and retain their separate Hub/QA
attribution. No executable was built or delivered.
