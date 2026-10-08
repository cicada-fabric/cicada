# Native foreground queue validation

## Current CLI 0.161.0 foreground acceptance — PASS_ZERO_PAID_SYNTHETIC_RUNTIME_ONLY

The existing opt-in real-PTY/official-queue fixture now pins CLI 0.161.0 SHA256
`9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c`
(292,309,256 bytes) and Runtime
`sha256:e7540d8a8ff83952fe0dc8e46c20446d45566a2f6fb1195a98d0ab6afe216a29`.
The single [actual result](../.cicada-data/native-foreground-queue-0161-20261008a/result.json)
SHA256 `703342d494993bc6a5550d42a583626d734cfd2032491c6cea73465ecebe4259`
(8,364 bytes) records PASS in 5.144 s; Main observed driver exit 0. Human UI draft PASS,
foreground busy queue PASS and official queue exit 0. Tested script SHA256
`d52baea798e08a8d794828dec0926fd132d547699c3a84d4a3c3740efb7018fc`
(91,983 bytes) is distinct from CLI/image pins. Main reports original thread
`01a118ed-8499-7410-bd89-c82c8138f71f`, zero paid calls, network none and
driver-reported private-directory cleanup. The [independent review](../.cicada-data/native-foreground-queue-0161-20261008a/root-independent-review.NONAUTH.json)
SHA256 `f7f8e03c3ac9e8514938ef848e862f9329d4a34a5889b3d8baa87d3e40f25a49`
(2,571 bytes) confirms original turn completion, then queued start/completion,
then draft start/completion; busy queue count 1, zero new starts while busy,
and exact draft-plus-suffix matching. It confirms the exact owned container
absent, six resident metadata unchanged and tested script unchanged.
Private-directory cleanup remains DRIVER_REPORTED_ONLY_NOT_INDEPENDENTLY_VERIFIED.
Earlier passes retain their tested source; this UI pass does not validate native
sandbox execution.

The [445 experimental-schema receipt](../.cicada-data/native-observer-wiring-20261007/runtime0161-experimental-schema-20261007c/result.NONAUTH.json)
records the exact CLI generation. Existing `initialize` with experimentalApi true,
`initialized`, queue/list and lifecycle notification shapes remain compatible.
Pinned release [Unix transport](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/app-server-transport/src/transport/unix_socket.rs#L76)
and [daemon-directory policy](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/uds/src/daemon_directory.rs)
place the actual socket in `/tmp/codex-daemon-1000/sha256(canonical-advertised-path)`
and expose the advertised `/tmp/cfq.sock` as a symlink. App-server, observer,
TUI and literal official queue command share one container namespace, so the
existing advertised endpoint resolves to that same protected socket; no host
socket sharing or guessed alternative API is introduced.

Main executed this bounded command once:

```sh
/usr/bin/timeout --signal=TERM --kill-after=1s 179s /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B /home/zyf/CICADA/scripts/test-native-foreground-queue.py --run-native --timeout 140 --result /home/zyf/CICADA/.cicada-data/native-foreground-queue-0161-20261008a/result.json
```

The 140-second evidence deadline retains the existing cleanup bound and outer
179+1-second cap. Default OFF, network none, read-only root, dropped capabilities,
no-new-privileges, UID 1000, private writable home, resource caps and no credential
mounts remain unchanged. The synthetic loopback provider tests UI protocol, busy queue and exact
draft-plus-suffix behavior; this proves neither paid model context nor full
business end-to-end acceptance. The prior
original A auto6 cause remains UNKNOWN; no second run is instructed.

## Historical 0.160.1 foreground acceptance — PASS_ZERO_PAID_SYNTHETIC_RUNTIME_ONLY

The single actual [result](../.cicada-data/native-foreground-queue-161-20261007a/result.json)
`f6ead433418e84fe44e87f2842dd96f4a4b2930a3f4d4c03541d646883e5ee0e`
passed in 4.927s with exit 0 on pinned source `52cd877a…`, CLI 0.160.1
`f34a4d23…` and Runtime `ebea4c99…`. Thread
`01a115a2-5aa0-7d43-80be-ccdb8a51137c` retained the busy queue and unsent draft,
then submitted the exact draft-plus-suffix. Responses were synthetic local,
paid calls 0 and network none. Independent review `e29a2aef43a9dc48584c15950aff79481ca9360fd70fe02408f84eafa595bb83`
confirmed exact owned CID absence and unchanged script. Private-directory cleanup is original driver-reported, not independently proved by that review.

The actual bounded command was:

```sh
/usr/bin/timeout --signal=TERM --kill-after=1s 179s /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B /home/zyf/CICADA/scripts/test-native-foreground-queue.py --run-native --timeout 140 --result /home/zyf/CICADA/.cicada-data/native-foreground-queue-161-20261007a/result.json
```

Private writable `/codex` tmpfs held `/codex/.codex`, outside `/tmp`; config was
0600. No host credentials or repository bind, model override, retries or PTY
delivery fallback were introduced. This PASS proves only the tested synthetic
Linux CLI/TUI path, not paid model/context or provider behavior. Earlier 0.160.0
results below retain their historical counts and attribution. No further run
is authorized by this record.

## Historical 0.160.0 fixture and results — preserved


This opt-in probe checks whether the pinned Codex 0.160.0 TUI keeps a locally
typed, unsent composer draft while the official `codex queue` command adds a
message to that exact busy native thread. It is a Runtime/UI acceptance test;
it does not call an OpenAI model or measure paid model behavior.

OpenAI's [Queue and Steer guidance](https://developers.openai.com/blog/mastering-codex-remote-for-engineering)
describes Queue as waiting for the current response to finish before sending
the next turn. The probe independently measures the local 0.160.0 CLI/TUI
path. The guidance does not specify whether a CLI queue operation preserves
unsubmitted text in a TUI composer.

## Isolated run

Running the script without flags is read-only and reports `NOT_RUN`. The only
execution switch is explicit:

```sh
python3 scripts/test-native-foreground-queue.py --run-native --timeout 140 \
  --result .cicada-data/native-foreground-queue-20261005-new-run/result.json
```

Choose a fresh, absent result path for each run. The driver refuses to
overwrite existing result artifacts.

The driver uses only Runtime image
`sha256:d6004eb3f669966f7a30796333b8a4b1635b30ded40cc7d186e19c42c196818f` and
requires the CLI and app-server handshake to report 0.160.0. It creates one
uniquely labelled disposable container with a fresh `CODEX_HOME`, a real TUI
attached to a PTY, and an app-server Unix socket. A synthetic Responses
provider runs on loopback inside the same container. The container has
`--network none`, a read-only root filesystem, no host credential mounts or
environment forwarding, blank known provider-key variables, and only a dummy
local-provider key. No repository tree is mounted; the default mode binds only
a private controller directory. The driver acts only on the container ID it
created and verifies that ID is absent before reporting a pass.

The driver explicitly trusts only the synthetic `/tmp/cicada-workspace` in its
fresh container-local Codex configuration. It waits for the TUI's pinned
startup-composer placeholder (`Ask Codex to do anything`) to appear on the
attached terminal before typing. A process spawn alone is not treated as TUI
readiness. The driver starts one synthetic foreground prompt and holds its
provider request open. It types a unique draft sentinel into the TUI without Enter,
then runs the official `codex queue --remote ... --thread <observed-id>` CLI
against the same server. Before releasing the held request, it requires the
read-only queue list to contain exactly one queued submission, no
original-turn completion, and the exact main-Thread/original-turn
provider POST still held. Its initial busy proof is an explicit same-server
`thread/resume` snapshot with the single original turn `inProgress`; an original
`turn/started` notification may be absent. The driver neither fabricates nor
replays lifecycle events. Auxiliary title requests are excluded from the main
Thread request count. The local provider then completes the foreground and
queued turns with synthetic responses. The driver appends a suffix to the
still-unsent TUI draft and simulates the user's explicit Enter. The
main-Thread draft-turn provider request must contain the exact original
sentinel followed by the suffix.

Only the original `inProgress` resume snapshot, the queue and held-request
snapshots, future real lifecycle events for original/queued/draft turns,
successful synthetic completion statuses, and the final draft-plus-suffix
request can produce
`PASS_ZERO_PAID_SYNTHETIC_RUNTIME_ONLY`. An observed interruption or lost draft
is `FAIL`. Unsupported or incomplete TUI/event evidence is `BLOCKED`; it is
never upgraded from a CLI exit code or HTTP success alone. The default run is
`NOT_RUN`.

The test uses terminal input only to simulate a human entering the initial
synthetic prompt and later submitting the draft. Product delivery is exercised
through the official `codex queue` command; the PTY is not a delivery fallback.
All prompts are random synthetic markers. The driver records only their
presence booleans and request hashes, not request bodies, credentials, or full
prompt text. For diagnosing startup failure, it retains at most 16 KiB of
terminal output in a separate mode-0600 private file; the bytes are not printed
or copied into the public result JSON. The 140-second evidence deadline plus
owned resource cleanup is bounded below 180 seconds.

## Limits

A `PASS` from this probe would establish behavior only for the pinned Linux
Runtime image and tested 0.160.0 TUI/CLI path with the local synthetic
provider. It would not establish behavior for another Codex version, desktop
UI, network provider, or model. The draft guarantee is established by the
synthetic provider receiving the exact text after the user submits it; the test
does not claim that every UI renders intermediate terminal state identically.
All three recorded attempts are `BLOCKED` and provide no draft or busy-turn
evidence.

## Run record

The first attempt used the command above, the pinned image ID, and
container `8f235812cc7d2d6da10a66cd0ad3643118eeb3fac28b9c745bb26ad856780dd3`.
It ended in 1.1 seconds with exit code 2 and `BLOCKED`. The controller status
reported `runtime_version_ok=true` but `phase=appserver_initialize_failed`
before TUI readiness; the attached `docker start -ai` exited 23. The sanitized
status showed no provider requests; the queue/draft checks remained `NOT_RUN`,
and paid model calls were zero. The attempted driver's recorded SHA-256 is
`d21691a1119e56d03f3868aa726130dcd16fa4ff2855969f4458b492d97ac5db`.

A later static audit found that the embedded wrapper
called `re.search` without importing `re` into its separate Python process. If
initialization returned successfully, that would raise `NameError` and produce
the same generic phase. The first run retained no exception subtype, so it
cannot establish whether this was the observed failure or whether an earlier
handshake step failed. This run does not establish whether the TUI preserves a
draft or whether queueing leaves its foreground turn untouched.

The cached 0.160.0 protocol schema confirms the request payload's required
`clientInfo.name` and `clientInfo.version` fields, and the CLI help lists
`unix://` as a supported app-server transport. The current driver validates
its response version and emits the schema's `initialized` notification shape.
The schema files inspected were `InitializeParams.json`
(SHA-256 `b55124e7c0f36a1789396daa5578217a92be67f053903696236686e59f6f212e`),
`InitializeResponse.json`
(SHA-256 `62ad689c2cb6379913c1d72749cfd8de5089d35760214123518eb92eef11acc9`),
and `ClientNotification.json`
(SHA-256 `706cf248d75027c84a3c63348d0ed507182e8eba40069dd17541793de029145a`).

The runner initially failed to recognize Docker's lowercase `no such object`
diagnostic, so its result JSON recorded cleanup as unconfirmed and masked the
primary failure reason. A separate post-run check inspected that exact CID and
confirmed it was absent (Docker exit 1, `no such object`); the runner-owned
`/tmp/cicada-native-foreground-queue-v6oxwvyt` directory was then removed after
checking its owner and contents. The sanitized confirmation is in
`.cicada-data/native-foreground-queue-20261004/post-cleanup-verification.json`
(SHA-256 `a30dafc7d99a35ccb1764b22772183d315623ae90378eb85d7c70c60cea73810`).
The driver now handles that diagnostic case-insensitively and preserves the
primary run failure alongside any cleanup issue. It also imports `re` inside
the embedded wrapper, separates the request, response-version, and initialized
notification failures into sanitized status codes, and sends `initialized`
without an extra `params` object. Static checks found no other unbound global
names in the embedded wrapper.

The second attempt was authorized after those driver corrections. It used:

```sh
python3 scripts/test-native-foreground-queue.py --run-native --timeout 140 \
  --result .cicada-data/native-foreground-queue-20261004-fixed02/result.json
```

Its driver SHA-256 was
`3096724809ad9b9fd1406e9cd9e2bef4aa78a863c39496be9211c50448d2b8d4`, the same
pinned image, and container
`19fab23d5e143691112b7f26d66ec5f583b61d34ebb6392f43f68d444e621a52`. It ended
in 37.093 seconds with exit code 2 and `BLOCKED`, reason
`timeout_waiting_for_first_synthetic_provider_request`. The driver passed its
initialize/version gate and reached the TUI-started wait state, then sent the
synthetic initial prompt. Within the bounded first-turn wait it did not observe
the required combination of a `turn/started` event and local synthetic
provider request; the result does not identify which half was missing. Queue,
busy-turn, and draft checks remained `NOT_RUN`; paid model calls were zero.

The runner reported both owned resources removed. A separate check confirmed
that exact CID was absent and found no remaining directories matching its
private-directory prefix. The sanitized receipt is
`.cicada-data/native-foreground-queue-20261004-fixed02/post-cleanup-verification.json`
(SHA-256 `4f7997e594e9bfcc8ea3212752d49e3921266baec50cf95f4b79e9ed094bce66`).
This second attempt still does not establish foreground-turn or draft behavior;
those properties remain `BLOCKED`/unknown.

The second attempt's saved result did not keep separate startup counters: the
private observer files were removed, and its wait required both a provider
request and `turn/started`. Therefore its record cannot tell which observation
was absent. The pinned Codex source object
`a956835d020762cb2b570053af06f643a11c0ecc` shows that this driver reported
`tui_started` immediately after spawning the CLI and then sent input after a
fixed one-second delay. It did not observe that the composer was visible. The
CLI source also has an explicit `--cd` project-trust check; the earlier fresh
workspace configuration had no trust decision. These are harness startup
gaps and plausible causes of the timeout, not proof of what happened in that
run.

The same source sets the terminal startup probe budget to 100 ms and defaults
the cursor position when a response is absent. Its ignored PTY startup test
does not reply to terminal capability queries and still signals its internal
`draft-ready` point after constructing the editable startup composer. Thus this
source does not identify missing cursor-position replies as a fatal startup
cause. It does not expose that internal marker to an external test driver.

The current driver addresses these observability gaps without changing Codex:
it marks only the synthetic workspace trusted, waits for the literal composer
placeholder before sending the first test input, and writes distinct scalar
counts for provider requests and app-server `thread/started`/`turn/started`/
`turn/completed` events, together with TUI process liveness/exit code, composer
marker visibility, and terminal output byte count. The marker match stores no
terminal text.

The third authorized attempt used the corrected driver above with:

```sh
python3 scripts/test-native-foreground-queue.py --run-native --timeout 140 \
  --result .cicada-data/native-foreground-queue-20261004-ready03/result.json
```

Driver SHA-256 was
`ea8acb5d56379cad6b43f458f70cec5b937649e3db219510a1b669e13ed065e8`; the
pinned image was unchanged. It ended in 36.457 seconds with exit code 2 and
`BLOCKED`, reason `timeout_waiting_for_first_synthetic_provider_request`.
This time the composer marker was seen. The separate diagnostics show the TUI
was spawned and exited with code 1, with zero observed provider requests and
zero `thread/started`, `turn/started`, and `turn/completed` notifications on
the controller connection. That connection only initialized; it did not
subscribe to the TUI-created thread. The app-server attaches a new thread's
listener to the connection that sent `thread/start`, so these empty controller
notification counts do not prove that no TUI thread or turn existed. The
zero-provider count does show that no request reached the synthetic local
provider before the observed CLI exit. The container reported 3,016 terminal
output bytes, but this run did not retain the terminal tail, so the CLI's
specific exit error is unknown. Queue, busy-turn, and draft checks remain
`NOT_RUN`, and paid model calls were zero.

The pinned TUI source does not contain a `RemoteComposer` type. Its actual path
starts a fresh thread asynchronously through `thread/start` when launching the
composer, then submits user input as a turn after the user sends it. Its
`thread/start` request carries the selected model/provider config. The third
attempt's provider config omitted `requires_openai_auth`; the pinned provider
type defaults that field to false. The current driver writes `false` explicitly.
The synthetic provider uses a loopback base URL and only the dummy
`CICADA_SYNTHETIC_API_KEY`. The container receives no host credential mount or
host environment forwarding, uses fresh tmpfs `HOME`/`CODEX_HOME`, and has
`--network none`.

The app-server `initialize` request does not subscribe to already-existing
threads. A later source review of pinned Codex commit
`a956835d020762cb2b570053af06f643a11c0ecc` found that an initialized live
connection is attached to threads created later in that same app-server. The
prior empty event counts therefore do not show that the observer was
unsupported, and the TUI's exit before a provider request still leaves thread
creation and listener delivery unconfirmed. The bounded read-only
`thread/list` alternative is not part of this probe. The current driver also
keeps a 16 KiB bounded in-memory PTY tail and writes it to a separate
mode-0600 file beside the result when a result path is supplied. It does not
retain raw output from the third run above; that run's CLI error stays unknown.

The current driver also has an opt-in startup-diagnostic-only mode. It sends
one synthetic foreground prompt and stops when the first local provider POST is
observed or the TUI exits. It skips the queue and draft checks. A successful
result would establish only that this isolated TUI reached the local synthetic
provider; it would not establish queue behavior, foreground-turn safety, or
draft preservation. The bounded terminal tail is saved only to a separate
private file beside the result, never included in stdout or result JSON. Root
authorized one startup-only diagnostic with this command:

```sh
python3 scripts/test-native-foreground-queue.py --run-native \
  --startup-diagnostic-only --timeout 55 \
  --result .cicada-data/native-foreground-queue-20261004-startup-diagnostic-only/result.json
```

The diagnostic used driver SHA-256
`c2b438167ba9f45b47758252345d4927456cb23a4e05eedb13f56cdd3f941e29` and the
pinned image ID above. It ended after 7.094 seconds with exit code 2 and
`BLOCKED`, reason `tui_exited_before_first_synthetic_provider_request`. The
app-server initialized and the composer placeholder appeared; then the TUI
exited with code 1 before the synthetic local provider received a POST. Its
short sanitized terminal error was `Error: Read-only file system (os error
30)`. The terminal did not identify the path that returned this error, so the
specific failing filesystem operation remains unknown. The observer was
initialized in the same app-server before the TUI launched; pinned source
shows such live connections are auto-attached to subsequently created threads,
but attachment is asynchronous and best-effort. The zero event counts do not
establish whether the thread was created or whether notifications arrived
before the TUI exit. Queue, busy-turn, and draft checks remain `NOT_RUN`; paid
model calls were zero.

The private result is
`.cicada-data/native-foreground-queue-20261004-startup-diagnostic-only/result.json`
(SHA-256 `0a8b8caca09a4af9454c8637356c4354ed851cd343288eaac3f0d1cc7b8084f5`).
Its 1,272-byte terminal tail is stored separately at
`.cicada-data/native-foreground-queue-20261004-startup-diagnostic-only/terminal-output-tail.private.bin`
(SHA-256 `03bb2031076e4938a55773ae63ae0d730edc6331a3c39b13f054d8e19b7fdf3e`);
the file and stdout/stderr captures are mode 0600 in a mode-0700 directory.
The driver reported its owned container and private directory removed. An
independent check confirmed exact container ID
`54f7b59b1f1a74c77ffa1919fec0188ef47e5f247aaf76a03b9a02d2bd07214c` is absent
and found no leftover temporary directories with the driver's private prefix.

A follow-up availability probe used one `--rm` container from the same pinned
image with `--network none`, read-only root, all capabilities dropped,
`no-new-privileges`, UID/GID 1000, no host mounts, and no environment overrides.
Its only command was `/bin/sh -c 'command -v strace'`; stdout and stderr were
empty, so the image did not provide a `strace` executable. No Codex process was
started. The host has `/usr/bin/strace`, but it was not mounted into the
container. The probe wrapper failed to persist `docker run`'s return code after
the container exited; exit code 1 is inferred from the shell's no-match
`command -v` behavior, not independently recorded. No retry was made. Exact
container ID
`02fab4d1ced3a2e4775fd7e7314d79c51421cca34a99e32a3fa7a9c0cf0d916d` is absent.
The private receipt is
`.cicada-data/native-foreground-queue-20261004-strace-probe/receipt.json`
(SHA-256 `0b9e0c6dbc07e903b1f0f597d71521b32fc622294135274cda6a69c44d2d79e9`).
This image therefore cannot provide the proposed in-container file-syscall
trace by itself; the EROFS target path remains unknown. The driver now has an
opt-in, static-only prepared mode that stages the host's SHA-pinned `strace`,
loader, and five resolved libraries in a separate owned directory, then mounts
only that tool directory read-only. It traces failed `%file` syscalls from the
app-server and its descendants; stdout is continuously drained and only up to
16 EROFS lines of 4 KiB each can be retained in a separate mode-0600 private
artifact. The traced process keeps the existing network-none, read-only-root,
cap-drop-all and default seccomp settings. The option is restricted to
startup-diagnostic mode and requires a result path. The corrected output path
has not been run; it does not change the recorded startup `BLOCKED` result or
establish the EROFS path.

One authorized run of the initial trace plumbing used driver SHA-256
`19ce637268a1e334a52ca830af67102e2e0262ae44b5ec86df4586908dab8f75`, ended in
10.080 seconds with `BLOCKED`, and observed the same TUI EROFS message with no
provider POST. Its trace pipe received zero bytes. A separate harmless host
`strace 6.8` probe established that `-o -` creates a literal file named `-`
rather than writing to stdout; therefore that run collected no syscall trace
and cannot diagnose the EROFS path. The driver now names `/dev/stdout` as the
trace output. This correction has only passed static checks and has not been
validated in the pinned Runtime. The saved result is
`.cicada-data/native-foreground-queue-20261004-startup-filetrace/result.json`
(SHA-256 `d9fc395a7d5c45a54110cb73aa7429ff98f6114c36f963d561cef840b0962fc1`);
its terminal tail remains a separate mode-0600 private file. The exact owned
container was independently confirmed absent, and the driver reported both
private directories removed.

The prepared command, pending Root authorization, is:

```sh
python3 scripts/test-native-foreground-queue.py --run-native \
  --startup-diagnostic-only --trace-app-file-failures --timeout 55 \
  --result .cicada-data/native-foreground-queue-20261004-startup-filetrace/result.json
```

The driver reported both owned resources removed. An independent post-run
check confirmed that exact CID
`2b964533518c079aa88e70f1c0372f62c555bae03be74ceb62f204dafa5d4f4a` is absent
and found no remaining directories matching the private temporary-directory
prefix. The result SHA-256 is
`7a6fd4d94f1f529bccdbc3ab01db238f8e922c6e7fa59d99e3d52b3e40cce0f1`; the
independent cleanup receipt is
`.cicada-data/native-foreground-queue-20261004-ready03/post-cleanup-verification.json`
(SHA-256 `c898907fa68fb316897e1be0c1479df987d0ef1e6c64acf4df1d50c8dfc8eb82`).
This remains evidence only for a test-controlled PTY and the official CLI on
the pinned synthetic local-provider setup; it is not evidence of real model or
provider behavior. At the time of this Oct 4 record, no later Runtime attempt
had yet been made.

On Oct 5, one authorized corrected app-server-only trace run used driver
SHA-256 `bc46bba2220eb475b58aaa1300b8b4b526a705750ca7978e1d0abd6da4c62e7b`
and the pinned image. It ended after 10.215 seconds with exit code 2 and
`BLOCKED`, reason `tui_exited_before_first_synthetic_provider_request`. The
composer marker appeared, the TUI exited with code 1, and the local provider
received zero requests. The bounded app-server-descendant trace drained
38,145 bytes and retained zero EROFS file-syscall lines without truncation;
no ptrace-denial diagnostic appeared. The trace process was killed during
cleanup after the TUI exit. The terminal tail contains only
`Error: Read-only file system (os error 30)` and no path. This run therefore
does not identify the failing syscall or path: the trace scope did not include
TUI-local filesystem calls. Its result is
`.cicada-data/native-foreground-queue-20261005-startup-filetrace/result.json`
(SHA-256 `e1de7165739fc5982ddc2178f73ab9208f8f2d1ecc96c8089930d4d918c40755`);
the separate terminal tail is mode 0600 with SHA-256
`2d74bff1761ebf2a6a74a920d9ccd1127eedbba697fd4f0eebe9c8b8e8f479d3`. Exact
container `babb14ba922ebc44a4952e2c50b51fea83cf4e7333c221a17c3e45ff7abce283`
was independently confirmed absent; the driver reports its controller and
tracer directories removed.

The next diagnostic is prepared as a separate opt-in TUI-only trace scope. It
reuses the same hash-pinned tool staging and bounded EROFS-line collector. The
TUI keeps inherited PTY stdin; its stdout and stderr are redirected to duplicated
inherited PTY descriptors, while strace writes to its own pipe for collection.
Only failed `%file` syscalls are examined, at most 16 EROFS lines of 4 KiB each
are retained privately, and the existing isolation settings remain unchanged.
The TUI trace option requires startup-diagnostic mode and cannot be combined
with the app-server trace option. This TUI-specific mode has passed only static
and CLI-rejection checks; it has not been run in the Runtime.

The proposed one-shot command is:

```sh
python3 scripts/test-native-foreground-queue.py --run-native \
  --startup-diagnostic-only --trace-tui-file-failures --timeout 55 \
  --result .cicada-data/native-foreground-queue-20261005-startup-tui-filetrace/result.json
```

That one authorized Oct 5 TUI-only trace run used driver SHA-256
`f5d276e3d88739584a9a3ec6a74588e92fd0297cbca1037d86084ac1b507ce40` and the
pinned Codex 0.160.0 image. It exited 2 after 7.068 seconds with
`BLOCKED`, reason `tui_exited_before_first_synthetic_provider_request`; the
TUI exited 1 after the composer marker appeared, and the synthetic provider
received zero requests. The complete, untruncated bounded TUI trace captured
one failed file syscall:
`open("/var/log/cicada/codex/codex-tui.log", O_WRONLY|O_CREAT|O_APPEND|..., 0600) = -1 EROFS`.
This identifies the startup failure in the disposable fixture, not a queue or
draft result. The result is
`.cicada-data/native-foreground-queue-20261005-startup-tui-filetrace/result.json`
(SHA-256 `00338fc4a2cac172797a92bb41c162d647eb305b43970d2d0ad68519dfd46d48`);
the private terminal tail and trace remain mode 0600. Exact container
`2474c040688ad0b9486d60bdebc8e07fab3e6beb24993a3a8c7d43cfb921d679` and its
private scratch directories were independently confirmed absent.

The pinned upstream source explains the path selection: Codex 0.160.0 checks
the effective `log_dir` setting and opens `codex-tui.log` there during TUI
startup (`tui/src/startup_orchestration.rs:718-727, 774-789`, commit
`a956835d020762cb2b570053af06f643a11c0ecc`). The project image copies
`docker/codex-config.toml` to `/etc/codex/config.toml`, whose line 8 sets that
same `/var/log/cicada/codex` directory. The fixture supplied its own user
config but did not set `log_dir`; upstream configuration precedence puts User
config above System config (`config/src/loader/README.md:26-35`). The driver
now explicitly points its generated disposable config to
`/tmp/cicada-home/.codex/log`, inside the existing writable `/tmp` tmpfs. At
the time of this trace record, that one-line fixture correction had passed
host and embedded syntax checks only and had not yet been exercised in the
pinned Runtime. The observed run did not
submit a provider request and is not a foreground queue, busy-turn, or draft
preservation pass. A fresh full foreground queue/draft gate is proposed only
after separate authorization; no result is claimed here.

The subsequent authorized full foreground gate used driver SHA-256
`1113daeeae763ae29843d7b6beb0a488dcdbf083aca0733d83f1b4e60689ef4a`, including
the disposable `log_dir` override above. It ran 37.07 seconds and ended with
exit code 2, `BLOCKED`, reason
`timeout_waiting_for_first_synthetic_provider_request`. The result records
server ready, TUI spawned, and the empty-composer marker seen. The bounded
terminal tail has no EROFS message or old log path; it contains the initial
synthetic prompt marker once. No synthetic provider POST arrived, and the TUI
was stopped during timeout cleanup (`tui_exit_code=-15`). No native thread ID
was observed: `thread/started`, `turn/started`, and `turn/completed` counts were
all zero. Consequently the native-thread queue call, busy-queue observation,
and user-draft-plus-suffix submission were all `NOT_RUN`; this is not a queue
or draft-preservation result. Exact container
`2b012def13119d83301ad2e66f6642ceccbddb92e779277e3da7920881205db7` was
independently confirmed absent; the driver and a run-window check found its
private scratch removed. The result is
`.cicada-data/native-foreground-queue-20261005-logfix/result.json` (SHA-256
`32f5ce8d80501e098f8475022b965f37b0f58ded70e6bfee8f7effa12758182d`); its
terminal tail is a separate mode-0600 file.

The tail shows the empty-composer placeholder before the initial test text,
but this does not establish that Codex accepted the text or Enter. The driver
sent the initial synthetic text and carriage return together in one PTY write;
the later draft-plus-suffix submission was written the same way, but this run
did not reach it. In pinned Codex 0.160.0 source, the composer can ignore key
events while input is disabled (`tui/src/bottom_pane/chat_composer.rs:1957-1963`),
and Enter received during an active paste burst is accumulated as a newline
instead of submitted (`chat_composer.rs:3625-3642`). The paste-burst state
machine uses an 8 ms character/Unix active-idle threshold and a 120 ms Enter
suppression window (`tui/src/bottom_pane/paste_burst.rs:157-170, 329-342`).
This makes text-plus-Enter in one bulk PTY write a source-confirmed fixture
hazard consistent with the visible text and zero requests. The saved run does
not establish that this exact branch fired, and the zero lifecycle events do
not test or refute same-server thread auto-attachment.

The driver now writes each synthetic text input first, waits 0.35 seconds,
then writes carriage return separately at both the initial-prompt and
draft-suffix submission sites. This crosses the pinned paste-burst windows
while leaving Codex's normal paste protection enabled. The change has passed
host and embedded syntax checks only and has not been run in the pinned
Runtime. The proposed single full foreground queue/draft gate, pending Root
authorization, is:

```sh
python3 scripts/test-native-foreground-queue.py --run-native --timeout 140 \
  --result .cicada-data/native-foreground-queue-20261005-keysettle/result.json
```

That authorized Oct 5 key-settle attempt used driver SHA-256
`b604fb73df8f8d11960fe438aa7e008cfdd25fc3511bdb66c6403737b2a5088f` and the
pinned image. It ended after 37.066 seconds with exit code 2 and `BLOCKED`,
reason `timeout_waiting_for_first_synthetic_provider_request`. The composer
placeholder appeared; the provider received zero requests. One
`thread/started` event was observed, with zero `turn/started` and
`turn/completed` events. The TUI was stopped during timeout cleanup
(`tui_exit_code=-15`), so its exit code does not establish a product failure.
The queue, busy-turn, and draft stages were `NOT_RUN`; paid model calls were
zero. The result is
`.cicada-data/native-foreground-queue-20261005-keysettle/result.json` (SHA-256
`d889f1bd66b837cfc79bb3a9a02ec51b2f6482b4297b24bcd813732b307122b9`). Its
separate mode-0600 terminal tail is 6,422 bytes with SHA-256
`2976fe05d29fc65ff12f8067340b9407587cc4b8883d2e4f733a1198734ea16a`. The
exact container
`89af7c9fab380c4e604632401d9e73e4b2944e944ee93e641a7bfe1d27a50974` was
confirmed absent, and its private directory was removed.

Root's independent sanitized review of that tail found a model migration from
the configured `gpt-5.6-luna` to `gpt-6-luna` with medium effort; the initial
synthetic text remained in the composer. The pinned Codex 0.160.0 model
catalog marks `gpt-6-luna` as the upgrade for `gpt-5.6-luna`. Its startup
migration screen defaults to “Try New Model,” and Enter accepts that choice
and persists the target model and its default effort. The startup composer
can display text before its submission intent reaches the live turn loop;
startup drains typeahead before opening an interactive migration prompt, then
restores the draft later. This is consistent with the observed model change
and unsubmitted text, but the run did not record which screen received the
first Enter. No provider POST arrived, so this run does not establish model
request semantics or any queue/draft behavior.

The driver now seeds only the fresh disposable Codex config with
`[notice.model_migrations]` mapping `gpt-5.6-luna` to `gpt-6-luna`. This
records the one migration acknowledgement needed to avoid the startup modal;
the configured model and effort remain unchanged, with no `--model` override.
Each synthetic provider request also records the boolean
`expected_model_present`, which is true only when its request model is exactly
`gpt-5.6-luna`. The driver requires that boolean for the initial, queued, and
draft requests before a pass can be reported. Passing `--model gpt-6-luna`
would skip the migration by changing the model under test; passing
`--model gpt-5.6-luna` would leave migration eligible, so this fixture uses
only the disposable acknowledgement mapping. The prepared driver SHA-256 is
`929a2b015be83f8e509c0076ebf8a0cb7ad545fa027dae4fc3d9abdb4ab1ed37`. This
correction has passed only host and embedded syntax checks; it has not run in
the pinned Runtime. One fresh full gate is proposed, pending Root authorization:

```sh
python3 scripts/test-native-foreground-queue.py --run-native --timeout 140 \
  --result .cicada-data/native-foreground-queue-20261005-modelack/result.json
```

The model-ack run above observed two synthetic provider requests and two
`thread/started` events, but no `turn/started` or `turn/completed` events. Its
saved result did not retain the request summaries, so they cannot be
reconstructed from that historical artifact. The current driver preserves
only request indexes, body hashes, and model/prompt/response booleans when a
run ends.

A bounded notification-only diagnostic is now prepared. It counts notification
method names matching `[A-Za-z0-9_./-]` up to 80 characters and 64 distinct
names, with further or invalid names aggregated into an `other` count. Failure
results retain at most 32 lifecycle records containing only the method, valid
UUID thread/turn IDs, and a short validated turn status. `thread/started`
records also retain a closed thread-source enum and a typed ephemeral flag.
Wait predicates and queue behavior are unchanged. Host and embedded syntax
checks plus in-memory sanitizer-bound checks passed; this diagnostic has not
run in the Runtime. Current driver SHA-256:
`d24805dc122021744b81ba036d6a7e9d2145f87e827afb36b4491ac1d37c3f53`.

## Oct 5 final synthetic foreground gate

The one-shot run used driver SHA-256
`d1d4335a6e6b3bf4a4a7d87de30ee76b320412af926d5ab039b77de0b8103812` with the
pinned Codex 0.160.0 image, network none and a synthetic local provider.
[Result](../.cicada-data/native-foreground-queue-20261005-final-wait/result.json),
SHA-256 `0ccc22f29a6052fde4c01d52533e2a08ad97b389bfc13b4e3dca6595be647fa4`:
exit 0 / 3.996 seconds / `PASS_ZERO_PAID_SYNTHETIC_RUNTIME_ONLY`; busy queue
and draft preservation passed. The active user Thread
`01a10a48-7aec-7851-81f8-276a10e5c8e5` had an `inProgress` turn snapshot through
same-server `thread/resume`; its queue was visible once while busy and empty
after consumption. Main-thread provider calls were joined by native thread and
turn IDs; the unsent draft was absent from the queued request and later arrived
with its suffix. Root's [terminal review](../.cicada-data/native-foreground-queue-20261005-final-wait/root-terminal-review.NONAUTH.json),
SHA-256 `c6b4ea75208e3ff5ce1e6e166f50b90a8a0daebf26e99536f16643a4a3bd49e7`,
confirms the owned CID is absent.

The previous `explicit-subscription` result remains BLOCKED (exit 2 / 4.034s;
SHA-256 `713df74df51dd0dd5cdcf72c3402c98e90646e57705b21e985260615511fc6c7`):
its wait predicate treated the empty ID pair as truthy. The corrected predicate
requires both turn IDs; deterministic prefix and wrong-ID checks passed. This
synthetic pass does not establish real-model consumption, G1, production or
physical-device acceptance; Oct 5 G1C remains FAIL / A3 NOT_REACHED (see
[current checkpoint](v01-final-release-exit-checkpoint-validation.md#current-closeout-evidence)).
