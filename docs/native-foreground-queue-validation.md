# Native foreground queue validation

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
  --result .cicada-data/native-foreground-queue-20261004/result.json
```

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
read-only queue list to contain exactly that queued submission, one
`turn/started` event, no `turn/completed` event, and only the first provider
request. The local provider then completes the foreground turn and the queued
turn with synthetic responses. The driver appends a suffix to the still-unsent
TUI draft and simulates the user's explicit Enter. The next local provider
request must contain the exact original sentinel followed by the suffix.

Only the ordered three-turn event sequence (foreground, queued message, user
draft), successful synthetic completion statuses, exact queue/list evidence,
the held foreground request remaining pending until release, and the final
draft-plus-suffix request can produce
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
provider behavior. No further Runtime attempt has been made.
