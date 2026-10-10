# Opt-in real native queue crash acceptance

## Current CLI 0.162.1 queue-crash gate — scoped PASS

The current acceptance source is pinned by test file SHA-256
`b28cae8d017d9ec148223c603a85d5934e4800e50f4543414368d533d7cbbb17`;
this is the exact source used by the current gate, not an attribution to clean
HEAD alone. It requires official CLI output `codex-cli 0.162.1` and an
initialized app-server `userAgent` containing the exact 0.162.1 version.
It uses an independent disposable copy of a saved historical synthetic B
profile, an exact CLI hash and Runtime image receipt, an owned app-server
socket, and a pinned full-history count/hash. The fixture receipt attests that
provider credentials/config are absent and provider egress is disabled.

The [actual 0.162.1 gate receipt](../.cicada-data/native-observer-wiring-20261007/g4-cli01621-native-20261010a/output-01621-001/result.NONAUTH.json)
has SHA-256 `51cadc91c894e4feff454a3552035943677d2a5671632e8c6401029cc473b291`;
it records `PASS_INJECTED_BEFORE_LEDGER_REAL_QUEUE_ONLY`, `test_exit=0`, CLI
0.162.1, and Runtime image
`sha256:e9690980b153132186780c66126a78b98ed87c3d5e99abf3303b6277e48f697e`.
The gate observed one real official-CLI submission in the exact cold Thread's
native queue, matching the literal input hash. It killed the adapter process
after the queue operation returned and before the local injection ledger was
finished. Restart retained `INJECTION_UNCERTAIN`; attempts to reinject using
either the original or a new attempt were refused, and the exact queue witness
remained one submission. The saved B copy had two turns and ten items before
the run; the test observed no new turn and unchanged history. This is evidence
of the queue-before-ledger crash window, not model consumption or full G4.

The receipt records `NETWORK_NONE` with the fixture's provider-egress policy
attested by its owner; `provider_request_count` is `NOT_INSTRUMENTED`, so no
independent provider POST count is claimed. The [Root postcheck](../.cicada-data/native-observer-wiring-20261007/g4-cli01621-native-20261010a/output-01621-001/ROOT-POSTCHECK.NONAUTH.json)
SHA-256 `2e7fac77e020c32ebfc65cac18b0ae7aece6ec4d9243a80c1bc41c2d6090a275`
confirms the disposable fixture was deleted, exact owned selectors were
absent, and six protected residents were unchanged.

The deterministic version selector passed once in the pinned local Go image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
(`go1.27.1 linux/amd64`). It used the source SHA above, a read-only repository
and module cache, network disabled, a private fresh build cache, UID 1000,
read-only root, dropped capabilities, no-new-privileges, 2 CPUs, 3 GiB memory,
and 256 pids. The exact in-container argv was:

```sh
go test -json -p=1 -mod=readonly -count=1 -timeout=90s ./cmd/cicada -run '^TestMachineNativeRealQueueRequiresExactCLI0162$'
```

It exited 0: one top-level test and all three subtests passed, with zero skips
or failures; package elapsed time was 0.008s and host elapsed time was 97.988s.
The owned container CID and exact name were independently absent after cleanup.
This selector validates CLI version choice only; it does not exercise a CLI,
Runtime, real queue, model, provider, or Native crash window. A preceding Docker
launcher invocation exited 125 before container creation, with no CID or Go
JSON events. Its stderr was not retained, so the cause remains **UNKNOWN**; it
is neither a test PASS nor a test FAIL. The corrected run above is the only
completed selector run. Its private structured receipt and retained-log hash
are recorded separately at
[`result.NONAUTH.json`](../.cicada-data/g4-cli0162-version-selector-20261010b/result.NONAUTH.json).

## Historical CLI 0.162.0 source gate — separate scoped PASS

The historical opt-in acceptance source required the exact official CLI output
`codex-cli 0.162.0` and an initialized app-server `userAgent` containing the
exact 0.162.0 version. Its focused local selector checked that 0.161.0 and a
version suffix were rejected. The historical 0.161.0 PASS below remains
attributed to its original binary, Runtime image, test source and receipt.

That historical 0.162.0 gate required an independent disposable copy of a saved
synthetic B profile, an exact CLI hash and Runtime image receipt, a canonical
owned app-server socket, a full-history count/hash and the original saved cwd.
The profile must have provider credentials/config absent and provider egress
disabled; these Runtime properties are owner-attested by the fixture receipt.
The gate makes no `thread/start` or `turn/start` call and records zero new turns.

The historical 0.162.0 source's deterministic CLI-version gate and
crash-fixture tests were built from test source SHA-256
`b87b59d151b56d4bb8437c37463f81f7db5618cba57188b61eb99814e402bd57` with
Go `go1.27.1 linux/amd64`. The focused normal and race selectors each passed
6 top-level tests and 3 subtests, with zero failures or skips. The reviewed test
binary SHA-256 is
`150455791a1dbf3e06daa59e012e5f3f85c8369b1d24ab1c07c331f9cf8f4ed0`
(39,632,616 bytes). The build and tests ran in a network-disabled, read-only,
UID 1000 container; no CLI, app-server, Runtime, provider, credentials, thread
or turn were started. The metadata-only receipt is
[`result.NONAUTH.json`](../.cicada-data/native-observer-wiring-20261007/g4-cli162-build-20261009a/result.NONAUTH.json)
(SHA-256 `de59e8a5a2919693c7a5c8e23da350ea541e3fbe17254cdf2fb3ed841e1364ab`).
This is deterministic source validation. The bounded actual 0.162.0 run used
the official CLI SHA-256
`50ed828f357c655a3c82054d346cab8434f24901f14ec19b8267571bdd008b38` and
Runtime image `sha256:c04cf162ee1e1dd88eaef40e823b88e56c9aac6a8341911dda8064095322a4cf`.
Its [metadata-only result](../.cicada-data/native-observer-wiring-20261007/g4-cli162-runtime-20261009a/result.NONAUTH.json)
SHA-256 is `4e3c6e11a7e70f595b8f2d8693e1b907861306a79d297d9a07a764829a4bb6d3`.
On the exact saved synthetic B SID `01a11879-9f9b-7c62-89d0-504635ca7b7b`,
the gate witnessed exactly one real queue submission, killed only the adapter
after `Cmd.Wait` and before ledger finish, retained `INJECTION_UNCERTAIN`, and
refused reinjection. It observed zero new turns and an unchanged two-turn,
12-item history; the isolated Runtime had network egress disabled and the test
used no credentials or provider/model calls.

The first invocation stopped at the initial cold snapshot before the queue
command because it supplied the CLI 0.161 canonical-history receipt hash.
Original DB, WAL and saved-rollout bytes were unchanged. A separate read-only
0.162 app-server baseline queried `thread/read`, `thread/turns/list` and
`thread/queue/list`; it found the same cold SID, two completed turns, 12 items,
an empty queue and a new canonical full-history SHA-256
`d43e63b43b0e2338b60a558ae877dff6b4d283382428f9cec378fee0aa2814fa`. The
single authorized rerun pinned that 0.162 baseline and passed. The initial
preflight failure is retained in the result receipt; no history guard was
relaxed. The final receipt records owned-container and fixture cleanup and the
unchanged six-resident inventory.

## Historical CLI 0.161.0 real-queue checkpoint — narrow PASS

Root's [actual gate receipt](../.cicada-data/native-observer-wiring-20261007/g4-cli161-runtime-20261007e/result.NONAUTH.json) SHA256
`f8e3aa19f08afd660eb392e5fb4623a489f72288203e1f8482eee7bc91a86474`
records PASS / exit 0: gate 5.32 s, Root elapsed 8.440 s, one gate invocation and zero turn starts/models.
Original B remained unchanged with two completed frozen turns, canonical history
SHA256 `b326600e907b5216eb07d44de1c0ca6514eb897a441426b9940d3306bcb0d51d`.
The gate witnessed EXACT_ONE_SUBMISSION, retained INJECTION_UNCERTAIN and refused
original/new reinjection. Two owned containers and the fixture root were absent;
original rollout/history DB/WAL and six residents were unchanged. Only safe
metadata is retained here, not history payloads.

The [build/deterministic receipt](../.cicada-data/native-observer-wiring-20261007/g4-cli161-build-20261007c/receipt.NONAUTH.json)
SHA256 `e90a9607041fadde05ff02b640ea1cef8a5b03b6f210189654f44fd74d16a7df`
records normal 5 / race 5 methods PASS, zero failures/skips; its native gate NOT_RUN
is distinct from the later actual gate. Test source SHA256
`9036edb93849df0f3dde8a1d7c9e9bcedbab9d85aed905462177362ca5321f82`
and binary SHA256 `0a6a5a650caddb848957a8a1810d0f28550548cb34be95f698d22a7dee3ea93a`
are separate from official CLI SHA256
`9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c`
(292,309,256 bytes) and Runtime image
`sha256:e7540d8a8ff83952fe0dc8e46c20446d45566a2f6fb1195a98d0ab6afe216a29`.

The binary was built on dev 5c9c7c3 with only the two exact test-version predicates
dirty, not solely clean HEAD or historical clean 326. Binary size is 39,410,888
bytes; paginated snapshot metadata records 106,496 bytes / two turns / 12 items.
Release-exact official source at commit
`979011409de0a60b52f179721948e65531d26144`,
[physical socket path](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/app-server-transport/src/transport/unix_socket.rs#L76) and [advertised symlink](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/app-server-transport/src/transport/unix_socket.rs#L106), distinguishes the advertised
socket symlink from actual `/tmp/codex-daemon-UID/sha256(canonical-advertised-path)`.
Root shared an owned `ROOT/s` mode 0700 at that protected directory and supplied
the actual canonical 99-byte socket path without symlink traversal. The
[daemon-directory policy](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/uds/src/daemon_directory.rs) fixes the protected directory and owner checks. The schema
command remains `codex app-server generate-json-schema --experimental --out /schema`.
The [paginated-history reader](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/thread-store/src/local/thread_history/read.rs#L116) uses the history database. For genuine paginated B, Root made a consistent private SQLite backup from
independent copies of the original synthetic history DB/WAL; no state5, auth,
configuration, grant or key files were copied and no SID/history was changed.

Earlier [c startup failure](../.cicada-data/native-observer-wiring-20261007/g4-cli161-runtime-20261007c/result.NONAUTH.json)
and [d profile-readiness failure](../.cicada-data/native-observer-wiring-20261007/g4-cli161-runtime-20261007d/result.NONAUTH.json)
remain FAIL with zero gate invocations, not failed executions of the G4 gate.
The [later fixture retirement](../.cicada-data/native-observer-wiring-20261007/root-g4-preparation-fixture-retirement-20261008a.NONAUTH.json)
(SHA256 `1de518254ac14bcda5a701a9b01c45c45022b4e15f263826ccf3a32487a75885`)
removed only the owned c/d copies and retained their reports and original B.
Their original root-retained flags remain historical facts.
The successful fixture used the canonical owned daemon socket and a consistent
independent paginated-history snapshot; no guard or frozen-history requirement
was relaxed. This result covers injected-before-ledger only; remaining G4/G5/V67, paid
Native acceptance and final context are not closed. G2 FAIL / G3 NOT_REACHED,
sandbox BLOCKED and paid image e754 Native NOT_RUN remain. Overall v0.1 is
PARTIAL; Control counts are NOT_INSTRUMENTED.

## Historical CLI 0.161.0 preparation — acceptance NOT_RUN

The current fixture pins official CLI SHA256
`9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c`
(292,309,256 bytes) and Runtime image
`sha256:e7540d8a8ff83952fe0dc8e46c20446d45566a2f6fb1195a98d0ab6afe216a29`.
Root generated 445 schemas once with `codex app-server generate-json-schema
--experimental --out /schema`; the [public schema-only receipt](../.cicada-data/native-observer-wiring-20261007/runtime0161-experimental-schema-20261007c/result.NONAUTH.json)
records exit 0, zero models/Native sessions/credential access and owned-container
absence. This is compatibility evidence, not a G4 acceptance pass.

The experimental schema covers `thread/queue/list` with `threadId` and `limit`,
returning `data`/`nextCursor` and queued submissions with `id`/`input`.
QueueListParams SHA256 is
`b4c889089eee8a0f785ff85e0128a4d3f347353870fa848221096a472223773b`;
QueueListResponse SHA256 is
`be4e0bfa6fc776101f96582543605d2eff6186309a08903203512b99c5005926`.
Existing metadata-only `thread/read`, explicit ascending/full `thread/turns/list`,
experimental initialization and turn-start rejection match these schemas;
response Turn.itemsView still defaults to full when omitted. The earlier
315-schema nonexperimental inventory did not cover queue requests and cannot
establish their absence. Historical 0.160.0 schema and fixture results below
retain their original scope. Deterministic and real zero-queue validation of this
new pin remain NOT_RUN; cold original B, history, uncertainty and no-reinjection
guards are unchanged.

## Native fixture supplied by its owner

Run only after other native ownership work has finished. Supply a separate,
independent byte copy of a genuinely saved historical **synthetic B** profile.
Preserve the source B profile unchanged. Original A, user/resident profiles,
production TUI, shared development Hub and their credentials are outside this
gate. The receipt's profile scope is an owner attestation requiring independent
copy/source evidence; this test does not certify the source profile's provenance.

The owner supplies a private JSON receipt and its independently checked SHA-256:

```json
{
  "schema": "cicada.synthetic-native-queue-crash.v1",
  "root": "/tmp/cicada-native-queue-crash-UNIQUE",
  "cli": "/absolute/canonical/path/to/official/codex",
  "cli_sha256": "OWNER_VERIFIED_64_LOWERCASE_HEX",
  "runtime_image": "sha256:OWNER_VERIFIED_64_LOWERCASE_HEX",
  "socket": "/tmp/cicada-native-queue-crash-UNIQUE/server.sock",
  "codex_home": "/tmp/cicada-native-queue-crash-UNIQUE/codex-home",
  "sid": "ACTUAL_SYNTHETIC_NATIVE_UUID",
  "synthetic": true,
  "credentials_absent": true,
  "provider_egress_disabled": true,
  "max_provider_posts": 0,
  "profile_scope": "independent-copy-historical-synthetic-b",
  "baseline_turn_count": 2,
  "baseline_history_sha256": "OWNER_VERIFIED_CANONICAL_FULL_HISTORY_64_HEX"
}
```

These are placeholders, not usable fixture values. The receipt must be one JSON
object of at most 8192 bytes, with no unknown fields. Paths must be canonical,
absolute, at most 512 bytes and contain no symlink traversal. The Unix socket
path is at most 100 bytes. Socket and CODEX_HOME must be inside the private
`cicada-native-queue-crash-*` root (no group/other permission). CLI must be an
executable regular file of at most 512 MiB, with the receipt's exact hash. The
named test-only `realQueueMaxCLIBytes` cap rejects oversized files before hashing.
The independently measured official 0.160.0 CLI in Runtime image
`sha256:d6004eb3f669966f7a30796333b8a4b1635b30ded40cc7d186e19c42c196818f`
is 289,101,384 bytes, which exceeds the original 256 MiB cap. Exact CLI digest and
version checks still apply. The current source gate requires exact CLI and
app-server version 0.162.1; receipts in this section retain their original
0.161.0 attribution.

The socket must expose the already-running official app-server's WebSocket
protocol directly. The fixture's actual synthetic B Thread must be cold
(`notLoaded`) with an empty native queue and an explicitly pinned historical
turn count from zero through four. The example's count is illustrative, not a
measured receipt. Every historical turn must be completed, unique, and contain
its full persisted items without an error. Its genuine saved rollout metadata
must identify the same SID and the test process's current working directory.
Do not manufacture a rollout record or alter its cwd/history. For a historical
profile whose saved cwd is `/workspace`, run the reviewed compiled test binary
from `/workspace`; `go test` normally uses `cicada-go/cmd/cicada` instead.

The gate requests `thread/turns/list` with `limit=8`, `sortDirection=asc`,
`itemsView=full` and requires a complete unpaginated result. The explicit
`baseline_turn_count` must be present, non-null and at most four. Canonical
history is the entire `data` array, preserving its turn/item array order and
every returned field: decode with Go `json.Decoder.UseNumber`, then
`json.Marshal` (object keys sorted, number tokens retained, default HTML and
U+2028/U+2029 escaping, no indentation or trailing newline). Its SHA-256 must
equal `baseline_history_sha256` on initial, pre-kill and final snapshots.
Pagination cursors are excluded from the hash. Unknown/new history fields
remain included rather than silently dropped. Full history is never printed.

These checks follow the existing official 0.160.0 experimental generated schema
in `CICADA_real_codex_prep_20261002/cli/schema/experimental/v2`: params SHA-256
`2a8b93d7d4437cc25e16a1dde16d8db3c338d39e16c5eece2a56e943a21577d7`,
response SHA-256
`8db83d38553204a223cf349680c59b0cc674ba95a4637e1995bfeabd73c80219`.
`Turn` requires `id`, `items`, `status`; `itemsView` defaults to `full` when
omitted. Response requires `data`, with optional/null terminal `nextCursor`.

Provider credentials must be absent from that Runtime, including persisted
authentication and provider config, and provider egress must be disabled. The
test strips inherited credentials from the adapter child's environment. It
cannot inspect the already-running Runtime's container/image/network; image
identity and zero provider egress are explicitly **owner-attested** receipt
properties, requiring separate owner evidence. The test measures zero **new**
observed turn starts and an unchanged historical baseline; it does not equate
turn count with HTTP POST count. Maximum authorized new model turns and provider
POSTs are both zero. All unknown server requests and native errors fail closed.

## Invocation and assertions

From `cicada-go`, with the owner-supplied fixture available in this execution
namespace:

```sh
CICADA_NATIVE_QUEUE_CRASH_ACCEPTANCE=1 \
CICADA_NATIVE_QUEUE_CRASH_FIXTURE=/absolute/path/to/private-fixture.json \
CICADA_NATIVE_QUEUE_CRASH_FIXTURE_SHA256=OWNER_CHECKED_RECEIPT_SHA256 \
go test -p 2 -mod=readonly ./cmd/cicada \
  -run '^TestMachineNativeRealQueueCrashAcceptance$' -count=1 -timeout=120s -v
```

Alternatively, the owner can use a test executable compiled from the reviewed
source and run its exact selector in that namespace. Record executable hash,
source fingerprint, Go toolchain, CLI hash/version, Runtime image digest and
owner receipt digest independently. This new test source does not relabel the
previous clean 4804411 package or any historical native evidence.

The test connects read-only observation first: experimental `initialize`,
`initialized`, exact `thread/read`, `thread/turns/list`, `thread/queue/list`.
It then admits one visibly synthetic sealed delivery through the real Hub/Node
fixture and invokes the actual official CLI with literal argv:

```text
codex queue --remote unix://EXACT_OWNED_SOCKET --thread EXACT_SID --message LITERAL_PRODUCTION_PROMPT
```

No shell interprets the message. The per-call private command dependency records
only SID and the literal prompt hash; full prompt, CLI streams, history, tokens
and provider data are not printed. No public fault flag, new dependency, wire
change or production configuration is added.

The private existing `queue_wait_succeeded` observer blocks the adapter child
after actual CLI `Wait()==nil`, before `FinishNativeOperation`. The parent
requires exactly one queue/list submission matching the dispatch input hash,
unchanged cold SID and frozen full-history baseline, raw writer `INJECTING`, inbox `INJECTING`,
an observed production Guard and only `NODE_RECEIVED` receipts. It then SIGKILLs
only that adapter child, never the app-server or another process.

Production reopen/reconcile must retain the journal and produce inbox/native
`INJECTION_UNCERTAIN`, with only `NODE_RECEIVED → INJECTION_UNCERTAIN` receipts.
Both original and changed remote attempt replay must return the typed uncertain
error without another command preparation/dispatch. Final exact queue identity
and input hash must equal the pre-kill witness, with zero new observed turns and
the exact initial historical count/hash. Missing, duplicate, paginated, conflicting or unavailable queue evidence
fails the gate; it does not authorize a retry or reconcile uncertainty to success.

Successful typed scope is `real_queue_crash_gate=PASS`,
`queue_witness=EXACT_ONE_SUBMISSION`, `adapter_recovery=INJECTION_UNCERTAIN`,
`reinjection=REFUSED_ORIGINAL_AND_NEW_ATTEMPT`, `actual_turn_started=0`, and
`baseline_history=UNCHANGED` with the independently pinned historical count.
Provider egress/image identity remain owner-attested. Native busy delivery,
human foreground draft protection, model consumption, original-A context
continuity, Android, physical devices and public HTTPS remain **NOT_RUN** for
this gate. A queue receipt is not native idempotency or exactly-once execution.

## Local deterministic validation

The fixture decoder and queue witness tests reject wrong receipt hashes, SID,
input hashes, unsafe paths, provider policy and duplicate queue entries. The
incomplete opt-in subprocess must fail before any native fixture access. A
separately labeled synthetic plumbing test checks the actual-SID substitution
through the existing Join/Guard/context fixture and preflight rejection; its
manufactured session record is never accepted as native proof.

Focused selectors are:

```sh
go test -p 2 -mod=readonly ./cmd/cicada \
  -run '^(TestMachineNativeRealQueueRequiresExactCLI0162|TestMachineNativeRealQueueCrash(FixtureValidation|FrozenHistory|OptInRefusesIncompleteFixture|OversizedCLI|RelayFixtureScope))$' \
  -count=1 -timeout=120s -v
go test -race -p 2 -mod=readonly ./cmd/cicada \
  -run '^(TestMachineNativeRealQueueRequiresExactCLI0162|TestMachineNativeRealQueueCrash(FixtureValidation|FrozenHistory|OptInRefusesIncompleteFixture|OversizedCLI|RelayFixtureScope))$' \
  -count=1 -timeout=120s -v
```

These deterministic results must be recorded separately from the opt-in native
gate. The helper selector's no-op return in a normal test run is not native
acceptance. Local validation uses the existing pinned Go 1.27.1 bookworm image,
network disabled, existing module cache, two CPUs and a 3 GiB memory limit.

2026-10-03 original local checkpoint: all three deterministic checks passed in both
focused and race runs. The helper's normal no-op selector returned separately;
the actual native acceptance selector skipped. The native Runtime was **NOT_RUN**,
with no provider/model execution. The test source SHA-256 was
`bd4ab408e6f47d31511822739a7c3d1e1759f0625adcdb1750e4418252629d69`.
The ignored local receipt and exact argv/logs are in
`.cicada-data/native-queue-crash-checkpoint/receipt.json`, `focused.jsonl`, and
`race.jsonl`. No full default Go rerun was performed and historical clean-480
results/artifacts retain their original attribution.

The 512 MiB cap update adds a sparse executable of `realQueueMaxCLIBytes + 1`
and an inert Unix listener solely for deterministic negative plumbing. Its
specific size-fence error must occur before the digest check. These files are
never executed and provide no native evidence. Updated focused/race evidence
is recorded separately in
`.cicada-data/native-queue-crash-checkpoint/cli-cap512/receipt.json`.
All four deterministic checks passed normally and under race for test source
SHA-256 `f30b029f50288b45713247f88eb38519970641b86bbc4ab27d42bb051bdb15cb`.
The actual native gate skipped again; no Runtime/model/provider execution or
full default Go rerun occurred.

## Separate zero-turn fixture limitation

The prior official 0.160.0 fixture preparation reported **NOT_READY**: a genuine
`thread/start` SID with no turns created no saved rollout. After the same-profile
owned restart, `thread/read` and turns/list returned `-32600` (not loaded),
queue/list returned `-32603` (no rollout), thread/list was empty and actual
rollout count was zero. The preserved owner record is
`.cicada-data/native-queue-crash-fixture/preparation-limitation-receipt.json`.
Zero historical turns were an artificial test constraint, not a CICADA product
requirement. This adaptation accepts a pinned saved historical synthetic B
baseline; it does not turn the earlier limitation into a product/native PASS.
That 0.160.0 attempt remained **NOT_RUN** pending authorization and a ready
independent B-copy fixture; the current 0.162.1 result at the top covers only its separately scoped
injected-before-ledger queue-crash case.

The frozen-baseline adaptation's local focused and race checks both passed all
five deterministic checks for test source SHA-256
`a10e1571a4b850a174949354201b51f34498aff2c1c318013b16b64c3f39813b`.
The native acceptance selector skipped; no Runtime, queue, model/provider or
full-suite run occurred. New evidence is kept separately in
`.cicada-data/native-queue-crash-checkpoint/frozen-b-baseline/receipt.json`.
The actual independent B-copy full-history count/hash remains an owner-supplied
readiness requirement, not a reconstructed or fabricated receipt.


## 2026-10-04 actual clean-326 injected-before-ledger gate — scoped PASS

The opt-in gate later ran once against the clean committed 326ecb9d2f963a16f6a7248db9d71a1eeb4718d9 executable, built from an exact 900-input committed-tree inventory. The test binary SHA-256 is b8f571316247ff0a2607b705ca37679e060e01bce60a12ac42f3a501ccae6474. The exact selector exited 0 with TestMachineNativeRealQueueCrashAcceptance passing in 4.91 seconds; total elapsed was 14.54 seconds.

The actual redacted [gate result](../.cicada-data/native-queue-crash-fixture/real-gate-nonauth-20261004/result.json) is 19,602 bytes, SHA-256 729d4f1a9bae53edf3cf6dce29b00f87e197255dad349142830db193d973b60e. The independent post-gate Core review is 19,368 bytes, SHA-256 cbe4d478214e3fd89f00131e2cfbac7b83b3e6cecd2e8e4b355ab58e52119bc7; it verified the exact clean-326 input inventory and independently confirmed that both exact owned CIDs/PIDs and all three temporary paths are absent.

The bounded witness was one queue submission, adapter recovery INJECTION_UNCERTAIN, reinjection of both the original and new attempt refused, zero actual turns, and the two-turn synthetic-B baseline history unchanged. The fixture used an independent copy of historical synthetic B, with credentials absent and provider egress disabled. Provider POSTs are owner-attested zero-egress with network disabled; the independent reviewer did not measure packet-level HTTP POSTs.

This proves the tested injected-before-ledger recovery/refusal behavior for that pinned clean-326 binary and fixture. It does not prove exactly-once execution, model consumption, safe retry, original-A context continuity, G1, busy delivery, foreground-input protection, the current dirty full-Go source, Android, physical-device or public-HTTPS behavior. The older NOT_RUN statements above accurately describe their earlier runs; this later evidence supersedes only the actual-gate pending state, not those other limits.
