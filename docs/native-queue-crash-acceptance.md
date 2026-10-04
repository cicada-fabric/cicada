# Opt-in real native queue crash acceptance

This test targets the real-queue evidence gap for CICADA.md §16.5. It uses the
production same-Group Guard, inbox, relay journal, physical writer, injection
intent, outcome and recovery path. The Hub, enrollment and grants are disposable
synthetic Go fixtures. The native queue process and its queue witness must come
from the owner's disposable official Codex CLI/app-server 0.160.0 fixture.

The test does not start Docker, a Runtime, a Thread, resume, a model turn or a
provider request. It does not accept a synthetic queue helper as native evidence.
Without explicit opt-in, native acceptance is **SKIP / NOT_RUN**. Enabling the
gate with an incomplete or invalid fixture is a failure before native dispatch.

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
version checks still apply. CLI
version and initialized app-server userAgent must report 0.160.0.

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
  -run '^TestMachineNativeRealQueueCrash' -count=1 -timeout=120s -v
go test -race -p 2 -mod=readonly ./cmd/cicada \
  -run '^TestMachineNativeRealQueueCrash(FixtureValidation|FrozenHistory|OptInRefusesIncompleteFixture|OversizedCLI|RelayFixtureScope)$' \
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
Actual native acceptance remains **NOT_RUN** pending Root authorization and a
ready independent B-copy fixture.

The frozen-baseline adaptation's local focused and race checks both passed all
five deterministic checks for test source SHA-256
`a10e1571a4b850a174949354201b51f34498aff2c1c318013b16b64c3f39813b`.
The native acceptance selector skipped; no Runtime, queue, model/provider or
full-suite run occurred. New evidence is kept separately in
`.cicada-data/native-queue-crash-checkpoint/frozen-b-baseline/receipt.json`.
The actual independent B-copy full-history count/hash remains an owner-supplied
readiness requirement, not a reconstructed or fabricated receipt.
