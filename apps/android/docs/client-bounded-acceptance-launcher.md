# Bounded Android acceptance launcher

## Purpose and current result

The launcher prepares the fixed offline Android environment, reports its actual
readiness, and waits for one independently authorized business plan in the same
process. After the carrier reports READY, it immediately verifies the carrier,
installed artifacts and running Android environment before starting the declared
flow. No agent poll or model turn is required between those steps.

This checkpoint is an **offline harness change**. It does not replace the F9
failure or establish encrypted enrollment, bilateral Link consent, a Target
React Native Alert, a native Worker, physical-device or public HTTPS acceptance.
Those new runtime checks are **NOT_RUN**. The original F9 evidence is retained in
the [fixed delivery record](client-hub-v1.6.4-dd81575-validation.md).

## Target and artifact provenance

The Root-approved bootstrap plan supplies the complete immutable Core target.
Core source, Hub/interop images, archive and source fingerprint are independently
pinned there; a business ticket cannot change them. Scope must reproduce those
same six values. The protocol, wire, schema and catalog below remain fixed.
Client source, product checkpoint, APKs and emulator have their own provenance.

The Core values below describe the independently reviewed clean **0213538
delivery**. Its [provenance record](client-hub-v1.6.4-0213538-provenance.md)
covers archive, immutable Git inputs and image metadata only. Encrypted Android
runtime remains **NOT_RUN**. The dd81575 images and F9 outcome retain their
historical attribution.

| Input | Reference delivery / invariant |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / schema / operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Contract archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Core source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Source dirty | `false` |
| Hub image | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interop image | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Emulator image | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| App APK SHA-256 | `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` |
| Test APK SHA-256 | `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6` |
| Product checkpoint | `508ca333c8ae90d27a8191ac828a7be16b71c7b3` |
| Docker data root | `/gpu1-share/data/docker-root` |
| Client cache | `/gpu1-share/data/cicada-client` |

The launcher commit and source hashes are separately recorded in its delivery
receipt. They must not be substituted for the product/APK checkpoint above.
There is no APK rebuild in this change.

Core's frozen `delivery-manifest.json` has SHA-256
`e922f5634ad037b93e6fdb117261fea153b05fd2c060521d2cc265cb6c8feeb5`.
Its `client-bootstrap-target.json` has SHA-256
`6183c8b1d77908450df9251ecd5d7fc5992ebb0afce0d57ee4d1586544e11ed2`.
Read its `bootstrap_target` object and apply the explicit local mapping:
`revision→core_commit`, `hub_image→hub_image_id`,
`interop_image→interop_image_id`,
`contract_package_sha256→contract_archive_sha256`; catalog and fingerprint
retain their names. Add the fixed protocol/wire/schema/count/clean fields.
Use byte-identical public metadata copies in the Client cache for
`source_root_plan_refs`; Root must approve their original hashes.

## Entry points and command plan

The supervisor is `scripts/interop/v164-bounded-acceptance.py`. Its BOOT helper
is `scripts/interop/v164-acceptance-boot.py`; its read-only hot helper is
`scripts/interop/v164-acceptance-hot.py`. Existing Android selectors and proof
validation remain in their existing implementation.

The following are command templates, not current execution authorization:

```bash
python3 scripts/interop/v164-bounded-acceptance.py \
  --bootstrap-plan "$BOOTSTRAP_PLAN" \
  --bootstrap-plan-sha256 "$ROOT_BOOTSTRAP_SHA256" --check-plan

python3 scripts/interop/v164-bounded-acceptance.py \
  --bootstrap-plan "$BOOTSTRAP_PLAN" \
  --bootstrap-plan-sha256 "$ROOT_BOOTSTRAP_SHA256" --execute
```

The first command only checks inputs. The second requires a separate Root
approval for one fresh BOOT. The bootstrap plan must bind the clean full Client
commit, complete approved immutable inputs, all declared source files and their independently
approved hashes. Its original idle deadline is an exact UTC second, more than
90 seconds and at most 1,200 seconds ahead when validated. The Android run and
launcher evidence roots must be fresh, distinct private Client-cache locations.
The Android run ID must match
`v16-deterministic-v164-f6-[A-Za-z0-9_-]{1,80}`.

Prepare the helper, external Owner actor and source-derived Client/Core adapters
before BOOT. The old fixture-09 scripts contain fixed paths and hashes; they
cannot be reused for a fresh run. Prepare fresh adapters from the declared
source, approve their exact bytes and freeze them before issuing Root GO.

1. Root authorizes a cold BOOT plan. The supervisor starts only its owned,
   network-none emulator, installs the frozen APKs and reads four properties.
2. The supervisor verifies the canonical BOOT receipt and performs the existing
   read-only Android bootstrap preflight, then publishes `READY` on stdout.
3. Root permits Core to create the fresh fixed-image fixture. Core supplies the
   actual public references, custody boundary, Scope and one Root GO.
4. Root supplies one combined business-plan ticket on the still-open stdin.
   The supervisor validates it, prepares and binds the declared public inputs,
   starts the carrier, verifies actual hot readiness and runs the flow once.
5. On completion, failure, cancellation or deadline, cleanup proceeds in order:
   flow, carrier, owned emulator. Core remains responsible for its own resources.

No acknowledgment is emitted during BOOT, prepare, bind, preflight, carrier or
an active flow. Core's coordinator may send its terminal acknowledgment only
after actual completion or cancellation. An early `nonce_used` acknowledgment
would trigger Core cleanup and invalidate the lane.

## Frozen handoff formats

All plan JSON is bounded, duplicate-free and must have the exact top-level
fields below. SHA-256 pins refer to the original file bytes. Inputs must be
regular files without symlink aliases or extra hard links; private inputs use
mode `0600`. Public delivery/source-plan metadata also permits `0644`. The
nine topology references preserve the existing fixture modes: setup `0644`,
helper binary `0755`, runner `0700`, all others `0600`, bounded at 32 MiB each.
Large APKs and reference binaries are hashed as streams. No bearer, private key
or device code is a plan argument.

### Bootstrap plan

Schema: `cicada.client-v164-bounded-bootstrap-plan.v1`.

| Field | Meaning |
|---|---|
| `schema`, `approval_id`, `client_commit` | Exact schema, Root BOOT approval label and clean full Client commit |
| `target` | Root-approved Core/contract/source/Hub/interop/catalog tuple; keys are `core_commit`, `contract_revision`, `wire_version`, `schema_version`, `operation_count`, `contract_archive_sha256`, `source_fingerprint`, `source_dirty`, `hub_image_id`, `interop_image_id`, `catalog_sha256`. Source/image/archive pins require full lowercase hashes and `source_dirty:false`; protocol/wire/schema/count/catalog must match the values above |
| `docker_root`, `cache_root` | Exact host layout above |
| `android` | `run_id`, `evidence_root`, `image_id`, `network:"none"`, and `app` / `test`, each `{path,sha256}` |
| `source_refs` | Named `{path,sha256,role}` references; required roles `boot`, `runtime_consumer`, `stop_runner` |
| `launcher_evidence_root` | Separate fresh private evidence directory |
| `idle_deadline` | Original fixed UTC cutoff; cannot be extended |
| `timeouts` | Positive integer seconds: `boot_seconds≤90`, `command_seconds≤180`, `carrier_ready_seconds≤60`, `cleanup_seconds≤20` |

The BOOT helper writes `launcher-boot.redacted.json` using compact sorted-key
ASCII JSON with one trailing newline. Its exact fields are `schema`, `result`,
`run_id`, `evidence_root`, `container`, `container_id`, `image_id`, `network`,
`app_sha256`, `test_sha256`, `runtime_properties`, `ready_observed_at_utc`,
`idle_deadline`, `supervisor_pid`, `cold_boot_elapsed_seconds`, `supervision`,
`business`. Required values include `result:"BOOT_READY"`,
`supervision:"LAUNCHER_ONLY"`, `business:"NOT_RUN"`, the actual full container
ID, actual parent supervisor PID and the original deadline. Runtime properties
are `api_level:"35"`, `android_release:"15"`, `abi:"x86_64"`, `emulator:"1"`.

Only after both BOOT and read-only preflight pass does the supervisor publish:

```json
{"event":"READY","run_id":"<fresh Android run>","container_id":"<actual full ID>","boot_receipt_sha256":"<original receipt SHA>","bootstrap_plan_sha256":"<Root-pinned plan SHA>","launcher_pid":12345,"idle_deadline":"<original UTC cutoff>"}
```

The sample PID and angle-bracket values are inert format examples.

Let `E` be the Android evidence root and `L` the separate launcher evidence
root in the approved plan. BOOT's original canonical record is
`E/launcher-boot.redacted.json`. The runtime record is
`E/android-runtime.redacted.json`, with the existing six-field F9 shape
(`schema`, `image_id` and the four properties). The read-only Android readiness
result is the original `L/02-bootstrap-preflight.stdout.private` JSON line:
`result`, `run_id`, `container_id`, `image_id`, `network`, `runtime_properties`,
`hub:"NOT_CHECKED"`, `root_delivery:"NOT_CHECKED"`. The command journal binds
its hash and actual command/exit. Core readiness must be established separately.
The controller captures the supervisor's stdout READY event on the same pipe;
there is no independent file-release watcher.

### One stdin ticket and business plan

Root writes one UTF-8 JSON line, at most 4,096 bytes, to this process's stdin:

```json
{"plan_path":"/gpu1-share/data/cicada-client/<fresh>/business.private.json","plan_sha256":"<independently approved SHA-256>"}
```

The trusted controller must retain the pipe so it can deliver this line after
actual READY. EOF before a ticket cancels waiting. A second frame is rejected,
including a frame arriving during execution. There is no polling directory,
retry ticket or model-dependent handoff. The ticket's hash binds the combined
plan; delivery of a ticket does not supply or replace Root authorization.

Business schema: `cicada.client-v164-bounded-business-plan.v1`.

| Required fields | Meaning |
|---|---|
| `schema`, `bootstrap_plan_sha256`, `container_id`, `boot_receipt_sha256` | Bind this observed BOOT and exact bootstrap plan |
| `fixture_root`, `fixture_label`, `scope_token` | Fresh exact Core fixture identity; F9 reuse is rejected |
| `scope`, `go`, `delivery_pins`, `delivery_metadata` | Each `{path,sha256}` with independently supplied original-byte pins |
| `source_root_plan_refs` | Nonempty list of separately pinned Root source-plan files |
| `topology_refs` | Nine named public references, each `{path,sha256}`: `client_setup`, `custody_manifest`, `fixture_public`, `helper_binary`, `helper_provenance`, `helper_source`, `hub_ready`, `reference_manifest`, `runner` |
| `source_refs` | Named `{path,sha256,role}` references; required business roles `bind`, `carrier`, `hot_preflight`, `flow`; all invoked source is declared |
| `carrier_tag` | Fresh bounded carrier evidence tag |
| `declared_flow_order` | Exactly `source-device`, `target-device`, `source-key`, `source-none`, `target-key-rn`, `target-none` |
| `business_stop_at_utc` | Fixed stop no later than original idle, Scope or GO expiry |
| `commands` | `prepare` list (at most eight), `bind`, `carrier`, `hot_preflight`, `flow` |

Each command has exactly `source_ref`, `args`, `timeout_seconds`. The supervisor
invokes the pinned Python source with an argument array; it does not evaluate a
shell string. The single `flow` command is the approved existing six-phase
driver. It must record each phase's command, UTC start/end, duration and exit;
a supervisor-level zero exit alone is not business acceptance.

The hot-helper argument array is:

```json
["--evidence-root","{EVIDENCE_ROOT}","--run-id","{ANDROID_RUN_ID}","--tag","{CARRIER_TAG}","--carrier-host-pid","{CARRIER_HOST_PID}","--carrier-pid","{CARRIER_PID}","--consumer-script","{RUNTIME_CONSUMER_PATH}","--consumer-sha256","{RUNTIME_CONSUMER_SHA256}","--delivery-pins","{DELIVERY_PINS}","--delivery-pins-sha256","{DELIVERY_PINS_SHA256}","--delivery-metadata","{DELIVERY_METADATA}","--delivery-metadata-sha256","{DELIVERY_METADATA_SHA256}","--fixture-root","{FIXTURE_ROOT}"]
```

Carrier PIDs come only from actual READY. Runtime consumer path/hash come from
the approved bootstrap source reference. `{READINESS_SHA256}` refers to the
separate `emulator-readiness.redacted.json`, never the BOOT receipt.

The existing Scope schema is `cicada.f8.m5-owner-actor-scope.v1`. Its fixed map
must bind all six revision/image/package/catalog/fingerprint values from the
Root-approved bootstrap target. It must also bind `max_signature_requests:6`,
the actual `ready` and `owned_manifest` references, `key_manifest_digest` and
the Link `contract_digest`. `Scope.ready` pins the aggregate
`fixture/public/READY.json`. This is distinct from the `hub_ready` member of
its nine public references. The supervisor binds all nine projected path/SHA
pairs and the aggregate's setup, Hub-ready, reference-manifest and owned-manifest
digests before releasing commands.
The Root GO schema is `cicada.f8.owner-actor-root-go.v1`, with exactly `schema`,
`scope_token`, `scope_path`, `scope_sha256`, `approval_id`, `root_thread_id`,
`approved`, `approved_at`, `expires_at`, `max_requests`. It requires actual Root
identity, `approved:true`, `max_requests:6`, a fresh token and the exact Scope
bytes. Core's owned-manifest and four public-reference digests must also be
present in the delivered Scope and verified artifact set. The immutable delivery
validator remains responsible for their detailed consistency checks.

### Immediate hot preflight

The carrier's actual stdout READY binds its owned host PID and Docker-exec PID.
The supervisor passes those observed PIDs to the pinned hot helper, rechecks that
its carrier child is running, and validates the private marker and zero-activity
JSONL. The helper performs the existing artifact and actual Android preflight,
then rereads the carrier evidence. Any changed identity, transaction or failure
before the flow rejects release.

The hot result has exactly `result:"PASS"`, `container_id`, `host_pid`,
`carrier_pid`, `tag`, `fault:"none"`, `allowed_route_count:5`,
`transaction_count:0`, `marker_sha256`, `log_sha256`,
`android_preflight:"ANDROID_BOOTSTRAP_CHECK_PASS"`.
Allowed routes remain only identity, public capabilities, enrollment, encrypted
RPC and original-packet recovery. It grants no fault-injection authority.
The actual hot output path and hash are recorded under label `hot_preflight`
in `L/command-journal.private.jsonl`; its sequence depends on the number of
declared preparation commands. Do not infer it from an old F9 filename.

## Failure handling and evidence

The original idle cutoff is captured on a monotonic clock. Scope/GO may only
shorten it. Signals, late extra tickets, child failure and timeouts stop the
flow without retries. Cleanup has its own bounded resource-removal budget; it
never permits a later signature or business request. A partial BOOT is cleaned
using the owned driver marker even if no final BOOT receipt was returned.

The supervisor records actual argument arrays, start/end UTC, duration, timeout,
return code and output hashes. Business content is not written into the
supervisor's public receipt. If the flow started and its outcome is unknown,
pending signed packets and operation state must remain available to the existing
recovery fence. Cleanup cannot convert uncertainty into success.

`OUTCOME_UNKNOWN_PRESERVE_PENDING` is a stop/recovery requirement, not a claim
that Android recovery passed. The supervisor neither clears a Client fence nor
creates a replacement operation. It does not export Android private keys or
application data. Removal of the disposable emulator ends that test device;
future live evidence must record the original pending packet identity/counter
and authoritative reconciliation before claiming recovery acceptance.

Offline evidence is kept outside Git at
`/gpu1-share/data/cicada-client/v164-bounded-launcher-offline-20261003/`.
The cold APK input hash check took **0.300393 seconds**, exit `0`; filesystem
cache state was uncontrolled. This measures input checking only, not emulator
BOOT, cold storage or a live signing window. Its receipt
`cold-input-check.redacted.json` has SHA-256
`a2d565a2f139cf776a201054f9416bf944d14c2acfd8f9c488982bc731dcf095`.
New BOOT duration and hot duration are **NOT_RUN** until a separately approved
fresh execution supplies actual receipts.

The final delivery receipt binds the launcher Client commit, all new source
hashes, the narrow Docker test command and exit, and the unchanged APK pair.
No fixture, enrollment, Owner signature or business RPC is created by the
offline tests. Core must first freeze fresh adapters and supply a separate
Root BOOT approval, then the fresh exact delivery and one business GO.

## Completed offline validation

Actual command:

```bash
docker run --rm --network none --user 1000:1000 \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --volume /home/zyf/CICADA_CLIENT:/workspace:ro \
  --workdir /workspace/scripts/interop \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest -v test_v164_acceptance_boot test_v164_bounded_acceptance
```

Final result: **PASS**, 17 tests, exit `0`, 0.212 seconds of synthetic test
execution. The five recorded attempt exits are `1, 1, 0, 0, 0`; the first two
failed on draft test-fixture/API mismatches. Their original output remains
retained. The last run includes the corrected distinct aggregate/Hub READY
binding and does not inherit the earlier source's result.

Coverage includes BOOT shape/runtime-property/readiness tampering; fixed APK
checks; exact source/Scope/GO and deadline bounds; nine reference mode/size/hash
checks; wrong carrier identity and unexpected activity; second-ticket rejection;
child cancellation/timeout; partial BOOT cleanup; one flow and ordered
carrier/emulator cleanup without ACK or retry. Child processes, Docker and
Android inside the test cases are mocked. Only the enclosing test container
runs. This is **PASS for synthetic harness regression**; live entry execution
and business results remain **NOT_RUN**.

Receipt: `bounded-launcher-tests.private.json` under the evidence directory
above, mode `0600`, SHA-256
`230d3b0048a5f5d55a004fd79c4532accd4e891f840d74abd75c5b041039b2e7`.

| Frozen source | SHA-256 |
|---|---|
| `v164-bounded-acceptance.py` | `e651f1a75a3098414f5d50a640df9df6e80b80a3367c915e8b2d09e27acf1678` |
| `v164-acceptance-boot.py` | `84b40ceb595d583b3c187b66844ea89105b56001b1dd303fd7db2e506423fa50` |
| `v164-acceptance-hot.py` | `e89482cf0fa8f6678f2a18f159fe8a71a350ccecf54584ba6f9bb90fcf870ccc` |
| `test_v164_acceptance_boot.py` | `91d8a6dd42017fb72835a3a2778e1be79c652b7f6e73ef6bd1838dc05ba19b91` |
| `test_v164_bounded_acceptance.py` | `89458b8997f04b44ec828e82916200678112d01f9446ccd85d5f1f874d274b59` |
