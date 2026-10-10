# Bounded Android Link recovery loop

## Final consumer freeze: original 82-request flow

Date: 2026-10-10. The final host consumer pins the actual four Core Parent
artifacts below, rather than the earlier three-file preparation. This is a
**PASS for offline consumer compatibility only**. Root's latest delivered
instruction explicitly revokes SOURCE-only and selects the original 82-request
flow: each case exports and enrolls the real TARGET Android device first,
then creates, enrolls and activates SOURCE. SOURCE must remain active from
review/signing through original capture, recovery and finish. No profile
reactivation or return switch is performed. Eight cases create sixteen fresh
profiles plus the initial default, within the fixed APK's limit of 32.

The read-only ruling is `ROOT-REVIEWED-FINAL-JOINT-RULING.NONAUTH.md`, SHA-256
`dee42017fa44371b24ecb53a6d640861de43a2957c97e264d5b7b962f53bf706`.
The four exact existing TARGET/SOURCE export/enrollment selectors are preserved;
their presence in the immutable APK does not establish execution. The separate
TARGET Go operator produces only the independently attributed encrypted
KEY-two/NONE-four reconciliation. Its device, counters and signatures are
actual Go evidence, not Android enrollment. Only SOURCE Link proof is tested,
and TARGET Android registration cannot imply TARGET Link approval or bilateral
acceptance. No Go-target preparation DTO, helper or compiler is added.

The prior SOURCE-only diagnosis is superseded. Its actual blocked observations
and receipts remain historical evidence in the preparation directory; they do
not describe this selected flow. Online remains **HOLD** until Root supplies
the reviewed config/template, actual owned paths and one separately issued
finite Master GO. No Android, Hub, native Runtime or model has been started.

### Independently checked consumer inputs

All four files are under the frozen Core delivery's `joint-preparation/`
directory. They must be regular, canonical, current-user-owned, single-link,
bounded mode-0600 files. The Client hashes and parses public metadata only;
it does not execute Parent, adapter or helper code.

| Artifact | SHA-256 |
|---|---|
| `joint-parent.py` | `479adcd3edad8c4a540a65e5a2fc858bbf1ef5862c1754e5ecd3339b9c96e794` |
| `joint-adapter-parent-ready.py` | `7dc6eb20d16326fa96c62d412a91e972c3eea19af5b4b37fd18b1d29404d37a4` |
| `JOINT-PARENT-INTERFACE.NONAUTH.md` | `8f7bc4e7d1d1d5ffb0e02e7f9380211cbbd2d0100a6b4ea577b79be8bb82f570` |
| `ADAPTER-PARENT-FREEZE.NONAUTH.json` | `6fa1159becf4dcb47b91324c0d25f3bce9ad5cd1cba8fc201320f99cdbe65d39` |

The freeze must retain `PASS_PREPARATION_SCOPE_ONLY`, `online=NOT_GO` and its
exact five-file map, including both historical Core test pins. The nine READY
references and 17-field READY shape remain closed. `fixture.sh` must hash to
the adapter bytes, never the Parent or old adapter. The Android origin is
exactly `http://127.0.0.1:8787`; the owned network-none bridge uses
`127.0.0.1:18944`. Root must install, verify and remove only
`adb reverse tcp:8787 tcp:18944`, after the bridge listener is ready.
Old `10.0.2.2`, hostname aliases and changed ports are refused.

Plan v2 and the twelfth driver pin are existing safeguards, not new interfaces
added during this closure. `core_fixture_root` and `core_case_index` bind each
case to Root's exact `/tmp/cicada-joint-e2a-<opaque>/cases/0..7` tree, eliminating
caller-selected roots and case drift. Root, `cases`, and each selected case
must actually exist with mode 0700, current UID, canonical lexical/real paths
and no symlinks. The existing `v164-frozen-joint-inputs.py` pin binds source
artifacts, Runner, public references and fixed typed-control paths; it prevents
accepting stale F6 metadata as e2a evidence. No additional helper is introduced.

### Final offline results and delivery

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010`.
The tested parent is `6509a1cdf3eb159d7f9a770821b4345f78c36ba9`,
**dirty=true**. Tests bind every relevant Python source hash and verify that
those bytes did not change during execution. The final committed source,
twelve driver hashes, callback export, immutable APK attribution and actual
receipts are bound separately in `final82-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.
The initial files under the earlier `v164-e2a1908-final-consumer-freeze-offline-20261010`
root retain the superseded SOURCE-only diagnosis and earlier consumer byte
attribution. Root must use this final82 delivery. Its last source correction
removes an extra EOF blank line; application/Kotlin/production bytes do not
change. The original staged whitespace-check failure (exit 2) is retained in
the final delivery, followed by the corrected combined-diff check (exit 0).

| Gate | Status | Actual result / evidence |
|---|---|---|
| Docker offline Python suite | PASS | 151 tests, no failures or skips, exit 0; 5.196 seconds unittest / 6.182 seconds wrapper; `python.receipt.redacted.json` |
| Four Core source pins and exact freeze map | PASS | Read-only audit, exit 0; `final82-coordination.receipt.redacted.json` |
| APK pair and Root-endorsed pins unchanged | PASS | Exact-byte audit, exit 0; `final82-coordination.receipt.redacted.json` |
| Offline container absence | PASS | Exact-ID query, exit 0, zero matches; `final82-delivery/offline-plan.receipt.NONAUTH.json` |
| Plan schema and source-pin validation | PASS | Offline full-plan template only, exit 0, 0.838 seconds; `final82-delivery/offline-plan.receipt.NONAUTH.json` |
| Original 82-request mapping | PASS for read-only source compatibility | TARGET-first/SOURCE-last selected explicitly; actual choreography remains NOT_RUN |
| Eight Android recovery cases | NOT_RUN | Online HOLD; no Root GO |
| TARGET Go preparation and mixed reconciliation execution | NOT_RUN | No new runtime execution; historical Core evidence is not this Client acceptance |
| Android readonly reconciliation | NOT_RUN | No applicable selector in the immutable APK |
| Real native Worker, physical Android, public HTTPS | NOT_RUN | Separate acceptance gates |

Executed command, exit 0:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010/run-offline.private.py
```

Its receipt preserves the exact command:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-final-consumer=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

Final input audit and export command, exit 0:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010/freeze-inputs.private.py
```

Offline plan command, exit 0:

```sh
python3 /gpu1-share/data/cicada-client/v164-e2a1908-final82-consumer-offline-20261010/verify-plan.offline.private.py
```

`final82-coordination.receipt.redacted.json` checks the pinned inputs and binds
the unchanged tested source hashes. No original receipt is relabeled and
Android acceptance is not performed.
The final82 delivery includes two distinct templates: the offline full Client
v2 plan and `root-parent-template.private.json`, using Core's existing
`cicada.e2a1908-joint-loop-template.v1` format. The Parent template has seven
top-level fields and `relative_root=cases/<index>`; it deliberately contains
neither `core_fixture_root` nor `core_case_index`. Root derives those values
from actual `BOOT_READY`, records their provenance, and binds the resulting
Client plan into GO without extending the original expiry. A full v2 Client
plan is not substituted for the Parent's pre-BOOT template.

Negative tests exercise stale source bytes/pins/names, changed Parent,
incorrect freeze entries/status, old or Parent Runner hashes, old/aliased
Android origins, arbitrary roots, wrong case indices, lexical aliases,
non-directories, public permissions and symlinked directory levels.
Unchanged callback guards require exactly 25 top-level receipt fields and
eleven NONE policy fields. Candidate origin/hash, candidate 1, current HEAD 0,
original proof correlations and KEY-two/NONE-four ordered encrypted reads
remain mandatory. Android readonly remains `NOT_RUN`; NONE records retain
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`.

All historical failures, receipts and APK attribution below are retained.
No APK/Kotlin, production protocol/image, real key, Hub lifecycle or database
was changed. No push or merge is performed.

## Scope and artifact boundary

This test-only supervisor extends the [clean e2a1908 preparation](client-link-recovery-e2a1908-preparation.md).
It uses the existing immutable application/test APK pair and existing native
selectors. It changes no application feature, production protocol, permission,
Grant policy, sequence allocation or recovery fence. The old dd81575 F6
validator remains unchanged and is not an e2a1908 validator.

Online execution remains **HOLD** until Root supplies the complete fresh
inputs, independently pinned files and one finite GO. Offline mock tests are
not Android, Hub, Native Runtime or business acceptance. APK attribution
remains the actual `9b56832` dirty build/input inventory in the preparation
record; the new host supervisor is attributed separately.

| Immutable APK | SHA-256 |
|---|---|
| Application | `3af7b674c8daaaff4fc4442d13a2b30ad069d5195eed0c90b9b5ebcd754601f9` |
| Instrumentation | `243922e556170dff6dfcbbe6840a80f32f37727a56421ed9016652dc962297ae` |

Root and its Core adapter own Hub lifecycle, keys, external signing,
`FrameAdapter`, transport mapping, carrier snapshots and its private
FAULT_READY FD. The loop owns only its Client CLI subprocess groups and
private Client evidence. It never reads a Hub database, signs a proof,
receives a bearer/private key, exports a pending packet, calls a model or
rebuilds an APK.

## Scheduling and deadlines

Exactly eight cases cover `link.key_grant` and `link.review_policy_grant`
against `response-loss`, `processing`, `uncertain` and `legacy`. The frozen
Core adapter orders the four KEY cases first, then the four NONE cases; only
SOURCE receives the fault. This does not claim sixteen bilateral fault
invocations. Every case has a distinct run, fixture root, Link, both Owners,
Groups, Endpoints and two fresh Android device identities. Android enrolls
TARGET first, then creates and enrolls SOURCE. SOURCE remains active until its
recovery completes. The two actual native enrollment exports must show distinct
profiles and an increasing selection generation. Returning to an old profile
would invalidate its saved generation; no such return is assumed or performed.
These runtime checks are **NOT_RUN** while online execution is on HOLD.

| Budget | Maximum |
|---|---:|
| Root-owned emulator readiness/install | 480 seconds |
| Each case | 360 seconds |
| Direct enrollment, native review and signing handoffs | 120 seconds |
| Opaque activation, original capture and capture export | 75 seconds |
| Matched FAULT_READY, optional owned restart and READY staging | 45 seconds |
| One original recovery, result export and carrier snapshot | 60 seconds |
| Separate participating Owner reconciliation | 60 seconds |
| Android closure and evidence | 240 seconds |
| Entire run | 3600 seconds |

The outer deadline is the earlier of 3600 seconds and the exact Root GO expiry.
The loop reserves 240 seconds before work begins. All case/stage deadlines are
absolute monotonic cutoffs clipped to their parent. Binding and reviewed proof
expiry can shorten a case; neither is extended. Each child execution reserves
two seconds inside its stage deadline for TERM/KILL/reaping. The parent channel
checks the remaining absolute deadline for every receive, so a slow partial
reply does not reset the budget.

These are abort limits, not measured promises that a case will finish. Any
failure stops later cases. An interrupted case is `UNKNOWN`, an explicitly
missing prerequisite is `BLOCKED`, and unstarted cases stay `NOT_RUN`. No
automatic retry, new operation, replacement packet, second recovery or
proof renewal is performed. Original app-private pending/retired state and
failure receipts remain untouched.

## Minimal invocation

All paths below are operator-supplied; examples do not name real identities.
The loop is `scripts/interop/v164-link-recovery-loop.py`; deadline/process
handling is `scripts/interop/v164-recovery-loop-budget.py`.

Offline plan validation, with no child, socket or Android operation:

```sh
python3 scripts/interop/v164-link-recovery-loop.py \
  --plan "$ROOT_PLAN" --plan-sha256 "$ROOT_PLAN_SHA" --validate-plan
```

Runtime invocation, deferred until the separate Root GO:

```sh
python3 scripts/interop/v164-link-recovery-loop.py \
  --plan "$ROOT_PLAN" --plan-sha256 "$ROOT_PLAN_SHA" \
  --root-go "$ROOT_GO" --root-go-sha256 "$ROOT_GO_SHA" \
  --parent-fd "$LOOP_PARENT_FD"
```

Root passes a private inherited Unix stream socket whose peer UID matches the
Client operator. This socket is **separate** from the carrier's control FD.
No child inherits it. The existing carrier control message remains exactly
`kind`, `envelope_b64`, `envelope_sha256`, with `kind=fault-ready`.

The Core parent can implement the same boundary in-process by supplying a
`request(event, case_id, payload, deadline)` object to `RecoveryLoop`. Such an
implementation must enforce that absolute deadline itself; the socket
implementation provides the bounded cross-process variant.

## Closed test coordination formats

These schemas describe host test coordination. They add no Hub API or authority.
Core can map its delivered sidecar/public paths into this boundary without
changing the old strict READY format or native Client contracts.

A `FileRef` has exactly `path` and `sha256`. Inputs are operator-owned,
non-symlink, single-link, bounded mode-0600 JSON/JSONL files under the selected
case root or Client evidence root. Device and review exports contain only
public material. Database, environment, key and secret-directory inputs are
refused. The loop snapshots exact hashed input bytes before invoking the
existing staging CLI, which normalizes some older JSON wrappers.

The plan schema is `cicada.client-v164-recovery-loop-plan.v2`, with exactly:

- `schema`, `batch_id`, `core_fixture_root`, `android_evidence`, `evidence_root`;
- `apk_pins`: a Root-owned FileRef using the existing recovery APK-pin schema;
- `driver_sha256`: all twelve exact Client driver/module files named by `DRIVERS`;
- `cases`: eight objects, each containing `case_id`, `core_case_index`, `run_id`,
  `side=source`, `operation`, `mode`, `fixture_root`.

Root constructs this plan after Core's `BOOT_READY` supplies the actual fresh
`/tmp/cicada-joint-e2a-<opaque>/` root. Case indices are exactly 0–7 and roots
are exactly `<core_fixture_root>/cases/<index>`. Run IDs share the Core run base
and end in `-<index>`. The fixed public interface currently pins the base
`v164-e2a1908-joint-20261010`; a new delivery needs new independently verified
pins. Preparing the Core process remains Root's responsibility and requires its
separate GO.

`android_evidence` belongs to the existing recovery runner and has parent
`v16-deterministic-v164-recovery-<fresh-label>`. `evidence_root` is a separate
fresh mode-0700 directory below `/gpu1-share/data/cicada-client`. Runtime
creates a GO-consumed marker before contacting the parent or spawning a child;
the same plan/evidence location cannot be rerun. Proposed immutable APK-pin
bytes remain mode 0400 in the preparation delivery; Root must supply its own
exact-byte 0600 copy and independently endorse its SHA. Reader permissions
are not relaxed.

GO schema: `cicada.client-v164-recovery-loop-go.v1`. Exact fields are `schema`,
`root_thread_id`, `batch_id`, `plan_sha256`, `approved`, `approval_id`, `issued_at`,
`expires_at`, `outer_seconds=3600`, `case_seconds=360`. Root thread is
`01a0a91b-c2b6-76b2-baf5-95422f4deeef`; `approved` must be true and the UTC lease
must already be valid, no longer than 3600 seconds. Supplying this file is not
permission to run online before Root's separate GO. More than 240 seconds must
remain before GO is consumed. File fields and a matching socket UID do not
authenticate Root approval; the trusted Root parent owns that provenance.

Parent request schema: `cicada.client-v164-recovery-loop-request.v1`. Exact
fields: `schema`, `request_id`, `batch_id`, `case_id`, `event`, `remaining_ms`,
`payload`. One reply is a bounded LF-terminated JSON record with schema
`cicada.client-v164-recovery-loop-reply.v1`, the same correlation fields,
`result=READY|BLOCKED|FAIL`, and `payload`. Duplicate keys, mismatched IDs/events,
extra records, credential fields, EOF and late replies are rejected.

## Parent event mapping

The parent receives only public-file references/hashes and redacted correlation.
It must not send private keys, bearer values, device codes or raw packet/proof
contents through the channel.

| Event | Loop request | Required READY payload / parent action |
|---|---|---|
| `BOOT_READY` | Empty; no case | `ownership` FileRef for the exact owned network-none emulator; `core_fixture_root` equal to the plan |
| `CASE_READY` | `core_control={action:prepare,case:<index>}` | `ready` FileRef at `public/READY.json`; `setups={source:<FileRef>,target:<FileRef>}`; exact `binding`; UTC `valid_until` equal to Core's coordination deadline |
| `SIGN_ENROLLMENT` | Exported `device` FileRef; typed `device` control with side and `manifest_sha256` | `grant` FileRef at `signed-proofs/<side>-device-grant.json`; TARGET first, then SOURCE |
| `LINK_SELECTION` | `device` and encrypted-capabilities `enrollment` receipt FileRefs | `selection` FileRef; NONE additionally `policy` FileRef |
| `SIGN_CONSENT` | Native `review` FileRef; typed SOURCE `proof` control with `input_sha256` | `proof` FileRef at `signed-proofs/source-link-proof.json`; UTC `valid_until` exactly equal to the exported flat signing request expiry and within the native maximum |
| `ACTIVATE_OPAQUE` | `enrollment` FileRef; typed SOURCE `proxy` control | `carrier_manifest`, `raw_ready`, `scenario` FileRefs at `public/carrier-manifest.json`, `public/proxy-ready.jsonl`, `public/recovery-scenario.json` |
| `FAULT_READY` | Immutable Android `capture` FileRef; typed `capture` control with `capture_sha256` | `ready` FileRef at `public/fault-envelope.json`, `capture_verified=true`, `control_installed=true`; Core must emit `CAPTURE_VERIFIED` before Root forwards the control frame; uncertain requires Root's actual restart after the matched event |
| `CARRIER_SNAPSHOT` | `capture`, `result` FileRefs | `snapshot` FileRef from the parent's actual `FrameAdapter.evidence_snapshot()` |
| `FINISH_CASE` | `result`, `snapshot` FileRefs; typed `finish` control with `result_sha256`, `carrier_sha256` | `case_finished=true` only after Core's `CASE_FINISHED`; called before separate reconciliation |
| `RECONCILE_DIRECT` | `capture`, `result`, native `review` FileRefs | `receipt` FileRef from the opposite participating Owner/device/session over direct encrypted Hub RPC |
| `CLOSE_ANDROID` | `ownership` FileRef or null; `child_journal_directory`; no case | `receipt` FileRef for exact owned Android process/container closure |

The strict 17-field F6 READY shape is preserved. The new
`v164-frozen-joint-inputs.py` validates its nine exact public reference paths,
modes, sizes and hashes, clean e2a provenance and cross-file identities. It
reads only public metadata and public helper/source bytes; it neither executes
those helpers nor opens the private files listed in the custody description.
The loop never calls the old dd81575 delivery validator with e2a data. Root
validates any additional private sidecar in its original delivered format.
The mapped `binding` has exactly `hub_id`, `owner_id`, `owner_key_id`, `device_id`,
`link_id`, `link_version`, `source_owner_id`, `target_owner_id`, `source_group_id`,
`target_group_id`, `source_endpoint_id`, `target_endpoint_id`. The selected
setup and Link selection must match. The carrier manifest and raw READY are
independently parsed by the existing e2a carrier and must match the current
Android enrollment epoch, Owner/device and scenario.

Core's nested public setup is not an Android onboarding DTO: it is mode 0644
and has no device ID. Root explicitly assigns fresh opaque device IDs and
creates mode-0600 public onboarding wrappers under Client evidence. The loop
checks their full Hub/Owner public keys against Core's pinned metadata. Root
also supplies the existing closed Link-selection and NONE-policy wrappers;
their profile/generation comes from the actual SOURCE device export. Static
fixture manifest data never replaces the native live encrypted review.

Root copies each exact Android public export, without normalization, to the
Core case's fixed `client-inputs/` path before writing its typed control to
the inherited Core FD. Device files are named `<side>-device-enrollment.json`,
reviews `<side>-review.json`, and capture/result/carrier files are
`capture.json`, `result.json`, `carrier.json`. Only hashes and typed fields go
through Core's FD; public-file references go through the separate Client socket.
Raw Core `PROXY_READY` does not carry the READY-byte digest: use the pinned
manifest's `ready_raw_sha256`. Buffer unsolicited Core `FAULT_READY`; verify
Android capture through Core first, then install its exact carrier frame.

Root enrolls its separate participating reconciliation session on the direct
path. Android enrolls both fresh case profiles before opaque routing. After
the original fault the selected transport admits only that original recovery;
local staging/export commands do not send fresh Hub RPC. Root keeps the carrier
and original packet correlation in memory across both uncertain Hub restarts.

## Separate-session reconciliation boundary

The fixed APK has no standalone v1.6.4 readonly KEY/NONE reconciliation selector.
Existing `submitsHostSigned*` tests write grants before reading status; they are
not substituted for readonly reconciliation. The v1.6.1 default-NONE selector
rejects v1.6.4 and is also not a substitute. No new Kotlin or APK is introduced.

Root's `RECONCILE_DIRECT` implementation must use a separately enrolled,
opposite-side Owner/device session and perform actual encrypted reads. It
verifies response signatures, AAD/counters, current Endpoint proofs, independent
Owner keys and manifest/binding scope. KEY proof evidence comes from those
verified reads. On the fixed e2a image, NONE `link.review_policy_status` exposes
only the current HEAD; a singly accepted pending candidate requires the
separately authorized Core fixture verification described below. It returns a
redacted receipt with schema
`cicada.client-v164-recovery-loop-direct-reconciliation.v1`. Exact fields are
defined by `validate_reconciliation`: case/run/Hub/Link/binding hashes and
version, participating Owner/device/epoch, direct/encrypted/readonly markers,
manifest digest and verification markers, original proof hash and observation,
both side statuses, policy mode, bilateral verification, `policy` and correlated
reads. `manifest_digest` must equal the native reviewed manifest digest.
The frozen proposal's explicit top-level list matches the existing 25 fields;
no field is added to that list or to the callback envelope. All eight fresh
Cases that submit only the SOURCE Link proof require the opposite side to be `MISSING` and
`bilateral_verified=false`.

Each read has exactly `operation`, `operation_id_sha256`, `request_sha256`,
`response_sha256`, `request_sequence`, `response_sequence`. IDs are unique and
sequence strings strictly increase. KEY requires exactly `link.key_manifest`
then `link.key_grants`; NONE requires exactly those two followed by
`link.review_policy_status` then `link.review_policy_preview`. Extra, repeated
or reordered reads are refused. Any write, faulted device, foreign Owner,
wrong scope/proof or inferred bilateral acceptance is refused.

Only response-loss runs the original handler; its original proof must be
observed accepted. Outer processing/uncertain/legacy evidence must not invent
original proof acceptance. NONE reconciliation distinguishes the exact signed
candidate from a default/current HEAD0: a head alone cannot establish grant
acceptance. KEY requires `policy=null`. NONE requires a closed object with:

- `candidate_version`, `candidate_digest`, `candidate_current`;
- `candidate_evidence_origin`, `candidate_evidence_receipt_sha256`;
- `head_version`, `head_digest`, `head_current`;
- `head_source_status`, `head_target_status`, `head_bilateral_verified`.

Candidate version must be `1` in both the receipt and native review; its digest
must match the native review. All four NONE cases require
`candidate_current=false`, current head version `0`, empty head digest, both
head statuses `MISSING` and no head bilateral verification. Response-loss has
candidate SOURCE `VERIFIED` and TARGET `MISSING`; the three outer modes have
both candidate sides `MISSING`. A promoted candidate or bilateral receipt is
refused for this fresh fixture. This distinguishes the candidate from the
active head without adding a Client query API.

For NONE, the four real encrypted reads provide the current manifest, KEY
grants, policy HEAD and exact candidate preview. They do not supply evidence
that the singly approved candidate proof was stored. Core alone may inspect
the exact disposable fixture state using SQLite `mode=ro` and `query_only`,
and run the production signature, scope and expiry verifier against the
current independent Owner pins and exact original captured proof SHA-256.
Presence or database counts without that verification are insufficient. The
Client neither opens the database nor receives raw proof/database contents.

The two new nested fields are mandatory test coordination metadata:

| Case evidence | Required `candidate_evidence_origin` |
|---|---|
| Response-loss with the original SOURCE proof observed and verified | `DB_READONLY_VERIFIED_SIGNED_PROOF` |
| Processing, uncertain or legacy, with the original candidate proof confirmed absent | `DB_READONLY_CONFIRMED_ABSENT` |

`candidate_evidence_receipt_sha256` is a canonical lowercase 64-character hash
of the actual Core readonly verification receipt. RootParent must verify and
hash that receipt, correlate its Link/candidate/current bindings and original
proof hash, and supply the hash in the callback. The Client validates the
origin, digest format and existing case/proof/status correlations; it does not
independently execute the database or signature verification represented by
that hash. Missing or unverifiable provenance must produce a parent
`BLOCKED` reply and stop the loop, including NONE response-loss. No candidate
query endpoint or Android capability is introduced.

In NONE receipts, top-level `proof_observed`, `source_status` and
`target_status` describe the separately verified candidate, while the nested
`head_*` fields describe the encrypted HEAD response. `encrypted_verified`
and `transport=DIRECT` apply to the correlated RPC reads, not the database
candidate evidence. `owner_proofs_verified=true` means all present proofs and
expected missing sides were checked; it never implies bilateral acceptance.
`bilateral_verified` must remain false in all eight fresh cases.

The final KEY case record labels reconciliation as
`CORE_PARENT_SEPARATE_ENCRYPTED_OWNER_SESSION`; the final NONE case record uses
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`. Android standalone readonly
reconciliation stays `NOT_RUN`. These are test-only provenance labels;
`policy=null` remains mandatory for KEY. Receipt checks correlate Root evidence;
they do not independently execute/decrypt that separate session on Android. Native
recovery receipts continue to say business acceptance is unestablished until
this separately attributed reconciliation succeeds.

## Owned Android closure

The parent boot ownership file schema is
`cicada.client-v164-recovery-loop-android-owned.v1`, with `schema`, full
`container_id`, exact `image_id`, `network=none`, `auto_remove=true`, `label`
and runner `run_id`. Root independently inspects the actual container, including
its auto-removal setting. It binds the existing recovery runner label and image.

Client children run in new sessions. Private, fsynced process journals record
start PID/PGID/start ticks and command digest before waiting, then finish/reap
evidence. Root can use those journals if the loop itself is interrupted. TERM
and KILL require a fresh Linux `/proc` check for the exact session, UID and
leader identity. Unverifiable ownership yields UNKNOWN; no broad process-name
kill is used. Remote Android instrumentation is owned by Root's exact emulator
and must be terminated through that ownership boundary too.

Close receipt schema: `cicada.client-v164-recovery-loop-android-close.v1`, with
`schema`, `ownership_sha256`, `container_id_sha256`, `removed=true`,
`absence_exit_code=1`, `absence_confirmed=true`, `process_groups_closed=true`,
and two or three distinct `command_receipts` FileRefs. Each receipt has schema
`cicada.client-v164-recovery-loop-android-command.v1` and exactly `schema`,
`role`, `argv`, `exit_code`, `stdout_sha256`, `stderr_sha256`,
`absence_confirmed`. Commands use the full owned container ID:

| Role | Exact argv | Exit | Absence confirmed |
|---|---|---:|---|
| `stop` | `docker stop --time 10 <full-id>` | 0 | false |
| `remove` | `docker rm --force <full-id>` | 0 | false |
| `absence` | `docker inspect <full-id> --format {{.Id}}` | 1 | true |

At least one stop/removal receipt and the absence receipt are required; duplicate
roles, paths and hashes are refused. Root records the actual bounded commands,
stream digests and independent absence confirmation. The existing runner uses
`docker run --rm`: stopping that exact container may establish removal without
a subsequent `docker rm` command. The Client joins the
receipt to its exact boot ownership; a process exit alone does not establish
container removal. If boot fails before ownership is delivered, cleanup remains
UNKNOWN rather than claiming closure. Hub/Node/helper/key disposal remains
Root's separate responsibility.

## Verification and current status

### Final frozen callback clarification

The Root-authorized proposal was independently read and SHA-256 checked:
`/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-e2a1908-20261010/joint-preparation/CALLBACK-FROZEN-PROPOSAL.NONAUTH.md`,
`486b0c2be499a08a50acf272c8f01801a4105ecc7a67ddf2d4cfb2748afbf717`.
The callback envelope, 25 top-level receipt fields and eleven nested NONE
policy fields are unchanged from the preceding metadata extension. The final
NONE result label is exactly
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`.
The test-only validator now refuses any bilateral acceptance, candidate
promotion, wrong candidate version or extra/repeated/reordered direct read
in these fresh fixtures that submit only the SOURCE proof. This does not change Kotlin, the APK
pair, production contracts, pins, Grants, packet sequences or recovery fences.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-final-callback-freeze-offline-20261010`.
Actual tests ran against parent Client
`608fae2a54cbd34e92cae481c46e6a48b003964e`, **dirty=true**.
Docker offline verification is **PASS**, 141 tests, exit **0**, 6.181 seconds
including startup. The tests exercise all eight synthetic status combinations
and reject false bilateral/head promotion and altered receipt boundaries.
They do not execute Core database verification or Android.

Actual command:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-final-callback=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

Loop SHA-256:
`6a22e02b41da5118c922673780dbbd711d8df7159bb7fd9828b579fe7aef3dfa`;
reconciliation test source:
`68d00b743057d537e083d8f586b078413ad568a9903c34ba768303352946e973`;
test receipt:
`0aab6644730182d87be846658f3d2c3057de921bb5d3a1135a9e864bd24cae43`.

The actual audit command was
`python3 /gpu1-share/data/cicada-client/v164-e2a1908-final-callback-freeze-offline-20261010/audit-offline.private.py`,
exit **0**. Frozen Core interface/proposal hashes, eleven unchanged companion
drivers and both immutable APKs are **PASS**. The offline test container was
absent after completion: **PASS**, query exit **0**, zero matches. Receipts are
`frozen-interface-verification.redacted.json`,
`callback-proposal-verification.redacted.json`,
`immutable-input-audit.redacted.json` and
`offline-container-absence.receipt.redacted.json` under that evidence root.

The final plan template passed Docker `--validate-plan`, exit **0**,
0.79 seconds; exact argv and actual container absence are recorded in
`frozen-delivery/offline-plan.receipt.NONAUTH.json`. The plan is only an
offline template, with placeholder paths and no execution authorization.
The frozen delivery contains `companion-driver-pins.private.json` for eleven
unchanged files and `driver-pins.private.json` for all twelve exact plan pins,
including the changed loop. It binds the final callback metadata, Client
commit/tree/source inventory, unchanged APK attribution and actual receipts
in `commit-delivery.receipt.redacted.json` and
`frozen-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`.

Root must review the frozen loop/Parent mapping, render actual paths and bind
the actual plan hash into a separate finite GO. Online remains **HOLD**.
All eight Android cases, real candidate evidence verification, opposite-Owner
reconciliation, encrypted runtime capabilities, profile transitions and owned
Android closure are **NOT_RUN**. Android readonly, physical-device, public
HTTPS and Native Worker results remain **NOT_RUN**. Missing verified candidate
provenance must yield **BLOCKED**. Earlier receipts, failures and APK build
attribution are retained. No push or merge is performed.

### Historical mixed NONE metadata extension: 608fae2

Only the host test coordination policy receipt and its provenance label change
in this successor. The socket request/reply schemas, callback FileRefs, Core
controls, selectors, plan v2, deadlines, packet/grant/sequence/fence validation,
Kotlin, APK pair and fixed e2a Hub remain unchanged. The two new policy fields
and exact expected origins are defined in the reconciliation section above.
No production candidate-query API is present or inferred.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-mixed-none-reconciliation-offline-20261010`.
Testing used parent Client `888b587ce103208bdb5e7da33e56217757a4c09f`,
**dirty=true**. Its 140 Python tests passed with exit **0**, 6.184 seconds
including Docker startup, and all tested source hashes remained unchanged.
Tests explicitly accept the singly verified SOURCE proof with current HEAD0,
confirm absence in all three outer fault modes, refuse missing or misleading
evidence metadata, and retain all four required encrypted reads. These use
synthetic receipts; neither database verification nor Android execution occurs.

Actual command:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-mixed-none=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

Current loop SHA-256:
`d736dafee975fdc6671d989902b52b9593275580a66705c1536ea1d388da1734`;
reconciliation test source:
`1780f9c495b8233fe8bf50caa4971c0bc93a3f2d26111b1dfc1f3e279d62e1d3`;
test receipt:
`92bc8524eb26aa06e290aa76e4b391c3378bce4d02023d23a2eba22c2a079052`.
Frozen public-interface pins, eleven unchanged companion drivers and both APK
hashes were independently checked: **PASS**, audit command exit **0**.
The offline test container was absent after completion: **PASS**, query exit
**0**, zero matches. Their evidence files are
`frozen-interface-verification.redacted.json`, `immutable-input-audit.redacted.json`
and `offline-container-absence.receipt.redacted.json` in the successor root.
The actual audit command was
`python3 /gpu1-share/data/cicada-client/v164-e2a1908-mixed-none-reconciliation-offline-20261010/audit-offline.private.py`.

The successor `frozen-delivery/loop-plan.template.private.json` passed the
existing Docker `--validate-plan` command, exit **0**, 0.84 seconds. Exact argv,
readonly public mounts, log hash and confirmed offline-container absence are
in `frozen-delivery/offline-plan.receipt.NONAUTH.json`. This validates the
frozen schema/driver/endorsed-APK metadata with placeholder paths; it is not a
runtime plan or Root GO. Root must render actual BOOT_READY and evidence paths,
recompute the plan hash and bind it into a separately reviewed finite GO.

The final source commit, twelve driver pins, plan template and unchanged APK
attribution are bound in the successor `commit-delivery.receipt.redacted.json`
and `frozen-delivery/CLIENT-LOOP-DELIVERY.NONAUTH.json`. Previous frozen
schema exports and offline results remain attributed to `888b587`; they are
not silently updated or reused as current-source acceptance.

All eight Android scenarios, actual Core candidate verification, encrypted
runtime capabilities, separate Owner reconciliation and Android closure are
**NOT_RUN** while online remains **HOLD**. Android readonly, physical hardware,
public HTTPS and Native Worker remain **NOT_RUN**. RootParent must return
**BLOCKED** if it cannot supply verified candidate provenance. No push or merge
is performed.

### Historical frozen joint-interface alignment: 888b587

The following three Core delivery files were independently read and checked;
none was executed. Core checkout `36ebfab` does not replace the Hub image's
clean `e2a1908` source attribution.

| Frozen joint preparation file | SHA-256 |
|---|---|
| `JOINT-8CASE-INTERFACE.NONAUTH.md` | `618ecef915ad00c6f9fc61d842285989a8e61c59eded900c26aa64cc0e216805` |
| `ADAPTER-FREEZE.NONAUTH.json` | `eb34be4e43c4ae8e64e5b7fc397e76be0a2ef47b10cd5313918361b4d6eaa107` |
| `joint-adapter.py` | `29d906da160859f0a8a6711449fee69e89c6729ddb2947de9e963e92013622c4` |

They remain under the Core delivery's `joint-preparation/` directory. The
Client helper pins these exact bytes before plan validation; no proposed
configuration or APK-pin file constitutes Root GO. The existing strict
carrier READY, grant validation, sequence allocation and recovery fences remain
unchanged. A case is not complete merely because the Core fixture is ready:
the Android capture, one recovery, Core finish and actual separate encrypted
reconciliation must all complete within their deadlines.

Current evidence is recorded separately under
`/gpu1-share/data/cicada-client/v164-e2a1908-frozen-joint-loop-offline-20261010`.
Testing used Client parent HEAD
`015d2d3fd2518c24369a8d296ff341e256f58eda`, **dirty=true**. The source-bound
test receipt and final commit receipt preserve that attribution separately
from the unchanged APK build input snapshot.

| Current offline verification | Result / actual exit | Evidence in that directory |
|---|---|---|
| Docker Python suite | **PASS**; 140 tests; exit 0; 6.283 seconds including container startup | `python.receipt.redacted.json`, `python.private.log` |
| Source unchanged throughout test execution | **PASS**; test launcher exit 0 | Full per-file hashes in the test receipt |
| Frozen interface, freeze manifest and adapter exact bytes | **PASS**; audit exit 0 | `frozen-interface-verification.redacted.json` |
| Nine old drivers and fixed APK pair unchanged | **PASS**; audit exit 0 | `immutable-input-audit.redacted.json` |
| Offline test-container absence | **PASS**; `docker ps` exit 0, zero matches | `offline-container-absence.receipt.redacted.json` |

Actual Docker command for the current suite:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-frozen-joint=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

The actual host audit command was
`python3 /gpu1-share/data/cicada-client/v164-e2a1908-frozen-joint-loop-offline-20261010/audit-offline.private.py`,
exit **0**. It only verifies public frozen metadata, hashes existing drivers
and APKs, and checks absence of its offline-container label. It does not
operate a Hub or resident deployment. Docker data root was confirmed as
`/gpu1-share/data/docker-root` (`docker info --format '{{.DockerRootDir}}'`, exit 0).

The new tests cover v2 plan rejections, closed controls/paths, public metadata
mismatch, exact-byte/mode/symlink pins, Go timestamps and literal capture
verification. The all-eight supervisor-order test mocks `one_case`; it tests
scheduling and closure, not an Android/Core exchange. Existing recovery and
carrier tests remain part of the suite. No offline test result is an online
case result.

The first frozen-interface suite also passed 140 tests, exit 0, 6.283 seconds.
Review then found that plan validation allowed a consistent run base broader
than Core's fixed run ID. The validator now rejects that mismatch before
runtime and its fixtures use the exact frozen base. `attempt01.*` preserves
the first source pins, receipt and log; the final rerun above passed with the
corrected source. Neither attempt executed Android or Core.

| Current host source | SHA-256 |
|---|---|
| `v164-link-recovery-loop.py` | `2fcd14e57f540ee35d5108cd8157c0e0e2b7566899033ad3cd06de7f545e67ee` |
| `v164-recovery-loop-budget.py` (unchanged) | `b4563b0f0119018e36da8a3a1b13bbf7dc4feceaa9104746242f3683c4908328` |
| `v164-frozen-joint-inputs.py` | `55382c6391f837d05bc1247931c27a4de068534ed58405cf41ef4528d6388178` |
| `test_v164_link_recovery_loop.py` | `134606a3646936d31ba5017bee8f6f5597ea42e0fbc5eef6b5c0de7b2a644a29` |
| `test_v164_frozen_joint_inputs.py` | `0f300f874fdb3201592b30045a19b8380ce4a31832811bcfbb7dd7f65192834b` |

Current test-receipt SHA-256:
`4b6932624cea42041d5aa58558a0ae4f08f9fc754cda2e84ab89823c3e1674c7`.
The final commit/tree, input inventory, twelve driver hashes and unchanged APK
attribution are bound in `commit-delivery.receipt.redacted.json`; these files
are private evidence outside Git. No push or merge is performed.

Runtime capability validation, both Android enrollments/profile transitions,
the eight Android recovery cases, opposite-Owner encrypted reconciliation and
owned emulator closure remain **NOT_RUN** pending joint GO. A requirement for
standalone Android readonly reconciliation is **BLOCKED** by the missing
selector in the fixed APK; the external Core-parent receipt is explicitly a
different execution layer. Physical Android and public HTTPS are **NOT_RUN**.

### Historical first loop checkpoint

The results and source hashes below belong to Client checkpoint
`015d2d3fd2518c24369a8d296ff341e256f58eda` and the first loop interface. They
remain evidence for that checkpoint and are not substituted for the new
frozen-interface verification.

The fixed target remains clean Core
`e2a1908c71b2bcc103f5edf1ba2231e0fc1ccb59`, `client-hub-v1.6.4`, wire 1,
catalog 55. The frozen Hub image is
`sha256:532dc1ccfd8f66ab024bd298d16e5901356b602301085b5a75405c3a2de4ff01`;
test image is
`sha256:73ec018a026a27fb04ec0c651bafa976ebbed71efca87d302d0c7c4c2e59ba6a`.
Protocol bundle SHA-256 is
`bb54bdf34fb6fd4e9528a61e29a0b8cf7089b6f081da6f6d7b74d1c0d3d80568`;
catalog SHA-256 is
`953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`.
Independent frozen-delivery verification remains attributed to the preparation
record; this step does not inspect or operate a running Hub.

Evidence root:
`/gpu1-share/data/cicada-client/v164-e2a1908-recovery-loop-offline-20261010`.

| Verification | Status | Actual evidence |
|---|---|---|
| Initial Docker Python suite | FAIL | 129 tests, 2 failures; exit 1, 6.232 seconds; `attempt01.failed-python.receipt.redacted.json` |
| Corrected Docker Python suite | PASS | 129 tests, no failures/skips; exit 0, 6.210 seconds; `python.receipt.redacted.json` |
| Tested Python source unchanged during final execution | PASS | Full source hashes in the final receipt |
| Nine existing driver/module files unchanged from preparation HEAD | PASS | `immutable-input-audit.redacted.json` |
| Immutable application/test APK bytes and build attribution | PASS | Same audit; no rebuild |
| Offline test-container absence | PASS | `offline-container-absence.receipt.redacted.json` |
| Current-image Android KEY/NONE response-loss | NOT_RUN | Online HOLD |
| Current-image Android KEY/NONE processing | NOT_RUN | Online HOLD |
| Current-image Android KEY/NONE uncertain and two owned Hub restarts | NOT_RUN | Online HOLD |
| Current-image Android KEY/NONE legacy | NOT_RUN | Online HOLD |
| Actual direct encrypted opposite-Owner reconciliation | NOT_RUN | Root callback and joint GO required |
| Current Android emulator execution and closure | NOT_RUN | Offline subprocess tests are not Android execution |
| Standalone fixed-APK Android readonly reconciliation | NOT_RUN | No applicable existing selector; attributed external callback required |
| Physical Android / public HTTPS / native Worker | NOT_RUN | Outside this offline preparation |

Both test attempts used the following actual command, with no Core, APK,
credential or Docker socket mounted into the test container:

```sh
docker run --rm --pull=never --network=none --cpus=1 --memory=1g \
  --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000 \
  --label ai.cicada.client.offline-recovery-loop=20261010 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop -p 'test_v164_*.py' -v
```

The initial failures checked ownership journals after their test temporary
directories had been deleted. Moving those checks inside the directory lifetime
fixed the tests; process exit, group closure and leader-reap assertions were
already passing. The failed attempt and its exact source hashes remain preserved.
Final tests exercise synthetic files, local Unix socket pairs and harmless
Python children. They verify deadline/rejection/closure behavior and the existing
recovery consumers. They do not establish Hub or Android business acceptance.

| New source | SHA-256 |
|---|---|
| `v164-link-recovery-loop.py` | `27f48da40d455efc6b7797cd2071b45293e677f4956b44fbbf44528b2d8990d5` |
| `v164-recovery-loop-budget.py` | `b4563b0f0119018e36da8a3a1b13bbf7dc4feceaa9104746242f3683c4908328` |
| `test_v164_link_recovery_loop.py` | `06653ad9ee8678348fc960b88ef3311072726c012aec0ea86728cae5cd316a9b` |

Final test-receipt SHA-256:
`21170821b080ae0ea56143e1fcdefe50edf2084f1a2df2e403b9fd20b7aff1df`.
The final Client commit/tree, dirty state, source inventory and eleven driver
pins are bound in `commit-delivery.receipt.redacted.json` in the evidence root.
Testing used parent HEAD `43738f4dc4b209074f989fbd375a8ce05587bf4c`,
**dirty=true**, with the new host files. The APK build remains the separate
`9b56832` dirty/input snapshot above; neither commit is substituted for its
actual build source. No APK, key, pending ciphertext or private evidence is
added to Git. No push or merge is performed.

### Coordination prompt

> Map the fresh one-Hub/eight-case Core adapter into the private event interface
> above. Independently pin the twelve current host drivers separately from the
> unchanged APK pair. Deliver the full closed F6 READY and its nine pinned refs,
> both normalized public setups and fixed typed-control output paths,
> direct enrollment signing, current native reviews/proofs, owned opaque
> activation, capture verification and matched control installation. Root alone performs two actual
> uncertain restarts and supplies verified direct reconciliation from another
> participating Owner session, then exact Android closure receipts. Use the
> accepted absolute budgets and stop on the first failure. No old F38/dd81575
> result or synthetic receipt can become a new Android PASS.
