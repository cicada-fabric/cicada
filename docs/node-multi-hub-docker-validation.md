# Independent two-Hub Docker transport validation

The original clean `25bc586232db43362c6e03eccef1fa3a0dbec8ee` / Hub image `41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4` validation remains historical evidence of empty claims, SSE, credential isolation and restart continuity. Its original independent checkout, patch and receipts are immutable. That gate did not exercise nonempty delivery or Endpoint Join. This document describes the remaining v0.1 fixture based on clean `52cc2f6e0f97829332be372cb302cdb9f0ab0558`. Its first two attempts failed on fixture readiness and Control startup; the third exposed concurrent shared native-context registry initialization failure in the shipped Node. Each original source and failed receipt remains immutable. The bounded Core repair configures SQLite busy waiting before initialization and uses immediate check-and-record transactions; it adds no API, protocol, dependency or cryptographic change.

The driver accepts a clean production checkout and fixed producer/build metadata hashes rather than a fixed Main path or HEAD alone. It explicitly parses the accepted producer schema, checks the producer and build source inventory, current clean revision, standard v4 input fingerprint, catalog, image labels/IDs and shipped binary digest. It compares actual production source and index before/after and verifies its current standard input inventory against the producer. The dirty fixture checkout has a separate full bytes/raw-mode inventory and index. Checkout modes can differ from production modes. Software `0.1.0-dev`, contract `client-hub-v1.6.4`, wire 1, catalog SHA and the 55-operation count remain distinct domains. Interop image identity is verified only; this gate does not execute the independent Client interoperability tests.

For the accepted clean52 artifacts, run from the independent fixture checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-multi-hub-docker.py \
  --source-revision 52cc2f6e0f97829332be372cb302cdb9f0ab0558 \
  --production-source /home/zyf/CICADA \
  --producer-receipt /home/zyf/CICADA/.cicada-data/clean-52cc2f6-20261002/std-producer.json \
  --producer-sha256 9236481418555028d85859f36be26b7620c672899fc078e15097b3641f918648 \
  --build-receipt /home/zyf/CICADA/.cicada-data/clean-52cc2f6-20261002/std-build.json \
  --build-sha256 f7cb3d480d03905eaf9f009d43154670d1c401ec20d2c7cf09734e917bbb1e51 \
  --shipped-binary-sha256 f15d0175b9082e78d0df79b7a13b5aaaf4c8c59f81fdb2c96b32d767af7e8400 \
  --module-cache /home/zyf/CICADA/.cicada-data/m1-gomodcache \
  --node-artifact .cicada-data/multihub-remaining-52cc2f6-20261002/fixed-node/producer.json \
  --node-artifact-sha256 "$ACTUAL_FROZEN_NODE_PRODUCER_SHA256" \
  --evidence .cicada-data/multihub-remaining-52cc2f6-20261002/run-01
```

The accepted production Hub image is `sha256:d3c101d4ee92ddc667b84b4da94a46a5905b8fbbb06689455a195a660e253b02`; Interop is `sha256:8775af9377edda83e4f5af61ff11057d4e946b771de240ed20607f7935e34d5a`. Their standard v4 fingerprint is `f91d265cdb4c04156b1c353aac40f374b204922827df4a77091b43de58cbc97a` over 887 inputs; catalog SHA is `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`. This driver builds neither image. It compiles a separate synthetic test helper with pinned Go 1.27.1 image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, offline read-only modules, read-only source and private outputs/cache. The original attempts extracted the shipped CLI and verified its clean52 digest. For the Core repair, a distinct actual production Node CLI is compiled from the frozen dirty independent checkout, and `--node-artifact` binds its exact bytes/raw mode, Go tool, build command receipt and full source inventory. This binary is not the clean52 shipped `f15d…` CLI. The clean52 Hub and Interop producer identities remain unchanged. Modified Core is refused unless that separately attributed Node artifact is supplied. The fixture helper and production Node executable retain separate hashes/build information.

Two independent production Hub containers have separate SQLite stores, Hub/Control identities, Owners and approved Node credentials. Two physical synthetic Node containers each run one production `machine agent --hubs-file /node/hubs.json --state-root /node/state --relay-only --interval 1s` process with two workers. Each Node shares its own WriterRoot/admission/native-context ledgers across its workers and keeps identity, token, Endpoint keys, crypto replay and inbox state in separate per-Hub directories. The Agent origins remain loopback. The fixture observers also listen on the unpublished owned internal interface for the bounded lost-response probe and forward only to their own Hub; there is no Hub-to-Hub forwarding or egress.

Fixture preparation creates visibly synthetic identities, approved device/Node credentials, ACTIVE Networks, Owner-signed invitations and local Owner-key trust. Four Endpoint enrollments use actual production HTTP Join and native-binding APIs, signed Endpoint key candidates and encrypted Control key-manifest/key-grant RPCs. These enrollment calls run on normal production Control Hubs with zero Goals/Workers, an unavailable fixture-only Codex path, disabled snapshot GC and a long monitor interval. The driver then stops/removes those processes and reopens the same stores and Hub identities with production `serve --fabric-only` before peer traffic. A real encrypted key-manifest request then requires typed HTTP 503 with unchanged peer business rows at both Control-absent Hubs. No business Runtime calls occur. Hub enrollment of synthetic native-session coordinates is not real native Runtime session verification. Owner confirmation is synthetic fixture preparation, not Android or real operator evidence.

Each Hub uses the same fixed Network/message/request IDs in its independent database. Actual sealed SEND and ASK travel from its sender Node to its receiver Node; a manually composed synthetic REPLY travels back within that same Hub. Current peer-key bundles, Owner grants, production Endpoint crypto/outbox and HTTP relay APIs construct and accept the opaque envelopes. No SQL fabricates message acceptance, injection or consumption. A fixture observer loses the response to one successfully committed SEND; the exact message ID and ciphertext are retried against the production API. Hub and both Node processes restart; exact opaque retries, request/reply correlation and per-Hub replay rows remain independent.

Actual Node claims and current authorization must persist ciphertext through the production crypto replay ledger and Node inbox. The read-only oracle opens the original envelope with the actual Endpoint identities and exact route, checks verified sequence, plaintext byte equality, ciphertext digest, inbox coordinates including the exact Join native session, and one replay row. The Hub receipt must match the actual native-binding API response ID/epoch; Join access-session ID is a separate domain. It requires a real Hub `NODE_RECEIVED` receipt and reports actual receipt layers. Any layer beyond the Core constants `RELAY_ACCEPTED`, `NODE_RECEIVED` and `FAILED` rejects this zero-runtime gate. Node inbox `NODE_RECEIVED` or subsequent `FAILED` is permitted; neither establishes execution or nonexecution. Native queues, injection, application acknowledgement, result acceptance and consumption remain unconfirmed. No fake Runtime/queue receipt is generated.

Negative checks use actual HTTP guards: foreign-Hub Node credentials, foreign Owner credentials, wrong Node paths, management bearer at Node routes, foreign-Hub Network session, wrong Network selector, foreign-Hub Endpoint lookup and transplanted SEND/ASK/REPLY ciphertext. The relevant business table rows are hashed before and after the Network/ciphertext denials and must remain unchanged. Observers retain bounded route/status counts and exact SSE ready-frame flags, never headers, tokens or full payloads. Runtime evidence separately identifies relay acceptance, actual Node persistence/decryption, manual synthetic reply and unrun Runtime consumption.

`--self-test` runs four Python standard-library tests for producer/Node artifact identity cross-binding and cleanup after a sticky secret-scan failure, including foreign-resource refusal. Focused Go normal/race checks cover ownership/private coordinate rejection, exact typed HTTP denials and fragmented SSE observation. Core normal/race tests use actual child processes and explicit barriers: concurrent existing-registry opens wait for an exclusive lock, persistent locks fail within the bounded timeout without history loss, and competing dedicated scopes yield exactly one accepted history and one scope conflict. Escaped filenames and separate in-memory registries retain their existing semantics. No global lock or blind retry is introduced. These checks do not replace the real gate. Every actual command records argv, exit, timeout, safe stdout/stderr and hashes; failed attempts remain immutable and skips are not passes. The three fixture source files and two authorized Core source/test files, including this document, freeze before the final runtime attempt. Actual results are authoritative in the fresh evidence directory's `receipt.json`, `commands.json`, source inventories, binary identities and bounded logs.

All resources carry a unique owner label and removal requires that exact label. Cleanup discovers timed-out resources and reports failures; private synthetic keys and payload trees are removed in `finally`, with filesystem cleanup errors surfaced. Main, Client, global settings, accepted producer artifacts and previous evidence receive no writes from this slice. Models/provider calls, real native Runtime/session verification, native queue injection/consumption, Android, physical devices, public HTTPS, real credentials and cross-Hub forwarding are **NOT_RUN**. This finite evidence does not authorize closed Client operations or claim whole-product completion.

## Current Node Hub lifecycle acceptance preparation (2026-11-04)

Current qualification superseding the preparation below: Root accepts
**SCOPED_PASS** for six actual lifecycle scenarios across a preserved five-case
subset and one affected-Group rerun, not one six-PASS run. Production is
`afb2bad8`; actual two-Hub current-NPT/default CLI/Hook/facade/Agent crypto is
separate from the four-case client Docker PASS and installed-CLI
zero-connection systemd PASS. The
[current validation ledger](native-app-validation.md#node-hub-coexistence-acceptance-preparation-2026-11-04)
contains exact source/binary/log/result hashes, original failed attempts and
NOT_RUN scopes. Historical Docker artifacts above keep their original source.

The historical artifact/source results above retain their original attribution.
They provide reusable two-Hub isolation, Network-direct ciphertext, outage,
response-loss and restart fixtures; they do not qualify dynamic current-NPT Hub
add/remove or routing a current Group through its Network's authoritative Hub.
The old driver also pins its own toolchain/artifact/cache identities; fresh
execution must bind the reviewed current source and actual build inputs.

QA prepares the existing [six-scenario matrix](native-app-validation.md#node-hub-coexistence-acceptance-preparation-2026-11-04)
on `b34fbce` in `task/v01-node-hub-validation`, with isolated synthetic current
NPT/TLS/SQLite/Group helpers. Registry/facade wiring awaits Root's closed API
review. No new test or Docker gate has run. Static two-worker configuration is
not dynamic addition/deletion acceptance. New native Runtime, physical Node,
Windows DPAPI/ACL and public HTTPS remain NOT_RUN. Root owns scoped execution,
the disposable Docker decision and final packaging; no real service is changed.

For the separately planned physical cutover, the user retires
`198.200.58.176` and retains only Aliyun `8.155.139.253:8787`. Its A-offline
add-B/remove-A/cold-reopen checks and later enrolled-Node/App-unbind continuity
remain NOT_RUN. They do not replace disposable healthy-two-Hub concurrency or
Group-selector collision qualification. This note authorizes no fixture to use
either real Hub as disposable state.

The pending current fixture also needs healthy legacy-A adoption through its
protected exact old-pin to managed-ID/epoch receipt, retaining original Endpoint,
native SID, state paths and unresolved records. Root additionally requires a
deterministic admission/removal barrier: the fence CAS shares the final native
check/Begin/Start gate, post-fence starts refuse, and LOCAL_STOPPED requires real
quiescence. B remains independent while one physical Thread still has one
writer. Real `off`/`status` ownership and stop proofs must distinguish an unknown
manual daemon from a stopped managed unit. These are NOT_RUN additions to the
existing matrix, not new native/Docker results or authorization to touch a real
service.

The removal matrix includes both a used-connection positive and a native-unknown
negative. Trusted exact QueueAccepted evidence permits local stop while Hub
consumption remains unconfirmed; history stays retained and is not marked
consumed/cancelled. Genuine native/provider INJECTING, INJECTION_UNCERTAIN or
START_UNVERIFIED remains fenced STOP_PENDING. Unknown network originals remain
isolated from B and retained, without automatically making local stop impossible.
These cases are NOT_RUN and confer no native Runtime/consumption qualification.

Five current cmd-layer tagged targets are now drafted in the existing
[acceptance record](native-app-validation.md#node-hub-coexistence-acceptance-preparation-2026-11-04).
They use current CLI `join --thread … --hub ALIAS`, the actual routed Hook/front,
current NPT/private ACK and live production Agent inbox observation. The
synthetic offline queue subprocess is the existing Go test executable; it
does not call a provider. The fifth reuses those Hubs for actual unmanaged-A
NPT/Agent/Thread, explicit stop and protected from-service adoption before B is
added. The old PID/instance may change during the explicit stop/adoption;
adding B must leave the adopted A instance unchanged. Its service runner is
scripted and cannot qualify systemd. Compile and all five executions remain NOT_RUN.
Root will use the existing `test-client-hub-interop.sh --suite client` as the
general disposable Docker gate, retaining its evidence separately from these
dual-Hub tagged tests. This preparation adds no new Docker driver and does not
attribute any historical gate pass to the new source.

Subsequent status: QA's one pinned offline Docker **compile-only** operation
exited 0; the original wrapper's cleanup-parser exit 1 remains recorded and a
separate exact-ID/name absence closeout confirms Docker cleanup. Root ran the
exact resulting binary independently: attempt 1 exited **1**, with **2 PASS /
3 FAIL / 0 SKIP** and unchanged source. Current NPT/add-remove-cold and the
admission barrier passed; original-service adoption failed on a fixture
transport argument conflict, while both Group/native-unknown targets stopped
at an actual local-user report timeout. These are failed integration evidence,
not a Docker interop or whole-lifecycle pass. The
[current validation record](native-app-validation.md#node-hub-coexistence-acceptance-preparation-2026-11-04)
contains exact manifests, artifact/log/result hashes and the unvalidated fixture
correction. The general client Docker interop and actual systemd/Runtime/Windows
qualifications remain separate and NOT_RUN for this lifecycle at this point.

Root subsequently reviewed carrier `4340057e` for the exact public-metadata
read gate and the error-only retained-artifact validation seam. QA's pending
sixth real target reuses the original adoption fixture for storage0/adoptLive1/
LOCAL_STOPPED2/explicitSameAliasLive3, retaining original keys, Endpoint/SID,
cache/outbox pin/rows/schema and unknown App packet, while fresh live3 works,
old live0/1 refuses and B continues unchanged. It introduces no alternate
database, namespace or fabricated report/row. The combined next source awaits
App wiring and is NOT_RUN, including compile; attempt 1 retains its original
binary, source manifest and failed result.

Final scope closeout: Root scope-acceptance SHA-256 is
`455782097db65558a2c2b425c10381f7fe03deea993293d51da26827e669323a`.
The original six-target run remains FAIL / 1, 5 PASS / 1 FAIL / 0 SKIP; the last
failure followed a test SSE-close hang and exact-process SIGTERM. Its original
result SHA-256 is
`82c704946b1f2dd3b1cc143589c009701f75dec327b97610eaf7e8efd082acbc`.
Only the outage fixture changed. The affected Group target then passed
separately, exit 0, 42.111 seconds, result SHA-256
`df546537b8be2058cdc9dcf9ce58d3e65997ffae94dbf4f5d3c71232b88a0a5e`.
Root verified all 950 production Go/module inputs identical to clean candidate
`afb2bad8` across both QA freezes. The old failure is not relabeled PASS and
the five completed cases are not reattributed to the rerun binary.

The actual general client Docker gate is PASS / 0 for four cases with exact
owned cleanup CONFIRMED, result SHA-256
`f3d9cf97fa1f356ea82d6f44791ce7bdcefc77571d096040568b4bbaf1ee57ff`.
The real installed delivered CLI systemd gate is PASS for zero connections
only, result SHA-256
`f2f4e11d37844b84f8ef1f2b0c60f11a059125714e31349bed591fd4983e9c58`;
owned unit/fixture cleanup is confirmed and the original resident Node PID is
unchanged. These separate layers do not establish connected-Node systemd,
native Runtime/model consumption, physical Windows GUI/DPAPI/ACL, Android,
public HTTPS, resident migration or the user's physical Hub cutover. Those
remain NOT_RUN. The frozen source-bound candidate ZIP SHA-256 is
`502046d93965f2b649ffc5ffd449c08cec83da56ad5400144aec1e01e600f581`;
Root finalizes archive metadata after the QA checkpoint, preserving production
binary/candidate attribution.
