# Native Endpoint / Owner directory checkpoint validation

This record covers `native-endpoint-directory-v1`, not the frozen installation
H1 proposal, a deployment or actual native Runtime consumption. The implementation
and [contract](native-endpoint-directory-contract.md) share one task checkpoint.
The producer is `task/n2-hub`, based on `bb0644b68627579af470ead52035d42618372c75`
plus the recorded dirty sources. A dirty build is not attributed solely to HEAD.

## Source and environment

Evidence is outside Git at
`/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`. Each run has
`source-manifest.json`, `receipt.json`, `stdout.jsonl` and `stderr.log`, retaining
its exact base, file hashes, immutable image, command, test counts and exit.

The fixed builder is
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
Go 1.27.3, UID/GID 1000, network disabled, read-only source/module cache and a
task-owned build cache, `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`,
`GOMAXPROCS=4`. All account/Owner/Node/Thread fixtures and keys are synthetic.
No resident Hub, actual Thread/SID, provider credentials or model is used.

The Docker image disappeared from the daemon during this work. The attempted
`focused-current-20261020T145323Z` could not start: exit 125, zero tests, source
manifest `0ab0be7a66e77f7baf96a4f0eb388db2ed5e47bbf31ebc5e0da5c3c1122e14db9`.
This is an environment failure, not a pass. The official builder tag was pulled
back to the same fixed image ID; no resident deployment was recreated or replaced.

A read-only copy of the image's Go toolchain was extracted into the task cache
for the App/QA collaborators. Its `image-toolchain-receipt.json` records origin
and executable hashes: Go `5f5eb6d0b2fb6aa0bb5d5f8c5f1c944e0de955c925f0111af92a9d8f79680b5b`,
gofmt `fd464d1c9098a6714d06bd3fcd2a1fedcdd291e710241160ebb663bf99adf2f8`.
A parallel slow upstream tar transfer was cancelled and retained as an unverified
partial file; it is not claimed as a checksum-verified toolchain or test input.

## Checks

The scoped results below retain their separate input manifests. The original
aggregate FAIL is not rewritten as an aggregate pass. All four originally failing
cases pass their corrected affected selectors; unchanged passing cases are not
added twice. There is no claim of a fresh full-repository aggregate pass.

| Run | Recorded result | Attribution |
|---|---|---|
| `final-focused-20261020T150858Z` | FAIL: 220 pass / 4 fail / 0 skip; 81 passing and 2 failing top-level tests | Manifest `4732ef2bdb32c32ff1eaa93af9d2008c3416105d36cb2233b8daf3f89d0fd1b0`. One new capabilities newline parse failure; old external-writer topology revocation join/authorization tests returned SQLITE_BUSY. These failures are not erased by later checks. |
| `availability-correction-20261020T151210Z` | PASS: 4 / 0 / 0, exit 0 | Manifest `0ed204ce6755743b43d76c06c6a256888a2e9e6cd3ddb7c5e6b6ec99d4bc45fa`. Corrected the bounded public parser to accept the HTTP encoder's final newline; wire and actual encrypted TCP Owner-read checks pass. |
| `scoped-vet-20261020T151252Z` | PASS, exit 0 | Same `0ed204ce...` source; Store, Fabric, Control, Server, wire, crypto, authorization, Hub Nodes, catalog and CLI packages. |
| `targeted-race-20261020T151251Z` | PASS: 23 / 0 / 0; 17 top-level, exit 0 | Same `0ed204ce...` source. New Endpoint/Owner read, concurrent same-SID, current revocation, Pair discovery and directory privacy cases. |
| `mutation-guard-correction-20261020T151916Z` | PASS: 63 / 0 / 0; 7 top-level, exit 0 | Manifest `580255f276470a0986b5f98861ccd27165cf5130266682d465b973612e531cb5`. Complete topology mutation-guard selector, including all external-writer revocation subcases and unchanged denial expectations. |
| `disposable-tcp-interop-20261020T151917Z` | PASS: 3 / 0 / 0, exit 0 | Same `580255f2...` source. Actual Hub Nodes/account/PQ HTTP services in a disposable network-disabled Docker container: register→reuse original Pair identity→withdraw actual Group/Network leases; strict terminal errors/exact retries; availability→Owner-proof private read→current revocation. No Control inference or model. |
| `mutation-store-vet-20261020T151918Z` | PASS, exit 0 | Same `580255f2...` source; final Store writer-order correction. |
| `final-client-catalog-20261020T152135Z` | PASS: 4 / 0 / 0, exit 0 | Same `580255f2...` source; the complete Go catalog/authoritative-contract checks. |

The integration owner independently reproduced the same old external-writer
join/authorization failures on clean `bb0644b`: 2 pass / 3 fail / 0 skip,
including the failing parent. Its separate evidence is
`/home/zyf/Cicada/.local/evidence/native-ux-root/baseline-guard-20261020T151234Z-a8cebc/`.
The approved repair is limited to taking the trusted SQLite writer before the
native-Pair legacy-scope schema read in those two mutators. It changes no
permission or denial expectation. The affected-selector correction passes separately as recorded above; the original
failures and clean-baseline reproduction remain attributed to their tested sources.

Earlier development attempts remain under their own source manifests and
receipts: `initial-focused-20261020T135124Z`,
`owner-read-compile-20261020T140147Z`,
`owner-read-focused-20261020T140456Z`,
`owner-read-focused-v2-20261020T140616Z`, and
`owner-read-focused-v3-20261020T140820Z`. They retain the nil-scanner/carrier
scaffolding, invalid synthetic immutable-epoch mutation, test compile errors,
and old-N2-TTL mismatch found during development. The TTL correction follows the
reviewed N3 semantics: a new genuine Owner read proof has an independent finite
purpose; the expired old N2 operation scope stays expired.

The contract checks are `python3 scripts/endpoint-directory-contract.py`,
`python3 scripts/client-contract.py check` and
`python3 scripts/native-pair-contract.py`. They retain wire 1, Client catalog 55
and old activation operations. The Client contract Python suite passed 18 tests.
No Android frozen copy or Android business code is changed.

## Covered behavior and limits

The targeted cases check zero rights, immutable repeated metadata, cwd/Owner/Node
fences, concurrent same-SID claims through independent Store connections,
current Node/Owner/key/device revocation, exact sealed-response retry/restart,
Group and Network-only Leave CAS, actual lease/edge withdrawal, no `left` revival,
Pair reuse without replacement identities, and pre-LIMIT candidate filtering.

The Owner read cases use actual Owner signatures and App/Node PQ packets. They
cover old N2 TTL expiry with a new distinct proof while the old operation remains
denied; no device/account-only substitution; finite UTC windows including time
sampled after the writer lock; stable cursor checks; long-path byte-limited pages;
exact cached snapshots; temporary bounded-cache backpressure; current Node
revocation denying cached private paths; same-Owner metadata; and foreign-card,
direct-ID/Node/workspace resolution and ambiguity privacy.

Registration is not an active native writer. Generic Node RPC can still report
an uncertain result between the business commit and response sealing; the
retained identity is reconciled instead of creating another Thread/Endpoint.
This checkpoint does not implement rename/CAS updates, re-enable a left Pair SID,
delegate Owner endpoint-key signing, preassign an App-selected Endpoint to a Pair
slot, or run a model. The live Thread must explicitly select the human Pair label
and A/B slot; the App reviews actual joined Endpoints and original consents.

Node local-bridge wiring and the per-call current-Thread Hook are subsequent
scopes. Actual Codex Runtime, current Windows App UI/DPAPI/ACL/uninstall, Android,
physical devices, public HTTPS, real keys and deployment upgrade are **NOT_RUN**
for this checkpoint. The user's earlier successful two-Thread Pair behavior
remains user-reported evidence for its original source, not a pass for this patch.


The authoritative Client contract export is retained at
`/home/zyf/Cicada/.local/artifacts/node-endpoint-registration/client-contract/`,
bundle SHA-256 `c6ded1351c0f9efdbe1b64d52c45235b6c45a235558e82b0b7fef3f71a8418ed`.
It explicitly records base `bb0644b...` plus dirty contract content, not a clean
build attributed solely to that base. Catalog SHA-256 remains
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.
The final candidate/commit receipt links the exact tested source hashes and
post-test documentation hashes; adding this evidence record does not change the
Go code tested by the final correction/TCP/vet gates.


## Follow-up: bounded Node admission backpressure

This separate correction is based on clean backend `d3acd4bfe6f3f10867db6a5e3ae432f8477d9748`
plus its own dirty manifest. Independent QA observed four valid identical Node
packets competing for Hub Nodes' two processing slots: excess requests were
incorrectly reported as HTTP 403 by the shared handler. Its original FAIL remains
in QA's separately owned native App validation; it is not an authorization pass.

The producer now distinguishes `hubnodes.ErrBusy` from unavailable/authentication
errors and returns HTTP 429 with `Retry-After: 1`. Capacity stays two; there is no
unbounded queue, new identity or new authority. The sender keeps the original
packet and operation fence. Cancellation retains its existing semantics.

`busy-admission-correction-20261020T154736Z` passed 3/0/0, exit 0, on the same fixed
Go 1.27.3 image, with dirty manifest
`c8b1389692bead8c018de860596c5f424982677ed21dca8588db79be725177e7`.
The deterministic capacity/cancellation/release unit and existing actual TCP
registration/Pair-reuse/Leave/exact-retry checks pass. This producer run does not
claim QA's separate four-way fault/recovery gate has passed; that rerun retains
its own source, request packets and receipts. Node self-inventory, local bridge
and context-ticket work remain later scopes.


## Follow-up: private Node-operator directory

The Node-operator profile adds bounded `node.endpoints.list` and its public
capability format on the same existing GET path. It does not change the empty
query's Owner format or add an Endpoint/model `directory.read` grant.
`node-operator-final-20261020T155753Z` passed 5/0/0, exit 0; the related vet run
`node-operator-vet-20261020T155755Z` passed, exit 0. Their exact dirty source is
base `2ab4e5155f4d8c082f69a3fe2764b6d7fee84e72` plus manifest
`82f33d29c5d0f587fcec457262dd972f3800cc01fdda4e54086ce75a599663c8`, using the
same fixed image and isolated synthetic environment described above.

The cases check actual PQ/TCP zero-rights discovery, separation of public Node
and Owner capability formats, old-format and wrong-pin refusal, current Node
revocation, foreign Owner/Node filtering before LIMIT with deliberately earlier
foreign IDs, cursor refusal, noncreating exact self lookup, stable long-path
pagination and complete 48-KiB result bounds. A synthetic second-Node metadata row
is a filtering fixture, not evidence of a second actual Owner-approved Node.

Independent QA's separate two-selector correction on `2ab4e51` plus its dirty
acceptance driver passed 2/0/0 and observed two HTTP 429 responses to four
concurrent identical packets. Serial exact retries returned the same PQ receipt
and the database retained one zero-rights Endpoint. Its receipt is
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261020T155233Z-lR0KG4/result.json`,
SHA-256 `c5771e67d02db87dc9bb185e85a1b7a125cbf277634de44adbc21901d8442418`.
That result is not a fresh nine-selector aggregate, Owner-read App consumption,
local bridge, context-ticket, actual native Runtime or physical-device pass.


After the integration owner fast-forwarded this producer to App paths baseline
`73d6f9ad13c26ad7cf203e2924adcc7a46104213`, the previously tested directory Go
changes remained byte-identical. The affected CLI compile-only run
`node-operator-post-paths-compile-20261020T160237Z` completed with exit 0 and zero
selected tests (manifest `b1fe22b0755b5c316a212242a2c6b752dc78f7a5d47149c58df25ac3cdf20759`).
This is a build check, not a new directory functional run, Windows/native Runtime
pass, or reason to duplicate already completed scoped tests.

## Follow-up: local adapter, exact intent recovery and context authority

This producer checkpoint is based on `4215ddce83443673d9b3f4c70a3db7ba02fcc434`
plus its own dirty source manifests. It implements the existing private socket's
Endpoint register/Leave/operator-directory/available-Pair/named-Join adapter,
durable exact intents, and the local HMAC issue/consume authority. It does not
modify App/Android implementation, main dispatch, old protocol identifiers,
existing Owner identities or keys, scopes, consent requirements or live state.

All runs below used the same pinned Go 1.27.3 Docker image, no container network,
read-only source and module cache, task-specific build cache, synthetic keys and
disposable private socket/TCP/SQLite fixtures. No shared development Hub was used.
Evidence is retained under
`/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`.

| Run | Result | Exact dirty source manifest |
| --- | --- | --- |
| `local-bridge-final-functional-20261020T162513Z` | 11 pass / 0 fail / 0 skip | `8db1977c8a4d69650c62cb7a219ae9f993a6c0ffa5ae53041eef3ab4b636f89a` |
| `local-bridge-fence-correction-20261020T162648Z` | 2 pass / 0 fail / 0 skip | `04dac1a4d4b1f7e9fb58bcb433a5c3b8d091e3883960499a8eab7699d397beb1` |
| `local-bridge-frozen-race-20261020T162742Z` | 9 pass / 0 fail / 0 skip, `-race` | `04dac1a4d4b1f7e9fb58bcb433a5c3b8d091e3883960499a8eab7699d397beb1` |
| `local-bridge-frozen-vet-20261020T162742Z` | exit 0 | same `04dac1a4...` |
| `local-context-monotonic-correction-20261020T162903Z` | 4 pass / 0 fail / 0 skip | `bf652cdd65b5fccb46880796559f65e8d4103f87d5ceb4e0d9e764b908e05d1b` |
| `local-context-monotonic-vet-20261020T162903Z` | exit 0 | same `bf652cdd...` |

The final four-line correction preserves Go's monotonic clock in live 30-second
ticket comparisons and formats only the returned expiry as UTC. Its narrow
rerun covers all three authority tests and the actual private IPC/TCP adapter
test; the full matrix was not repeated. Final source-after checks match all
manifest files before this validation prose was added. Candidate receipts map
all final Go blobs to that exact correction source.

The tests establish concurrent atomic single-use context consumption, wrong
tool/arguments/nonce/origin/binding refusal, expiry, 512-live-ticket backpressure
without live eviction, process-key restart invalidation, one bounded non-link
owned transcript record, actual fork ID matching, and unsupported subagent or
unknown ancestry. The real production private socket issues and consumes a
ticket and rejects its replay. This uses synthetic metadata, not a native Hook.

Intent tests establish exact Leave digest and packet retention across ACK loss,
disk reload/startup recovery, and atomic receipt/outbox persistence. Expired old
Leave cannot prepare a self read, old IDs cannot change their issue millisecond,
time-floor persistence prevents rollback resurrection, completed/local-only
history is collected rather than imposing a lifetime quota, and unknown packets
survive collection. Full short-window capacity rejects new work before a counter
or packet is allocated. Authenticated Pair refusal remains a retained refusal.

The actual Hub/SQLite/PQ/TCP test uses the new private IPC to register an offline
private Endpoint, list it as the local Node operator, reject a nonexistent Leave
without creating an Endpoint, then choose the exact human Pair label and A slot.
It reuses the registered Endpoint under the original real synthetic Owner proof.
After the Hub commits Join and its ACK is deliberately lost, the exact retry
sends byte-identical original packets with the same generation. One joined slot
does not admit the Pair, sign its keys, synthesize consent or run a model.
Existing dual-consent/relay and explicit-new-intent fence regressions also pass
in the separately attributed functional run.

Historical failures are retained. The first endpoint run
`local-endpoint-focused-20261020T162015Z` had 2 pass / 1 fail / 0 skip: its test
reused a JSON decode destination whose omitted pending field retained its prior
value. Resetting the destination fixed the evidence assertion; production receipt
logic was unchanged for that failure. The earlier cold race run
`local-bridge-final-race-20261020T162602Z` reported 8/0/0, but source changed in
the host working tree during its read-only mount, so its explicit mutability
note excludes it as a final source gate. It is not substituted for the frozen
9/0/0 run above.

Actual per-call Codex Hook/MCP Runtime, TUI/desktop ticket lifecycle, hostile
same-UID isolation, Windows IPC/GUI/DPAPI/ACL, Android, physical devices, public
HTTPS, real keys and resident deployments remain **NOT_RUN** here. Hook/MCP
consumption and the operator CLI surface belong to their separately reviewed
consumer work. These results do not prove human intent, native anti-inheritance,
Runtime message consumption, or a completed user-facing installation.

State compatibility is directional: the new binary reads the prior Node state,
and the new local intent/floor fields are optional additions under existing
state Version 1. After those fields are written, an older binary's strict JSON
reader rejects the state rather than understanding the new recovery records.
Downward binary compatibility and automatic downgrade/migration are not claimed;
refusal must preserve the original state and identity, never initialize a
replacement identity to bypass it. This checkpoint did not deploy or downgrade
a resident Node.

## Follow-up: operator command client persistence

The client helper is limited to two new Go files plus this contract/evidence
update. It does not parse prompts, detect SID, modify Hook/MCP/App implementation,
change the MCP session schema, or add a service, queue or dependency. All input
contexts/keys/credentials in its tests are visibly synthetic and disposable.

`operator-intent-focused-20261020T164650Z` reported 15/0/0 on base
`97d8a1d22643ddf911c8842ac9f95802928189df` plus dirty manifest
`67ddefb122ecf27911a29dc8ab7438d2f1b6308026aae60d97e1b5c3701b2db9`.
After adding the explicit same-command/new-candidate-ID recovery assertion,
`operator-intent-final-race-20261020T164817Z` reported 15/0/0 with `-race`, and
`operator-intent-final-vet-20261020T164817Z` exited 0. Both use dirty manifest
`e136dd4ca999248986a85fd953c913b420b5194f5f99d18e9114a7c8174ed6c8` on the
same base. Those counts comprise six substantive top-level tests, eight nested
response cases, and one subprocess-harness selector which returns without work
outside its child role. The harness return is not a separate product pass.

After those gates were sealed, one additional missing-Join-credential negative
case changed only the test file. Its narrow response-binding selector,
`operator-intent-credential-correction-20261020T165014Z`, reported 10/0/0
(one top-level test plus nine cases), manifest
`0bf7a70ef34285b560d0554cddbc34f0cdd3e8d68ed372aad2fd7b9fe72f3ad3`.
Production Go remained byte-identical to the race/vet source. Each final gate's
source-after receipt checks all manifest files before documentation was added;
the candidate maps final blobs to their actual tested sources. These are scoped,
separately attributed results, not a new aggregate count on a clean commit.

The deterministic cases cover persistence before IPC, lost replies and exact
restart retry, injected prepare/result durable-writer failures, different
command/API/Node/SID/cwd refusal, incomplete/unknown/forged response refusal,
malformed intent hashes and nonprivate/symlink paths. A genuine pair of isolated
OS subprocesses prepares the same file concurrently and receives one identical
original request. Acknowledgment is idempotent for its own result and cannot
clear a later command. Unknown or missing-credential results cannot be acked.

The actual existing private IPC/Hub/SQLite/PQ test deliberately loses a committed
named Join response, reopens the client, recovers the same intent, persists its
Join in the existing MCP session store, then acknowledges it. It uses the
production store and socket; no real Codex Runtime, model call or new native
Thread is run. The pinned Go 1.27.3 Docker image, no-container-network policy,
task cache and source/module read-only mounts are the same as earlier gates.

Actual user-command Hook/MCP dispatch, native Runtime consumption, hostile
same-UID isolation, Windows ACL/IPC/GUI, Android, physical devices, public HTTPS
and resident deployment remain **NOT_RUN** for this helper checkpoint. A
privately cached completion is historical evidence; current authorization and
lease renewal still require the existing Guard and native-scope paths.

## Follow-up: Node-managed explicit Pair leases

The checkpoint adds only a Node-owned worker and private recovery metadata,
plus a context-bounded existing-database Nodekeys read entry. It uses the existing
Guard, native scope, policy/pin, sealed receipt, heartbeat, outbox and secret-file
services. No App/MCP/main consumer, public protocol identifier, new dependency,
resident Hub or real key is changed.

The pre-refusal/I/O-review source on dirty base
`18868bade057d5da97afe3e8139cc3cafb104afe`, manifest
`e727d8ab7947a0f51fe339feded1baaba15aaf784f622f330b600695b39ff3d4`,
passed `managed-pair-combined-functional-20261020T175026Z` (21/0/0, 13 top-level),
`managed-pair-combined-vet-20261020T175026Z` (exit 0), and
`managed-pair-combined-race-20261020T175243Z` (19/0/0, 11 top-level, 488.152 s).
These remain evidence for those exact dirty bytes, not clean later commits.
The task then preserved all five WIP files byte-for-byte across the authorized
fast-forward to asset-only base
`c3a1517c7b47864a5d9d9a20c6de9ee444799622`; the external receipt is
`managed-pair-asset-ff-receipt.json`, SHA-256
`6f49db5d02fe29a7b3a0b49e77f1a940007521331435929fd9ca89658b9330da`.

The review added durable no-dispatch refusal fences and transient-I/O handling.
`managed-pair-refusal-io-final-functional-20261020T181937Z` passed 21/0/0
(9 substantive top-level tests and 12 nested cases), dirty manifest
`eab5c9cc124c61d3e754da2191d924e47eda90548da58051cb32d67c750c9937`
on that c3a1517 base. It covers the real operator helper/IPC capacity and typo
refusal, ACK and fresh-command recovery, old-command fencing, a dispatched
Join with its new marker absent remaining UNKNOWN, independent pending ID/
packet/receipt/local-step evidence, fence-write failure, real SQLite EXCLUSIVE
lock failure and same-original recovery, confirmed deleted policy/pin, and the
existing-only reader's missing paths/bad permissions/old schema/live WAL/
query-only/context/busy budget. The Store itself permits just one nonterminal
Pair per Owner/Hub/Node. Duplicate-label and truncated-directory negatives use
visibly synthetic authenticated directory responses over the real socket and
client helper; they do not claim the current Store can create duplicate Pairs.
Two earlier failed functional attempts are retained separately: one test compared
a pre-wake marker before locking the keeper, and the attempted second real Pair
was correctly refused by the Store. Fixture correction did not weaken production
checks. The earlier vet on manifest b2a101ca7453422fbcbbd2b4b7045665ed75eb77ae02d6563914441a0a6f715b
passed; only the synthetic-directory test changed afterward.

The remaining managed tests cover lost committed Join ACK and byte-identical
restart retry, durable ACTIVE before IPC completion, failed activation-write
recovery without a second Join, unknown reservation retention and safe known
history collection, actual Leave/Owner pin revocation/Hub Pair revocation/epoch
change/native-access expiry/peer ceiling, normal Owner dual-consent transition,
Node plus ordinary session heartbeat concurrency, delayed reply and concurrent
Leave, unchanged-expiry no-write (bytes and inode), concurrent genuine encrypted
outbox ACK loss, current-state merge and failed batch-persist rollback/restart.
The cold Node-only case uses the actual 30-second worker and shortens only its
disposable Hub's original native/access leases to 40 seconds; it crosses that
old deadline with no joined MCP, first tool or model call. It is not a real
five-minute native Runtime wait. The ordinary concurrent session call follows
the same heartbeat endpoint as MCP; it is not an actual MCP worker lifecycle.

All gates use the pinned Go 1.27.3 Docker image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network-disabled containers, disposable loopback Hub/SQLite/PQ/native-record
fixtures, source/module read-only mounts and task-local caches. Source-after
checks compare every manifest file before subsequent edits. Actual Runtime,
Windows IPC/GUI/ACL, Android, physical devices, public HTTPS, real credentials,
model service, resident deployments and installation acceptance are **NOT_RUN**
by these Hub/Node gates and must remain separately attributed to consumer/QA
records. Private Version 1 state compatibility is directional, as in the contract.

### Final frozen gates and storage-availability correction

On dirty c3a1517 source manifest
`3c64bf38eb1112da1141b8c9e8c5f85dcfe2f85638d62a3fa63f6eafa4db34d2`,
`managed-pair-final-functional-20261020T182137Z` passed 62/0/0 (33 top-level,
including the operator subprocess harness's empty parent selector, which is
not an independent product pass). The full Nodekeys package regression,
`managed-pair-final-nodekeys-regression-20261020T182240Z`, passed 120/0/0
(74 top-level); `managed-pair-final-vet-20261020T182137Z` exited 0.

The same source's `managed-pair-final-race-20261020T182137Z` is **NOT_A_PASS**:
it exited 1 at Go's default ten-minute package timeout (cmd package 600.044 s,
runner 639.849 s). It emitted 27 completed case passes and no case-failure or
DATA RACE warning, but the package gate failed. At timeout the next test was
still in its disposable Hub bootstrap HTTP setup. Do not turn partial case
events into a passed gate or combine them into a clean-commit aggregate.

Root's final review distinguished an unavailable database path from a missing
authorization row in a successfully opened valid original database. Only the
former's `os.ErrNotExist` permanent-stop classification was removed (plus its
unused import); all other production blobs remained unchanged. A new actual
TCP/SQLite case moves the existing synthetic database away, verifies no POST,
no replacement database and no marker change, restores the same database within
the last proven lease and renews the same frozen binding. It then repeats the
fault past the last proven deadline, persists STOPPED, restores the database,
and proves there is no renewal or second Join. Restoring storage cannot borrow
a new lease or peer ceiling. Confirmed missing policy/pin and revoked/changed
authority still stop through the existing services.

The resulting dirty c3a1517 source manifest is
`6f16c49d2d13afef89d48f7e342918199812f786da0b9484f3122b5c53d08a7f`.
`managed-pair-storage-boundary-functional-20261020T183520Z` passed 22/0/0,
`managed-pair-storage-boundary-race-20261020T183529Z` passed 22/0/0
(10 substantive top-level tests and 12 nested cases, 292.977 s), and
`managed-pair-storage-boundary-vet-20261020T183529Z` exited 0. These scoped gates
cover all new refusal/storage cases and the existing-only reader, with an
explicit 20-minute test budget. They are the bounded follow-up to the timed-out
aggregate, not a claim that that aggregate passed. The prior core race gate on
e727d8ab remains separately attributed above. Each completed final gate has a
full unchanged-source after-check. After those checks, only this validation
record was appended; the candidate records final per-file hashes and each gate's
actual source. No Runtime or platform exclusion above is upgraded by these gates.

## 2026-10-22 installed local Node discovery

The shared local-discovery contract was reviewed before implementation. This
checkpoint separates file installation, the user's explicit start of the existing
Node Agent, and normal Codex plugin installation/trust. It owns only Node/shared
resolver/intent implementation and the existing contract/validation documents.
Component installation assets, MCP/Hook/plugin consumers and their actual Runtime
acceptance belong to separate App/QA changes. No new daemon, Hub public wire,
catalog operation, identity, Owner proof, grant or registration authority is added.

On dirty base `25cca3a9764cf485da2242efc03d92f594a465ae`, the initial compile-only
gate `local-node-discovery-compile-20261022T145548Z` exited 0 with zero tests,
manifest `0146687a3f035776ec851f03b1f56dc24c756a6665f709cbc3e68a288aa47e16`.
`local-node-discovery-focused-20261022T150025Z` passed 41/0/0 (14 top-level,
including the old operator subprocess harness's empty parent selector), manifest
`abba6f59e95b53d933d32b658ef2c66f9c26db052d6c250c5e019a4f71c94d81`.
Root's strict-transport review then added a fixed CONFIG_REQUIRED refusal for
an already selected strict-PQTLS runtime/transport, with no Pin/API extension or
standard-HTTPS fallback. Publication/Close are serialized within the existing
bridge lifecycle to preserve exact owned cleanup.

The final frozen source manifest is
`d17195b5486a3674d1e4f13eadd68a536325397686f6cd8e4c662c3f75e16298`
on that same dirty base. Its gates are separately recorded:

| Gate | Result | Scope |
| --- | --- | --- |
| `local-node-discovery-final-functional-20261022T150232Z` | exit 0, 96 pass / 0 fail / 1 skip; 51 passing top-level tests | New local discovery and pin-aware helper, all selected old operator/Endpoint/Agent/multi-Hub/shared-RPC regression selectors. Includes an empty subprocess parent harness, not a separate product acceptance. |
| `local-node-discovery-final-race-20261022T150305Z` | exit 0, 29/0/0; 11 top-level tests; 29.123 s | All new discovery/pin tests, original client recovery/process-lock and exact sealed RPC/claim-ticket recovery. Explicit 20-minute package budget. |
| `local-node-discovery-final-vet-20261022T150305Z` | exit 0 | `go vet ./cmd/cicada`. |

The skipped `TestMachineMultiHubDockerFixture` requires its explicit outer-fixture
opt-in; it is **NOT_RUN**, not a pass. Selected ordinary multi-Hub deterministic
regressions do run. These gates use the pinned Go 1.27.3 Docker image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network-disabled containers, disposable paths/sockets/loopback services, source
and module read-only mounts and task-local build caches. The original unchanged
TCP/PQ Endpoint/operator tests provide their bounded existing service interop;
this is not an independent outer multi-container deployment claim. Every gate
has a full unchanged-source after-check before subsequent documentation edits.

The new positive socket test uses the original synthetic Node-Control key/state
and actual production bridge/publisher. It verifies the exact original approved
binding, independent session/outbox paths, zero Hub HTTP calls, unchanged key/
state bytes, no cache or database creation, clean stop, a new process instance
with an identical stable pin after restart, and rejection of changed key epoch.
A separate selected strict-runtime context refuses CONFIG_REQUIRED while the
existing bridge remains alive; no TLS implementation is substituted or exercised.

Defensive input fixtures use explicit synthetic local socket replies, not positive
Hub authorization. They verify duplicate/unknown/trailing fields, changed nonce,
instance, root, digest, socket and key version, wrong permissions/symlinks, size
and directory limits, two candidates' ambiguity and exact selection, refusal to
skip a bad candidate, the shared three-second deadline and a shorter parent
budget across hanging sockets. CAS cleanup retains a replacement locator. Bad
opt-in CLI configuration fails before Node state/locator creation. The old
low-level bridge publishes nothing without an explicit root.

The pin-aware operator helper persists the complete stable pin before IPC, keeps
an uncertain original through client restart and a new live instance, refuses
retargeting authority/epoch/key versions/fingerprints/state/writer/cache paths
without modifying the original bytes or sending IPC, and preserves legacy
unfenced material as CONFIG_REQUIRED in root mode. The original explicit legacy
recovery remains usable; an uncertain result cannot become acknowledgeable.
New optional `connection_pin` metadata makes private intent compatibility
directional: an older strict reader may reject it. No automatic downgrade or
state replacement is supported.

Actual installed-plugin execution against an already running Codex daemon with
stale PATH/absent Cicada environment, actual separately App-approved two-Node
ambiguity, native Runtime, Windows IPC/ACL/UI, Android, physical devices, public
HTTPS, strict-PQTLS installed discovery and resident deployment are **NOT_RUN**
by this producer checkpoint. Consumer/QA must attribute those results to their
own integrated source/artifacts. No real service, key or user-state data was
used as a disposable fixture. The final candidate records any documentation-only
overlay and maps each committed blob to these actual dirty sources.

### Reviewed existing-root compatibility and unknown-locator preservation

Root's code review identified that an existing protected installation root can
be 0755 while the component installer deliberately preserves its permissions.
The earlier implementation required 0700 for the root and would have rejected
that valid installation. This was found by read-only review, not a claimed
successful real-user upgrade. The resolver/publisher now preserve the original
same-UID root with no group/world writes, retain pinned ancestor handles and
require only their new `run`/`nodes` directories to be 0700 (locators 0600).
A positive real-bridge case verifies a 0755 root remains 0755; 0775/0777 and a
symlink root still fail without chmod or Hub requests.

`local-node-root-permission-functional-20261022T151001Z` passed 26/0/0
(8 top-level), dirty manifest
`3c398eb9c09b9cdc14a9022081515fa7d3b91285e921f0b797fc02f543d0f669`
on the original 25cca3a base. The final publisher also strictly recognizes an
existing same-slot locator before replacing it; malformed/unknown private bytes
are retained. Its negative fixture verifies retained bytes and the Node's own
digest/instance rejection, without a Hub call or new authority. Directory capacity
is a bounded resolver limit, not a new cross-process installation quota service.

The resulting reviewed source manifest is
`dad3e2f2163d1ecd500769cae11ceaae86341da70cbe1e97684e489b54c1fa0d`
on dirty `25cca3a9764cf485da2242efc03d92f594a465ae`.
`local-node-discovery-reviewed-functional-20261022T151209Z` passed 27/0/0,
`local-node-discovery-reviewed-race-20261022T151225Z` passed 27/0/0
(9 substantive top-level tests and 18 nested cases; race 26.073 s), and
`local-node-discovery-reviewed-vet-20261022T151225Z` exited 0. These gates cover
all new discovery and pin-helper cases, including the root/publisher corrections.
All source-after checks cover the complete source manifest before this final
validation-only append. The broader 96/0/1 and prior race 29/0/0 remain attributed
to their earlier d17195b5 source; no aggregate clean-commit pass is invented.
The previously listed outer-fixture skip and actual consumer/platform exclusions
are unchanged. The candidate maps the final nine blobs and all gate receipts.

## 2026-10-22 managed-daemon TUI source compatibility

The actual QA three-stage run `run-20261022T160022Z-I8KCar` remains **FAIL** on
its original dirty 737f37f input. Its retained `result.json` SHA-256 is
`96c4c563513c342c7774f358b34b1d6ceed1aefe172d95bfc23a73028700e2c3`;
input manifest is
`8a04f3736af8c73264009842fded0a3ff8556612ade5420d27252a97a9714cbb`.
The metadata-only whitelist `native-record-checks.json` has SHA-256
`e29e99280650325954d17f44dadf258485ce8495ceb5642c8cacae4d6e72826f`.
Hub independently checked both retained file hashes and read only the whitelist,
not the full native transcript or private bodies/credentials. QA's genuine
Codex TUI records report `source=vscode`, `originator=codex-tui`, 0600 mode,
matching original cwd/current UID/open inode and containment under the original
CODEX_HOME. The Hook process's HOME/CODEX_HOME comparisons are true; direct
observation of its transcript_path is false/UNKNOWN, not newly proven here.
There is no fork in that observed record. A prior QA synthetic control-client
source is separate and is not the basis for product compatibility.

The existing shared transcript verifier accepted only cli or exec/codex_exec
and therefore rejected this exact real TUI tuple after initialization of the
shared daemon through `--remote`. The fix adds only the exact string pair
(vscode,codex-tui). Other vscode originators, missing/unknown/structured-subagent
sources remain refused. SID/session_id, configured record-root containment,
canonical cwd, ownership, non-writable permissions, inode, tickets, epochs and
current authorization checks are unchanged. No generic IDE or subagent support
is claimed, and source metadata does not become a human or cryptographic proof.

The synthetic reproducer first failed as expected: on dirty
`737f37f095e70ab3390e826d688f063bf00e59b5`,
`codex-daemon-origin-red-20261022T160429Z` exited 1 (0 pass / 1 fail / 0 skip),
manifest `59d13c604b7209acf4b4700772357b9d9d43232a0c12ad6f86c1c83f66ba638e`.
It retains its own source-after check and is not counted as a pass.

After the single source predicate and matching contract correction, manifest
`6cdb59965d9e696d53b31ec181fb9a453bc065257e33405d08f3eee53f35b4ad`
on the same dirty base passed
`codex-daemon-origin-functional-20261022T160609Z` (4/0/0),
`codex-daemon-origin-race-20261022T160609Z` (4/0/0, 23.296 s), and
`codex-daemon-origin-vet-20261022T160609Z` (exit 0).
These are four substantive context/ticket tests; the new table-driven test
checks the exact new tuple at 0600 and the already supported non-writable 0644
mode, wrong/missing originator, unknown/structured source, wrong SID/session_id,
cwd, writable record and symlink. Existing context atomic consumption, binding,
expiry, capacity and restart tests run in the same selected scope. No native
Codex process, provider/model or public deployment is executed by these producer
gates. They use the same pinned offline Go 1.27.3 Docker image and isolated
synthetic files as above. Every completed gate's source-after check is unchanged;
only this validation append follows those checks. The new candidate contains
exactly the shared verifier, its tests and existing contract/validation files.
QA must rerun the actual installed-plugin/shared-daemon chain on the integrated
fix before that original actual scope can acquire a separate passed receipt.

## 2026-10-22 local Codex context diagnostic stages

The bounded change adds `*LocalCodexContextError{Stage string}` to the shared
local transcript verifier. `errors.Is(err, errLocalCodexContext)` and the generic
public error text are preserved. `errors.As` exposes only one fixed stage:
ROOT, PATH, OWNERSHIP, PERMISSION, INODE, METADATA, SOURCE, SESSION or WORKSPACE.
It includes no native SID, path, record body or credentials. No IPC field or
permission rule changes. In particular mode-022 records remain refused by this
legacy verifier; the proposed local-domain profile is separate and unimplemented.

Validation on 2026-10-22 used a dirty tree based on
`96dcbe0fee8dc41644039f222933de777bb7e78c`, with full source manifest SHA-256
`ebdd38710098a8791c697fc2dc1ab529ce5d1cea6f5ce19747873b58c1a3cd8a`.
The manifest also contains the non-executable, uncommitted local-domain proposal;
that proposal is outside this checkpoint. This validation record is a subsequent
documentation-only overlay. The implementation SHA-256 values are:

* `cmd/cicada/local_codex_context.go`:
  `766d4e7b8824666a5753e16970570493f619d8ad81a436232ac9bbbcce1f9cf5`
* `cmd/cicada/local_codex_context_test.go`:
  `6a7dbcbbc74f840fe114fd61188f4d1c94bba3e39c37b59e2df0d21cb6a3c715`

All checks ran in a disposable network-disabled Docker container as UID 1000,
with Go 1.27.3 and pinned image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
Source and module-cache mounts were read-only. Post-check hashes confirmed every
manifest file unchanged throughout each gate.

| Command (under `cicada-go`) | Result | External evidence directory |
| --- | --- | --- |
| `go test -json -count=1 ./cmd/cicada -run '^TestLocalCodexContext'` | 11 pass, 0 fail, 0 skip; 5 top-level tests | `local-context-stages-20261022-20261022T172356Z` |
| Same selection with `-race` | 11 pass, 0 fail, 0 skip | `local-context-stages-race-20261022-20261022T172428Z` |
| `go vet ./cmd/cicada` | Exit 0 | `local-context-stages-vet-20261022-20261022T172428Z` |

Evidence directories are under
`/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`, each retaining
`source-manifest.json`, `receipt.json`, `source-after-check.json` and test output.
The new synthetic tests distinguish permission, source, SID, cwd, metadata and
containment failures while asserting the unchanged refusal and public error.
Existing context tests cover HMAC binding, one-use concurrency, expiry, restart,
source whitelist and symlink/mode refusal. No real credentials or native records
were used. Actual App consumption, remote issuer diagnosis, real Codex Runtime,
Windows, Android, physical devices and public HTTPS are NOT_RUN by this checkpoint.

## 2026-10-22 domain context IPC producer dependency

The small producer checkpoint adds comparable value fields
`LocalDomainVersion` and `LocalDomain` to `localEndpointRequest` and the consumed
`localCodexContext`, with `VerificationProfile` on the latter. A zero selection
omits all new fields from legacy JSON. Only explicit `endpoint_register` can
carry a complete version-1 selection; Pair/Leave/directory requests refuse it.
The HMAC covers the consumed context, so modifying its profile/policy metadata
invalidates the original ticket. Persistent request equality survives JSON
reload because selection is a value, not a pointer. `localEndpointResult` gains
an optional typed `LocalDomain` result. Default verification remains strict;
selected domain registration deliberately refuses until its backend is connected.
There is no caller-selected issue profile and no relaxed native-record check in
this checkpoint. Hook/MCP consumption and operator-ticket support are separate
implementation work; no business availability is established.

Normal and race commands each passed 13 tests (7 top-level), with no failure or
skip, and `go vet ./cmd/cicada` exited 0. The test selection was
`TestLocalCodexContext|TestLocalDomainEndpointRequest`. These ran in the same
pinned Go 1.27.3, UID-1000, network-disabled Docker environment described above,
on dirty base `79e789b7eb5ada0d60b13a5618ab4ad3b0d54ab1`. Full source manifest
SHA-256 was `6221c4d8d3ae5eb8e439a28633041f2ac6a2914037be78bac7bfd8c10f3c1edd`.
Every manifest file stayed unchanged through each gate. That source includes
uncommitted Store/Server work, compiled as dependencies but **not executed or
accepted as a service** by these tests; it is outside this small checkpoint.
This appended section is a documentation-only overlay.

Evidence under `/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`:

* `local-domain-ipc-producer-pass-20261022-20261022T185349Z`
* `local-domain-ipc-producer-race-20261022-20261022T185349Z`
* `local-domain-ipc-producer-vet-20261022-20261022T185349Z`

The first attempt retained 12 pass/1 fail because the new test fixture used a
request ID without the required timestamp binding. Reusing the existing proper
synthetic request constructor fixed the fixture; no production guard was relaxed.
Actual App/Node domain communication, permission-mode diagnostics, external
interop, other-UID domain signing, Windows/Android and public HTTPS are NOT_RUN.

## 2026-10-23 MCP directory target filters and Hub Nodes lookup aliases

The user reported a successful literal A Join followed by
`CODEX_TOOL_ARGUMENTS_INVALID` while resolving the target UX-B.
The sanitized invocation contained the advertised `query` and string
`workspace`, plus the existing connection-nonce context. No real native record,
conversation body, nonce, credential or full failure payload was read by this
producer. The fixed-stage refusal happened before Node ticket issuance:
`cicada_resolve` advertised `workspace`, but the common argument guard treated
that target filter as a forbidden caller identity field. The same conflict
affected the declared Node/harness filters of the five directory tools.

The fix closes validation over the exact existing per-tool properties, allowing
only declared target filters with their declared types. String values, including
empty strings, are retained without stripping or rewriting in the Hook/MCP
argument digest. Null and other wrong types refuse; `limit` uses the existing
strict integer parser. Unknown and caller identity/credential properties refuse
even when null or empty. Other tools retain their identity guards. The change
does not supply a caller identity or alter current authorization, scope, Owner
trust, message permissions, native records or the context-ticket lifecycle.

Hub Nodes also omitted the existing `/v2/fabric/find` and `/v2/fabric/inspect`
POST aliases. They now enter the same exact authentication, native self guard,
bounded decoder and `Fabric.Resolve` privacy chain as `/v2/fabric/resolve`.
MCP keeps each original HTTP path. No general Fabric prefix or new permission
is enabled. Incorrect methods, extra segments, zero directory rights, wrong
Group headers and current revocation still refuse.

All producer gates used a dirty tree based on
`cd9a396a6e91d874fbb821044e39221bc2e49a49`, synthetic keys/records and disposable
loopback HTTP/private IPC. The pinned Go 1.27.3 Docker image is
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
with network disabled, UID 1000 and read-only source/module mounts. Every
completed gate has a successful full source/base postcheck. Artifacts below are
under `/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`:

| Gate / source manifest SHA-256 | Result | Artifact directory |
|---|---|---|
| Parameter RED, old production + new tests; `d76cb240074846b544d4c41c11707f600e41dca26657a6d0efc6d6b2ffdb3d14` | Exit 1, 0 pass / 13 fail / 0 skip; 3 top-level failures. All five declared-filter cases refuse; actual Hook emits the incident's fixed error code before a Node ticket | `mcp-directory-filter-red-20261023-20261023T034557Z` |
| Alias RED, old production + new TCP assertions; `5f6f86945e331ba30484fe6ab5247f643f72fe37566cab1571f681f462259aa2` | Exit 1, 0 pass / 2 fail / 0 skip; exact find alias returns 404 before the expected existing zero-rights 403 guard | `mcp-directory-alias-red-20261023-20261023T034740Z` |
| Final normal, `278897fc018e1108dbfbe78f958c34c2707b61048436e6d195aae988be66d03a` | Exit 0, 58 pass / 0 fail / 0 skip; 12 top-level, 28.507 seconds | `mcp-directory-filter-final-normal-20261023-20261023T035315Z` |
| Final focused race, same source | Exit 0, 27 pass / 0 fail / 0 skip; 6 top-level, 146.847 seconds | `mcp-directory-filter-final-race-20261023-20261023T035315Z` |
| Final vet, same source: `cmd/cicada`, `internal/server`, `internal/fabric` | Exit 0 | `mcp-directory-filter-final-vet-20261023-20261023T035315Z` |

The final normal selector is
`^Test(MCPDirectory|CodexDirectory|LocalDomainHookMCPRelayAndNativeCallbackRealTCP|CicadaMCPRejectsForgedIdentityAndCredentialArguments|CodexManaged|CodexHookInvocationDiagnosticsRemainClosedAndPrivate|LocalDomainRealTCPActivationDelegationDeliveryAndRevocation|NativePairPeerRealTCPConsentResolveAskClaimAndRevoke|FabricG5DirectoryPrivacyHTTP|DirectoryOwnerPrivacyAndExactContextResolution)`
over `cmd/cicada`, `internal/server` and `internal/fabric`. The focused race
selects the exact two new unit/Hook test names, existing caller-claim rejection,
the Hook/MCP domain chain and ordinary domain/legacy Pair TCP tests; its exact
arguments are retained in its receipt. It excludes the maximum-native-fields
subcase, which passed in the final normal gate.

Coverage includes all five advertised filter sets and wrong/null types; unknown
and reserved keys; the same business digest at issue/consume; by-name synthetic
UX-B resolution with workspace/Node filters; unchanged caller whoami; incorrect
target filters and empty list results; alias methods and bounds; zero rights,
wrong Group and revoke; foreign-Owner redaction; and original Pair peer-only
resolution semantics. The integrated chain uses real Hook, Node IPC, Hub TCP,
PQ signatures and persistent stores. Its queue subprocesses are visibly
synthetic; it does not establish real Runtime consumption.

An initial GREEN attempt is retained as failed: normal 54 pass / 4 fail and
race 11 pass / 4 fail on manifest
`3a032f41e32c9cacc229745491801853f97fc37a02709c723e9a96f29d9b4abe`.
The added helper incorrectly expected a Pair caller to resolve itself; the
existing Pair resolver permits only its other exact peer. Only that test
expectation was corrected, preserving production Pair behavior and comparing
whoami before/after filtering. That race command also omitted the two new unit
tests through an overexact name selector; the final selector includes them.
No earlier whole gate is relabeled passing. This validation section is a
documentation-only overlay after the final gates; code/test hashes are unchanged.

QA independently reproduced the old-source refusal through real Host on
`run-20261023T035230Z-ZRfZNw`; its `result.json` SHA-256 is
`1991f26bb347c6012f939c528174bdd09673e96d6db52fce4c81a1cd570d4c5f`.
It crossed literal A/B and whoami before the filtered resolve refusal. QA owns
the same-driver new-source Runtime GREEN and native App acceptance records;
they are not claimed by these producer gates. Fresh-install automatic Owner
pin establishment (FB-03), Windows, Android, public HTTPS, cleanup/install and
deployment are outside this patch's executed acceptance. Existing scoped Native
and login-expiry successes retain their own historical sources.
# Owner-managed Groups: shared DTO and crypto source phase, 2026-10-26

Root approved the contract at `e3544d96118dfaa284f39c6d0f6fa787b228a4e5`.
This producer checkpoint implements only shared Go DTOs, strict request/review/
result validation, separate Owner request/persistent policy/Node-key proofs,
private native deny and registration commitments, and the existing PQ carrier
with exact profile-specific recovery limits. It does not install HTTP routes,
change Store schema/state, supply a Node/native-context/Guard/MCP/App consumer or
enable availability. Account authentication remains independent of Owner proof.

The evidence directory is
`/home/zyf/Cicada/.local/evidence/owner-groups-shared-20261026T114110Z/`.
Runs used Go 1.27.3, offline modules, synthetic identities and a dirty source
based on `e3544d9`; `source-before.json` and `source-after.json` fingerprint every
file in the three tested packages, module files and contract/check inputs.
The fingerprints match across the runs and are checked against the final
checkpoint. Logs and full commands are retained in `validation.json`.

| Gate | Result | Scope |
| --- | --- | --- |
| Focused normal | 36 pass / 0 fail / 0 skip; 21 top-level tests | New Owner/Node crypto, all three action reviews, actual five-request PQ roundtrips, original status/reconcile/nested receipt, uncertain outcome, canonical/authority/source negatives; selected existing Link/wire/activation/local-domain compatibility |
| Focused race | 15 pass / 0 fail / 0 skip; 12 top-level tests | New shared DTO/crypto/PQ codec tests only |
| Endpoint metadata + oracle | PASS; 5 tests / 60 rejected synthetic mutations | Compiled shared field order/phase is also checked in the Go suite; availability remains false |
| Activation / App-Node / Pair metadata | PASS | Existing scope/catalog compatibility only |

Initial failed scoped runs remain described in `initial-attempts.json`: the
generic large-frame opener lacked a trusted expected route, and one carrier
fixture incorrectly assumed that the maximum plaintext must fit the packet cap
after nested base64. Both were corrected before these final gates. Those early
dirty inputs lacked full source fingerprints and are not assigned the final
source or reported as passes.

Historical zero-time signature verification authenticates retained evidence
only. Actual Store/Node authority, atomic CAS/nonce/receipt persistence, Owner
control transitions, per-source five-right Actor Guards, independent renewal,
fresh Hook context, current peer evidence and self-groups MCP remain unimplemented
by this phase. Their tests, disposable Docker interop, maximum legal product DTO
carriers, App integration, actual Runtime and M1–M8 remain **NOT_RUN**. The generic
carrier test is not a maximum legal product DTO measurement. Windows/physical
device/public HTTPS retain separate acceptance. No real state, credentials or
resident deployment was used.

The shared commit `c8d29d8358206f5e15874d8a1b6c7f6ba54c9204` was integrated by
Root as `110db1e506d6fc012f3c42fba4d504e27a561406`. Its tests keep their original
source attribution. A separate SDK review fix adds exact ADD/REMOVE relation
revision checks, REMOVE's retained authenticated prior head argument and exact
policy-reference inheritance, and binds current snapshots to the operation's
Node/Network/Group. It changes no wire DTO/JSON field or schema. The caller must
retain REMOVE's prior head from the same target/decision-revision authenticated
card with its pending operation; a later snapshot cannot substitute for it.

Fix evidence is
`/home/zyf/Cicada/.local/evidence/owner-groups-sdk-fix-20261026/`.
Targeted normal and race each pass 12 test events / 9 top-level tests, with zero
failures/skips; metadata and five oracle tests pass. This includes wrong head,
policy ID/epoch and revisions, cross-Group/Network/Node current snapshots and an
unresolved operation with untargeted current cards. Before/after fingerprints
match and are checked against the fix commit. Actual Store/Node/Guard and all
M1–M8 remain NOT_RUN.

Node shared supplement evidence is
`/home/zyf/Cicada/.local/evidence/owner-groups-node-shared-20261026T124346Z/`.
Normal has 21 pass / 0 fail / 0 skip (18 top-level); race has 17 / 0 / 0
(14 top-level). This validates the closed Node DTOs, frozen projected
head/relation/manifest, exact manifest/challenge issue time and CAS bounds,
relation/authority page bijection, strict source union, raw Node replay digest,
scoped 128 KiB Node reconcile carrier and authenticated original APPLY no-effect
fence. Metadata/oracle checks pass. The unique targetless fence code is
ORIGINAL_NOT_ADMITTED; unseen originals are fenced even while fresh, and no
wrapper status or missing row settles pending. Node/Store/MCP/App consumers,
full current Guard/renewal state, maximum legal product DTO, Docker interop,
Runtime and M1–M8 are still NOT_RUN at this shared supplement. Source
fingerprints match before/after and are verified against its commit.

### Hub Store/RPC/source Guard candidate, 2026-10-26

The Hub implementation candidate uses schema 69 and retains the original
Owner, account, Node, Endpoint, key, binding, access-session and epoch coordinates.
CREATE is management-only; ADD remains PENDING_KEY until the exact signed Node
projection completes. Owner heads and original sealed operation receipts are
permanent. Group removal/expiry cannot fall back to the default contribution.
Public capabilities remain false pending the integrated Core/CLI validation.

Source-specific evidence is
`/home/zyf/Cicada/.local/evidence/owner-groups-hub-core-20261026T144616Z/`.
`source-before.json` records the dirty input at `3e9f01e` and 1,572 Go/module
hashes; the receipt verifies those bytes against the eventual checkpoint. A
standalone HEAD is not used to identify the pre-commit build.

| Gate | Result | Scope |
| --- | --- | --- |
| Relevant deterministic packages | 209 pass / 0 fail / 0 skip; 101 top-level | Owner/Node ledger, actual source Guards, strict wire/crypto, current directory targets, original lease, migration, legacy LocalDomain/sealed messaging and bounded directory/resolve compatibility |
| Focused race | 4 pass / 0 fail / 0 skip | Two actual Store source/expiry tests and two production HTTP/PQ flows |
| Disposable Docker | 4 pass / 0 fail / 0 skip | Same four Store/HTTP tests; pinned Go 1.27.3 image `sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`, network none, UID 1000, read-only source/modules, isolated SQLite and loopback listeners, Control nil |
| Contract metadata/oracle | PASS | Inventory/schema 69, false availability, five oracle tests / 60 rejected mutations; wire 1/catalog 55/old activation scopes unchanged |

The HTTP flows use the actual HubNodes Router, SDK packets, retained original
Endpoint candidate and delegated Node proofs, then peer-key/SEND/CLAIM/final
injection authorization. They cover actual five-minute cold renewal without
credential/identity replacement, ACTIVE removal preserving another Group,
READ/PREPARE lost-response recovery, packet conflict 409, uncertain outcome 503,
Root-revoked historical receipts and unknown query wrappers after login changes.
The Store tests place wider rights on the actual Principal before activation;
both Fabric-facing and transactional source Guards still allow only the five
reviewed rights, including denial of legacy global/Group Leave. Expired target
metadata is filtered from the native directory. Finite-expiry boundaries use the
production Store's injected At before/at/after a one-day policy expiry, followed
by reopen/renew/old-proof checks with the original default still active. This is
not a 24-hour wall-clock Runtime result.

The first overly broad normal selector retains a FAIL for the pre-existing
`TestStateMaintenanceDirectoryPolicyAndFailureCleanup` fixture: umask 077 made
its requested 0755 directory become 0700 before product code ran. Its exact
fixture passes separately under expected umask 022 (3 events / 1 top-level), with
no production or unrelated fixture change. That broad run also retains one
NOT_RUN live-owned-native test. Neither result is relabeled as a product pass;
the final relevant selector has no failure/skip.

Dependencies are the Owner Store checkpoint `fbcbe68`, Node Store `57ffe0e` and
HTTP/recovery fix `d1c6902`, with parent-branch mappings recorded in the receipt.
Their earlier exact overlay records retain their original attribution. Node CLI,
App, real native Runtime/M1–M8, Android, physical devices and public HTTPS are
separate gates. This Docker scope is production Hub/Node-protocol interoperability
with synthetic test clients, not a complete installed Node daemon/native Runtime.
Portable Hub checkpoint/export/restore for schema 69 remains unreviewed and
fails closed; ordinary Store reopen and exact durable-receipt recovery are
separate tested behavior. No shared development Hub or real credentials were
used, and no merge/push/deployment is included.

### Integrated availability and registration heartbeat candidate, 2026-10-26

The configured complete HubNodes service now advertises Available and
NativeSelfGroups. Inventory defaults and implementation phase are updated to
INTEGRATED_CANDIDATE; the bare DTO factory still advertises neither capability.
Availability supplies no Root, caller or Group authorization. This is a local
integration candidate for QA, with no Runtime/M1–M8, release or deployment pass.

The existing empty-Group heartbeat now has a narrow original-registration
path shared by full Fabric and bounded HubNodes routers. It checks the exact
original token/anchor, current Owner/Node and live native/access leases after
taking the writer. It renews liveness for five minutes, returns no Group or
membership authority, preserves key/token/IDs/epochs and creates no permanent
Node operation receipt. It works with G1 denied while G2 is active and after
last-Group removal. A cold token is rejected; resumption still needs the exact
signed Node renewal. The zero-Group actor rejection also exposed and fixed a
nil lookup for an absent Group; absence now denies rather than panicking.

Evidence is
`/home/zyf/Cicada/.local/evidence/owner-groups-live-cap-20261026T152436Z/`.
The combination uses canonical `5d0699d` (Core, Node CLI and App recovery) plus
hashed parent Hub changes. A reverse overlay supplies the 67 exact committed
Node CLI/nodekeys differences over the parent tree so runtime inventory reads
use the actual candidate JSON. Production HTTP, legacy LocalDomain TCP and
inventory checks pass 12 events / 5 top-level, with zero failures/skips; the
new production heartbeat case passes under race (1 event, zero failures/skips).
Metadata and five oracle tests pass. The receipt records the exact snapshots;
a dirty combination is not identified solely by its HEAD.

The first combination retains a consumer FAIL in
`TestEndpointGroupsExplicitJoinKeepsG1DenyAndG2WithoutAutoSelection`: enabling the
real service lets the ordinary managed wake batch observe relation revision 3
before the scripted fixture sends revision 2. Diagnostic comparison confirms
the original anchor is identical; the production rollback guard correctly
rejects the stale scripted snapshot. The Node writer is fixing only the fixture
under its existing mutex and retaining its actual anchor/receipts/high-water.
This failure remains unresolved at this candidate checkpoint and is not a pass.
Earlier inventory phase/default expectation failures and the Go-only-overlay
runtime-resource mismatch are also retained; final inventory/metadata checks
use the new availability values and pass. Final integrated consumer and real
Runtime gates remain pending. The previous Docker receipt belongs to Core
`755053b`; no new heartbeat Docker result is claimed here.

### Network source ceiling correction, 2026-10-26

A real full Fabric router with Control absent accepted the original registered
Endpoint's Network token for directory discovery after its Principal received
wider stored Network grants. NetworkAllows also accepted direct.send, and
global Network Leave revoked the original enrollment/access. This RED is
retained; the bounded HubNodes router's missing routes are not an authorization
oracle for the full router.

The service and transactional Network guards now cap registered Endpoints at
zero Network business rights, including bilateral participants and global
Leave. Self identity, native self-binding and original registration renewal
remain separate. The Endpoint invitation path now passes its existing
NetworkAccessScope into the transaction that rechecks authority and inserts
the invitation; the Owner CLI primitive remains available. A deterministic
ordering test uses the same authenticated scope before/after registration:
the independent enrollment succeeds before registration and the stale scope
cannot borrow Principal grants afterward. No dedicated scheduler race inside
that transaction is claimed.

The tested source is parent `56f01a7` plus the exact correction, not that HEAD
alone. Evidence at
`/home/zyf/Cicada/.local/evidence/owner-groups-network-guard-20261026/receipt.json`
has SHA-256
`c4da83b441dd9e69b6519727ed4c7484ebd931adf2f6c8873ce0b7483be78246`.
All 1,576 Go/module source hashes match before and after the gates. Final
normal tests pass 62 events / 15 top-level, race passes 6 / 3, and disposable
Docker passes 5 / 2, each with zero failures/skips. The Docker tests exercise
actual full-router Network rejection and registration-only heartbeat with
synthetic keys, UID 1000, no network, read-only source/modules and pinned image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
Contract metadata still passes with wire 1, catalog 55 and original activation
identifiers. The first Docker attempt could not execute the test binary from
its noexec temporary mount; its failed environment record is retained and is
not counted as a test pass. Final gates use an executable disposable tmpfs.

The independent nodekeys M2 correction is checkpoint `7d46a02`; it is not part
of these source hashes. QA's earlier real M1/M2 results remain attributed to
their frozen source. This checkpoint claims no real Runtime/M1–M8, Android,
physical device or public HTTPS pass, and changes no protocol identifier,
identity, key or deployment. Schema-69 portable restore remains unreviewed
and fail-closed as above.

### Correlated REPLY current evidence correction, 2026-10-26

Independent Runtime QA found an accepted REPLY with no original native queue
post and no REPLY in the Node Inbox. Its closed live Inbox snapshot is
`/home/zyf/Cicada/.local/evidence/native-pair-acceptance/run-20261026T182541Z-vhrU68/live-inbox-reply-barrier.json`,
SHA-256 `e78c5cf34a74c1b1568b6166eeff2ce64a6d46998477fddd6108da3ce6f56003`.
ASK and REPLY were each SENT once without an outbox error. That evidence alone
did not identify the missing stage and is retained as a failed Runtime result.

The real HTTP regression
`TestEndpointGroupsHTTPReplyPreservesReverseCurrentAndOriginalBinding`
reproduces the precise Hub defect using two original native registrations,
their G1 bindings/keys, an independently Owner-approved G2, real PQ ASK/REPLY,
claim and final authorization. ASK retains its original thirty-minute deadline;
REPLY returns REPLIED and is claimed, but its final authorization omits
EndpointGroupCurrent. The original reverse-pair helper copied the older Pair
and LocalDomain current evidence and omitted the new Endpoint Group current.
The Node therefore had no current source proof to verify before Inbox.Save.

The six-line production correction copies the original current value, swaps
its two Endpoint sources and assigns the reverse peer attempt. It leaves the
original pair/current unchanged. Final carrier construction still binds it to
the actual native-delivery attempt, with the original Owner heads, signed
policies, registration, keys and binding coordinates. No deadline or Guard is
relaxed. The real HTTP test independently verifies both resulting Owner proof
chains, exact reverse sources and original SID/binding; removing the receiver
then denies the same authorization.

Hub gate evidence is retained at
`/home/zyf/Cicada/.local/evidence/owner-groups-reply-current-20261026/`.
The test first fails on the missing current and passes after the correction.
Final relevant normal regression passes 16 events / 9 top-level, the new HTTP
case passes race (1 / 1) and disposable Docker (1 / 1), all with zero
failures/skips. All 1,168 internal Go/module source hashes remain identical
before and after those gates. Docker uses the pinned Go 1.27.3 image above,
UID 1000, no network, read-only source/modules and disposable executable tmpfs.
These synthetic protocol tests do not relabel the failed real Runtime run or
establish a new complete M1–M8 acceptance result.

The original Node writer supplied
`TestEndpointGroupsRealHTTPReplyReachesOriginalNodeInbox` in the same
checkpoint. It reuses the actual TCP enrollment fixture, Owner SDK and original
Node keys. The real claimed REPLY passes the production Node carrier parser,
independent peer proof and pin checks, decrypts with the original key and is
accepted into the original Node Inbox as NODE_RECEIVED with its G2 and causal
request/reply metadata. Four negative cases reject missing current, a changed
original binding, changed source and changed Owner head. The old Store produces
the expected RED at the real Node parser; the six-line Store correction passes
normal (7.001 seconds) and focused race (one main plus four subtests, zero
failures/skips). No native Runtime or OS queue subprocess executes in this gate.

Consumer evidence is
`/home/zyf/Cicada/.local/evidence/owner-groups-node-reply-regression/receipt.json`,
SHA-256 `32e9a93600c1611a17e2368960bc5a2cf274e038ab89e34069904000a073334a`.
Its selected source is clean canonical `4ae7fea` plus exactly the new cmd test
and corrected Store file via Go overlay. Production cmd/internal and module
files are identical between `8d65fbe` and `4ae7fea`; the intervening changes are
QA/driver/docs only. Selected Store SHA-256
`ecaf6320bb20d85e32484b2760b5647a691dc26c3c31b9393e8d80786984ec02`
and consumer test SHA-256
`777c054e15f8bd8c609face11d44035dd3ff5bed722b801bd730f190782778a9`
match the files included in this checkpoint. Its source remains stable before
and after the gates. This consumer combination is separate from the parent
Hub gate tree; neither is attributed solely to a dirty HEAD. The combined
receipt is `owner-groups-reply-current-20261026/receipt.json` in the evidence
directory above. Fresh complete original-Runtime M1–M8 remains pending.


## 2026-10-29 — recovered Complete installs its original Owner head

This producer change is based on `303639d21cc93087bf6fa051f329f95f52f72fb2`
with the retained dirty source manifests under
`/home/zyf/Cicada/.local/evidence/owner-groups-head-continuation-fix-20261029-01/`.
It adds no wire operation, contract revision, identity, external configuration or
business authority. The final seven-path source manifest is
`final-v3/manifest.json`, SHA-256
`861a8d1592ae3aaab0838cf7a65bb43ace95079c1f6cb8f43f018df3da9fe26c`.

The one approved four-original synthetic-native control is retained separately at
`/home/zyf/Cicada/.local/evidence/owner-groups-head-continuation-control-20261029-01/`.
Its `result.json` SHA-256 is
`3893816b61423bf92c5700d52b5bbdd2f8680193a9f054086714d60c716fa16b`.
The diagnostic reported **CONTROL_RED**: a real five-second Complete cancellation
followed by another original native's ordinary Describe settled the identical
Complete receipt without installing its Owner head. A later ordinary maintenance
batch installed it. This proves the missing local continuation; it does not prove
the particular 68-second delay or a GC cause in the retained YY0pOo Runtime.
The diagnostic's test-process PASS means its observation assertions completed;
it does not turn the product observation green.

Recovery now persists the authenticated response before local installation and
clears the original pending outbox only after that bounded installation succeeds.
It uses the original registration and exact Prepare generation/Challenge, existing
Owner pin and cryptographic grant checks, real current time and monotonic head
transaction. A cached response needs no additional reconcile RPC after a local
failure. Unknown evidence, storage failures and canceled budgets retain the
original packet/response. Only a fully verified historical success independently
proved expired, superseded or pinned to a revoked Owner key may settle without
installation; it returns an explicit local terminal error and preserves the
newer deny/head. Other originals can then continue. Historical time never grants
current use. The five-second native budget and 30-second Current remain unchanged.

| Validation stage and retained source | Result | Scope |
| --- | --- | --- |
| `normal.jsonl`, original `manifest.json` | 23 PASS, 0 FAIL, 0 SKIP; 78.650 s | New real recovery control, existing exact RPC recovery and P0 lifecycle; original composed recovery-plus-Describe assertion. |
| `race.jsonl`, original `manifest.json` | FAIL; 13 test PASS and 3 test FAIL; 448.972 s; no DATA RACE | The first head was installed 3.759 s after cancellation, before the subsequent B Describe failed its combined budget. Separately, P0 failed because its required early ACTIVE read was not produced. Neither failure is erased or attributed to a race detector finding. |
| `final/normal.jsonl`, `final/manifest.json` | Recovery test 17 PASS; package FAIL | Recovery and independent later Describe each use their own original five-second operation budget. The new guard's IO assertion incorrectly expected OS error wrapping from the existing string-formatting helper. |
| `final-v2/guard-normal.jsonl`, `final-v2/manifest.json` | 3 PASS, 0 FAIL, 0 SKIP; 0.027 s | Corrected test-only IO assertion and synchronized transport capture; cancellation/storage failures preserve the original and send no extra RPC. |
| `final-v2/race.jsonl`, `final-v2/manifest.json` | 20 PASS, 0 FAIL, 0 SKIP; 346.380 s; no DATA RACE | Both complete recovery branches, cached response reentry, wrong/mixed origin, wrong digest/epoch, missing Challenge, expiry, revoked pin and newer deny; no broad P0 race rerun. |
| `final-v3/late-cancel-normal.jsonl`, final source | 3 PASS, 0 FAIL, 0 SKIP; 15.135 s | The final fail-closed-only delta checks cancellation after historical crypto and immediately before installation. A private test clock cancels at that boundary; the original remains pending. The previous race result remains attributed to v2, not this delta. |
| `final-v3/docker/test.jsonl`, final source | 28 PASS, 0 FAIL, 0 SKIP; test 78.460 s, container 99.699 s; exit 0 | Latest exact six Go files; real P0 lifecycle/RPC tests plus recovery, cached-response guard and late cancellation. Owned container absence and unchanged source hashes verified. |

The initial unused-import build failure, the fixture sequence-floor rollback
failure, the original composite race failures and the IO-assertion failure remain
in their original logs. The fixture correction preserves the already used writer
sequence while reentering the old cached response. It does not change production
sequence semantics. Synthetic verification time qualifies only the expiry
negative; positive installation uses the real clock. Production diagnostic
observers were removed. No new full Runtime, physical Windows, Android, actual
24-hour expiry or public HTTPS result is claimed by these producer checks.

The final Docker receipt is `final-v3/docker/receipt.json`, SHA-256
`e4435cb0fbb4db86cc445733ef9a193aa4eb073d39838a5e3293e259ae9e4ab3`.
It uses pinned image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network disabled, UID/GID 1000, read-only source and module cache, task-owned
build cache and disposable tmpfs. The actually executed test binary SHA-256 is
`2cd4826a799402328aa8c0d355583c2b10fbd78c876f34ea91e55f101026e1f6`.
The Docker gate is a normal test execution, not another race or Runtime gate.


## Closed private context-issuer failure diagnostics — 2026-10-29

Producer base `d4566fcd969424dc47ab811bfdcfd8c65afc59e2` plus the four
`cmd/cicada` files frozen in
`owner-groups-m6-c-selection-control-20261029-04/issuer-diagnostic-review/`.
This independent checkpoint only adds the closed
`CICADA_NODE_CONTEXT_ISSUE_FAILURE` record to existing private daemon stderr.
The record contains a fixed stage/error enum, original budget/elapsed time and,
when an existing cached client can be TryLocked, serialized state size,
managed/generic reserve and 15 presence flags. BUSY/NOT_CACHED are explicit
unknown snapshots. It never opens, initializes or persists a client, and emits
no raw error text, path, identity, argument, code, nonce, ticket or packet.
The private Unix error response, public ticket-unavailable result and original
issuer verification/deadline/authorization behavior remain unchanged.

Normal deterministic checks: **5 top-level PASS**, zero failures/skips, 0.012s:
`TestCodexIssueFailureDiagnosticClosedErrors`,
`TestCodexIssueFailureDiagnosticReadOnlyAndBusy`, and the three existing
`TestCodexHook{InvocationDiagnosticsRemainClosedAndPrivate,
RecordDiagnosticBlocksWithoutChangingOriginal,RecordDiagnosticUsesOnlyTypedSafeStage}`
checks. Evidence is `diagnostic-hook-normal.jsonl` in that evidence root.
The new checks cover typed/wrapped closed errors, sanitizing unknown stages and
errors, retained-state byte equality, absence of synthetic secrets, nonblocking
busy handling and no missing-cache initialization. The earlier two-test run
also passed (0.010s); neither run contains a production credential.

No capacity change or real Runtime retest is part of this checkpoint. The
separate synthetic 04 control reproduces a history-full refusal, but the first
private issuer error and failure-time snapshot for original Runtime blqDI4 and
M7 1JdBiX remain NOT_RETAINED; this logging change does not retroactively prove
their cause. Race, disposable Docker interop, Android, actual Runtime, physical
Windows and public HTTPS were NOT_RUN for this diagnostic-only checkpoint.

## Confirmed context causes in registration verification — 2026-10-29

Producer base `e0a6a21c38be15fd8e88d9291828dabd7741e67e` plus the five Go
source/test files in
`/home/zyf/Cicada/.local/evidence/node-issuer-context-cause-20261029-01/tested-source-manifest.json`,
SHA-256 `71a5a150aaefc055db10017352f0763bd016d297476bd152e30db610de7918b0`.
This is an explicit dirty-source attribution, not that HEAD alone.

The original Hub-policy lookup and registration history/local-key/attestation
checks could fold a real context error into RegistrationRejected; Describe
could fold it again. A private wrapper now preserves only causes independently
confirmed by `errors.Is(DeadlineExceeded/Canceled)`. Structural, coordinate,
signature and other refusals retain RegistrationRejected. An expired/canceled
check context alone never reclassifies a permanent refusal.

The existing private stderr record adds only allowlisted
`registration_substage`, `child_ctx_error` and `underlying_deadline`. It captures
the context at the failed check before cancellation and preserves an inner
substage across Describe's outer classification. Unknown stage/context values
are sanitized; wrapped private error text is not emitted. The existing
nonblocking snapshot, original budget and 15 presence flags are unchanged.

The five-second attempt, original invocation deadline, two-attempt bound and
exact original-pending read eligibility are unchanged. In particular, a failure
after a read has settled does not create a new read, and an unrelated pending
write is never retried by verification. No identity, key, epoch, authority,
wire operation, public interface or caller authorization is added.

| Focused gate | Result |
| --- | --- |
| Normal, frozen five-file input | **10 top-level / 18 test PASS**, zero FAIL/SKIP, 42.555s, wrapper exit 0 |
| Necessary race, same input | **4 top-level / 9 test PASS**, zero FAIL/SKIP, 38.573s, wrapper exit 0 |
| Existing disposable cmd interop selection, same input | **10 top-level / 18 test PASS**, zero FAIL/SKIP, 42.361s, container exit 0 |

Raw JSONL, exact commands, source inventory, test binary hash and cleanup
receipts remain under the evidence root above. The qualification receipt has
SHA-256 `dc45280bc48e48a956800bc1dbcc5aff7b5aca6bd78fa2624f76b3b88854115a`;
the Docker receipt has SHA-256
`3e5256d62f9404896e8a36dd552f0447113d583179ddbf95941226f9090b663e`.
The container uses pinned image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
Go 1.27.3, network disabled, UID/GID 1000, read-only source/module cache and
disposable tmpfs; the exact owned container is absent afterward. `git diff
--check` passes. Only this validation document is added after the Go input
freeze; the five tested Go files remain byte-identical.

The direct verifier test uses the existing synthetic LocalDomain/Node fixture
and actual protected originals/local crypto state. It verifies real canceled
and expired contexts, permanent shape/coordinate refusal, unchanged Node state
and zero extra RPCs. The existing Unix recovery tests retain their exact
original/replay/fresh-read assertions, refusal/changed-native denial, repeated
timeout bound, pending-write fence and original-budget checks. The fixture's
sealed Describe projection is scripted; these producer checks do not establish
a new production Hub Guard or native Runtime acceptance run.

The historical HfnP8D run retains its original result and **NOT_RETAINED**
underlying registration cause. Its closed five-second timing and error enum do
not prove which check failed. This independent cause-preservation fix does not
backfill that cause, turn that cross run into PASS, or rerun complete cross/
M1–M8, physical Windows, Android or public HTTPS acceptance.

## Original ASK cold recovery and opt-in delivery phases — 2026-10-30

Producer base `f9bb826f9e5133296a0c553de266244e7ad7fcdd` plus six Go files
listed in the private evidence inventory
`/home/zyf/Cicada/.local/evidence/node-cold-original-ask-20261030-01/diagnostic-source-v2/manifest.json`,
SHA-256 `b17896f49daa2cda1fad8cc0edf28eeaa342f01ad465647252033a8f8322f27b`.
Tests qualify those dirty source bytes, not HEAD alone. This validation document
is added afterward; the six tested Go files remain byte-identical.

The cold producer test reuses actual HTTP Hub/Owner/Node registration and manual
Group grants, with one legacy-enrolled Node and two synthetic original native
records. It closes the bridge, context and native-history handle, removes the
Node-Control process cache, submits one original sealed ASK while offline, then
reopens the same existing root and runs production `processFabric`. It checks
the original identities, binding/epoch, ASK and write receipts, exact queue
arguments, durable `QUEUE_ACCEPTED`, and a second delivery check without another
ASK or queue invocation. An already completed Prepare's historical Challenge
response may retire under the existing retention rule; its request and the
successful Complete remain exact. The standalone corrected cold entry passes
in 8.179s, with two such retired responses. This is a cold handle/cache test,
not an OS-process restart or two scoped Node Runtime acceptance.

The existing default-off `CICADA_NODE_SEALED_PHASE_DEBUG=1` observer now covers
the poll's inbox recovery, journal open, claim/accept stages, reconciliation and
drain. Poll records omit claim coordinates and do not wrap the context or native
lifecycle callback. The same-Group drain installs its own observer with existing
sanitized original IDs and reports authorization, crypto, local context,
operation scope, writer wait and native queue stages. The existing lifecycle
callbacks additionally emit `QUEUE_WAIT`, `QUEUE_DURABLE` and `WRITER_CLOSED`
END records: command wait succeeded, the original writer outcome was durably
accepted, and that writer closed, respectively. These events do not prove
native consumption or a provider request. The original callback runs exactly
once. The 32-record bound applies independently to each poll/drain observer.
Default-off creates no observer/JSON or callback wrapper; logging failures do
not change delivery. No new protocol, persistent state read/write, authority, identity,
timeout, retry, counter or return-path policy is introduced by diagnostics.

| Focused gate | Result |
| --- | --- |
| Normal, frozen six-file input | **14 top-level / 25 test PASS**, zero FAIL/SKIP, 25.600s, exit 0 |
| Necessary race, same input | **8 top-level / 15 test PASS**, zero FAIL/SKIP, 212.245s, exit 0 |
| Disposable Docker, same normal selection/input | **14 top-level / 25 test PASS**, zero FAIL/SKIP, 25.980s, container exit 0 |

The Docker gate uses Go 1.27.3 and immutable image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network disabled, UID/GID 1000, read-only root/source/module cache and disposable
tmpfs. Exact owned container
`2bb84ef00987b01593d937f8764b622be84633cab6cbbda738169671f8f08352`
is absent afterward. Commands, source copies, binary digest, logs and cleanup
receipt remain under the evidence root above. Logical witness lines are decoded
with existing `owner_groups_logical_events`, joining test2json fragments only
within the same Test/Package through LF. Terminal test actions determine pass;
a deferred witness with error class NONE is insufficient.
The qualification receipt has SHA-256
`3371c9d902171f9b69f5cf23ecfba9fb4427112454db90d3f5684e2db6299b12`;
the Docker/cleanup receipt has SHA-256
`a67d9b55c5eca5a5e6de03cc9883910ca4557b339b6a59ea6c1aece8cdc717e5`.

The three initial standalone cold failures remain retained: a plaintext-only
getter oracle, a missing `fabric_messages` join in the replacement test query,
and an overly broad assertion against allowed Challenge-response retirement.
The initial diagnostic normal run also retains its four failed pre-drain
subcases: its generic test helper performed unrelated identity discovery;
explicit pinned test context corrected that fixture. None is reclassified as
a production recovery failure or erased by later passes. The final normal
selection includes the old Reply refusal cases, exact accepted replay,
historical writer outcome, busy-writer recovery, observer bounds/privacy,
logging failure, four pre-drain HTTP failures, actual Group poll/drain callback
uniqueness and retryable Guard-outage preservation.

Original cross run `run-20261029T235843Z-8b4Xge` remains FAIL at C5 with its
original source/artifacts and **NOT_DETERMINED** product cause. C1–C4's actual
Runtime passes remain separately attributed; C6/C7 were not run. This producer
test does not reproduce that failure, establish two scoped Node/process-loop
recovery, or qualify actual Codex daemon behavior. No Runtime rerun, App change,
physical Windows, Android or public HTTPS validation belongs to this checkpoint.
