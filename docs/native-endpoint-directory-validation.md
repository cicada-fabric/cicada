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
