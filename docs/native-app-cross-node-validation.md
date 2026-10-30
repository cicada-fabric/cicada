# Two-Node native acceptance entrypoint — 2026-10-29

## Current scopes — 2026-10-30

| Actual Runtime source / run | Root-reviewed status |
| --- | --- |
| Clean `64927cbe740f3d01ffc6a68250468394bd4dadb3`, QtqKRp | Complete four-Thread M1–M8 and parent PASS; eight facts, real lease boundary and final original-four witness valid. Independent logical-line reclassification is **SCOPED_PASS / 0**, accepted by Root. Original driver FAIL / 1 remains unchanged. |
| Clean `f9bb826f9e5133296a0c553de266244e7ad7fcdd`, 8b4Xge | Latest complete cross invocation is **FAIL / 1**: C1–C4 PASS, C5 original offline recovery FAIL, C6–C7/final eight witness NOT_RUN. Root independently verified 21 evidence hashes. Product or fixture root cause remains unestablished. |

The full result remains attributed to its actual `64927cbe` source and binaries.
Root's later combined-source review preserves its business guards and state
transitions; that review and error/diagnostic qualification are not another full
Runtime execution. No full rerun was performed for those reviewed changes.
The full reclassification Root receipt is
`~/Cicada/.local/evidence/n2-acceptance/frames-bootstrap-final-5d2304f-fgk_5mtf/root-review-a0fb120.json`,
SHA-256 `b8e3129304bd96ec5947f98eae78c2eb18c45835832a9d6b654c6db33f144cb0`.
See the [full evidence and original FAIL](#full-runtime-terminal-and-independent-log-reclassification--2026-10-29)
and [latest cross terminal receipt](#frozen-cross-runtime-terminal--2026-10-30).
Earlier failures below retain their exact source, result and missing evidence.
Windows DPAPI/ACL/GUI/IME, actual 24-hour expiry, Android, physical second Node
and public HTTPS remain NOT_RUN. These are scoped results, not a release or
all-platform acceptance.

## Initial entrypoint scope

At the initial entrypoint checkpoint, the actual Runtime gate was **NOT_RUN**.
That preparation qualified the executable entrypoint, its compilation and the
evidence classifier. The later actual failures and QA audit adaptation are
recorded below. The App producer's SDK-actor results, old M7 results and synthetic
classifier controls do not establish a two-Node native pass.

The initial production baseline is Root's frozen
`5f270726733c10e3335b753c304cdc0f5332acda`, including App checkpoint `8d8ccd5`
and default scoped capability availability. The QA entrypoint commit is
`d0e9717e00bdf9f0926152d19f8df8d8baf6aac7`. No Hub/App/Node production
implementation is modified by QA.
The enrollment contract revision is the shared value
`node-pair-trust-node-scoped-v1`; the Group contract remains
`owner-endpoint-groups-v1`. These are separate from the Git revision, binary
hash, software version, wire version and Docker image digest.

The single existing entrypoint is:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/native-ip-complete/run-owner-thread-groups-cea8036-20261029/payload/licenses \
  scripts/test-native-pair.sh --owner-endpoint-groups-cross-node
```

The script selects only `TestN3OwnerEndpointGroupsCrossNode`, uses the existing
90-minute timeout, and writes a fresh isolated run under
`~/Cicada/.local/{state,evidence,artifacts}/native-pair-acceptance/`.
Exit `0` means this separate scope's `SCOPED_PASS`, `1` means failure and `125`
means NOT_RUN. Preconditions can exit `2`. A skip, partial execution or stopped
fixture cannot fill a missing case. Root will integrate the QA checkpoint and
freeze the actual execution source before authorizing Runtime execution.

| Case | Required actual observation |
| --- | --- |
| C1 | One persistent native TLS Hub, one actual App/Owner/device; two separate CLI Node processes use their own scoped private device code, Owner review and private ACK. Independent policies select the same existing Network. Two actual Hosts retain four original native Threads each. Control inference remains off. |
| C2 | Actual App CREATE reviews create G/H; exact fresh cards and separate ADD reviews grant A0/A1/B0 in G and A0/B0 in H. All five edges complete real Node key projection. The other five originals gain no implicit edge. |
| C3 | A0→B0 and B0→A0 each complete a real native ASK/REPLY in G. Both request and reply reach the exact original native SID once. |
| C4 | Normally close the original App process; complete a native ASK/REPLY in H without reopening it. |
| C5 | Arm B0's receiver expectation while B is online, stop B, send one original durable ASK, observe zero native injection while offline, then restart B with its same root/key/binding. The Host retains the original SIDs/history. Complete that exact request/reply; retain the original immutable outbox identity without a replacement ASK. |
| C6 | Reopen the same App profile, explicitly select B using its actual saved card gesture, and REMOVE only B0-G through a fresh Owner review. Re-read all eight originals' G/H relations. Fresh B0-G selection and ASK are definitively refused; the exact refused body's native queue count remains zero. |
| C7 | A0↔A1 in G and both cross-Node directions A0↔B0 in H still work. Recheck refused-G zero injection and all eight original identities, endpoint keys, bindings and workspaces. Both Hosts close with zero real-model/literal-provider calls and exact provider accounting. |

The parent uses only frozen public Core Actions. B enrollment explicitly begins
with `ActionBeginAddNode`; reviews use `ActionReviewNodePairing` and
`ActionApproveNodePairing`; the original Node ACK is read with
`ActionRefreshNodePairing`. `ActionSelectSavedNode` copies the actual current
`Targets.GestureID`. Existing Network choice comes from `Targets.Networks`.
Every Group operation uses the exact Core Thread/candidate/relation/review card.
There is no parent positive signer, SQL grant, legacy enrollment substitution,
fake App API or additional transport. SQL observations are read-only identity
and immutable-outbox audits.

Each Node has a private home, user root, state, keystore, MCP state, SQLite
outbox, Codex home, four workspaces and process log. Long-lived children and
their cleanup belong to the parent test, so finishing a scenario does not kill
the next scenario's original processes. The closed receiver expectation does
not inject a native turn; only the actual receiving Node can deliver one.
Private logs, IPC, codes, secrets, keys and databases stay in disposable state.
Exported evidence contains public coordinates, closed facts and hashes.
App-action failures retain only `ActionFailed`, a closed `Phase` enum and
allowlisted App/Node/pairing/Group/policy error codes. Unknown text becomes
`OTHER`. A deterministic privacy control rejects arbitrary private text,
including uppercase values that resemble codes. The existing App test child
uses the parent's 90-minute process lifetime only under the new selector;
all existing selectors keep their 10-minute App child limit. This does not
extend any product account, consent, business-policy or credential deadline.

The existing driver pins:

- Go image `golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
- Codex `0.164.0`, SHA-256 `b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`, with its complete package mounted read-only.
- The populated module cache read-only; the task build cache has an exclusive `flock`. Docker has no external network; services communicate over real container-local TCP. No shared development Hub or public deployment is touched.

Compile-only evidence:
`~/Cicada/.local/evidence/n2-acceptance/cross-node-entrypoint-final-5f27072-6p6q8rpl/`.

| Check | Exit / measurement |
| --- | --- |
| Go version | 0; 0.476 s |
| Actual CLI build | 0; 2.247 s; binary SHA-256 `44edb93e1c1848f95c2d1ec24784cb4adacc4c4d0ab28ea62272423266beaaba` |
| N3 test binary build | 0; 6.237 s; binary SHA-256 `169d3e2a499df88a2f1ddb775e67272d0cbece8ff905b9db140ae8b3b26b67ea` |
| N3 vet | 0; 1.390 s |
| Closed App diagnostic privacy control | 0; 0.642 s; actual deterministic helper test, zero Hub/App/Node/Host starts |
| Source before/after | Stable; snapshot SHA-256 `60bbdeb8e8b24c0aede9261edf3628c587fba2d9945d4fee53ed2916d73d954b` |
| Compile result / manifest | SHA-256 `2f38acc0674c944d222e8b50067b029d54c29c7ef6a438dc7ed97a2f5d0b583a` / `46ea16e84b9db170db65deab9bb94ffe0b7b375ef34a0f1af69096ab5e4e27b1` |
| Cleanup | Container absent with Docker available; zero state files; owned empty state directory removed |

The compile snapshot is baseline **plus dirty QA files**, not HEAD alone.
The final compile includes the exact contract revision, closed diagnostics
and App child lifetime correction. Only documentation was completed afterward.
All compiled Go input hashes are retained for final checkpoint attribution.
The earlier successful compilation is retained separately at
`cross-node-entrypoint-compile-5f27072-uj0c9_ak/` with its original source scope.

The final synthetic oracle run is
`~/Cicada/.local/evidence/n2-acceptance/cross-node-entrypoint-final-5f27072-6p6q8rpl/oracle/`:
179 checks, exit 0, product **NOT_RUN**; result SHA-256
`5988270eff387dc49ff96ea11efd733bc263da44b47fd3becae9e03635c5b195`.
The command is
`python3 scripts/fixtures/native-pair/owner_groups_evidence_checks.py NEW_PRIVATE_DIR`.
Controls retain all old classifier assertions and reject missing/duplicate
cases, non-boolean facts, fewer than eight identities, one Node disguised as
two, changed original identities, missing/wrong/colliding native request routes,
source/binary drift, truncated JSON, failed build stages and unknown/remaining
Docker resources. An initial synthetic mutation incorrectly reused the expected
reverse-route target; that control was corrected, and its failed receipt remains
at `cross-node-entrypoint-5f27072-z3dzovto/`. It was not a product failure.

The new result requires all seven exact single terminal events, all closed
facts, one eight-original identity witness and six unique cross-Node native
request/reply witnesses with the exact directions and distinct G/H scopes.
It never closes the historical full M1–M8 gate. Existing full and M7 selectors
and their assertions are preserved.

Historical full M1–M8 explicitly uses legacy App-Node v1 and `--control-url`;
the default-enabled capability does not enter the `--hub-address` auto family
selector for those commands. A separate old NPT fixture uses address+auto and
would need explicit historical legacy selection before rerunning that separate
lane. This checkpoint does not change it or any M1–M8 production/test behavior.

Actual two-Node Runtime, complete M1–M8 on the new frozen source, Windows
DPAPI/ACL/GUI/IME, Android, a physical second Node and public HTTPS remain
**NOT_RUN**. No new production defect is established by compilation or these
synthetic classifier checks. Prior failures and their original source attribution
remain unchanged.

## First actual frozen Runtime runs — FAIL, 2026-10-29

This later section records actual execution and supersedes the preparation-only
NOT_RUN status above for the cases that ran. Root integrated QA `d0e9717` as
`0d5bfb62f92f7eaed3cba46b9275cbce5617eb1a`; both trees are
`1f3d3bcb098fdfeb682df315f4777cc253340d9c`. Both gates ran on clean
`d0e9717e00bdf9f0926152d19f8df8d8baf6aac7`, without source, assertion, timeout,
policy, permission or request changes between runs. The full gate began
immediately after the cross-Node gate reached its terminal result, as directed
by Root. Neither failure was retried.

| Gate | Actual outcome | Retained result |
| --- | --- | --- |
| `--owner-endpoint-groups-cross-node` | **FAIL / 1**, parent 346.60 s. C1 passes in 317.22 s with two actual scoped CLI Nodes and two actual four-original-Thread Hosts. C2 fails in 22.27 s at an actual App `ADD_ENDPOINT` APPLY. C3–C7 NOT_RUN. | `~/Cicada/.local/evidence/native-pair-acceptance/run-20261029T211957Z-tU3108/result.json`; SHA-256 `147f7d8a102cc4979bd413e15845f65c9e0461210ce32dfe0d82483a623616d6` |
| `--owner-endpoint-groups` | **FAIL / 1**, parent 293.43 s. M1 fails in 14.15 s during its first unseen-original Group CREATE recovery audit. M2–M8 NOT_RUN; none of their old results fills this execution. | `~/Cicada/.local/evidence/native-pair-acceptance/run-20261029T212654Z-kWsHgJ/result.json`; SHA-256 `9826cd4bb9a4e610097dc4ff6cbbc7127844fcc38fb326b58f4952f54d875716` |

Both actual runs have version, CLI compilation, test compilation and vet exit
`0`, with harness exit `1`. Their identical source before/after snapshot SHA-256
is `d5e69d088ea76d42e0251e0492f0c74b3836986f4f70be0962776e59bdcd4693`;
the source manifest is
`23d13bea8c87a92e1c2a259205f69385dacd8f54f1039ff63013fdd99c96debc`.
Each run's binary before/after hashes match: actual CLI SHA-256
`ad705a083b1b02983ac16bdec53f0110a97b18245f1989f0b220ea798866b21f`;
test binary SHA-256
`169d3e2a499df88a2f1ddb775e67272d0cbece8ff905b9db140ae8b3b26b67ea`.
These are the executed artifacts; the earlier compile-only CLI hash is not
substituted for the actual driver's build.

The C2 safe failure diagnostic is:

```text
action_failed=true phase=OWNER_READY
app_error_code= node_error_code= pairing_error_code=
group_error_code=APP_THREAD_GROUP_STORAGE_BUDGET policy_error_code=
```

The exact failure source is `owner_groups_cross_node_runtime_test.go:202`,
inside the five-edge ADD loop. It is **not** the first CREATE. The exact loop
edge was not retained in the closed runtime log and is not inferred from elapsed
time. Root assigned the observed App budget failure to the App owner for a
scoped reproduction/fix. No private vault, key, proof, code or payload was
exported, and QA made no production change or replacement request.

M1's original error is
`actual App Group packet record is missing or malformed`.
Its retained protocol audit is
`owner-groups-protocol-audit/843f1e8f38d9bc34.json`, SHA-256
`2efd2b3a877d3d73114a7af41996683506c5b21caa3dd797da328d94ce87e030`,
with 175 traces and 20 steps. The actual original APPLY is held before forward;
one subsequent reconcile is forwarded and returns HTTP 200. There is no
recovery business APPLY in that trace.

Read-only source inspection identifies an audit compatibility issue requiring
Root/App/QA coordination: the new `recoverThreadGroup` nested-receipt branch
authenticates the query response and directly stores the original inner receipt;
`acceptThreadGroupRecoveredReceipt` retires any saved query response. The old
`ownerGroupsOriginalReceipt` postcondition unconditionally loads
`appcore.endpoint-groups-recovery-response.v1` before verifying the independently
retained original receipt. The runtime error does not name the failed namespace;
the private fixture was cleaned normally. This source-derived finding does not
claim that the original business receipt was absent or that a Hub authorization
failed. The original strict audit, no-effect fence and exact-receipt assertions
remain unchanged in this run.

Control records and live handles are retained under
`~/Cicada/.local/evidence/n2-acceptance/cross-node-d0e9717-01/` and
`owner-groups-full-d0e9717-01/`. Closed read-only observers recorded two and
25 Host checkpoints respectively, with zero read retries and zero issuer-error
observations. The combined `closed-two-gate-receipts.json` SHA-256 is
`7acc6226818c8b3975c115dd0c4eebde57fe5953d675e4548631df04f7a117c4`.
Docker remains available; both owned containers are absent. Each task state
contains zero private files and only an empty `tmp` directory, retained with its
failed run. No resident/public service was touched. No further Runtime was
started after these two terminal failures.

Cross-Node communication, App-closed cross-Node communication, original offline
request/reply recovery, exact B0-G removal, final eight-original identity witness,
complete M1–M8, Windows DPAPI/ACL/GUI/IME, Android, physical second Node and public
HTTPS remain **NOT_RUN / unaccepted** on this source. The C1 pass and historical
M7-only pass cannot fill these missing gates. Later fixes require their own
source freeze and source-bound validation; these failed receipts stay unchanged.

## QA query-response audit adaptation — no new Runtime

After both gates terminated, Root confirmed the M1 failure as the old QA storage
assumption and authorized a minimal change to
`acceptance/n3/owner_groups_vault_audit_test.go`. The actual original recovery
request must still be in the closed App vault and match the exact real TCP POST:
method, shared reconcile path, forward/status, packet bytes, captured request
and response hashes, decoded route, original parent digest and valid DTO all
remain mandatory. The outer ciphertext comes from that actual captured response
and is independently authenticated with the existing shared verifier.

The audit additionally requires the obsolete query-response vault slot to be
retired; a nonempty slot or unknown storage result fails. The actual App must
independently retain the exact inner receipt in its original response slot,
byte-for-byte equal to the outer receipt, with the same original parent digest
and route. The shared verifier then independently authenticates that inner
receipt against the original APPLY and verifies its permanent no-effect fence
or precise reviewed COMPLETED effect. No synthetic response or upstream HTTP
success can supply the missing App acceptance witness. No M1–M8 business action,
deadline, real five-minute boundary, 75-second barrier or identity assertion is
changed. The new audit has not yet passed an actual full Runtime gate.

Final helper validation is retained at
`~/Cicada/.local/evidence/n2-acceptance/owner-groups-query-audit-final-c9a13d2-ndf0akex/`.
The tested source is documentation-only checkpoint
`c9a13d261fd2e2e3e8899174cee01589ca7bcd40` plus the recorded dirty QA helper;
the exact helper SHA-256 is
`ccb834d1df5086e311f40132b76b5c4b0e363e3d7a9c4341fc688ca4e64329a6`.
Root requested the final adaptation and both original failures as one checkpoint;
the unpublished documentation-only checkpoint is retained at
`task/archive-cross-node-failures-c9a13d2`. No tested source or failed receipt is
reattributed to the final documentation/QA commit.

| Related check | Result |
| --- | --- |
| N3 test compilation | exit 0; 2.241 s |
| Shared wire test compilation | exit 0; 1.682 s |
| Existing `TestN3OwnerGroupsSettlementRequiresLocalOriginalReceipt` | exit 0; 0.592 s; six passing test events |
| Existing `TestOwnerEndpointGroupsRequestReviewAndOriginalRecoveryPQ` and `TestOwnerEndpointGroupsReceiptRemainsOriginalAndUncertainNeverCompletes` | exit 0; 1.038 s; five passing test events |
| N3 vet | exit 0; 1.010 s |
| Source before/after | Stable; SHA-256 `852c89f0d21ec1a2ccbb92ce4a0745ff4b3f8548ec4646a03469dd50892afa4e` |
| Result / manifest | SHA-256 `189363b6101304c6494973bf2a28b01cd3cc81105ff557c8a13d949fd081b062` / `7c021a20f5cd415d0614275002e3746383a423369f1dcd1d4b767ccd1ab4df66` |

These are deterministic helper/real-cryptography/loopback-TCP checks. They run
no Hub/App/Node/Host process and fill no Runtime case. The pinned disposable
Docker container is absent, module cache was read-only, the task build cache was
exclusively locked and its temporary state has zero entries. An earlier helper
invocation attempted to execute the wire test from Docker's non-executable
`/tmp`; it failed before executing tests. That infrastructure failure is retained
unchanged at `owner-groups-query-audit-c9a13d2-iqd1p68h/`. The final invocation
uses the existing driver's compile-to-`/out` then `test2json` execution pattern;
no source change or deadline relaxation was needed.

At this historical `d0e9717` checkpoint, C2's App budget failure was assigned to
its owner, pending Root's integration of the producer fix and QA adaptation.
QA had not started another Runtime or modified production, requests or
permissions. The later scoped results and current C5 failure are recorded below.

## Repaired-source cross-Host fixture failure — 2026-10-29

Root froze `64927cbe740f3d01ffc6a68250468394bd4dadb3`, including the App budget
fix and QA recovery-audit adaptation. QA ran the unchanged existing cross-Node
gate on clean `task/v01-final-native-runtime`, preserving the old task branches
and both prior failed receipts. Run `run-20261029T220720Z-1nFg4G` is **FAIL / 1**:
C1 passes in 314.67 s, C2 passes in 175.14 s, and C3 fails in 31.72 s; parent
528.51 s. C4–C7 are NOT_RUN. C2's actual Owner reviews, all five key-ready Group
edges and eight-original relation checks now pass on this source. This scoped
result does not imply cross-Node native communication.

The exact failure occurs while registering the original receiver expectation,
before the first ASK: `WAIT_PARENT / ACTUAL_QUEUE_EXPECTATION_INVALID`.
Its result is
`~/Cicada/.local/evidence/native-pair-acceptance/run-20261029T220720Z-1nFg4G/result.json`,
SHA-256 `7ae3c45a940f5f5104e6dd9894735dcb76b17740c575e607f6b4f5c4ffa84ecc`.
Version, CLI/test compilation and vet all exit 0; harness exits 1. Source
before/after is stable, snapshot SHA-256
`89c4423d036c4774fcf6e192e782781f4f272e9a182f82c51da2f0800fe3881a`,
manifest `5929f8afe96563b84ffde7d03dee0d86f402d8718f1c80cd7bf7659d32e22ef2`.
The actual CLI remains
`ad705a083b1b02983ac16bdec53f0110a97b18245f1989f0b220ea798866b21f`;
test binary is
`7ed5dafa73c67f77e8f540c30e38a8855542441350ec03f42eb441e5224c776e`.
Both binary manifests match before/after. The container is absent, private state
files number zero, and only an empty task-owned `tmp` directory remains. The
closed observer retains seven records, zero read retries and zero issuer-error
observations. No original ASK/request or authority is replaced after this failure.

The cause is a QA adapter defect. `codex_domain_host.py:310` intentionally
requires its own independent fixture scope in each expected body. The original
cross-Node question included only the source Host marker but was registered on
the target Host; the reply had the inverse mismatch. The unchanged Host also
compares the exact receiving SID, message kind, sender/receiver Endpoint, Group,
request ID and one-post count. A cross-Host sender is valid only when it equals
the explicitly expected foreign Endpoint; it is not relabeled as the receiver.

Root authorized the minimal fix in the separate
`task/v01-cross-host-fixture-scopes` worktree, leaving the running frozen tree
unchanged: both visibly synthetic question/reply bodies now contain both
independent Host markers. The actual sender/receiver IDs, original native SIDs,
request correlation, idempotency key, ciphertext checks and exact once checks
are preserved. No generic Host/provider or production implementation changes.

The existing classifier suite gains one test with both request directions and
their reverse replies. It exercises the actual `StaticHostProvider` helper
without starting a server/Host. It rejects the original sender-only marker,
duplicate expectation, wrong sender/receiver Endpoint, wrong SID, Group,
request ID, wrong kind and duplicate delivery; each exact foreign-sender case
is admitted once. All 27 tests pass, exit 0, 0.011 s unittest time. Evidence:
`~/Cicada/.local/evidence/n2-acceptance/cross-host-scope-64927cb-hksom04w/`, result
SHA-256 `d147835a4f661ba34febf896023282dcc5704aad9a16fb819fad94b4dc5f4452`.
This is synthetic classifier qualification only; no new Runtime fact is emitted
and no previously qualified compilation or complete Runtime was rerun for it.

Following the failed cross gate, QA immediately started the existing full
`--owner-endpoint-groups` gate as authorized, on the same unchanged `64927cbe`:
`run-20261029T221657Z-QtqKRp`, live execution handle 4738, observer 92078.
At this fixture-fix checkpoint it is still running; its result must be recorded
under its actual source and cannot be inferred from the classifier tests.
Root requires only a subsequent cross-Node rerun after this QA-only fix; the
complete-gate result is mapped by exact production-blob equality instead of
rerunning it solely because synthetic fixture markers changed. That equivalence
mapping is separate evidence and is not an automatic pass.

## Full Runtime terminal and independent log reclassification — 2026-10-29

The unchanged `64927cbe740f3d01ffc6a68250468394bd4dadb3` full run
`run-20261029T221657Z-QtqKRp` is now terminal. All eight M1–M8 cases and their
parent pass, once each; parent elapsed time is 4051.15 s and M7 is 1265.82 s.
Version, both compilations, harness and vet exit 0. The original driver exits 1
because it treats each physical `test2json` Output event as a complete JSON
witness. The final four-identity line is split into four consecutive events of
1024, 1024, 1024 and 589 bytes, with the exact same Test/Package and LF only in
the last event. That is a QA evidence parser failure, not a missing identity
witness. The original FAIL result remains unchanged, SHA-256
`ad75ce148b1ce502f0ee68df24930e26dcd318223d1617de77a06bb7a25d4998`.

Root authorized bounded logical-line reassembly for this classifier. The helper
uses the existing strict JSON decoder, retains the exact Test/Package scope,
requires LF, and rejects interrupted/truncated output, scope changes and
oversized physical records/fragments/logical lines. Full, M7-only and cross-Node
finalizers share it. Existing facts, lease, identity, terminal count, source,
binary and cleanup validators remain unchanged. The existing synthetic oracle
retains its negative controls and gains fragmented full/cross positive controls
plus explicit framing refusals: 198 checks, exit 0, product NOT_RUN. The existing
Host classifier suite passes all 27 tests, exit 0. Neither suite is a Runtime
substitute.

The sealed original log and other regular evidence files were copied byte for
byte into a new evidence directory, independently reclassified with the corrected
helper, and checked again against the untouched originals. No Runtime was
repeated, no original result was overwritten, and the executed binaries were
reused unchanged. The independent result is **SCOPED_PASS / 0**: all eight facts,
the real lease boundary and unchanged original four identities validate, with
no malformed evidence. The actual tested Runtime source is still `64927cbe`;
the classifier is base `5d2304fcdcd4b61919458c81ff88cbf181328220` plus the recorded
dirty QA change, SHA-256
`04481dcb9da5a648a1e1deb0485d792e1b1f1375cffec048f91035454a373736`.

| Retained evidence | Path / SHA-256 |
| --- | --- |
| Original actual run | `~/Cicada/.local/evidence/native-pair-acceptance/run-20261029T221657Z-QtqKRp/` |
| Independent reclassification | `~/Cicada/.local/evidence/n2-acceptance/full-QtqKRp-independent-reclassification-wok_hijt/` |
| New `sealed-input/result.json` | `0980ffed5f54bf621402b6054f4e09b0833fd4c9193f7502ee463d25e9bb7832` |
| `reclassification-receipt.json` | `e7e82395ffde59972e11e73e0220edcf6c5f7220ee6c5479594c4d3303792bf3` |
| 198-check oracle result | `frames-bootstrap-final-5d2304f-fgk_5mtf/oracle/result.json`, SHA-256 `2de39c39a86692bafecee1b62510801c9e36aae82a300d3612ddb002135979d0` |
| Python qualification receipt | `frames-bootstrap-final-5d2304f-fgk_5mtf/result.json`, SHA-256 `7542cac97e70195c90b1b35ff4c8ec20045368f89c2973a35c8d6852fbc0a8fe` |

Both qualification directories are under `~/Cicada/.local/evidence/n2-acceptance/`.
The full run retains stable source/binary manifests, actual CLI SHA-256
`ad705a083b1b02983ac16bdec53f0110a97b18245f1989f0b220ea798866b21f`
and test binary SHA-256
`7ed5dafa73c67f77e8f540c30e38a8855542441350ec03f42eb441e5224c776e`.
The closed observer has 537 records, zero read retries and zero issuer-error
observations. Root independently checked the eight facts, final four identities,
1833 tracked plus three generated inputs, 21 evidence hashes, three audits and
the exact owned container's absence. This qualifies the full gate's scope on
its actual source; it does not fill cross-Node cases or physical-platform lanes.

## Cross retry bootstrap failure and closed diagnostics — 2026-10-29

After Root reviewed the two-Host marker fix, the existing cross gate ran once on
clean `5d2304fcdcd4b61919458c81ff88cbf181328220` in its separate worktree:
`run-20261029T232544Z-HfnP8D`. It is **FAIL / 1**. C1 fails in 196.94 s, parent
205.22 s; C2–C7 are NOT_RUN. The original parent error at
`owner_groups_cross_node_fixture_test.go:244` is
`actual Owner Group Host checkpoint timed out`, while awaiting the first Host's
checkpoint 0 with the unchanged three-minute deadline. No checkpoint-0 reply
arrived. The exact internal bootstrap stage, active native actor and Host exit
state were NOT_RETAINED. The closed observer has zero Host records and one
issuer-error observation. The body-marker fix is not reached; it is not an
established cause of this failure.

The issuer observation reports `VERIFICATION / REGISTRATION_REJECTED`, original
budget 29999 ms, elapsed 5181 ms, state 566858 bytes under an 8388608-byte limit,
5724598 bytes generic RPC headroom and all 15 pending flags false. It establishes
neither the cause of the registration rejection nor its causal relationship to
the Host timeout. Root assigned read-only investigation to the Hub owner. QA
did not replace an original pending request, change a proof or edit production
code. The original result is retained at
`~/Cicada/.local/evidence/native-pair-acceptance/run-20261029T232544Z-HfnP8D/result.json`,
SHA-256 `0a5cfd13064f72d40b97712eba2a274cad132507a77b8806c8acd5f5e4f5f7da`.
Source and actual binaries are stable, the exact owned container is absent,
and private state has zero files and only an empty `tmp` directory.

The comparison also found three ignored generated UI inputs absent from this
new worktree, although present in the earlier full run. This is an input
discrepancy, not an established failure cause. Original failed-run evidence and
worktree inputs remain unchanged. Only the next QA worktree restores exact
copies against the full run's recorded hashes, without rebuilding:

| Generated input under `cicada-go/internal/server/ui/generated/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `cicada-webcrypto.wasm.gz` | 1789916 | `2ea8127a27921c8de48ce01b2e08a7df551fe69cc59685e0c9028e2e089982c8` |
| `panel.manifest.json` | 575 | `cf47e7026ad05b60cb2e5c538bdbc53015cfa09cd76834d57ea27778a74f92dc` |
| `wasm_exec.js` | 16992 | `0c949f4996f9a89698e4b5c586de32249c3b69b7baadb64d220073cc04acba14` |

QA adds bounded bootstrap phase/actor/original-Thread-count/daemon-state records
through the existing private checkpoint-progress mechanism. Host timeout logs
also record whether the original process is running and whether an exit code
was observed. These closed records contain no SID, key, proof, code or payload.
The original three-minute Host wait, 90-minute parent, 75-second barrier, real
five-minute lease, original requests, four/eight identities and all business
assertions remain unchanged. No retry or acceptance branch is added.

This diagnostic-only Go change compiles and passes N3 vet in the existing pinned
disposable Docker image, exit 0 / 0, 8.582 / 1.668 s. Qualification is retained at
`~/Cicada/.local/evidence/n2-acceptance/frames-bootstrap-go-5d2304f-jboxirep/`,
result SHA-256
`95668a85fdc707b5e05d8277eb323a92167eaa945438ad942770160ae10531e2`.
Changed input hashes remain stable; the dependency cache is mounted read-only,
the task build cache is exclusively locked, the owned container is absent and
temporary state has zero entries. This compilation supplies no new Runtime
case. Root will integrate the minimal Hub error/diagnostic change and this QA
checkpoint before freezing a single complete C1→C7 retry; no standalone C1
preflight or further Runtime has started at this checkpoint.

Reproduction remains the existing driver selector after Root's next freeze:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/native-ip-complete/run-owner-thread-groups-cea8036-20261029/payload/licenses \
  scripts/test-native-pair.sh --owner-endpoint-groups-cross-node
python3 scripts/fixtures/native-pair/owner_groups_evidence_checks.py /absolute/new/task-owned-oracle-output
python3 scripts/test_native_pair_host_classifier.py
```

The first command is a future Runtime gate; the other two only qualify QA
helpers. Cross-Node C3–C7 remain unaccepted. Windows DPAPI, ACL, GUI and IME,
Android, physical second Node and public HTTPS remain NOT_RUN. Final plan/index
closure waits for Root's review and the actual remaining gate; this record does
not declare the product or all platforms accepted.

## Frozen cross Runtime terminal — 2026-10-30

Root integrated QA `a0fb120` and Hub's reviewed `7291a777` into clean
`f9bb826f9e5133296a0c553de266244e7ad7fcdd`, tree
`45c4add6161a9b1da724b104798bddd5ae2e8660`. QA created the separate
`task/v01-final-cross-runtime` worktree, retained every old ref/run, verified the
three ignored generated UI inputs against the full QtqKRp hashes above and
invoked the existing complete cross selector exactly once. No C1 preflight or
full M1–M8 rerun was performed. Frozen source and harness are both clean and
unchanged through execution; this later documentation checkpoint is not its
tested source.

Run `run-20261029T235843Z-8b4Xge` is **FAIL / 1**, parent 950.48 s:

| Case | Actual terminal result / elapsed |
| --- | --- |
| C1 scoped enrollment and originals | PASS / 311.74 s; both scoped private ACKs, two Nodes/eight original native Threads, independent policies in the same Network, one Hub/Owner/device, Control off |
| C2 explicit Owner Groups | PASS / 174.45 s; actual CREATE/ADD reviews, all five exact G/H edges key-ready, other originals have no implicit edge |
| C3 bidirectional native | PASS / 209.21 s; both cross-Node G ASK/REPLY directions reach the original native SIDs exactly once |
| C4 App-closed communication | PASS / 107.30 s; original App closes normally and the H native request/reply completes without App |
| C5 original offline recovery | FAIL / 140.90 s; exact original request's native queue never reaches one post within the unchanged 75-second barrier |
| C6 / C7 | NOT_RUN; exact B0-G removal, surviving-scope checks and final eight-original witness not reached |

Version, CLI/test compilation and vet exit 0; harness exits 1. The retained
result is
`~/Cicada/.local/evidence/native-pair-acceptance/run-20261029T235843Z-8b4Xge/result.json`,
SHA-256 `565b798884624ee79b267951ca596b65a2df2eb9e41f4bdeb8b01bf9a1fa0e1d`.
The original error at `owner_groups_cross_node_runtime_test.go:249` is
`actual Owner Group Host stopped`, with phase `WAIT_ORIGINAL_NATIVE_QUEUE` and
code `OWNER_GROUP_EXACT_NATIVE_QUEUE_NOT_ARRIVED`. No malformed evidence is
reported. There are three completed native roundtrip witnesses, from C3/C4;
they cannot supply C5 or the absent C7 routes.

C5's one original A0→B0 G ASK returns `SENT`, `retryable=false`. Retained hashes
are operation
`450c271ae4702e19c7ef15f90a1dbca6db5bd4275ce580a85345e00e5b6d88c8`,
request `42bda724feec3b3dab8573ca754668f06b843cd8d66205e0159b866463ee64cc`,
expected body
`79a0d2662dd6447c7aaddb29edfad1412e2463f3bcdb7d266d70e9faa51cf784`
and G `b41a1c84adc3ec4a4d6953394d35fc81693f70b1107d27f564a805d81977557b`.
The receiver command expects the exact original request hash; both current Group
selections use that G hash. The fixture's pre-restart exact outbox/target/body
read and offline zero-injection checks pass. The immutable outbox hash was a
local variable and is NOT_RETAINED in closed evidence; its post-restart equality
assertion and the final eight-identity audit are NOT_REACHED. Private DB/state
is cleaned normally, so no later private-state snapshot is inferred.

Retained Node root/key/binding checks and the retained Host's original-four
reply checks after Node restart complete before the receiver command. The closed observer then
retains 74 native-progress records, from `00:13:39.616830Z` through
`00:14:54.608380Z`, all with exact-body queue posts 0 and provider unclassified
posts 0. `receive_match` waits for that exact native arrival **before** executing
`cli.host_call`: the labelled `cicada_receive` was not executed. Its attached
Host diagnostic is from the preceding operation, not a successful receive.
ASK `SENT` does not prove native delivery. The minimal established failure is
absence of the exact native-delivery observation after retained restart; whether
the product attempted a native write and the product/fixture cause remain
NOT_DETERMINED. Root assigns the bounded product recovery investigation to the
Hub owner; QA only records the fixture/evidence boundary. No substitute ASK,
permission, deadline extension, code change or retry follows this failure.

Source-before/after SHA-256 is
`feadb56226215008103f6078b5288ee5bc7118c1499876226a05eba775d2c14c`,
manifest `8754860e207b4075961b21ea65001fabf5fd297dfab39268dc056d85c7c3e682`.
Actual CLI SHA-256 is
`b9e381cd3a0258bbd939c2457ff1aa2f18b4f9b1523039b7263592ed6ac67acf`
(42102066 bytes); actual test binary is
`11e89782c87a1cbd257079fbba0ca6552daf7ccfacdf1ad02c03db56587c8006`
(37493060 bytes). Both before/after binary manifests match. The dependency
cache is read-only and build cache exclusively locked. Docker remains available,
the exact owned container is independently absent, private state files number
zero and only an empty `tmp` directory remains. The read-only observer has
195 records, zero read retries and zero issuer observations.

The external private observer retained its old fields and added only the three
closed Hub diagnostics: 14 allowed `registration_substage` values, four
`child_ctx_error` values, and exact-boolean `underlying_deadline`. Its 42
synthetic filter checks pass, exit 0; old-field output is identical and raw
private text is not exported. This selfcheck is not a Runtime case. The private
observer was the only adjusted external template; production and QA source
remained frozen.

All following receipts are under
`~/Cicada/.local/evidence/n2-acceptance/cross-final-f9bb826-01/`:

| Receipt | SHA-256 / scope |
| --- | --- |
| `freeze-manifest.json` | `83ed4eecba77b5c9bce15ed4f6a93201ffbfe83789a65841bf76c85c1cee6095` |
| `root-freeze-review.json` | `88f8f728e20a8686db91ec779e77264adf6608cd1bcc4409c64ca36d3f342343`; combined source, three generated inputs, observer and preserved full business branches |
| `terminal-failure.json` | `b43aefd03fb72a5b7b366be8152ab7b9682b28c98d0a014489ecf558f88748ac`; QA closed evidence and explicit retention limits |
| `root-review-8b4Xge-failure.json` | `1fa06c42ec97bb395ccfb6f6a2e353adabc00e48ef0f18501b7f97fc3fde91a9`; independent 21-hash/source/binary/cleanup review, FAIL retained |

No new Runtime has started. Any necessary fix and subsequent execution requires
Root's new review/freeze and the same existing complete cross entrypoint.
QtqKRp's accepted full scope, all earlier failures and every physical/24-hour
NOT_RUN boundary remain independently attributed.

## C5 offline recovery ordering — preparation only, 2026-10-30

After the terminal 8b4Xge failure, Root authorized a minimal test-only correction
on recording base `28688c6f911946256b8c53049c09b2d62f71792a`, in the separate
`task/v01-cross-restart-order` worktree. The original receiving Node is killed
and checked stopped before the existing `restart_host` command. That command
keeps the Python coordinator, original four SIDs, provider expectations and
history while restarting the Codex daemon/proxy. Its complete original-four
reply must arrive while the Node remains stopped, and the original ASK body's
known queue count must still be zero. Only then may the original Node start,
live-pin and original root/key/binding checks proceed. No daemon stop follows
that live Node. The runtime call supplies its existing `e.question` for the
zero check, without creating a replacement body or Host interface.

This keeps one original ASK/request/operation/outbox, App closure, unchanged
75-second native barrier, current final Guard, exact request/reply native once
checks and final identity/outbox assertions. No writer latch, extra retry,
authority, product timeout or implementation change is added. The intended
scope remains an original offline request across same-state Node recovery.
It does not qualify recovery of an already-accepted native turn interrupted
by a later daemon crash. The earlier sequence permits that additional window;
the retained 8b4Xge evidence does not establish that it occurred. Its original
FAIL and NOT_DETERMINED cause remain unchanged. This new ordering has not run
an actual Runtime gate.

Root also authorized the existing `CICADA_NODE_SEALED_PHASE_DEBUG=1` opt-in only
on these disposable cross-Node `start` commands, both initial and restarted.
The six-field common environment, Host and private-code reader retain their
original environment. No new product flag or product default is introduced.
An external private observer extends its existing file reader with a closed
`NODE_SEALED_PHASE` projection: 23 phase, three state and 11 error enums; only
hashed coordinates, fixed-key aggregate counts and at most eight correlation
groups of 32 rows are retained. No per-event payload/raw-error log is exported.
Observation timestamps are external read times, not product event times.
The producer's 32-row and original per-loop semantics are unchanged.

The existing 42 issuer controls retain identical projected output. Projection
checks cover 759 closed enum combinations, 36 unsafe-coordinate records,
13 malformed/unknown refusals, 480 sample-bound inputs, stream fragmentation
and duplicate-free rescans. They exit 0 and supply no Runtime fact. The exact
qualified schema file matches frozen Hub
`114f79bcde12d732fba013627155745101043f05`, integrated by Root as
`bc75e6341109d2f269890c97281ebbc918c20d55`; file SHA-256
`f2018e82058f5240f0f733cc01d6b8b55b8c8d1bcb8dc46877fe60d4bd8e1e2e`.
That byte mapping does not execute or accept the combined future Runtime.

Final qualification is base `28688c6` plus the recorded two dirty Go test files,
not HEAD alone. Evidence is retained at
`~/Cicada/.local/evidence/n2-acceptance/cross-restart-order-28688c6-px8egfm_/`:

| Check / receipt | Result |
| --- | --- |
| N3 test compilation | exit 0 / 6.729 s |
| Existing `TestN3OwnerGroupsControlPublication` | exit 0 / 0.666 s; one top-level PASS, no Hub/App/Node/Host start |
| N3 vet | exit 0 / 1.468 s |
| `deterministic-final-result.json` | SHA-256 `83aaca02694d13086ccdc99cc88bf6cf41ec296e2515c400aa621426e6c54074` |
| `observer-selfcheck-result.json` | SHA-256 `ef7eac0981b22ddd542a3964feac858e86ef742dd5dd627008d1e56f6ff34564` |
| `phase-schema-frozen-mapping.json` | SHA-256 `38ed24ec3a9e69a4b594e1e07e650adbffd6f7aa3718b496d14ceab14acb40d2` |
| External observer template | SHA-256 `21ca0e53a5e5ff287e8a21f095764f7f770ff36ded528e3b3a51d78dea9c557d`; retarget only to a fresh Root-frozen run |

The pinned disposable Docker uses a read-only module cache and exclusively
locked task build cache. Tested Go hashes are stable; the exact container is
absent and temporary state has zero entries. Three generated UI inputs match
the original full-run hashes. The earlier successful qualification before the
Node-only opt-in is retained separately; the final receipt covers that last
test-file change. No Runtime has started, and no failed original was replaced.
Root will review this one checkpoint with the Hub diagnostic source before a
combined freeze and any separately authorized complete C1→C7 invocation.
