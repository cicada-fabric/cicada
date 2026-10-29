# Two-Node native acceptance entrypoint — 2026-10-29

At the initial entrypoint checkpoint, the actual Runtime gate was **NOT_RUN**.
That preparation qualified the executable entrypoint, its compilation and the
evidence classifier. The later actual failures and QA audit adaptation are
recorded below. The App producer's SDK-actor results, old M7 results and synthetic
classifier controls do not establish a two-Node native pass.

The production baseline is Root's frozen
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

The current product blocker remains C2's App budget failure, assigned to its
owner. Root will integrate that producer fix and this QA adaptation before
providing a new source freeze for the two actual gates. QA has not started
another Runtime or modified a production implementation, request or permission.

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
