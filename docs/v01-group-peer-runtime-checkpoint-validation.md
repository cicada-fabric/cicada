# Group, peer privacy and runtime checkpoint validation

## Current checkpoint — 2026-10-02 integrated-next-core, SCOPED_PASS

This record describes the frozen integrated candidate and its acceptance boundaries.
The nine-path documentation patch is prepared separately; it does not run QA or
change product code, Client, state, deployment, keys, counters or resident services.
Historical validation remains attached to its tested source. Overall v0.1 and
Architecture v2.3 remain **PARTIAL**.

Main `dev` 的集成候选基于 Git HEAD `c146d58f67f6f4b3e14a8e56a8c68ddc60400713`，工作树含未提交变更；
完整源码 canonical SHA-256 为 `ec160b087221e3118022fcb22b04af1338fea5ea3257e5bf84580af346afa9d1`（1052 个路径），STD 构建输入
`source_fingerprint` 为 `4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032`（882 项）。两者范围不同，均不能只归于 HEAD。
当前软件 `0.1.0-dev`、Architecture v2.3、Hub schema **57**、
`client-hub-v1.6.4`、encrypted wire **1**、catalog **55** 项操作分别记录；
catalog SHA-256 为 `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`。

The full-source freeze covers **1052 paths**; STD build inputs cover **882 entries**.
The STD inventory SHA-256 is
`6eaf5ed26fd5ff6ab65b4c32d89b765bfbedb4ca034794e584f5698790f1c5e3`,
which is a third domain, distinct from the source fingerprint above. Source metadata
does not identify a built binary/image. No new clean commit, protocol archive,
binary hash, image ID or registry digest is predicted here. Applying this docs-only
patch changes the full-source inventory; executed QA remains attributed to ec160.
Root must separately record documentation applicability and exact clean artifacts.

The authority for the tested input is
[finalfreeze.json](../.cicada-data/integrated-next-core-20261002/finalfreeze.json),
SHA-256 `3fb9fd20128d92e8e78ddcee847d4edc7694a1b6ca1f5328bae5b600d24b15bc`.
Its referenced full-source manifest SHA is
`e097af33f2607bdad6b9643a0102e9bc75183a9a1f583e2a3be636e36a298812`;
STD source metadata SHA is
`020f065b886a7d62382bf32e273834a607de7c84f7fe978e530ce0751160f813`.
These are metadata-file hashes, not replacement source fingerprints.

## Mechanical integration scope

**86 paths = 6 + 13 + 30 + 27 + 10** were mechanically integrated.
The receipts establish exact source/preimage checks, preserved unrelated work,
raw modes and index; they explicitly do not report executed Main gates.

| Scope | Source behavior | Mechanical receipt |
|---|---|---|
| panel6 | Group nesting explicit preview/confirm CAS, repeated drop no-op, cycle/stale refusal and existing uncertain-write fence | [panel receipt](../.cicada-data/integrated-next-core-20261002/panel/receipt.json) |
| policy13 | Current reviewer `link.review` and leased binding Guard, qualification snapshots and selected original bilateral Owner proof evidence; contract v1.6.4 | [policy receipt](../.cicada-data/integrated-next-core-20261002/policy-integration/receipt.json) |
| privacy30 | Peer responsibility DTOs, legacy plaintext submit denial, trusted per-Task publisher/result-recipient assignment and immutable registered sealed references | [privacy receipt](../.cicada-data/integrated-next-core-20261002/privacy-integration/receipt.json) |
| D2 TLS27 | Fresh committed current-authority reads, stopped maintenance/activation recovery, checked Hub/Node restart and TLS-only maintenance capability | [D2 receipt](../.cicada-data/integrated-next-core-20261002/d2-integration/receipt.json) |
| N2 reliability10 | Link/Network-direct/original Monitor notice native-delivery lifecycle, bounded recovery and existing Hub202 SEND receipt sequence decoding | [N2 receipt](../.cicada-data/integrated-next-core-20261002/n2-integration/receipt.json) |

The Task mcp.go integration preserves the existing Restore WriterRoot mapping.
These counts include tests, contracts and component docs; they are not a count of
completed product features. Historical independent component gates retain their
own manifests, images and selectors.

## Security, migration and recovery boundaries

Task peers receive metadata, not objective, acceptance criteria, result summary,
evidence prose or claim keys. Ordinary sealed SEND is a candidate only. A formal
definition/result reference must bind its actual persisted message ID/digest/SEND
route, exact publisher/reader/result recipient, current trusted assignment/version,
content version, current key/binding/enrollment and Task revision/Owner epoch.
Current Artifact ACL/version/digest guards remain; references do not expose title
or summary or grant content/workspace rights. Definition registration records a guarded reference without advancing Task business
revision. First result registration atomically records a body-free PENDING result
and CASes Task to `RESULT_SUBMITTED`. An exact lost-response retry rechecks current
authority without repeating the transition or reference/event insertion. Acceptance
uses a separate current-guarded business CAS. Generic messages and fabricated purpose labels do
not grant Task authority. Legitimate trusted Control management prose/history is
preserved; old rows remain management-only or explicitly unavailable, not silently
reclassified as encrypted. See [Task contract](task-peer-privacy-contract.md).

Schema **57** `v2.task.peer_sealed_references` adds the assignment/reference
sidecars and immutable-reference/definition-uniqueness rules. D1 **56**
`v2.node.tls_authority` and its initializer, prior migration checksums, management
history, private keys, epochs, permanent nonce/serial floors and replay counters
remain preserved. Actual 55→56→57 failure/reopen/history/checksum tests are one
finite acceptance layer; no production StateDir or power-loss/downgrade result is
inferred. Git rollback is not database or external side-effect rollback.

N2 accepts the integer `sequence` already returned by the Hub sealed SEND `202`;
the earlier strict decoder rejected that existing response field. Unknown-field
decoding stays strict. Relay sequence is not the Endpoint encrypted sequence;
this compatibility fix does not change Hub wire or Client contract. Writer-held
Guard, original attempt/outcome and bounded Monitor traversal do not provide an
atomic Hub-to-Runtime transaction. Queue success remains
`CONSUMPTION_UNCONFIRMED`; ambiguous started work stays uncertain without blind
reinjection. Monitor notice recovery is separate from broadcast payload fanout.
See [N2 record](native-reliability-n2-checkpoint-validation.md).

TLS maintenance requires stopping Hub signing and every Agent/writer sharing the
WriterRoot, exact new Owner authorization and offline D1 installation/activation,
approved Hub peer-narrowing configuration, checked Hub restart and checked Node
startup. There is no hot reload, general renewal delegation or production CA/key
ceremony acceptance. Runtime checks independently retained floors, local trust,
current committed authority and held real locks; restored signatures or ACTIVE
labels alone are insufficient. [D2 startup](node-tls-runtime-startup.md) and
[maintenance](node-tls-renewal-recovery.md) retain their component source limits.

Restore CLI uses an opaque exclusively locked `TLSMaintenanceRead` capability
while quarantine remains held. It cannot become a general transport, release the
hold, initialize keys, checkpoint source SQLite, reset replay/counters or authorize
retry. Ordinary `node.recovery.status` still needs the existing management
provider; a Control-free Hub supplies only the dedicated fresh TLS current query
plus independent Relay/SSE. Metadata absence such as NOT_RECORDED never proves
nonexecution. Recovery/installation and quarantine release remain separate.

## Current execution evidence

| Layer | Draft status | Authoritative result location and limit |
|---|---|---|
| Integrated finite normal/race/vet/build/contract/Python and disposable gates | **SCOPED_PASS** | [qa/runs](../.cicada-data/integrated-next-core-20261002/qa/runs/); exact commands/exits/asserted selectors/counts/source-before-after determine each result |
| D2 default/CGO-off/cgo-OpenSSL/race/vet/current-query/startup | **PASS (bounded)** | [d2-qa](../.cicada-data/integrated-next-core-20261002/d2-qa/); batch-native is a Go execution environment, not installed native Runtime/model |
| New clean source/image/protocol handoff | **NOT_RUN** | Requires actual post-review clean identity and exact-image/package receipts; no hash/commit inferred from dirty HEAD |
| Current Android and real native Runtime/model | **NOT_RUN** | Separate fixed-source/APK/runtime acceptance; ordinary Go tests, cooperating subprocesses and synthetic queue are not this layer |
| Physical devices/Nodes, public HTTPS, production restore/CA/deployment | **NOT_RUN** | Separate authorized maintenance/device/deployment evidence required |

The [actual QA receipt](../.cicada-data/integrated-next-core-20261002/qa/receipt.json)
is **SCOPED_PASS**, SHA-256
`567ea1f0c88192c0bd639b9d1a5804cd11a6a68e6a857f6697642d20c2e4256c`:
**41 finite commands, 243 top-level PASS and 308 subtest PASS, 0 FAIL/0 SKIP,
30 actual test-binary execution records / 18 unique binary SHA-256 values**.
These are aggregate finite-selector counts,
not an all-package/full-suite result. The separate exact dirty-image interop gate
passed **2 top-level + 3 subtests**, with **2** actual test binaries; the Chromium
gate passed **20** named steps and Task privacy passed **15 events / 10 unique
cases**. Their owned cleanup and private-fixture removal passed. Source bytes/raw
modes/index and residents matched before/after; product model invocations were **0**.

The [QA manifest](../.cicada-data/integrated-next-core-20261002/qa/manifest.json)
SHA-256 is `c1ce6a9f2d4bfd44b27a5ee376af4b237ced3b94baa3a2b897580406eab155d1`.
Root's [independent read-only verification](../.cicada-data/integrated-next-core-20261002/root-final-qa-review.json),
SHA-256 `2a83a7fd57a45b99ad519af738f2a93a244c85a345dfac433ee64b168950a506`,
verified **604 indexed artifacts** with zero mismatches. Exact argv, exits,
selectors, source and binary hashes remain in those receipts, not inferred here.
The two actual current-QA `preflight-attempt-01.json` and
`preflight-attempt-02.json` failures remain retained; the final result does not
turn them into PASS or replace their original attribution.

The [D2 final report](../.cicada-data/integrated-next-core-20261002/d2-qa/main-freeze1/FINAL_REPORT.json)
SHA-256 is `8e58b8a28d263f629279b0bc6cb038b78f9e5ba77bfe07e4559236f4a6d8e89f`.
It records **51 commands**, runner exit **0**, **28 retained test binaries**,
native/cgo-OpenSSL and race runs each **30 top-level + 47 subtests, 0 fail/skip**,
**7 vet** package checks and **14 compile-only** default/CGO-off binaries.
Compile-only is not runtime execution. Its independent D2-domain fingerprint
`b94507abfeb93a60292928401f2a4a0f31089bd49072f99259fe2f5328cfe8fb`
is distinct from the same full-source ec160 and STD4380 domains. All 51 owned
disposable command containers were absent after cleanup. The retained earlier
35-second race FAIL remains attached to its separate prior source. Go native/cgo
and synthetic TLS startup are not installed Codex Runtime/model acceptance.

The actual dirty STD QA Hub image is
`sha256:5e90ae36322d9a0f6f0b0bf5378af4670703c9e29c20cbfe693da43d95c39bc1`;
the interop image is
`sha256:6b13ec1766ed4cafc654f96e2b614c3146e943e48a6dc5eaf96cd6b184368b8d`.
They identify these bounded dirty-source gates and are not a new clean Client
delivery. No current Android/native Runtime/physical/public-HTTPS result follows
from them. Native helpers without asserted tests, SKIP and NOT_RUN do not count
as PASS. No QA, build or runtime was started by this documentation task.

## Independent Client handoff

Android 既有已验收运行基线仍为 clean 144 / v1.6.1；e8 / v1.6.3 导入与
offline Kotlin candidate checks 只归原来源。Client 当前本地策略为 **39 implemented / 16 closed**，
五项 `link.key_manifest`、`link.key_grants`、`link.key_grant`、
`link.review_policy_preview`、`link.review_policy_grant` 及独立 directory permission
extension 继续关闭，待新 clean 工件交付后分别验收、逐项开放。
`link.review_policy_status` 已实现 metadata 读取，不在这五项中；它不授予签名、路由或投递权限。

The [Client e8/v1.6.3 report](../../CICADA_CLIENT/docs/client-hub-v1.6.3-e8a029d-validation.md),
[operation readiness](../../CICADA_CLIENT/docs/client-hub-v1.6-operation-readiness.md)
and [development plan](../../CICADA_CLIENT/docs/development-plan.md) are read-only
references. They establish their own offline candidate/provenance and old144
runtime scope, not v1.6.4 Android acceptance. Public catalog availability is not
caller authorization. Keep independent trusted Owner pins, exact current
qualifications/proofs, explicit consent, persistent original-packet recovery and
uncertainty fences; only individually accepted flows may open after new clean
delivery. This slice changes no Client file or installed package.

## Historical attribution retained

The original eight documentation bodies remain historical source records under
explicit historical boundaries. Clean144/e64, e8/72ec, original48, Task/privacy,
D1/D2, panel and N2 component results retain their own tested source and limits.
Their Android/native successes, Store race budget timeout, earlier literal
expectation failures and driver failures do not migrate to ec160/v1.6.4 by
mechanical integration or later PASS. Prior checkpoint details remain in
[clean artifact/native validation](v01-clean-artifact-native-checkpoint-validation.md)
and [Task/Restore/D1 validation](v01-task-restore-d1-checkpoint-validation.md).
The adopted specification and prompt are unchanged; implementation evidence
belongs to the architecture audit/plan/status/migration and this validation record.
