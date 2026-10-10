# Architecture v2.3 completion ledger

## Current closeout index — v0.1 PARTIAL

Use the [current validation closeout](v01-current-closeout-20261009-validation.md#current-20261010)
as the single current evidence index. Development software is **0.0.2**, with the **client-hub-v1.6.5** signer-preview
source contract. Earlier signer QA ran on recorded dirty259 with 14 frozen
preview paths; its source attribution remains unchanged. Policy QA
passed normal 71 tests, catalog 4, compatibility 2 and vet; narrow race passed
34 tests, while broad race's two 180s package timeouts remain FAIL. See
[signer validation](link-policy-signer-preview-validation.md) for exact scope.
Clean Core c688 delivered the v1.6.5 Hub/test images and contract bundle; the
separate disposable interop passed five source-scoped checks on its own images.
Clean c688 full Go passed 3,016 tests (1,543 top / 1,473 sub), 23 skipped,
30 packages and exit 0 in 895.740764s, with no source overlay. Exact artifact
identities and independent postchecks are in the current closeout.
G4/G5 qa-a5 passed 40 tests / two packages per normal and race phase, with zero
skips/failures. Real G4 A3 passed the official 0.162.1 queue/crash gate in
20.146s with zero model calls/new turns, without proving model consumption.

Joint7 passed four KEY cases; fresh NONE response-loss remained UNKNOWN at
PREPARING (`LINK_OWNER_KEY_NOT_CURRENT`), and three NONE cases were NOT_RUN.
The Client's KEY-lifecycle dependency caused fresh NONE rejection; the new
preview reads only the authenticated own-side registered ACTIVE signer and
requires an independent complete-identity pin. Client e3d26f8/JVM30/v1.6.4-CLOSED describes the historical candidate only.
Client APK producer 1151 and host source 3cfb identify the tested runtime sources; no new APK build is implied.
Joint8 failed on stale catalog/contract pins; joint9 failed on the stale helper
six-field tuple. Joint10 separately reconciled all eight cases and performed two
owned Hub restarts, but its final 65th close control exceeded the old 64 bound:
overall FAIL remains. All three runs have independently confirmed cleanup.
Joint11 passed all eight Android recovery cases and the unique final close ACK,
with two exact owned Hub restarts and recorded cleanup CONFIRMED; model calls: 0.
Independent postcheck confirmed exact owned-resource absence, closed child
journals and unchanged source/resident snapshots; see the current closeout. KEY uses
independent encrypted Go reads; NONE combines encrypted head reads and signed
candidate DB_READONLY verification, without Android status-read or Native proof.
The clean308d full-Go test overlay and shipping0002e scoped G2/G3
assertions keep their original source; the latter's overall cleanup FAIL is not
rewritten. Shipping a4 remains ordinary Worker scope PASS only.

Next: implement and accept V67 account-bound native direct; separately accept
the remaining physical Runtime/device/public HTTPS gates. Generic V67 same-node is UNSUPPORTED; physical StopVerifier,
real-device and public HTTPS are NOT_RUN. The earlier clean-e2a aggregate remains
INCOMPLETE. Overall first-release acceptance remains **PARTIAL**; main/0.1.0
requires the user's actual acceptance and separate authorization.

## Scoped managed PQTLS fixture evidence — retained source


[Managed fixture validation](pqtls-managed-fixture-validation.md) records focused normal and race 8 top-level / 12 subtests each PASS, full `cmd/cicada` 402 top-level / 287 subtest pass events with 13 opt-in skips, and tagged vet exit 0. These seven-test-path results remain separate from the shipping-build timeout and blocked Native acceptance.

## Historical Native permission wire checkpoint — v0.1 PARTIAL

Both managed adapters now omit sandbox overrides when resuming or starting turns on existing Native threads; fresh Worker defaults remain. [Scoped wire QA and installed synthetic semantics](native-permission-preservation-validation.md) records normal and race 8 top-level / 8 subtests each PASS plus one installed synthetic cold-resume policy/history case PASS; filesystem/network enforcement remains NOT_TESTED, without broader acceptance transfer.

## Historical G5 live-U / Monitor boundary checkpoint — v0.1 PARTIAL

Production Monitor approval-boundary normal/race checks passed (1 top-level / 2 subtests each, zero failures/skips); live zero-turn U variant C passed its bounded production Directory fixture. [Exact source, failed A/B boundaries and scoped evidence](g5-native-monitor-boundary-validation.md) keep these results separate from full G5 and Native context acceptance.

## Historical G5 HTTP privacy checkpoint — v0.1 PARTIAL

Production HTTP directory/Artifact privacy tests and four retained regressions passed (6 top-level / 28 subtests, zero failures/skips); race validation passed the two new tests / 23 subtests with zero failures/skips. [Source, exact fixture scope and remaining G5 assertions](g5-http-privacy-validation.md) distinguish protocol authorization/redaction from Native, model memory and full G5 acceptance. Earlier counts and evidence retain their tested source.

## Historical local-trust admission checkpoint — v0.1 PARTIAL

Queued Link, Network-direct and same-Group admission now rechecks Node-local Owner trust after physical writer acquisition; Link/same-Group also recheck the previously verified pin snapshot. [Source-scoped RED/GREEN evidence and limits](native-local-trust-admission-validation.md) records 11 top-level / 15 subtests GREEN and 15 nodekeys tests PASS; 6 top-level / 8 subtests race validation also passed. This closes the tested writer-wait revocation gap, without upgrading Native/context, Worker or the remaining acceptance gates.

## Historical production-handler protocol checkpoint — v0.1 PARTIAL

Main's scoped production Fabric HTTP handler test and three shared-fixture regressions passed (4 tests, 0 failures/skips), using issued Join sessions and recording Codex only. [Validation and retained preparation failures](native-production-handler-control-isolation-validation.md) distinguish authenticated Manager unavailability from the successful opaque ASK/REPLY roundtrip. This does not close full T9, Native/context or general Worker acceptance; existing counts and remaining gates are unchanged.


## Historical delegated external-sandbox checkpoint — v0.1 PARTIAL

Main's single zero-model native `command/exec` fixture passed five Docker/DAC/network-none predicates; this is not product workspace-write or original-thread acceptance. [Scoped evidence and integration blockers](native-external-sandbox-validation.md) retain the prior namespace failure, G2 FAIL / G3 NOT_REACHED, A6 UNKNOWN and general Worker BLOCKED. The current six-turn Native lane has no complete optional external-sandbox fixture: its automatic turns retain workspace-write and its Runtime envelope does not establish the required hardening or secret-read isolation. No new Native readiness command or binding was prepared.


## Historical selected native tool-registration checkpoint — v0.1 PARTIAL

ONE disposable CLI 0.161.0 synthetic START / actual-unload / same-SID RESUME probe passed selected tool-registration checks: six explicit excluded-tool rejections and two benign MCP pings, with ten local synthetic requests and zero paid/external calls. See [frozen inputs, failed variants and narrow evidence scope](native-selected-tool-registration-validation.md). This does not establish full MCP-only policy, general Worker sandbox or original-thread G2/G3 acceptance.

Sandbox BLOCKED, A6 UNKNOWN, G2 FAIL / G3 NOT_REACHED, inspected V67 local submission UNSUPPORTED and remaining external gates are unchanged. Historical counts and prior acceptance retain their tested source.

## Historical permission / Control-boundary checkpoint — v0.1 PARTIAL

The clean c56 protocol fixtures passed the eight-selector permission subset (8 tests / 43 subtests / 3 packages) and the two-selector Control-boundary subset (2 tests / 0 subtests / 2 packages), each with zero failures or skips. These are scoped protocol results, not full G5/T9 or Native/context acceptance; see [source, evidence and limitations](v01-permission-control-boundary-validation.md).

Sandbox BLOCKED, A6 UNKNOWN, G2 FAIL / G3 NOT_REACHED, fresh Node local SEND/ASK UNSUPPORTED, and remaining full G4/G5/external gates remain unchanged. Historical counts and evidence retain their tested source.

## Historical scoped checkpoint — closed projection QA only

Closed Native-error projection passed scoped offline QA; fresh projection Native validation is NOT_RUN, prior Native FAIL remains unchanged, and G2–G5/V67/current external gates remain unclosed without altering historical counts or overall PARTIAL status ([evidence](native-request-observer-io-validation.md)).

## Historical scoped checkpoint — response-byte QA, Native FAIL

The explicit response-byte candidate passed scoped offline QA, fresh zero preparation passed, and Main’s sole raw-mode Native run failed with A final/context completion not proved; G2–G5/V67 and overall v0.1 remain PARTIAL, with historical acceptance and all ledger counts unchanged ([evidence](native-request-observer-io-validation.md)).

## Historical scoped checkpoint — runner QA, Native FAIL

Source-bound runner QA and fresh zero preparation passed, but the sole latest six-turn Native G2/G3 run failed with A final/context completion not proved, so G2–G5/V67 and overall v0.1 remain PARTIAL; historical G1 acceptance and ledger counts retain their original scopes ([evidence](native-request-observer-io-validation.md)).

## Historical scoped checkpoint — 2026-10-07

Historical G1 retains its old-product scoped PASS; current checked-PQ/wiring/zero gates passed but the sole current Native G2/G3 run failed before its third turn, leaving G2–G5/V67 and overall v0.1 PARTIAL ([Native evidence](native-request-observer-io-validation.md)).

## 2026-10-04 当前账本入口

整体 **PARTIAL**。当前收尾只维护[唯一状态表](architecture-v2-status.md#current-closeout)，精确结果见[验证入口](v01-final-release-exit-checkpoint-validation.md#current-closeout-evidence)。Resource6 / schema 58、Main Hub dirty delta 的 normal / vet PASS、F38 fixed-021 / Client caa9、Native clean-857 prepare 各自归源；本 Main58 race 未重跑。F38 的五 Link 授权 scoped PASS 不增加旧 V01–V88 计数，也不关闭完整 G1、安全恢复、SQLite v29 未闭失败或外部环境 gate。

下方旧计数和记录保留为历史，不能相加为当前完成率。

## 2026-10-04 historical ledger — integrated dirty source; product PARTIAL

The frozen combined full-Go run passed on the integrated dirty source: exit 0, 30 packages, 2,599 PASS events, 18 SKIP, 0 FAIL. Same-source final vet exited 0. These results are not a clean-326ecb9-only claim; exact source pins and receipts are in the validation report. The earlier restore-only failure and its exact-source PASS/PASS/FAIL reproduction remain preserved.

The clean-326 actual injected-before-ledger queue gate later passed once on an independent historical synthetic B copy: one submission, adapter recovery INJECTION_UNCERTAIN, original/new attempt reinjection refused, zero model turns and baseline history unchanged. It does not establish G1, model consumption, exactly-once execution or busy/foreground safety. G1's latest v3 original-A continuation remains OUTCOME_UNKNOWN after one upstream POST and HTTP-reader IncompleteRead; no completed/final response or provider attribution is established. The separate v6 strict-context Golden remains FAIL.

Resource Release is frozen for review after normal/race selectors each passed 16 top-level + 26 subtests with zero skips/failures; an independent review found no blocker within the seven-path scope. It does not provide process-stop proof or close advisory GPU/workspace reconciliation. Acquire rechecks current Task claim; later operations on a still-current ResourceLease do not recheck Task ownership, so Task handoff/expiry alone does not cancel it.

The latest online-tested Client pair (3254ba12cac22d0f77510999f53e6b6bc2c80aa8) passed 36 offline checks; F36 is FAIL / OUTCOME_UNKNOWN: the exact-Link list wait failed before Target prepare, KEY signing, consent or native Alert; four signatures were observed (Source 3 / Target Device 1), with Target KEY/NONE unsigned. Root cause and viewport remain UNKNOWN. Terminal exit 0 records closure only; terminal CORE_ACK_NOT_SENT and the later one Root ACK exit 0 are separate. F35 on a80d1a9 remains FAIL / OUTCOME_UNKNOWN, with no bilateral acceptance. The separate offline Forwarder seven-check selector passed but does not prove actual G1.

The new disposable dirty-326 Docker Go TCP gate passed (script/test exit 0; 2 top-level + 3 subtests, zero skips/failures), with contract check and 17 artifact tests passing. Root independently verified owned-container, image-tag and scratch cleanup. Exact tested source and image identities are in the validation report; this scoped result does not establish Android, Native Runtime or full product acceptance.

Overall v0.1 is **PARTIAL**. Clean-021 Hub/contract and clean-480 Node package keep their original artifact identities. Physical-device, public HTTPS and production gates are NOT_RUN. Full RBAC remains deferred to v0.2.

## Historical ledgers before the clean-1ca baseline

以下旧 current ledger、矩阵和数字只表示其原测试来源。

## 2026-10-02 checkpoint ledger — accepted finite source; product PARTIAL

被测15路径组合的一次full default Go为1340 top＋1006 sub PASS、17 SKIP；有限TLS native/race各9 top＋52 sub、0 fail/skip。
旧clean Main的4 FAIL/16 SKIP完整保留；standalone组件与固定M5 Docker结果不迁移到组合未运行项，也不增加历史36/88完成计数。
逐域证据、Native启动两FAIL和Client待验状态见[本检查点验证](v01-current-authority-multihub-checkpoint-validation.md)。

## Historical ledgers before this checkpoint


## Historical 2026-10-02 ledger — integration complete; QA PASS（有限范围）; product PARTIAL

Main `dev` 的集成候选基于 Git HEAD `c146d58f67f6f4b3e14a8e56a8c68ddc60400713`，工作树含未提交变更；
完整源码 canonical SHA-256 为 `ec160b087221e3118022fcb22b04af1338fea5ea3257e5bf84580af346afa9d1`（1052 个路径），STD 构建输入
`source_fingerprint` 为 `4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032`（882 项）。两者范围不同，均不能只归于 HEAD。
当前软件 `0.1.0-dev`、Architecture v2.3、Hub schema **57**、
`client-hub-v1.6.4`、encrypted wire **1**、catalog **55** 项操作分别记录；
catalog SHA-256 为 `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`。

已机械集成 **86 路径 = panel 6 + review policy 13 + Task privacy 30 + D2 TLS 27 + N2 reliability 10**。
机械集成证明精确源码合并与保全，不能替代运行验收。当前统一 QA 为 **SCOPED_PASS**：41 个有限命令，243 top-level＋308 subtests，
0 fail/0 skip，30 条test-binary执行记录（18 unique SHA）；D2独立51命令的有限检查亦PASS。
这些结果仅归ec160/STD4380，不是全仓、real Runtime或新clean交付PASS。
完整身份、各范围、证据入口和下一出口见[本检查点验证](v01-group-peer-runtime-checkpoint-validation.md)。

当前集成状态不增加历史36/88 PASS计数，也不作100%声明。panel/reviewer/privacy/TLS/native
各自有限门禁和统一源码证据分开；原48race预算FAIL、旧literal预期FAIL与后续有限修正复验、
early driver FAIL、旧native/Android results保留原来源，不能被最终绿结果覆盖。

Android 既有已验收运行基线仍为 clean 144 / v1.6.1；e8 / v1.6.3 导入与
offline Kotlin candidate checks 只归原来源。Client 当前本地策略为 **39 implemented / 16 closed**，
五项 `link.key_manifest`、`link.key_grants`、`link.key_grant`、
`link.review_policy_preview`、`link.review_policy_grant` 及独立 directory permission
extension 继续关闭，待新 clean 工件交付后分别验收、逐项开放。
`link.review_policy_status` 已实现 metadata 读取，不在这五项中；它不授予签名、路由或投递权限。

旧 clean-144 Android/native、e8、原48与各组件结果保持原 source/image/APK/selector
归属；历史 FAIL、timeout、SKIP 和 NOT_RUN 均保留。本组合实际 native Runtime/model、
Android、物理设备、公网 HTTPS、生产恢复/部署验收不由 Go、cgo/OpenSSL 或合成门禁推导。
恢复 metadata 不授权解隔离、重试、重建 counter 或外部副作用重做；整体 v0.1/v2.3 仍为 **PARTIAL**。


本组合实际[QA receipt](../.cicada-data/integrated-next-core-20261002/qa/receipt.json)
SHA `567ea1f0c88192c0bd639b9d1a5804cd11a6a68e6a857f6697642d20c2e4256c`；
[D2 FINAL_REPORT](../.cicada-data/integrated-next-core-20261002/d2-qa/main-freeze1/FINAL_REPORT.json)
SHA `8e58b8a28d263f629279b0bc6cb038b78f9e5ba77bfe07e4559236f4a6d8e89f`。
两个本轮preflight FAIL保留原证据；新的clean工件交付仍待完成。

## Historical ledgers, acceptance matrices and phase rows before integrated-next-core

以下“current ledger”、Acceptance matrix、Golden paths、Architecture phases及其v1.6.1/schema55
文字只保留原时点证据；当前身份及证据以上方入口为准，产品验收仍未完成。
历史V66措辞勘误、旧数值及原source/image/APK links均保留。

## Historical prior checkpoint — 2026-10-02 current ledger — 分源记录；Main组合有界PASS

当前57代码＋五文档候选与原48、N1/TLS/reviewer组件、clean e8工件、旧144 Android/native及owned cleanup的完整证据集中见[组合检查点验证](v01-task-restore-d1-checkpoint-validation.md)。新组合10个聚焦命令及STD镜像门禁 **PASS（有界）**；原48 race预算FAIL、残余PASS与reviewer原120s FAIL分别保留。Client v1.6.3五操作、N2、D2、privacy57和实际产品闭环尚待验收；V66独立新源已通过但未集成Main，不能把组件或旧APK结果当最终PASS。

历史矩阵36/88是原时点行数，不是当前整体完成百分比。V66旧限界句“result does not list drag/box/proposal gestures as assertions”不准确：C4真实12聚合steps确实包含pointer box、Endpoint→Group、PROPOSED Link及recovery断言；准确脚本/Chrome151/source/receipt归属见[组合检查点验证](v01-task-restore-d1-checkpoint-validation.md)中的V66说明。保留旧原文并以此纠正，不把历史Browser PASS迁移到新Main。Group→Group reparent drag的repeat/cycle/staleCAS已在独立671c源验收，Main仍待集成。

按[五检查点计划](architecture-v2-plan.md)收敛；metadata不授权quarantine release/retry，BLOCKED/NOT_RUN/SKIP不当PASS，不作100%声明。以下历史正文和数值保留各自测试来源。

**Historical 2026-10-02 state before clean e8 delivery and the 48-file overlay: clean 144 is delivered; integrated v1.6.3 focused Main QA passed; clean artifacts and Client selectors remain pending. Overall v0.1 is PARTIAL.**

Clean Main `144e079`, standard source `e64f2449…`, captured 806 exact build inputs. Its STD/PQ artifacts, bounded native checks and later Client v1.6.1 delivery remain exact-source results in the [clean artifact/native validation](v01-clean-artifact-native-checkpoint-validation.md).

Integrated dirty Main source-input fingerprint `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` on Git HEAD `144e079` is candidate v1.6.3/catalog `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`, wire 1, 55 operations and schema v55. Its six-package focused normal gate passed 49 top + 128 subtests, zero skips/failures; affected vet/build, contract check/export/verify and Python 15 + 17 subtests passed. Stable source/standard input metadata records 835 entries and 829 Go-projection entries. The [receipt](../.cicada-data/combined-link-proof-20261002/receipt.json) SHA is `6416728daca6fdf4e95f0b0fc60f06ad6dd4ca77ed910ab7c1f2ba90fe8c12e7`. It is not a full default/tagged/race rerun. The dirty local contract bundle `8b22ceb…` is integrity-only, not delivery.

The seven-path Monitor/ACK source passed its separate focused normal/race gate; the 14-file Link-proof patch passed separate focused normal/race and encrypted loopback checks on `144e079 + Directory15`. The prior `cb4d` full Go/tagged results remain attributed to that source, and its broad Store race timeout remains FAIL. No component result is relabeled as a full integrated pass.

A fifth zero-model fixture remains `READY_HELD_LIVE_FOR_CLIENT` on exact clean 144/v1.6.1: two endpoints joined and a synthetic `PROPOSED` Link with `NONE` review policies/no accepted sides, 97 commands exit 0 and zero model/provider/turn/inject calls. It is not Android approval, activation, native Ask/Reply or consumption; four earlier fixture failures remain. The Client carrier preflight fails under its old exact-one-Hub guard; its dedicated correction is underway and current selectors are **NOT_RUN**. PQ authority D1, Task and restore-validation are separate, unaccepted workstreams. Same-Node default Hub Relay has component proof; `nativeDirect` remains unsupported. The separate Task worktree review found peer list/get/claim/renew/accept expose objective/acceptance prose and submit summary lacks explicit Manager recipient/purpose, a v0.1 security release gap. The next slice must use trusted purpose classification and existing sealed-object transport, enforce Task/ArtifactACL/current binding/ownerEpoch, and reject legacy plaintext routes; legitimate Control-management plaintext remains. PQ D1 startup/reload/current-authority-floor/renewal is still PARTIAL outside Main. Matrix counts remain 36/88 rows; recovery metadata does not authorize quarantine release or retry.

**Historical 2026-10-01 C4 unified checkpoint — PASS (bounded; v0.1.x remains incomplete):** the frozen source snapshot is [`closure-20261001T165647Z`](../.cicada-data/next-checkpoint/closure-20261001T165647Z/gate-summary.json), fingerprint `31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2`, based on dirty `dev` revision `f4e4725c5d81c54b166f4291b9d450c70954e6df`; catalog SHA-256 is `1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`. Pinned Go 1.27.1 full Go passed: 27 packages, 1,105 top-level tests and 553 subtests, 12 skips, 0 failures; build, vet, contract check and Python 26 passed. All three disposable Docker suites actually ran their named test and passed ([Client](../.cicada-data/next-checkpoint/closure-20261001T165647Z/client-interop/result.json), [Network M1](../.cicada-data/next-checkpoint/closure-20261001T165647Z/network-m1-interop/result.json), [Group Spaces M2](../.cicada-data/next-checkpoint/closure-20261001T165647Z/group-spaces-m2-interop/result.json)); the 12-step loopback Browser gate passed in 29.755 seconds and cleaned its owned fixtures. Native Runtime on this candidate, physical Nodes and public HTTPS are **NOT_RUN**; product pure-PQ TLS is **NOT_IMPLEMENTED**. The gate records `full_v01_acceptance=INCOMPLETE`; a bounded checkpoint is not Architecture v2.3 completion.

**Retained C3 predecessor failures:** source fingerprint `5b8f151377455ded03a5b71113528c51c3c1e2363855bad0d4e59ce517b9ebf3` passed full Go (1,104 top-level + 553 subtests, 27 packages, 12 skips), vet and build, but its three Docker test drivers failed before test execution because the non-root runner could not traverse `/src`; its Browser gate failed at `canvas_endpoint_admission_0` because the topology snapshot omitted current `context_policy`. These failures remain in the [C3 gate summary](../.cicada-data/next-checkpoint/closure-20261001T161902Z/gate-summary.json). C4 separately fixes test-stage source readability and the snapshot projection, then reruns all three actual Docker tests and the Browser gate successfully; C4 evidence does not overwrite C3.

**Independent Client v1.6 result:** clean Client commit `9cf2b81c256b6a3f17681f28993e7857726e2121` passed its bounded fixed-f4 Android/Hub checks; Root verified 17 receipt/APK hashes and the committed-source match. The Client report records 63 Kotlin tests, but its final clean-commit rebuild is **NOT_RUN**, 20 of 55 Hub operations remain closed, current native Endpoint consent and the broader fault matrix are not accepted, and physical-device/public-HTTPS checks are **NOT_RUN**. This Client result belongs to its own source, APKs and clean f4 Hub, not the dirty C4 candidate; see the [Client validation report](../../CICADA_CLIENT/docs/client-hub-v1.6-f4e4725-validation.md) and [receipt review](v01-recovery-panel-checkpoint-validation.md).

**Historical f55 candidate (2026-10-01, superseded):** root froze read-only source snapshot `final-code-git-snapshot-20261001T102124Z`, fingerprint `f55b5255628030857ac88bd7edbd6da7da1b63d543014c76111f9219f46ad255`, based on dirty `dev` revision `bd79ff93c90ecafc28a2471dd9523444903b39e6`. Its Hub image is `sha256:da88805eaa1987a1c6e06448fc5cddf7d4ce368e8b5eeb3071a1406dad2cb977`; exact source/build metadata are [here](../.cicada-data/v01-finish-20260930T145216Z/final-code-snapshot.json) and [here](../.cicada-data/v01-finish-20260930T145216Z/final-code-hub-build-20261001T102124Z.json). Candidate catalog is Client `client-hub-v1.6`, 55 operations, SHA-256 `1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`. Full Go passed with 1,079 top-level tests + 535 subtests, 26 packages, 12 skips and zero failures; vet, v1.6 contract and 19 Python tests passed. The f55 Client, Network M1 and Group Spaces M2 disposable Docker suites all passed ([Client](../.cicada-data/v01-finish-20260930T145216Z/final-code-client-20261001T102124Z/result.json), [Network](../.cicada-data/v01-finish-20260930T145216Z/final-code-network-m1-20261001T102124Z/result.json), [Group Spaces](../.cicada-data/v01-finish-20260930T145216Z/final-code-group-spaces-m2-20261001T102124Z/result.json)). At the historical f55 stage overall status was PENDING. The prior 2858 production-equivalent source gate passed; Worker approval passed on a separately attributed driver-test overlay; joined V68 passed on a separate test-helper overlay; f55 Browser and separately attributed 432f native peer results passed; this is not a clean Client handoff or release.

**Preceding candidate results (432f, not transferred to f55):** the read-only snapshot `repair-accepted-git-snapshot-20261001T094228Z`, fingerprint `432f3971f51945a054d3519a9a1bbd197d987be20d998f4339df0df637737c21`, produced 1,079 top-level PASS + 535 subtest PASS, 26 packages PASS, 12 SKIP and 0 FAIL, plus vet, focused race, 19 Python, 20 shell syntax, vectors, WASM and bounded Browser PASS. On that source, V68 and real Worker approval failed; the initial Node-Control HTTP attempt failed and a later independent protocol-only overlay passed. Its Client Docker fixture failed, then the Client-only repair passed on distinct cf168 source/image. Full details and limits are in [the v0.1.x checkpoint report](v01-completion-checkpoint-validation.md).

The preceding 432f bounded Go result is 1,079 top-level PASS + 535 subtest PASS, 26 packages PASS, 12 top-level SKIP and 0 FAIL. `go vet ./...` passed. The focused race run passed 20 tests in four packages; Python discovery passed 19 tests and all 20 shell files passed `bash -n`. Contract check/public-vector selectors, production WASM builds, Node 24 WASM checks and Chrome 151 loopback Browser flow passed with the evidence pinned in the checkpoint report. That 432f Browser result did not exercise the later C4 uncertain-write step or public HTTPS, and did not independently assert the canvas pointer gestures.

Docker/runtime layers remain mixed. On 432f, `network-m1` and `group-spaces-m2` passed but `client` failed at `TestClientDockerHubSmoke` because its disposable fixture still sent the retired pairing DTO. The repaired Client suite passed separately on cf168; it does not convert the 432f three-suite result to PASS. The bounded M5 service scenario passed with two production Fabric handlers/SQLite stores and a relay-only multi-Hub Agent in one Go process; it does not prove two Hub processes or isolated Docker Node namespaces. On 432f, V68 has recorded FAIL results at `fabric_only_control_absent` and later `real_node_join`. The first Node-Control HTTP driver attempt failed, then an independent overlay driver passed `TestNodeControlV1HTTPProtocolFlow` on 432f product source with synthetic identities; this is HTTP_PROTOCOL only, not Node agent/native recovery. The first opt-in Codex Worker approval gate failed at `native_approval_not_observed`; its driver used mismatched host cwd/container mount paths. The repaired driver-test overlay passed the real gate on 432f (76.83 s); retain the old failure. See the individual outcomes in the checkpoint report.

The five-target release build and seven packaging tests passed under separate build fingerprint `c411c70998426592ea4aa4c13da8f01308b9aac182ce482f8ad9214a9f343cc9`; no release was published. One fresh idle Hub footprint was measured (13.2 MiB image, 30.3 MiB RSS), which is not a load or capacity result. Current Client v1.6 has a separately attributed bounded Android/Hub PASS on clean f4, but native current Endpoint consent, broader fault matrix and final clean-commit rebuild remain unaccepted/NOT_RUN. Native peer acceptance specifically on f55, two isolated Hub processes, two physical Nodes, public HTTPS, capacity stress, real provider throttling and production stop/reconciliation remain **NOT_RUN**. The C4 Browser's `uncertain_write_fence` step passed using controlled synthetic durable interrupted-state injection; an actual process-kill/inject-before-ledger window remains **NOT_RUN**. Separately attributed 432f ASK/REPLY and native-test-overlay broadcast passed; V68 passed on a separate 840a test-helper overlay; the prior 2858 production-equivalent source gate PASS remains historical. The bounded Android v1.5 result belongs to its separately pinned bd79 Hub, Client commit/APK and package; it does not transfer to v1.6.

**Historical failed snapshots retained:** c7's compile-only/full-Go failures and 49dca's full-Go failures remain linked to those exact snapshots ([c7 compile](../.cicada-data/v01-finish-20260930T145216Z/framework-compile-20261001T052517Z.json), [c7 full Go](../.cicada-data/v01-finish-20260930T145216Z/framework-full-go-20261001T052517Z.json), [49dca summary](../.cicada-data/v01-finish-20260930T145216Z/repair-second-full-go-20261001T080319Z.json)). They are not the 432f result. The earlier incomplete archive attempt remains `FAIL_FIXTURE_INPUTS_MISSING`. The final source f55 and its image are frozen; its own full Go and three-suite Docker evidence is linked above. Do not copy 432f or cf168 Browser/M5/native/repair evidence to f55. Historical matrix entries below retain their original source, image and Client/APK attribution.

## Acceptance matrix

| ID | Status | Evidence in code/tests | Remaining acceptance |
|---|---|---|---|
| V01 | PASS | `internal/fabric/service.go`: `TestUnjoinedNativeSessionIsNotDirectoryObject`; `store/fabric_v2.go` | Keep all current Directory/Relay/Node surfaces covered by the same negative. |
| V02 | PASS | `internal/fabric/service_test.go`: `TestExplicitJoinIsIdempotentAndRotatesBindingCredential`; `store/fabric_v2_test.go` | Passed in c33f full Go; retain future regression coverage. |
| V03 | PASS | `internal/store/fabric_v2_test.go`: role binding/Join tests; `internal/server/fabric_v2_test.go` | No material remaining backend gap identified; retain regression coverage. |
| V04 | PARTIAL | `cmd/cicada/mcp.go` reports failed/non-unique current-session discovery | No black-box test with multiple real native candidates proving ambiguity is refused. |
| V05 | PASS | `internal/fabric/service_test.go`: `TestDirectoryIsGroupScopedAndNeverGuesses` | Passed in c33f full Go; preserve multi-Hub scope in future work. |
| V06 | PARTIAL | Directory scopes and key-bound Links in `internal/fabric`, `internal/store/communication_links_v2.go` | External EndpointCard for an authorized Link and no unrelated member enumeration are not fully exposed/accepted. |
| V07 | PASS | `internal/fabric/service_test.go`: `TestDirectoryIsGroupScopedAndNeverGuesses` | Preserve explicit ambiguity behavior through Network and Hub selection. |
| V08 | PASS (service scope) | `internal/fabric/network_endpoint_leave_test.go`: `TestGlobalEndpointLeaveThenGroupOnlyJoinDoesNotRestoreNetwork`; Store leave tests | Broaden final HTTP/MCP/CLI revoke matrix and prove each new Hub context is independently revoked. |
| V09 | PARTIAL | Legacy inbox and scoped Artifact guards; `docs/architecture-v2-status.md` V09 | Full object-level history policy for older plaintext message history and exports remains incomplete. |
| V10 | PARTIAL | `internal/store/endpoint_group_v2_test.go`: `TestEndpointCanJoinSecondGroupWithoutReplacingNativeBinding`; real same-host native multi-group evidence in `docs/architecture-v2-native-validation.md` | Product warning for shared model memory and sensitive-Group dedicated-Thread control are not complete. |
| V11 | PASS | `internal/store/relay_v2_test.go`: durable REQUEST creation; MCP ask paths in `cmd/cicada/mcp.go` | Passed in c33f full Go; retain surface regression coverage. |
| V12 | PASS (bounded native G1) | `docs/architecture-v2-native-validation.md`; `cmd/cicada/machine_sealed_rpc_fullchain_test.go` | Historical native proof does not cover unattended wake or M3–M5 source; retain exact provenance. |
| V13 | PASS | `internal/store/relay_v2_test.go`: offline queued request/rejoin cases | Add multi-Hub isolation once M5 exists. |
| V14 | PASS | `internal/store/relay_v2_test.go`: `TestRelayV2IdempotencyUsesSenderScopeAndDigest` | Re-run after multi-Hub address/scope changes. |
| V15 | PASS | Same test; conflicting digest must not overwrite | Re-run after multi-Hub address/scope changes. |
| V16 | PASS | `internal/store/relay_v2_test.go`: `TestRelayV2ForgedAckRejectedAndFailureRequeues` | Expand to Node credential transfer and old-writer fencing in M5. |
| V17 | PASS | `internal/store/relay_v2_test.go`: correlated reply/recipient validation | Re-run with Hub-qualified request identity in M5. |
| V18 | PASS | `internal/store/relay_v2_test.go`: `TestRelayV2CursorSurvivesReadDisconnectAndRestart`; M3 `TestGroupSpaceSyncUsesCommitOrderAndRetainsWatermarkAfterPurge` is separate | Space sync does not mark read; real Node/native reconnect and unread experience remain distinct acceptance. |
| V19 | PASS | `internal/store/relay_v2_test.go`: `TestRelayV2ExpiryCancelAndLateReplyAreAtomic` | Preserve bounded behavior. |
| V20 | PARTIAL | Request cancel states in Store/Fabric | A cancel request does not prove native execution stopped or external side effects were reconciled. |
| V21 | PARTIAL | `internal/store/relay_causal_v2_test.go`; candidate MCP/outbox carries trusted `parent_request_id` through Group/Link/Network ASK; REPLY inherits the durable request route and Node authorization projection | Freeze and verify no caller-forged parent, cycle/depth/root-total budget remains terminal 409 without minting a fresh root, while temporary capacity alone is 429 + Retry-After. |
| V22 | PARTIAL | `internal/store/group_spaces_v2.go` quotas; broadcast caps in Store | Wake budget, rate limiting and large fan-out/backpressure stress are not fully accepted. |
| V23 | PARTIAL | Shared Fabric service is used by HTTP/MCP/CLI; legacy route rejection tests | Existing-route inventory is finite; not every adapter/background retry path has a cross-surface equivalence test. |
| V24 | PARTIAL | Message inbox is endpoint-targeted; M2 `group_space_records_v2` provides scoped history; current M3 read state and body-free hint have deterministic backend coverage | Native product unread behavior and full historical export/search scope remain. |
| V25 | PASS (bounded native) | `docs/architecture-v2-native-validation.md`: original A/B UUID continuity | Historical proof is not a test of every current Hub/runtime candidate. |
| V26 | PARTIAL (bounded local serialization) | `internal/store/fabric_v2_test.go`: binding lease/epoch CAS; `TestNativeWriterSerializesAcrossHubScopesAndPersistsEpoch` | The c33f bounded gate covers durable native-outcome refusal of uncertain retry and changed-attempt scope; earlier epoch audit alone did not fence delayed completions. Real two-Hub active connection and interrupted write remain unaccepted. |
| V27 | PASS | Binding takeover/old token tests under `internal/store` and `internal/nodekeys` | Add Hub-credential rotation/revocation cases in M5. |
| V28 | PARTIAL | `cmd/cicada/machine_injection_fault_test.go`: `TestNativeProcessFailureAfterStartIsUncertainAndNeverReinjected` | No controlled kill of a real Codex injector in the inject-before-ledger window. |
| V29 | PARTIAL | Official Codex queue path; no tmux/Enter injection in `machine_sealed_receive.go` | Human foreground typing/concurrent turn has not been stress-tested in a real Runtime. |
| V30 | PARTIAL | Unsupported harness/queue errors are explicit in `cmd/cicada/machine_agent.go` | Authorized replacement/handoff lineage and context discontinuity are incomplete. |
| V31 | PASS (bounded data-plane) | `internal/server/fabric_v2_test.go`: `TestFabricJoinAndHistoricalReadsWorkWithoutControlBusiness`; M1 N13 HTTP test | M2/M3 and full G2 Control-free paths need their own result; Control remains present in the full Hub container. |
| V32 | PASS (regression suite) | `internal/control`, `internal/server`, whole-Go gate recorded for M2 candidate | c33f full Go PASS; do not infer every user-facing management scenario from one test. |
| V33 | PARTIAL | Relay/Node journal restart tests; `TestMachineSealedAskReconnectClaimsDurableOfflineMessage` | No real process kill at every G4 boundary in a two-physical-Node run. |
| V34 | PARTIAL (attempt/intent fence implemented; runtime throttle not connected) | Node provider sidecar persists bounded attempt state and per-attempt intent hashes; `ProviderAdmissionOutcome.Attempt` is mandatory for exact-generation CAS, and Node-Control ClaimTicket v2 persists the random admission intent/generation. Delayed old-generation outcomes are rejected; focused race and C4 full Go passed. | Runtime still does not feed trusted provider rate-limit/known-not-injected classifications into bounded retry/backoff. Legacy v1 tickets and unbound old ledger rows remain fail-closed for explicit local reconciliation; never auto-attach a generation or retry `INJECTION_UNCERTAIN`. C4's Node-subtree backup omitted the shared `WriterRoot/node-provider-admission.sqlite3`; archive v2 now includes it with native-history/writer/resource fences under offline exclusive ownership. Restored or missing/mismatched fences remain quarantined, without product clear/reconnect; never recreate the ledger or infer a generation from a ticket. |
| V35 | PARTIAL | Link and scope guards in `internal/store/communication_links_v2.go`; `TestCommunicationLinkProposalRejectsForeignOwnerAndNeverBecomesActive`; sealed route tests | Cross-owner direct Link passes only on same-host logical Nodes; two physical Nodes, broader revoke/rejoin and cold-wake paths remain. |
| V36 | PARTIAL | `cmd/cicada/machine_sealed_rpc_fullchain_test.go`; `TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative` documented in native validation | Real native proof used two logical Nodes and controlled resume; no dual physical Node or unattended wake. |
| V37 | PASS | `internal/store/shared_task_v2.go` and `shared_task_v2_test.go` separate accepted request/task result states | Re-run with M3 record references and future Network Task routes. |
| V38 | PARTIAL | Ordinary sealed Link path does not call Monitor; tests in `cmd/cicada/machine_sealed_rpc_fullchain_test.go` | Explicit monitor-required offline waiting policy is not implemented. |
| V39 | PARTIAL | Legacy representative owner/epoch state in `internal/store/gateway_v2.go`; Monitor broadcast authority tests | New optional reviewer owner/failover semantics are incomplete; M4 regrouping is not this review lease. |
| V40 | PARTIAL | Producer/evidence lineage in Gateway and M2 producer-signed body in `internal/e2ee/group_spaces.go` | Broad direct-result, broadcast and Monitor-summary preservation matrix is incomplete. |
| V41 | PARTIAL | `internal/store/communication_link_grants_v2_test.go`; `cmd/cicada/machine_sealed_receive_test.go` | Existing link tests cover narrow action/scope/revocation paths; dual-physical and all enqueue/claim/inject/read permutations remain. |
| V42 | PARTIAL | Contact revoke plus Link proposal/grant version fences in Store | Activated cross-user link revocation against pending deliveries and old endpoint key material needs broader acceptance. |
| V43 | PASS | `internal/store/shared_task_v2_test.go`: `TestSharedTaskConcurrentClaimAndStaleCandidate` | Re-run whole race/frozen-source gate. |
| V44 | PASS | Same test and result-revision guards | Preserve non-authoritative stale candidate semantics. |
| V45 | PASS | `internal/store/shared_task_v2_test.go`: `TestSharedTaskDependenciesPreventCyclesAndPrematureClaim` | Re-run regression. |
| V46 | PARTIAL | `internal/store/resource_lease_v2_test.go`: `TestResourceLeaseCrossGroupSingleAuthorityAndQuarantine` | Same canonical GPU resource conflicts across groups at Store level; no real GPU executor enforcement run. |
| V47 | PARTIAL | `TestManagedBlobExecutorRejectsStaleEpoch` proves fencing for bounded managed-blob writes | GPU/workspace lease remains `advisory`; arbitrary shell and long-running native work are not fenced by this executor. |
| V48 | PARTIAL | `TestResourceLeaseExpiryDoesNotAssumeOldProcessStopped`; quarantine/reconcile Store APIs | Synthetic confirmation exists; real old process stop/isolation and post-crash reconciliation remain. |
| V49 | PARTIAL | Shared Task result submission/acceptance state tests | Full per-task evidence policy and independent executor evidence are not universal. |
| V50 | PARTIAL | Scoped Artifact hash/read tests under `internal/store` and `internal/server` | A changed content/version is rejected in tested paths; complete external object replacement/storage-integrity path not run. |
| V51 | PARTIAL | `internal/server/artifact_v2_group_scope_test.go`: `TestArtifactV2HonorsExplicitGroupScopeForMultiGroupEndpoint` | Exact-file sharing is guarded, but end-to-end external storage/path traversal and artifact export matrix remains. |
| V52 | PARTIAL | v45 cross-Node metadata/CAS and v54 same-Node local SEND-ledger proof/metadata proposal with Node revalidation are wired; Hub same-Node path does not relay the envelope/body | Neither handoff path proves delivery/consumption or stops existing processes. Node restart/no-ACK, side-effect reconciliation and explicit stop-confirmed ResourceLease release are unaccepted. |
| V53 | PASS | `internal/fabric/service_test.go`: `TestActorForgeryAndRevocationFailClosed`; MCP forgery tests | Add M5 credential portability checks. |
| V54 | PARTIAL | Strict request fields and no peer-to-Approval write path in `internal/server`; Monitor/approval tests | Dedicated prompt-injection acceptance at actual execution boundary is absent. |
| V55 | PARTIAL | Trusted actor/provenance in Gateway and Node notice paths | No full malicious Monitor instruction run through a real guarded executor. |
| V56 | PARTIAL | Membership revocation blocks Store reads/writes; Artifact scope test above | Search/export and every historical object/ref surface are not exhaustively fenced. |
| V57 | PASS (current peer-write backend) | `internal/server/fabric_plaintext_capability_test.go`: `TestPlaintextFabricPeerWritesAreRetiredBeforeBodyRead`; `internal/server/network_active_entrypoints_test.go`; `internal/e2ee/endpoint_test.go`, `network_direct_test.go`, `group_spaces_test.go` | Current new peer writes require sealed payload; old plaintext `/v2/fabric/send|ask|reply` returns 410. This does not claim that all historical stored records are encrypted. v40 dual-Owner new-record boards have separate proof and Guard tests; cross-owner history remains denied. |
| V58 | PARTIAL | Historical subtree/Store migration tests plus current archive-v2 shared WriterRoot inclusion, shared/exclusive-lock and exact-bundle synthetic tests; [current source/gates](v01-transport-recovery-checkpoint-validation.md). | Restores remain quarantined; production device recovery, explicit post-restore Hub/Node ticket/counter reconciliation and real stop/rollback fencing remain. |
| V59 | PARTIAL | Secret-scanning, token file permissions and environment filtering tests | Production crash dump/host collection paths are not tested. |
| V60 | PASS (synthetic migration) | `internal/store/migrations_v2.go`; M1 `TestNetworkV34UpgradeInterruptionPreservesCompleteLedgerAndMappingScope`; M2 migration tests | Does not constitute production StateDir power-loss recovery. |
| V61 | PARTIAL | Retired `/v1` routes and M1 `TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials` (36 route-family cases) | Finite existing-route inventory only; every MCP/CLI/Node/background route and all newly added routes require continued checks. |
| V62 | PARTIAL | Current reads check authoritative Store membership/epoch in `internal/fabric` and `internal/store` | Authority service outage/failure injection is not a complete black-box matrix. |
| V63 | PASS (reporting behavior) | M1/M2 validation reports separate `NOT_RUN`, `SKIP` and `BLOCKED` layers | This is evidence discipline, not a runtime feature. Preserve it in the final report. |
| V64 | PARTIAL (bounded actual-TCP sample) | Independent dirty 4fb `c23ef9…` run-2 PASS: one 1-CPU/128-MiB Hub, 64 synthetic Endpoints/two synthetic Nodes/16 HTTP workers; expected sender ASK cap/backpressure and cancellation/reply progress. [Source and exact metrics](v01-transport-recovery-checkpoint-validation.md). Run-1 fixture failure retained. | No sustained fleet/native/physical/public-HTTPS or combined-main/PQ capacity guarantee. PASS count unchanged; queue/cancel states are not model consumption or process-stop evidence. |
| V65 | PARTIAL | Endpoint multi-Group Store/MCP/HTTP tests and native G1 multi-group run | Full scope matrix plus user memory warning/sensitive-thread policy is incomplete. |
| V66 | PARTIAL (browser flow bounded; new pointer gestures not separately asserted) | `ui/panel-canvas.js` implements Endpoint→Group admission preview/confirm, Endpoint→Endpoint proposal gesture and box selection; 432f and f55 Chrome 151 results cover pin, encrypted vault/enrollment, topology/status/canvas and topology apply | The result does not list drag/box/proposal gestures as assertions. Gesture preview/CAS stale denial, no implicit activation, uncertain-write recovery and public HTTPS remain unaccepted/NOT_RUN. |
| V67 | PARTIAL | `TestMCPSealedSameNodeGroupAskReplyNative` and its 2026-09-24 native record: real Codex queue into the exact native Thread, no Hub Relay business delivery, original-Thread reply observed | This proves the existing same-Node route for that exact supported CLI queue. The general TUI/direct native API adapter is unsupported; keep that unsupported scope distinct from this bounded PASS. |
| V68 | PASS (bounded joined Docker; 840a test-helper overlay) | Base 432f plus reply-correlation helper fingerprint 840a2209…: two real Node agents on separate private bridges, Hub restarts twice, MCP ASK/receive/REPLY, exact retry/dedup, wrong-ACK denial, ciphertext and outbound-only topology checks PASS; labelled cleanup PASS. [Evidence and retained failures](v01-completion-checkpoint-validation.md). | Recording fake queue, not native; does not transfer to f55 or prove physical hosts/public HTTPS. Earlier 432f FAILs remain unchanged. |
| V69 | PARTIAL | Bilateral key-bound grants and same-host two-owner native sealed Link ASK/REPLY | Dual-physical Node, public HTTPS and complete visibility/revoke test absent. |
| V70 | PARTIAL | `TestDirectoryIsGroupScopedAndNeverGuesses`; explicit multi-Group scope tests | Full native MCP request/resolve test across two same-name candidates and Hub/Network selection remains. |
| V71 | PARTIAL | Durable offline/SSE tests plus 840a joined two-Node Docker gate: two Hub restarts, persisted DB/outbox exact retry, reconnect dedup and wrong-ACK rejection PASS | Recording fake queue; not physical Nodes, every kill window or native consumption during fault recovery. Original V68 failures retained. |
| V72 | PASS (bounded native same-Group broadcast) | 432f product + owned native-test overlay: `TestMCPSealedSameGroupBroadcastNative` PASS 298.14 s; both original recipient Threads consumed broadcast and prior context | Earlier FAILs retained. This does not prove physical dual-Node, wake budget, all authorization/fault windows or a native PASS on final source. |
| V73 | PASS (bounded historical Android + native run) | `../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md`: Hub source `25013b5…`, Hub image `a1cf39…`, Client contract v1.3; tested product APK source `9568b2ff6d4e156b70484c10b7fd5195405004b0` / SHA `f8c82d…8700`; instrumentation test source `02cefa94bc6096f7196d1df572a22a1f64774d74` / SHA `4cbc0e…f90b`; Core runner `0d532f2…` and recorded runtime image/binary | The exact run proves its bounded preview/confirm and two-recipient consumption. It is not attributable to Client `b627e70` by proximity; full React Native product flow, physical Android/Nodes and public HTTPS remain untested, and it does not transfer to `f30892f`. |
| V74 | PASS (M1 backend) | `docs/network-m1-validation.md` N01; `TestNetworkM1DockerHub`; Network Store/Fabric guards | Historical backend pass; re-run against final M3–M5 frozen source. |
| V75 | PARTIAL (backend Surface implemented) | Network Task/Broadcast lifecycle, early unpublished-route denial, outbox recovery, purpose consent/revoke and per-reader Guard have deterministic/suite coverage; v1.6/55-op dirty contract exported and verified, including new Policy/BROADCAST vectors. Independent Client `9cf2b81` passed bounded Kotlin/Hub checks against clean f4; this is separately sourced. | Client positive current Endpoint admission/dual-Owner authority and broader fault/revocation matrix remain unaccepted; final clean Client commit rebuild was not run and 20/55 operations remain closed. Catalog availability does not authorize callers. |
| V76 | PASS (M1 backend) | M1 N02–N04: `TestUnjoinedNativeSessionIsNotDirectoryObject`, `TestNetworkOnlyMCPStateCannotBecomeGroupAuthorization`, Network join tests | Product Client enrollment and real Runtime join are separate NOT_RUN layers. |
| V77 | PARTIAL (Core Store bounded, Surface WIP) | `internal/store/communication_links_v2.go`; v51 immutable external invite `direction`; direction-derived bidirectional Link SEND/ASK/REPLY Surface; separately bounded two-production-Fabric-service M5 test | Candidate invite preview and bilateral purpose-key consent, plus isolated two-Hub process, credential transplant/replay and Client/native acceptance remain. M5 same-process evidence does not cover these. |
| V78 | PARTIAL (54f bounded native multi-Hub Join PASS) | `TestMCPSealedNativeThreadJoinsTwoIndependentHubsNative` PASS on 54f, 160.92 s: same original Thread resumed into Hub B then A; independent origin/pins/Node credentials/Endpoint/cache, wrong-Hub token 401, scope count 1→2 and shared-memory risk, Control 0. [Evidence](../.cicada-data/v01-finish-20260930T145216Z/multihub-native-54f-20261001T1230Z.json). | One container/OS user, two logical TCP Hubs; not two independent Hub processes or physical Nodes. No peer-payload injection or provider-request-count assertion; synthetic replay metadata is separate from Runtime payload replay. |
| V79 | PARTIAL | M1 N10 and `TestNetworkPermissionPresetsHaveExactLeastPrivilegeGrants` | NetworkAdmin invitation scope is tested; all device/Node/private-key/history/user-Approval denial attempts are not exhaustively exercised. |
| V80 | PASS (synthetic SQLite/HTTP/CLI) | M1 N12, migration report/dry-run and interruption-preservation tests | No production StateDir migration, power-loss recovery or live mapping exercise. |
| V81 | PARTIAL | M1 N07–N09 revoke checks and Node pre-injection fence tests | Offline Nodes cannot provide instant global revoke; no full split-brain/lease-expiry physical test. |
| V82 | PARTIAL | M1 N05 hidden-scope/alias checks and M2 ciphertext-only fixture scan | Traffic timing, membership existence, retention and metadata access surfaces need one joined privacy audit. |
| V83 | PASS (M2 same-owner backend) | `internal/store/group_spaces_v2.go`: `ListGroupSpace`; `TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS` | Re-run passed in c33f full Go and disposable Group Spaces gate; no Android board content path. |
| V84 | PASS (M2 one-record, same-owner only) | `GetGroupSpaceHistoryManifest`, `GrantGroupSpaceHistorySealed`; M2 history test and `internal/e2ee/group_space_history.go` | v40 supports separately authorized new cross-owner Board records, not cross-owner historical grants; history remains fail closed. |
| V85 | PASS (M2 same-owner backend) | `internal/store/group_spaces_v2.go`; `internal/e2ee/group_spaces.go`; `TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS`; `TestGroupSpacesMCPAcrossNodesWithLostCommitResponse` | Real native authoring/reading and product UI are NOT_RUN. |
| V86 | PARTIAL (current M3 deterministic backend) | `TestGroupSpaceSyncUsesCommitOrderAndRetainsWatermarkAfterPurge`; Node/MCP sync and body-free SSE hint paths; three c33f disposable Docker suites PASS | Real native unread behavior, Android content surface and cross-resource Journal references remain unaccepted. |
| V87 | PARTIAL (deterministic backend plus bounded proposal evidence) | `TestDelegatedRegroupExactOwnerConsentCASAndAudit`; current nonpaid own Join/WhoAmI/CANDIDATE preflight without Directory/peer-traffic grants; separate historical paid Monitor proposal used synthetic operator `directory.read` CAS | Peer Directory/traffic remain guarded. Encrypted Owner Group-grant UX, genuine native approval/delegation, successful CAS/apply/audit, revoke/expiry/stale/current-binding cases and physical-device acceptance remain unaccepted. |
| V88 | PARTIAL (v40 bounded cross-owner board) | `TestCrossOwnerGroupAdmissionJoinAndDualKeyBoard`; `TestCrossOwnerGroupSpaceKeyRequiresBothIndependentLocalOwnerPinsAndProofs` | New-record dual-Owner admission/key proof works in deterministic tests; cross-owner history remains denied, and real Client/native join/content UX is unrun. |

## Golden paths

| Path | Status | Evidence | Remaining acceptance |
|---|---|---|---|
| G1 existing-context group ask/reply | PARTIAL (bounded native PASS) | Real-4 on dirty `bc6def…`/4fb runs seven actual CLI turns across two private Docker Node namespaces: explicit Join, offline sealed ASK, outbound reconnect, exact ASK/REPLY receives and original-context witnesses. B replies before receive; queue state remains `CONSUMPTION_UNCONFIRMED`. [Current provenance](v01-transport-recovery-checkpoint-validation.md); historical 432f unicast/broadcast [retain their own evidence](v01-completion-checkpoint-validation.md). | Combined-current-source native gate, unattended cold/busy wake, front-end typing race, dual physical hosts, public HTTPS and M2 native Board use remain. Exact tool receipt does not claim exactly-once or confirmed Runtime consumption. |
| G2 multi-Group and cross-Group direct | PARTIAL | Multi-Group same Endpoint and bilateral Link sealed ASK/REPLY; fake full-chain plus real Codex on two logical Nodes | Two physical Nodes, sole shared Hub route and both Node outbound-only in one run; current v2.3 same-host direct adapter; full Link revoke/rejoin and broadcast combination. |
| G3 Control outside data path | PARTIAL (bounded native PASS) | Real-4 `bc6def…`/4fb production `--fabric-only` structurally excludes Control construction, with authenticated management HTTP 503 and a Hub database/WAL/log blind-marker oracle; no invocation counter is instrumented. [Current provenance](v01-transport-recovery-checkpoint-validation.md). Historical 432f unicast/broadcast and c33f keep their own source attribution. | Extend to current M2/M3 native and full G2; bounded paths are not a universal Control-free proof. |
| G4 restart/disconnect/duplicate | PARTIAL | `relay_v2_test.go`, `machine_sealed_receive_test.go`, `TestMachineSealedAskReconnectClaimsDurableOfflineMessage` | Kill/restart at send, Relay commit, Node persist and native inject windows in one real service topology; preserve uncertain result semantics. |
| G5 authorization/data boundary | PARTIAL | Fabric forgery/revoke tests, Link grant tests, Artifact scope, M1 route inventory, M2 cutoff/history denials, v40 dual-Owner proof negatives | Full matrix for Group+Network+Link+space history, unread hints, Monitor, current/new cross-owner reader proof, multi-Hub credential transplant and search/export. |

## Architecture phases and remaining scope

| Phase | Current conclusion | Next acceptance |
|---|---|---|
| v2-A identity/Group/Guard | PARTIAL overall; M1 Network backend N01–N13 passed on its recorded candidate | Close editable topology/migration UI gaps and complete legacy/hidden-object route inventory. |
| v2-B native async/recovery | PARTIAL; durable sealed paths and selected native Codex paths exist | Real dual-physical-Node + one-Hub isolation, human foreground safety, kill-window recovery and explicit capability matrix. |
| v2-C memberships/links/broadcast | PARTIAL; bilateral sealed single-recipient route works in bounded scopes | Complete routes, selected zero/one relay, two-user revocation, physical broadcast and optional review policy. |
| v2-D task/resource/evidence | PARTIAL; task CAS and managed-blob executor fencing exist | Distinguish enforced operations from advisory GPU/workspace leases; real long-job stop/isolate/reconcile and evidence acceptance. |
| v2-E product/interop | PARTIAL; historical C4 browser and clean f4 Client checks retain their sources | Current contract is v1.6.1 / wire 1 / 55 operations with Hub schema v55. Client d580 offline build/JS/Kotlin/UI checks pass on its APKs; original build-time mode capture/provenance remains BLOCKED, and dd1 is retrospective only. Main PQ code is integrated but has no new image acceptance. Physical Android/public HTTPS remain NOT_RUN; certificate lifecycle and actual process-kill/stop reconciliation remain gaps. |
| M1 Network identity/Guard/migration | Backend PASS on fingerprint `479386…`; Android/native/physical/public layers NOT_RUN | Re-run backend regression at final freeze; do not relabel the earlier dirty-source run. |
| M2 encrypted Journal/Discussion | Backend PASS on fingerprint `76becd…`; that historical M2 candidate was same-owner, one Hub | Current v40 dual-Owner new-record path has its own c33f deterministic gate; historical M2 PASS does not prove it. Real Runtime/Android/device/public HTTPS remain separate. |
| M3 scoped cursor/unread hints | PASS (bounded deterministic backend), PARTIAL overall | Commit-order watermark, explicit read marker, current Guard and body-free wake have current Go gate coverage; native/browser/Android and Journal references remain separate. |
| M4 delegated regrouping | PASS (bounded deterministic backend), PARTIAL overall | Exact Owner route/delegation, topology CAS and audit have Go coverage. Attach-3 emulator UI passed but its native Join failed; preserve that receipt. A separate historical real-1 proposal stayed PROPOSED after a synthetic operator `directory.read` CAS. Current default-HTTP preflight without Directory/peer-traffic grants passes own Join/WhoAmI/CANDIDATE, while peer Directory/key/SEND remain guarded; it is not a real native Runtime PASS. Encrypted Owner grant, authorized apply/delegation/revoke and physical acceptance remain. |
| M5 multi-Hub Node/Client | PARTIAL (bounded native multi-Hub Join PASS) | 54f original-Thread Hub B→A Join/whoami passed with isolated pins/credentials/Endpoint/cache and explicit shared-memory risk; earlier same-process service evidence retains its source. Independent Hub processes, physical Nodes, peer payloads and Android multi-Hub recovery remain separate. |
| M2+ cross-owner boards | PASS (bounded dual-Owner Store/Nodekeys backend), PARTIAL overall | v40 new-record admission, consent and key proofs have deterministic coverage; cross-owner history remains denied; Android/native product flow is unrun. |

## Validation floor for the next frozen candidate

At the repository root: `go test -count=1 -timeout 15m ./...`, `go vet ./...`, the focused race selectors for touched Store/Fabric/Server/Node/MCP packages, `python3 scripts/client-contract.py check`, `python3 -m unittest discover -s scripts -p 'test_*.py'`, `bash -n scripts/test-architecture-v2-completion.sh`, and `git diff --check`. After that stable-source gate, invoke the one-shot orchestrator once with `scripts/test-architecture-v2-completion.sh`; it runs child disposable suites, writes private per-step logs/result JSON below `.cicada-data/architecture-v2-completion/`, and records before/after source metadata. Browser inputs must be explicitly pinned with `CICADA_HUB_IMAGE`, `CICADA_BUILD_METADATA`, and `CICADA_EXPECT_SOURCE_FINGERPRINT`. The optional `--native` invokes the real Codex Worker→approval→result gate only; it does not establish native peer Ask/Reply or Broadcast consumption. Android, physical devices and public HTTPS remain independent result fields, never inferred from this driver. Child scripts must own and remove only their labelled one-shot fixtures; six resident containers and shared Hub state are out of scope.

The initial matrix review was read-only; later work in this task is separately identified in the deployment/source records and is not product/native acceptance. Do not use the six resident baseline containers, a shared development Hub, real keys, Android UI, or a model token as an acceptance fixture.
