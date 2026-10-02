# Task / Restore / D1 组合检查点验证（2026-10-02）

Main `dev` 基于 `e8a029d79bbdddb75ea376afa76e62a5c8444f59`，集成Task/Restore/D1、N1、TLS restore fence与reviewer当前资格修复。**57代码路径＋五文档＝62 dirty路径的聚焦组合门禁和新STD实际镜像门禁PASS（有界）**。Hub schema56、Client `client-hub-v1.6.3` / wire1 / 55ops，catalog `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`；57不是schema版本，Task privacy/schema57另属新候选。

实际测试完整source1015 inputs/SHA `be2850c46997f59f3528843e0c02c4535f801675b6bdf8561adf2336f46aa51b`；STD852/SHA `4229d6ffb88629ce4efc3bbfac121c552cd1e5e6caf12f20f3ac97e21c387589`，Go投影846＝812Go＋34其他/SHA `5d9b1e40e12a71795841321a9cba07e99709f9a4b0cecd1b3ec2106c0efe2e22`，source/index/Go/STD before-after精确一致。此前代码pre-docpoint的1014输入`10b3ab5e…`只归加文档前，不是测试完整source。[最终receipt](../.cicada-data/integrated-n1-tls-reviewer-20261002/receipt.json) SHA `fa6fcc67a45aaf2a40e8cc12c35db47c91c34c29ea72797c1ad2b1f49cee6689`；[report](../.cicada-data/integrated-n1-tls-reviewer-20261002/report.md) SHA `a54d123cb11421cd64b837ca1302f56e8a5614ac8434c67a525ac727bdab0672`；[manifest](../.cicada-data/integrated-n1-tls-reviewer-20261002/manifest.json) SHA `2025039f30d09d866699bbc9a7ee5bb13508dc201c90812e0bee6fff22f935b1`。本次终态仅更新这五份文档；测试源与终态docdelta分别封存，Go/STD不变，不因文档重跑Go，也不把历史48命令搬到当前源。

| 当前组合实际门禁 | 结果 |
| --- | --- |
| [n1-normal](../.cicada-data/integrated-n1-tls-reviewer-20261002/n1-normal/result.json) | exit0，12 top/10 sub，1实际binary，零fail/skip。 |
| [n1-race](../.cicada-data/integrated-n1-tls-reviewer-20261002/n1-race/result.json) | exit0，12 top/10 sub，1实际binary，零fail/skip。 |
| [tls-backup-normal](../.cicada-data/integrated-n1-tls-reviewer-20261002/tls-backup-normal/result.json) | exit0，9 top/23 sub，1实际binary，零fail/skip。 |
| [tls-backup-race](../.cicada-data/integrated-n1-tls-reviewer-20261002/tls-backup-race/result.json) | exit0，9 top/23 sub，1实际binary，零fail/skip。 |
| [reviewer-normal](../.cicada-data/integrated-n1-tls-reviewer-20261002/reviewer-normal/result.json) | exit0，6 top/11 sub，1实际binary，零fail/skip。 |
| [reviewer-race](../.cicada-data/integrated-n1-tls-reviewer-20261002/reviewer-race/result.json) | exit0，2 top/11 sub，1实际binary，零fail/skip。 |
| [n1-transport-normal-once](../.cicada-data/integrated-n1-tls-reviewer-20261002/n1-transport-normal-once/result.json) | exit0，1 top/0 sub，1实际binary，零fail/skip。 |
| [affected-vet](../.cicada-data/integrated-n1-tls-reviewer-20261002/affected-vet/result.json) | exit0，零fail/skip。 |
| [affected-build](../.cicada-data/integrated-n1-tls-reviewer-20261002/affected-build/result.json) | exit0，零fail/skip。 |
| [contract-check](../.cicada-data/integrated-n1-tls-reviewer-20261002/contract-check/result.json) | exit0，零fail/skip。 |
| 新STD镜像实际TCP smoke/recovery | exit0，2 top/3 sub、2实际binaries、零fail/skip。 |

十个聚焦命令共实际执行7个测试二进制；STD门禁另2个，共9次执行，均保留hash与raw modes。新dirty Hub `sha256:78e6ca6f5bbfec05ad2ee71bf46f1709b41984965ecba8de485a36e5f6519e94`、interop `sha256:c7dc7f06c1fa8b3ab93be074da0a6e45ddddff68c2bb045949fbcc1c4a595d68`来自当前STD源，实际health/capabilities复核与private TCP门禁通过；exact-owned tags/fixtures已清理，clean e8交付镜像未触动。完整Docker argv、命令日志与二进制在receipt；以下仅列容器内实际argv，环境沿用下述pinned离线Go条件。

`n1-normal`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -run '^(TestMachineNativeDeliveryBusyPreservesClaimAndJournal|TestMachineNativeDeliveryAuthorityChangesDuringWriterWait|TestMachineNativeDeliveryCrashAfterSuccessfulWaitBeforeOutcome|TestMachineNativeDeliveryCrashAfterDurableOutcomeBeforeReceipt|TestMachineNativeDeliveryPreflightNeverPersistsIntent|TestMachineNativeDeliveryCleanupCannotReleaseInjecting|TestMachineNativeDeliveryStartedFailureAndCommitFailureStayUncertain|TestMachineNativeDeliveryAcceptedReplayUsesExactDurableIdentity|TestMachineNativeDeliveryDurableReceiptDeniedRetainsRecovery|TestMachineNativeDeliveryConflictingDurableIdentityIsFenced|TestMachineNativeDeliveryAmbiguousInboxAdmissionStaysUnknown|TestMachineNativeDeliveryStartedCancellationRecoversUnknown)$' ./cmd/cicada
```

`n1-race`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^(TestMachineNativeDeliveryBusyPreservesClaimAndJournal|TestMachineNativeDeliveryAuthorityChangesDuringWriterWait|TestMachineNativeDeliveryCrashAfterSuccessfulWaitBeforeOutcome|TestMachineNativeDeliveryCrashAfterDurableOutcomeBeforeReceipt|TestMachineNativeDeliveryPreflightNeverPersistsIntent|TestMachineNativeDeliveryCleanupCannotReleaseInjecting|TestMachineNativeDeliveryStartedFailureAndCommitFailureStayUncertain|TestMachineNativeDeliveryAcceptedReplayUsesExactDurableIdentity|TestMachineNativeDeliveryDurableReceiptDeniedRetainsRecovery|TestMachineNativeDeliveryConflictingDurableIdentityIsFenced|TestMachineNativeDeliveryAmbiguousInboxAdmissionStaysUnknown|TestMachineNativeDeliveryStartedCancellationRecoversUnknown)$' ./cmd/cicada
```

`tls-backup-normal`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -run '^(TestTLSBackupCapturesPrivateScopesAndWitnesses|TestTLSRestoreRetainsFloorsAndRemainsQuarantined|TestTLSRestoreRejectsMissingLowerAndConflictingFloors|TestTLSInventoryRejectsUnsafeLayouts|TestTLSArchiveTamperingRejected|TestTLSBackupWithoutWriterRootRejectsOmission|TestTLSRestoreFailedPublicationHoldsPartialState|TestTLSBackupCompetingProcess|TestTLSBackupMissingFloorRejectsWitnessRecreation)$' ./internal/nodebackup
```

`tls-backup-race`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^(TestTLSBackupCapturesPrivateScopesAndWitnesses|TestTLSRestoreRetainsFloorsAndRemainsQuarantined|TestTLSRestoreRejectsMissingLowerAndConflictingFloors|TestTLSInventoryRejectsUnsafeLayouts|TestTLSArchiveTamperingRejected|TestTLSBackupWithoutWriterRootRejectsOmission|TestTLSRestoreFailedPublicationHoldsPartialState|TestTLSBackupCompetingProcess|TestTLSBackupMissingFloorRejectsWitnessRecreation)$' ./internal/nodebackup
```

`reviewer-normal`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -run '^(TestCommunicationLinkReviewPolicyBilateralQueueFailoverAndDecision|TestCommunicationLinkReviewExpiryUsesOwnerProofDeadlineAndRecoversQueue|TestCommunicationLinkReviewPolicyRejectsPolicyMismatchAndStaleCAS|TestCommunicationLinkReviewPolicyRejectsCASOverflowAndPermitsFinalVersion|TestCommunicationLinkReviewPolicyCurrentReviewerQualification|TestCommunicationLinkReviewPolicyQualifiedCurrentReviewer)$' ./internal/store
```

`reviewer-race`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^(TestCommunicationLinkReviewPolicyCurrentReviewerQualification|TestCommunicationLinkReviewPolicyQualifiedCurrentReviewer)$' ./internal/store
```

`n1-transport-normal-once`：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -run '^(TestMachineNativeDeliveryTransport)$' ./cmd/cicada
```

`affected-vet`：

```sh
go vet -p=1 ./cmd/cicada ./internal/nodebackup ./internal/store
```

`affected-build`：

```sh
go build -p=1 ./cmd/cicada ./internal/nodebackup ./internal/store
```

`contract-check`：

```sh
/usr/bin/python3 scripts/client-contract.py check
```

`新STD镜像门禁`：

```sh
go test -work -json -count=1 -p=1 -timeout=15m -exec '/usr/bin/python3 /evidence/test-exec.py' -run '^TestClientDockerHub(Smoke|RecoveryFixture)$' ./internal/server ./cmd/client-recovery-fixture
```

clean e8/v1.6.3交付已由Root推送dev；其schema55/835-input STD与独立PQ结果仍归原clean源，见[STD artifact index](../.cicada-data/final-std-e8a029d-20261002/artifact-index.json) SHA `3cd74300c3ed53cd68f914781f3df2e913e27079a6271ebbb697854f50a5aec5` 和[PQ RESULTS](../.cicada-data/final-pqtls-e8a029d79bbdddb75ea376afa76e62a5c8444f59/RESULTS.json) SHA `60061d25e24a2acd1b2262dce4f57cae663ceafd0bbda37426f4795430ebf361`，不是本次dirty新镜像的验收。

这是 **原48 dirty候选** 的有界验收记录。基线 `e8a029d79bbdddb75ea376afa76e62a5c8444f59` + Task14/Restore20/D114，STD source `810c8e3de92851d021a702bdbace52f57add4f8593dde1bd5ac3dbfd92c870e5`，完整source `cdef33c321a37bfc040c6c8c8209e33e3ac0b2356df8683ca280be9b038e8e99`；848 STD/842 Go投影输入、schema56、Client v1.6.3/wire1/55ops。Source-before/after、owned48 bytes/raw modes、index保持一致。[最终receipt](../.cicada-data/integrated-task-restore-d1-20261002/receipt.json) SHA `744fccffba2526f20022bfd9c33e9668fbbd556958df3a91010d5d6df719acc5`；[report](../.cicada-data/integrated-task-restore-d1-20261002/report.md) SHA `6d7f29dd4ba473ab1980106b6c7fb5aa2f70509cad3ebb128fe14214543f28e9`。后续N1/TLS6/reviewer2组装会改变源码；这些结果不迁移到新源或代表whole-suite PASS。

| 原48实际门禁 | 结果与归属 |
| --- | --- |
| Task+Restore normal | exit0，135 top/91 sub，6 packages/6 actual binaries；`TestMachineRestoreRecoveryDisposableFixture` opt-in SKIP1。 |
| Task+Restore原race | **exit1 / FAIL**，cmd600.283s、Store600.221s包预算到期；122 top/91 sub及1 skip，其他4 packages PASS。失败栈与日志保留；不由残余成功推断无死锁或产品性能。 |
| 同source/samebin残余race | cmd仅unfinished `TestTaskHandoffRetiredLocalDeliveryAndCorruptHistoryFailClosed`：1 top；Store missing12 tops分成两组六个，各exit0/零skip。原race整命令仍FAIL，不重跑已完成选项。 |
| D1 default stubs | CGO0，23 top/49 sub、4实际binaries、exit0/零skip；不计native TLS覆盖。 |
| D1 OpenSSL3.5.9 tagged normal/race | 各23 top/82 sub、各4实际binaries、exit0/零skip；当前DER/安装/application-key/revoke test-process门禁，不是production lifecycle。 |
| 静态与合同 | affected9pkg vet/default build、D1 tagged vet、contract exit0；Restore Python8 tests exit0。 |
| dirty48 STD实际工件 | immutable Hub `sha256:83f6a9f454b537e9aa6eedb52f1abf1c4c01af8fc2b49dc49f849f83c084d90d` + interop `sha256:d652bc162d811f7476aaa2d5f224848d744cf26b429a9b4fa063d2f41c044174`；actual private TCP smoke/recovery2 top/3 sub、2 binaries、exit0/零skip。仅该dirty源QA工件，非clean产品交付；owned tags/containers/network已清理。 |

Go执行均使用 pinned `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`、networknone、user1000、GOTOOLCHAIN=local/GOPROXY=off/GOSUMDB=off，模块cache与source只读；native tagged使用既有accepted OpenSSL3.5.9 stage只读，无重新编译OpenSSL。完整Docker argv与执行二进制hash在各result和receipt；下列为实际容器内Go argv，不替代环境记录。

`task-restore-normal`（exit0；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/task-restore-normal/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -run '^Test.*(Recovery|Backup|Restore|SharedWriter|OwnerKeyTrust|PublishEndpointKeyCandidate|NodeControlOperator|Quarantine|MachineAgent|EndpointKeyPublication|Handoff|SharedTask|SameNodeGroupRelay|NodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl|MCPSealedSameGroupCrossNodeAskReplyFullChain|MachineRelayReconnectClaimsDurableOfflineMessage)' ./cmd/cicada ./internal/store ./internal/fabric ./internal/server ./internal/nodebackup ./internal/nodewire
```

`task-restore-race`（exit1；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/task-restore-race/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^Test.*(Recovery|Backup|Restore|SharedWriter|OwnerKeyTrust|PublishEndpointKeyCandidate|NodeControlOperator|Quarantine|MachineAgent|EndpointKeyPublication|Handoff|SharedTask|SameNodeGroupRelay|NodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl|MCPSealedSameGroupCrossNodeAskReplyFullChain|MachineRelayReconnectClaimsDurableOfflineMessage)' ./cmd/cicada ./internal/store ./internal/fabric ./internal/server ./internal/nodebackup ./internal/nodewire
```

`D1-tagged-normal`（exit0；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/D1-tagged-normal/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -tags cicada_pqtls -run '^Test(NodeTLSInstall|TLSApplication|NodeTLSAuthority|NodePQTransport|NetworkSessionTransport|NodeCertificateCannotBorrow|StrictNodeTransport)' ./internal/nodetransport ./internal/pqtls ./internal/server ./internal/store
```

`D1-tagged-race`（exit0；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/D1-tagged-race/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -tags cicada_pqtls -race -run '^Test(NodeTLSInstall|TLSApplication|NodeTLSAuthority|NodePQTransport|NetworkSessionTransport|NodeCertificateCannotBorrow|StrictNodeTransport)' ./internal/nodetransport ./internal/pqtls ./internal/server ./internal/store
```

`task-handoff-last-case-race`（exit0；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/task-handoff-last-case-race/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^TestTaskHandoffRetiredLocalDeliveryAndCorruptHistoryFailClosed$' ./cmd/cicada
```

`store-missing-race-1`（exit0；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/store-missing-race-1/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^(TestHubBackupDoesNotCaptureOrRestoreColocatedNodeState|TestSealedSharedTaskHandoffLegacyLocalHistoryNeverTransfers|TestSharedTaskConcurrentClaimAndStaleCandidate|TestSharedTaskDependenciesPreventCyclesAndPrematureClaim|TestSharedTaskSideEffectCompletedIsDurable|TestSharedTaskSideEffectCompletionAndHandoffReconciliationView)$' ./internal/store
```

`store-missing-race-2`（exit0；[完整result](../.cicada-data/integrated-task-restore-d1-20261002/store-missing-race-2/result.json)）：

```sh
go test -work -json -count=1 -p=1 -timeout=10m -exec '/usr/bin/python3 /evidence/test-exec.py' -race -run '^(TestSharedTaskSideEffectIntentIdempotencyAndReconciliation|TestSharedTaskSideEffectIntentSurvivesStoreRestart|TestSharedTaskSideEffectRetryRequiresProvenNotAppliedOutcome|TestStateBackupRejectsExistingBackupAndIncompleteTarget|TestStateBackupRestorePreservesSQLiteIdentityAndReplayState|TestUserMonitorConsentRecoveryFencesDeviceEpochAndKey)$' ./internal/store
```

当前新增切片仍按自己的源验收。N1独立source `bf4274fc4b332c63a1df0b8fe2b495326dde85e40894d1b5dd239a28e03055ca` 的[summary](../.cicada-data/worktree-evidence/CICADA_native_reliability_n1/native-reliability-n1-20261002/validation-summary.json) SHA `9cbab9de5451e63f1e44ed25c410126227bad9a431f09899ff88b73baca850d6`：normal/race各29 top、39含sub，零失败/skip；离线helper进程SIGKILL窗口证据及一个单独协议门禁。TLS六文件独立source `7156e21218cf50da8e30702f93e465212086492f31652c8938827a7c667e899f` 的[receipt](../../CICADA_tls_backup_fences/.cicada-data/tls-backup-fences/frozen/receipt.json) SHA `3acf7b55a4f1d3a623b9ae8f0264a8ad9a4d2e5d345238324928de4db81cf8e3`：nodebackup normal32 top/38 sub、focused race9 top/23 sub、affected vet/build exit0、零skip，floor/WriterRoot共享锁保全。reviewer当前资格两文件[results](/tmp/cicada-link-reviewer-qualification-20261002/results.json) SHA `2d591fcc836bafe825eadb7203d2131322efd061947398b3ada8af2ebc7f7e65`：normal6 top/11 sub/0skip，原120s race exit2保留FAIL；同race binary仅两个新增parent残余2 top/11 sub/0skip、240s预算内exit0，contract0。三者已机械集成；新Main门禁现已按本文开头receipt通过，原组件失败和结果保持自身归属，不由新窄门禁重写。

T9当前能声明的事实限定于N1 [TestMachineNativeDeliveryTransport](../.cicada-data/worktree-evidence/CICADA_native_reliability_n1/native-reliability-n1-20261002/owned-files-final/cicada-go/cmd/cicada/machine_native_delivery_test.go:870)：`NewFabricHandler(service, "")`未构造Control业务，实际`/v1/groups`返回503；MCP→Owner Unix socket→真实loopbackTCP/Fabric Store/Authorization→receiver subprocess→synthetic queue及分层receipt成功。测试未构造Planner/report业务，但没有独立调用计数；不是两个Hub进程、两物理Node或新真实native Ask/Reply/消费。queue1的最终状态为CONSUMPTION_UNCONFIRMED，不称模型消费完成。

旧144真实原Thread A/B Ask/Reply77步只归旧source/session/image；其[receipt](../../CICADA_native_acceptance_144e079/.cicada-data/native-exact-pair-144e079-native-20261002/result.json) SHA `bbf5bd38d34179be4a847709103bf94c02617f9f892a9fb1e229799e597680b2`独立保留。旧144/v1.6.1两Owner Android registration2 + Link status/recover10 selectors由Client自报告，Root仅独立核hash；不能当e8/v1.6.3的Client五操作、native审批或新T9 PASS。旧fixture [Core owned cleanup](/tmp/cicada-client-link-native-fixture-20261002/root-final-cleanup-result.json) SHA `52f5c124a8c06e96d7ca4eb6a49932a685c75ca1267d8f46239580e9a21a7544`实际exit0：3 containers/3 networks六资源移除、labels remaining0；private fixture文件保留给Supervisor，未删除fixture目录。

Client clean `36f127ef3e7b19fedf1f29e40be63a881f8baa17` 来源已独立只读核验：57 indexed evidence hashes、129源码/101Kotlin/41JS指纹、24 bundle成员与e8 images均匹配；runtime仍v1.6.1，无新APK/v1.6.3 live PASS。v1.6.3五操作仍关闭到验收；reviewer资格证据与双方current policy proof producer目前只有只读方案待批准。fresh encrypted link.key_manifest是同事务Hub当前scope/binding证据，retained Owner public identity只作discovery；独立peer Owner key/pin需外部可信输入，不能Hub自动trust。reviewerGuard修复有界PASS不能替代Android/native审批。Task privacy/schema57、TLS production D2/startup/SSE/reload/renewal、真实native与Android新产品闭环、物理Node/native-over-PQ/publicHTTPS/生产恢复仍PENDING或NOT_RUN。NIST算法选择与已测profile不构成整体FIPS认证声明。旧operator-only tagged CLI fixture未跑，记录NOT_RUN，不作FAIL；Restore run03旧11-case Docker仍归run03 source-v1。

历史 V66 的“result does not list drag/box/proposal gestures as assertions”限界句不准确，以下原文保留作旧记录并由本说明纠正：当前[Browser脚本](../scripts/test-hub-web-panel-browser.mjs) SHA `57f8a069e375883270ca63c8828f81b58567fb0c16007bd767380c32a4583668`，原C4 [Browser receipt](../.cicada-data/next-checkpoint/closure-20261001T165647Z/browser-final-1/result.json) SHA `bac1721fdc02b625ce5d149ffa5e42fae0494e0a72556de06b31bd437f7e4ec4`确实在12聚合steps中assert这些drag/box/proposal及recovery分支。其source `31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2`、Chrome151结果仍归历史；不因此接受当前reparent或新Main。

V66新六文件切片在独立671c源已验收：20个命名Browser steps及全部8项nesting/reparent checks PASS，Root独立核验source/full modes、step集合与owned cleanup；[receipt](../../CICADA_panel_gestures/.cicada-data/panel-gestures/frozen/receipt.json) SHA `e341ed1504cc54c0cecf7acf6e97effa99724093918fd56cece3d4b7ffa8b651`，[browser-2 result](../../CICADA_panel_gestures/.cicada-data/panel-gestures/browser-2/result.json) SHA `6ffb23e5c0dfd2e712bea1eb8afb8b4d3f2652c05d6d6ed83c173c0628f7b149`。原browser-1 FAIL/13PASS/7NOT_RUN与BuildKit失败保留；derived QA49379不是clean STD。无新API，尚未集成Main；native/body decrypt NOT_RUN。

按[五检查点计划](architecture-v2-plan.md)继续；metadata query不授权quarantine release、retry、writer接管或重复副作用。新增统一候选必须冻结自己的source、合同与实际工件再验；不从矩阵推导整体百分比、不宣称100%、不发布；用户已明确授权Root及时推送dev检查点，其他push不自动执行。
