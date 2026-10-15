# Android Client ↔ 开发 Hub 互操作记录（2026-09-23）

> **历史记录。** 本页的常驻 Hub 镜像没有 `fb0f07a` 的源码出处，不能用作 `client-hub-v1.1` 验收。当前协议包、镜像 ID、Client 提交和 APK 摘要见 [v1.1 验收](client-hub-v1.1-validation.md)。

## 环境与版本

- Client 分支：`dev/react-native`，基线提交 `8438b70`；本记录对应本分支新增 Kotlin Client-Control v1 代码。
- 核心开发 Hub：此前在核心 checkout 约 `4c564a7` 时使用 `./scripts/run-client-hub-dev.sh` 启动；容器 `cicada-client-hub-dev`，宿主机回环端口 `8787`。容器未嵌入 source revision，不能独立证明二进制的精确提交；公开 capability 和本轮设备 RPC 与当前契约一致。仅使用核心本地 `owner-key register` 登记开发测试 Owner 公钥；未调用旧 `/v1` bearer。核心源码未由本仓库修改。
- Docker 数据根目录：`/gpu1-share/data/docker-root`。Client 缓存、APK、开发测试公私钥与测试输出均在 `/gpu1-share/data/cicada-client`；私钥和 Grant 文件权限 `0600`，不在 Git。测试用 Owner 签名器源码是 [OwnerGrantSigner.java](../scripts/interop/OwnerGrantSigner.java)，与 APK 完全分离。
- APK：React Native/TypeScript UI + Android Kotlin 安全会话；Android 35 x86_64 Docker 模拟器通过 `--network host` 访问 `10.0.2.2:8787`。此 debug HTTP 仅用于本机回环测试，内层业务 RPC 仍由 ML-KEM-768、ML-DSA-65、AES-256-GCM 保护。

## 真实 Hub 结果

| 验证 | 命令/方法 | 结果 |
|---|---|
| Hub 运行与能力 | 核心启动脚本；`GET /v2/client/capabilities` | 启动成功；`status=partial`、`status_events=false`、`external_thread_links=false`、`status_changes_partial=true`。 |
| 构建 | `./scripts/docker-build-android-test.sh`；最终 `./scripts/docker-build.sh` | 两次 instrumentation 构建与最终 Android APK 构建均 exit 0。 |
| 独立 Owner Grant | 独立 BC 签名器生成 Owner/设备身份，核心本地命令登记 Owner 公钥；`POST /v2/client/devices/enroll` | 有效 Grant 返回 201/ACTIVE；原请求再次登记返回 403。Owner 私钥未交给 Hub 或 APK。 |
| Kotlin 密文互操作 | [HostPacketProbe.java](../scripts/interop/HostPacketProbe.java) 调用实际 APK Kotlin wire codec，发送到 Docker Hub 并验证/解密响应 | `session.capabilities` HTTP 200、签名与 AEAD 校验通过；external owner 得 18 项，resident manager owner 得 25 项。接收方 Control 公钥 ID 与 Manager Owner ID 是不同身份。 |
| RPC 重放 | 同一密文包原样重发；同序号/同操作 ID 重新封包 | 原包 HTTP 200 且响应字节完全相同；改动密文 HTTP 409。 |
| 响应篡改 | 修改 Hub 响应 envelope 的 ML-DSA 签名，再用 Android Kotlin wire codec 解密 | 验证器拒绝；未写入解密结果。 |
| 状态 | 加密 `status.snapshot`、`status.changes` | 200，签名验证通过；快照 `scope_mode=single_owner_control_database`，增量 `completeness=partial`。 |
| 设备撤销 | Manager 设备加密 `devices.revoke` 撤销另一设备，后者再次 RPC | 撤销 200、加密业务结果 `state=REVOKED`；已撤销设备新 RPC 返回 403。 |
| Host 精确重试 | 先封包持久化，暂停 Hub 后发送超时，恢复 Hub 后重发同一包 | 暂停期间 curl timeout/HTTP 000；恢复后 HTTP 200，响应签名和解密通过。 |
| Android 设备生成 | `ClientHubInteropTest#prepareDevice` | `OK (1 test)`；设备公钥由 App Kotlin/Keystore 代码产生，私钥未导出。 |
| Android 登记与读状态 | `ClientHubInteropTest#enrollAndRead` | `OK (1 test)`；独立 Owner Grant → Hub 201 → App 加密 `session.capabilities/status.snapshot/status.changes` 均通过。 |
| Android 断线恢复 | Hub 暂停时 `offlineLeavesExactPending`，恢复后 `recoverAfterOnline` | 各 `OK (1 test)`；30 秒超时留下待处理密文，重发后验证响应并清除待处理状态。 |
| Android 撤权隔离 | 另一 Manager 设备在 Hub 撤销 Android 设备后运行 `revokedDeviceIsFenced` | `OK (1 test)`；RPC 收到 403，App 持久 `authFenced`、`remoteEnabled=false`。 |
| Android 撤权后显式新设备 | `ClientHubInteropTest#explicitNewDeviceAfterRevocation` | `OK (1 test)`；生成不同设备公钥，清除本机登录，提示旧 Hub 设备记录可能仍在。 |
| Android 管理操作 | 新设备经独立 Grant 登记后运行 `ClientHubInteropTest#managerOperationsAgainstHub` | `OK (1 test)`；加密 `topology.snapshot/apply` 建组成功、陈旧版本业务拒绝后重读快照，`nodes.preview/confirm/list/revoke` 完成真实设备码绑定及撤销，`approvals.list/decide` 查询及不存在审批的业务拒绝，`intent.submit/status` 与最终 `status.snapshot` 通过。 |
| Android 页面 | `./scripts/docker-emulator-check.sh`，Android 35 干净模拟器 | exit 0；概览、节点、工作、管理、模型设置和输入面板均打开并通过 UI 文本断言。首次运行脚本的旧 Node 空状态文案断言失败，更新为实际文案后重跑通过；App 无启动崩溃。截图留在 `/gpu1-share/data/cicada-client/build-output/`。 |

Android instrumentation 源码为 [ClientHubInteropTest.kt](../android/app/src/androidTest/java/ai/cicada/client/ClientHubInteropTest.kt)。测试运行输出存放在 `/gpu1-share/data/cicada-client/interop/android-*-output.txt`，不进入仓库。Hub 保持运行供开发使用。核心仓库在测试期间出现其他工作区修改，本仓库未触碰这些核心源码文件；运行中的 Hub 镜像仍是上述已启动版本。

## 2026-09-24 增量验证

- 核心 HEAD 已推进到 `6b6d9f6`，且工作树有其他开发者的未提交改动；上方常驻开发 Hub 的精确源码提交未经镜像标记认证。本轮先核对核心已提交源码/路由仍包含 Client-Control v1 与相同 `intent.list/get/status` 契约，实际 Android 互操作继续针对该常驻开发 Hub。不能将此测试写作新核心镜像的独立验收。
- 新增 `ClientHubInteropTest#intentHistorySurvivesClientReload`：在已授权 Manager Android 设备上经加密 RPC 提交合成 Intent，重新创建 Client 会话对象后用加密 `session.capabilities`、`intent.list/get/status` 找回同一 ID、文本和进度。Docker `:app:assembleDebugAndroidTest` exit 0；Android 35 模拟器输出 `OK (1 test)`，instrumentation 退出码 0。测试使用不创建 Goal 的不支持类别，只针对开发 Hub。
- `./scripts/docker-build.sh` 最终重建 exit 0，产物在 `/gpu1-share/data/cicada-client/build-output/cicada-client-debug.apk`；在同一 Android 35 互操作模拟器安装并启动前一轮 APK 后，登录态显示 `E2EE · manager`。工作页点击「找回本人历史请求」后显示从 Hub 读取的 3 条当前 Owner Intent；展开其中一条，显示来源为加密 `intent.status` 的业务进度。UI 文本核查未发现错误页。最终重建只增加 `intent.list` 响应非数组时的错误提示；此修改还经 Docker 内 `tsc --noEmit` 验证 exit 0。
- `./scripts/docker-emulator-check.sh` exit 0；全新 Android 35 模拟器中的五页和输入面板文本断言通过。

## 2026-09-24 设备管理与状态可信度增量

- 核心 `devices.list/revoke` 请求/结果字段和 Goal 生命周期范围已重新对照 wire 文档、实际 Go handler 与测试；Manager/External 均可管理自己 Owner 的 Client 设备，只有 Manager 可调用 `goal.lifecycle`。移动 UI 同时核对公开能力与加密 `session.capabilities`；Goal 操作提交前再次读取权威快照和版本。没有修改核心源码或数据库。
- `./scripts/docker-build-android-test.sh` exit 0；Android 35 模拟器 `ClientHubInteropTest#clientDeviceListAndSelfRevokeGuard` 输出 `OK (1 test)`，ADB exit 0：加密列表含当前 ACTIVE 设备，自撤销返回加密业务拒绝，之后仍为 ACTIVE。
- 为验证成功路径，测试签名器在 `/gpu1-share/data/cicada-client/interop` 生成全新的可丢弃设备密钥和一次性 Grant，`POST /v2/client/devices/enroll` 返回 HTTP 201/ACTIVE。`ClientHubInteropTest#revokeDisposablePeerDeviceWithVersionGuard` 输出 `OK (1 test)`，ADB exit 0：过期版本加密业务拒绝且版本不变，当前版本撤销返回 REVOKED/version+1，重新读取列表一致。该被撤设备随后通过 Kotlin wire codec 构造新加密 RPC，真实 Hub 返回 HTTP 403。所有私钥、Grant、包和原始输出留在上述 Git 外目录，权限 `0600`。
- 已登录 App 的设置页手动点击“读取设备列表”，真实 Hub 返回 4 台本 Owner 的设备；当前手机标识正确，没有显示自撤销按钮。完整设备撤销 UI 按钮未用于真实撤销，本轮验证的是同一 Kotlin RPC/Guard 路径。
- 测试 Node 在 Git 外生成 `cicada_node_` bearer，只把 SHA-256 digest 提交给真实 Hub `POST /v2/nodes/device-code`（HTTP 201）；Android `ClientHubInteropTest#confirmDisposableNodeForQueuedGoal` 经加密 `nodes.preview/confirm` 返回 `OK (1 test)`；Node Relay heartbeat 返回 HTTP 204。Android `queuedGoalLifecycleAgainstDockerHub` 经加密 `intent.submit/status` 创建远端 queued Worker，再用 `goal.lifecycle` 暂停、验证快照、拒绝过期版本、恢复并再次暂停，输出 `OK (1 test)`。最终 `/v2/relay/nodes/{id}/jobs` 返回 HTTP 200 且可领取队列为空。该测试没有启动原生 Worker，也没有证明可暂停运行中的 Worker。
- 清理测试 Node：Android `revokeDisposableNodeAfterQueuedGoal` 经加密 `nodes.list/revoke` 输出 `OK (1 test)`。随后旧 Node bearer 的 heartbeat 返回 HTTP 401，表明 Relay 不再接受此凭据。首次检查误把预期码写为 403，命令因此退出 1；按该 Node 路由真实 401 行为重跑断言退出 0。测试 Goal 最后留在 paused，未有可领取任务。
- 在已登录 Android UI 的工作页定位该远端 Goal，点击“恢复排队”并确认，Hub 快照显示 queued，随后按钮变为“暂停排队”；再次点击确认后 Hub 快照显示 paused。两个 UI 操作均没有错误提示。
- 仅在持久 Android 35 模拟器上使用 root `iptables` 临时拒绝到 `10.0.2.2:8787` 的 TCP 输出，点击设置页加密 `devices.list`；概览保留先前已验签快照并显示“Hub 上次快照，待对账”及“新 RPC 已阻断”。移除规则后在设置页点击“恢复原始加密请求”，概览回到“Hub 权威快照”，`E2EE · manager` 仍有效且待对账警示消失。Android 系统代理改到无效地址的首次尝试没有使本地 Hub 连接失败，未计作断网验收；代理已恢复为 `:0`，`iptables` 规则已删除。真机前后台断线仍未验收。

## 2026-09-24 Link 提案 UI 与 Android RPC 增量

- 逐项重读核心 v1 wire、OpenAPI、`client_rpc_v2.go` 和双 owner Link 测试：`external_link_invites=true` 可提供邀请提案；`external_thread_links=false` 仍禁止呈现消息发送或“已连通”。`link.key_grant` 虽在 allowlist 中，Android 端缺完整 canonical contract 与 Endpoint attestation 验证器，因此签署入口保持隐藏。
- Android 管理页新增会话授权后的 `link.list` 分页、一次性 `link.invite_create`、受限 `link.invite_preview`、明确确认的 `link.invite_accept` 和按版本 `topology.apply/link.revoke`。token 仅保留当前内存并在切后台后清除；原始密文恢复若返回创建结果，App 可在管理页临时显示恢复的 token。PROPOSED 标签、Hub 数据范围与撤销后的权威重读都不表示路由已启用。
- `./scripts/docker-build.sh` 退出码 0；`./scripts/docker-build-android-test.sh` 退出码 0；Docker 内 `tsc --noEmit`、`npm run lint -- --quiet` 均退出码 0。首次 lint 检查发现原有三个 effect 闭包依赖错误，改为读取最新回调 ref 后复验通过。最终 APK 仍输出到 `/gpu1-share/data/cicada-client/build-output/`。
- 在持续运行的真实 Docker Hub 上，Android 35 已登记的 manager 设备运行 `ClientHubInteropTest#linkProposalReadAndUnauthorizedSourceAreEncryptedBusinessResults`；ADB 退出码 0、`OK (1 test)`。加密 `session.capabilities` 包含 Link operation；`link.list` 返回 owner-scoped 结构，非法 bearer 的 `link.invite_preview` 与非本人 Source 的 `link.invite_create` 均是验签解密后的业务拒绝。测试没有产生邀请 token，也未修改 Link 状态。
- 同一已登记模拟器安装本次 APK 后打开管理页，UI 层级包含「跨用户 Link 提案」；点「重读本人提案」，显示「已读取本人可见的 Link 元数据」和当前空列表。最终回调 ref 小改动后再次构建、覆盖安装并启动，管理页仍显示「创建提案邀请」。没有使用开发 fixture。
- 双 Owner 的 Android 成功路径已在下方隔离 Hub 补测。真实过期 token、错误目标绑定与 `link.key_grant` 签署仍未通过 Android 验收；没有据此宣称跨用户 Thread 已连接。

## 2026-09-24 隔离 Hub 的双 Owner Link 互操作

- 使用独立 Docker Hub 数据库 `cicada-link-interop-hub`、两个新 Android 35 AVD（source/target）和分别签发的一次性 OwnerDeviceGrant。测试桥接只把 Android debug 白名单地址 `10.0.2.2:8787` 转到该隔离 Hub 的 `/v2/client/identity`、`/v2/client/capabilities`、`/v2/client/rpc`；实际读取的 Hub ID 和 Control 公钥 ID 与独立固定值一致，旧 `/v1/communication-links` 返回 404。密钥、Grant、token 和原始输出仅在 App 私有目录及 `/gpu1-share/data/cicada-client/interop`，不进入 Git。
- 两端 Android 测试 `androidResolvesTheIsolatedHubIdentityThroughRelay`、`prepareDeviceIdentity`、`enrollOwnerAndCreateGroup`、`confirmBoundNode` 各次均为 `OK (1 test)`、命令退出码 0；加密 `session.capabilities` 均返回 `external`。两台测试 Node 分别用 Node 路由 `/v2/fabric/node/join` 获得 HTTP 201、`leased` 的 Endpoint，核对 owner/group/binding；Node 凭据没有保存在 Client。
- 来源端加密 `createOneUseInviteForJoinedEndpoint` 为 `OK (1 test)`、退出码 0。目标端 `previewAcceptReplayCasConflictAndRevoke` 为 `OK (1 test)`、退出码 0：无效 token、非本人 source 拒绝；预览只返回受限标签及精确方向、动作、范围、期限；一次性 token 接受后状态为 `PROPOSED`，再次使用被拒绝；目标端 `link.list` 可恢复提案；错误 `expected_link_version` 被拒且版本不变；正确版本撤销后为 `REVOKED`、版本加一。来源端 `sourceOwnerRecoversRevokedLinkFromList` 同为 `OK (1 test)`、退出码 0，读回相同撤销状态。被消费 token 随后从目标 App 私有测试文件删除。
- 目标外部 Owner 的 App 界面显示 `E2EE · external`，文字面板提示远程发送未启用；管理页显示 external 会话，Manager 专属审批和设备管理入口没有出现。此处只验证会话能力对 UI 的限制，服务端 Guard 拒绝由上述加密业务结果单独证明。
- 在来源端模拟 **Hub 已接受但响应丢失**：一次性测试 relay 只识别公开 route 的 `link.list` 操作，先将原始加密包转发到隔离 Hub，记录上游 HTTP 200，再丢弃返回给 Android 的响应；没有读取业务正文。`linkListLeavesExactPendingRequestWhenHubIsOffline` 与 `recoverExactPendingLinkListAfterHubRestarts` 两次 instrumentation 各为 `OK (1 test)`、退出码 0；前者在 `NETWORK_ERROR` 后保留原始请求，后者把同一密文包重发并验签 Hub 回放响应，清除 pending 后的 `link.list` 仍含 `REVOKED` Link。测试方法名是早期命名，实际没有重启 Hub，也没有验证离线写入；原始 relay 证据存于 Git 外 `/gpu1-share/data/cicada-client/link-interop/source/recovery-relay.log`。

## 2026-09-24 模拟器补测与代码整理

- `ClientHubInteropTest#managerReadAndRejectionMatrixAgainstDockerHub` 在已登记 Android 35 manager 模拟器对真实 Docker Hub 输出 `OK (1 test)`、ADB exit 0。已验签解密的成功读覆盖 `session.capabilities`、`status.snapshot/changes`、`topology.snapshot`、`nodes.list`、`approvals.list`、`devices.list`、`intent.list`；业务拒绝覆盖错误 Node code、不存在的 Approval/Group/Intent/Link 与无效邀请 token。业务拒绝仍在加密响应中表达，没有把 HTTP 200 当作写入成功。
- `ClientHubInteropTest#insecureTransportAndUnknownRpcAreRejectedBeforeNetwork` 在已登记 APK 中输出 `OK (1 test)`、ADB exit 0：非白名单明文 HTTP Hub 地址、调试端口 8788 和契约外 RPC 均在发包前拒绝；固定的 Hub/设备身份与请求序号没有变化。此项验证的是 Android Client 本地降级防护，不等同公网 HTTPS 证书验收。
- 新增 [run-activity-recovery.sh](../scripts/interop/run-activity-recovery.sh)：先核对 Docker 数据根目录与 AVD 身份，只在已登记的开发模拟器上临时拒绝到 `10.0.2.2:8787` 的流量；`offlineLeavesExactPending` 输出 `OK (1 test)`，重启 App、恢复网络并等待权威快照与尾随 `status.changes` 同步完成后，`sessionIsRecoveredAfterActivityRestart` 输出 `OK (1 test)`，脚本 exit 0。原始请求使用随机 operation ID，可重跑；临时 iptables 规则由 trap 清理。验收早期曾因错误 Activity 名和过早启动 instrumentation 而失败，修正等待条件后重跑通过；失败尝试不计为通过证据。
- 已登录 Android UI 实测文字输入：草稿写入后仍停留在确认面板；点击“确认并加密发送”后关闭面板，工作页显示 Hub 持久 Intent ID，点开后加密 `intent.status` 显示 `resolved`、分发 `DONE` 和 Control 返回的 Goal ID。界面仍明确写明 `DONE` 只表示分发完成。此次合成文本在常驻**开发** Hub 产生一条测试 Goal；没有编辑核心数据库或声称该 Goal 完成。实际 ID 和界面原始输出未写入 Git。
- 清理了未接入生产路径的 demo fixture、旧状态类型、无调用者的 TypeScript 候选 Hub helper、无人使用的等待脚本及 Jest 脚手架；Android Gradle 文件删除了无用的模板注释。Node/Goal 页改为按快照建立 Worker 索引，大列表按批创建卡片，管理拓扑/Node 列表在进入管理页时读取；概览继续读取待审批数。管理写入的提示现在区分“Hub 已接受但后续对账失败”和“写入未确认成功”。Docker 内 `tsc --noEmit --noUnusedLocals --noUnusedParameters`、`npm run lint -- --quiet`、shell 语法与 `git diff --check` 均 exit 0。
- 修正 SenseVoice 模型目录中的截断 SHA-256 后，最终 `./scripts/docker-build.sh` 再次 exit 0，交付调试 APK 在 `/gpu1-share/data/cicada-client/build-output/cicada-client-debug.apk`，SHA-256 `c5edbc86f380961f6a5747eabe46ba0f57f9d1338624c626d314e140177bbe3c`。`./scripts/docker-emulator-check.sh` exit 0：全新 Android 35 AVD 的概览、节点、工作、管理、设置与输入面板断言均通过；脚本现固定并显式使用本次 smoke 的 ADB serial，避免误操作其他并行模拟器。
- 在已登记 manager 模拟器覆盖安装最终 APK 后，工作页可见「Control 请求」快捷入口；点击后滚动到「Control 请求历史」与「找回本人历史请求」，该动作不产生新 Hub 写入。发布型 `:app:processReleaseMainManifest` exit 0，实际合并 Manifest 含 `android:usesCleartextTraffic="false"` 与 `android:allowBackup="false"`。这只验证发布配置，尚未签署或安装发布 APK，也不能替代公网 HTTPS 证书验收。
- `./scripts/docker-build-android-test.sh` 新测试 APK exit 0；`CICADA_EMULATOR_SECURITY_CHECK=1 ./scripts/docker-emulator-check.sh` 在**全新** Android 35 AVD 上同时运行 UI smoke 与 `ClientHubTrustNegativeTest#candidateWrongPinsAndInvalidGrantNeverEnroll`，输出 `OK (1 test)`、脚本 exit 0。候选 `/v2/client/identity` 保持未信任且不改变本机 pin；分别固定错误 Hub ID、错误 Control 公钥后，真实开发 Hub 身份核对均返回 `HUB_IDENTITY_MISMATCH`；固定与当前 Hub 相同的测试公钥后，无效 Grant 在本机返回 `INVALID_OWNER_GRANT`。最后仍未登记、没有加密 session 能力或 pending 包。该测试只验证拒绝路径；没有让 App 自动信任从网络读到的公钥。仪表输出保存在 Git 外 `/gpu1-share/data/cicada-client/build-output/cicada-trust-negative.txt`；临时模拟器随 Docker `--rm` 清理。

## 尚未据此宣称通过的范围

- 没有将普通 Endpoint↔Endpoint 消息证明为盲 Hub E2EE；`external_thread_links=false`，跨用户消息入口保持关闭。
- 没有生产公网 HTTPS、证书运维、真实手机硬件 Keystore/麦克风性能、iOS 或原生鸿蒙验收。
- 后端 `status.changes` 仅部分增量；HTTP 200/Intent DONE 不代表 Worker 读到消息或 Goal 完成。
- 本轮真实 Hub 验证覆盖会话、状态、重放、撤权、断线及上述管理操作。尚未覆盖拓扑/Node/审批每一种实体权限组合及实际待审批记录；UI 不以 fixture 声称通过。
