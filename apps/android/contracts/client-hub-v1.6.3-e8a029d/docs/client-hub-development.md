# Client / Hub 联合开发与验收

**Historical clean Hub delivery (2026-10-01):** revision `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, source fingerprint `6ab2d94a26dd41082b3177006095408b25d4e8c05cd54315db6c325be92eb5be`, image `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`. This v1.6.1/55-operation artifact and its bundle/report remain immutable; metadata predates additive input inventory capture. See the [historical delivery record](v01-transport-recovery-checkpoint-validation.md).

**Delivered clean Main checkpoint (2026-10-02):** Main `144e079`, standard source `e64f2449…`, exact 806-input inventory; STD Hub/interop and separate clean PQ image/package passed bounded gates. Clean Client `2ce183373429dddcb21259b54b3b261ae010bd55` delivered against v1.6.1; redacted receipt SHA `9069d2c4fa2dbd279fd1eca35eccc4b7bd0b8a9102651d6a724ca7ca4c60384f`, 40-entry evidence manifest SHA `5b0830b4130a9fde09873c8e6b7393d3f52aa868a67d416fa7ca6e06c8dd5b5d`. These source/APK-specific checks do not accept Android Node/Worker runtime, physical-device or public HTTPS behavior.

**Integrated Main candidate:** dirty source-input fingerprint `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` on Git HEAD `144e079`, contract v1.6.3/catalog `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`, wire 1/55 operations/schema v55. The integrated focused normal gate passed 49 top + 128 subtests across six packages, zero skips/failures; affected vet/build, contract check/export/verify and Python 15 + 17 subtests passed. Stable source/STD input metadata: 835/829. [Receipt](../.cicada-data/combined-link-proof-20261002/receipt.json), SHA `6416728daca6fdf4e95f0b0fc60f06ad6dd4ca77ed910ab7c1f2ba90fe8c12e7`. Full/tagged/race acceptance and exact clean v1.6.3 artifacts remain pending; there is no v1.6.3 Client repin.

The Client carrier preflight fails because its prior exact-one-Hub guard rejects the valid two-Node/three-bridge topology. A dedicated correction is underway using the exact public topology inventory; Client selectors and native runtime remain **NOT_RUN**. The fifth zero-model fixture used clean-144/v1.6.1, joined two endpoints and created a synthetic Link in `PROPOSED` state; both review policies were `NONE`, with no accepted sides. Its [receipt](/tmp/cicada-client-link-native-fixture-20261002/private-hop-freeze/approved-execution/result.json) SHA is `85ac6f8ff5f01dfac780cc9a4b53209fc9be679026cec1d9b8e0f890c697d4b1`. It is held for Client follow-up and is not Android approval, Link activation or native Ask/Reply. Four earlier fixture failures remain retained.

## Historical Client tooling and Link-status snapshots

The older Client notes below retain their tested source and delivery-time status; they do not supersede the clean 144 Client receipt above.

Client HEAD remains `65d6a399122055e1bd38dfb70fa93686806bee36`, with five developer-tooling files uncommitted and no APK/application build-source change or Android Hub repin. Independent clean-Git checks cover **793 build-input entries** of intermediate Main `06d0a58`; 20 synthetic checks PASS. The supplied tooling status is `/gpu1-share/data/cicada-client/hub-input-inventory-20261001/provenance/tooling-status.redacted.json`, SHA-256 `8562219bee5fe4b24ea0ddedd220ac3b0cb39e6077f271b12b32d4b48ba5927d`; independent clean-Git receipt SHA-256 `34c56f1b0f0b6ce8bd6fe76cea7b51289f5305cf4fa7d2b8b1a86cbea0cf38a0`. Initial failure logs are explicitly `NOT_AVAILABLE`, not PASS. This is tooling proof, without a final tooling commit or live Android/native/model acceptance.

That committed Client source has 39 implemented / 16 closed operations. Its earlier offline 67 JS, 5 Kotlin host and 11 checker tests plus app/test builds passed; lint recorded 0 errors / 23 warnings. Two synthetic-session tests compiled but were **NOT_RUN**; this is not live Hub/Node/model/runtime acceptance. Redacted receipt SHA `e8919709dfc53d30b0663c16af2e9b822bebc6a4599be6e5705ff063023c89a7`.

Independent Client `d580975a…` offline build/tests are source/APK-specific; its original build-time mode capture and provenance gate remain BLOCKED. The `dd1db40c…` reconstruction is retrospective and does not rewrite that receipt. The preceding clean `4fb241b`/C4 results below remain historical and keep their original source/image attribution.

历史 f4 clean bundle、metadata 和 Android/Kotlin 结果仍归原源，见 `.cicada-data/v01-finish-20260930T145216Z/client-v1.6-clean-handoff/metadata.json`、[历史交接说明](client-hub-handoff.md)与 [Client v1.6 f4 报告](../../CICADA_CLIENT/docs/client-hub-v1.6-f4e4725-validation.md)。其 clean Client commit 为 `9cf2b81c256b6a3f17681f28993e7857726e2121`（最终 clean commit rebuild NOT_RUN）；35 项本地实现不等于 55 项全部开放，20 项仍关闭。旧 Android/native 结果不转移到当前修订。

**已交付 recovery/panel 检查点：C4 PASS（有界后端；原 dirty-source 验收）。** 该检查点未升级合同、wire 或 catalog，现已纳入上述 clean 4fb 交付。旧 f4、2858、432f/54f native 与 Client 结果均保持原来源，不转移到新 candidate；新验收见 [recovery/panel 检查点](v01-recovery-panel-checkpoint-validation.md)。此前最终 dirty `2858c57ec3bc33f5f4d03f4f8c75ec6c13f89fd128a3a8a493b7c7605af51e17` 的 Go 27 packages、1,092 top-level + 547 subtests PASS、12 top-level SKIP、vet/contract/Python26/shell20，以及各 native overlay 的独立结果仍按 [旧检查点报告](v01-completion-checkpoint-validation.md)归属；skip 不是 pass。

本规范将两个仓库作为一个产品协作，但分别构建和发布。CICADA 拥有
Hub/Node/Control、权威状态和协议；CICADA_CLIENT 拥有 Android UI、端侧
密钥与手机生命周期。当前由本仓库落实服务端与联调工具，不修改 Client。

## 历史 2026-10-01 recovery/panel 交接顺序（保持原归属）

当前修订以已交付 clean 4fb 为基线；recovery/panel 原 dirty 源码曾独立冻结为 C4 `31dccec5…`，exact `c104b7bc…` 镜像的完整 Chromium canvas/recovery gate 已通过；同源 Go 27 包、1,105 top-level + 553 subtests PASS/12 SKIP/0 FAIL，以及 vet、contract、Python26、三套各自镜像的 disposable Docker gate 均通过。最终 clean checkpoint/交付 metadata 见上述 4fb 记录；原 dirty build 不能仅归于当时 f4 HEAD。此前 clean bd79 的 v1.5/46-operation 交付是历史，已由独立 v1.6/55-operation bundle 接续，不能再称当前冻结合同。v1.6 包包含 Network directory/Endpoint admission、Network purpose-key、Link reviewer Owner RPC、显式 Link invitation direction 与 Node pairing proof 字段；可用目录不替代 encrypted `session.capabilities`、逐入口 Owner consent 和服务端 Guard。新增 Network Task/Node MCP 能力不自动扩充 Android operation catalog。Hub Web canvas 仅通过后量子 encrypted Client packet 调用 Owner 操作，不能把 legacy bearer 或 browser-local state 当授权。Android 仍由 `../CICADA_CLIENT` 所有，本仓只读。

历史 f55 candidate 曾冻结为 dirty bd79-based source `f55b5255628030857ac88bd7edbd6da7da1b63d543014c76111f9219f46ad255` 与 Hub image `sha256:da88805eaa1987a1c6e06448fc5cddf7d4ce368e8b5eeb3071a1406dad2cb977`；不是 clean handoff。Full Go、vet、v1.6/55-operation contract、19 项 Python 与三套 disposable Docker 均已在 f55 PASS。前序 432f 的 Go/race/WASM/Browser/M5 证据不转移给 f55。432f 的 Client Docker 初次 FAIL、cf168 Client-only repair PASS、V68 FAIL、真实 Worker approval FAIL 与 Node-Control HTTP first FAIL/later protocol overlay PASS 均保持各自归属。该 f55 阶段 Android v1.6、双物理 Node、公网 HTTPS 与 f55 同源 peer-native 为 NOT_RUN；432f peer-native PASS 见上方独立归属。详见[检查点报告](v01-completion-checkpoint-validation.md)；该历史阶段的交付等待已结束：clean f4 metadata/bundle 已交付；本段结果仍只归旧源。

以下 `f30892f`、`b627e70` 与 v1.4 文字记录当时的 M2/M1 交接与验收，不描述当前候选状态。M2 既有全 Go/vet/race、合同与三套 disposable real-TCP Docker **PASS** 只归属其当时 dirty source fingerprint `76becd7…`。

独立 Client 的 v1.5 APK3 有界 Android recovery evidence 归属 Client commit `eb0db6f3d095b60b0f2f73bcfda0079ba33ad846` 与固定 bd79 Hub/source/APK/package，证明 Base、PROCESSING、UNCERTAIN transport recovery 等已记录范围；它不是 v1.6，也不证明当前 candidate。更早 `b627e70` handoff 与 v1.3 Monitor native report 仍是其自身固定旧 Hub/source 上的历史 bounded chain，不外推到当前 v1.6、双物理 Node、完整 React Native 生命周期或公网 HTTPS。所有外部结果按验证文档记录的实际 binary/APK/source/image 归属，不按仓库 HEAD 推断。详见[剩余验收账本](completion-ledger.md)与[检查点报告](v01-completion-checkpoint-validation.md)。

### 历史 2026-09-28 M1 后端矩阵 PASS（保持原归属）

`client-hub-v1.4` encrypted Client wire v1、Hub schema v36、catalog 36 项操作；`topology.snapshot` 的 Owner Network/Endpoint 视图、ACTIVE `group.create(network_id)`、Network endpoint `key_manifest/grant/status` 与 Network-scoped SEND/ASK/REPLY 后端通过。冻结源码 fingerprint `479386745593bf9dee679513cb2038cff08530abcc65fab1482736c4d837e3fe` 的 Go/vet/race、合同/Python 和 Client/Network disposable Docker 门禁均 PASS；见[当时状态](architecture-v2-status.md)和[后端验证矩阵](network-m1-validation.md)。这是 M1 backend evidence，不能推出当前 M2/M3/M4/M5/Android/native/public HTTPS PASS。

> **历史 2026-09-28 M1 ACTIVE 权限迁移有界检查点 PASS：** 当时全 Go/vet、聚焦 race、合同检查与两套独立 disposable Docker 门禁通过，见 [当时状态](architecture-v2-status.md) 和 [验证矩阵](network-m1-validation.md)。该候选仍为 `client-hub-v1.3`、33 项操作、wire v1、schema v35；当时 `group.create` 无 Network selector，在 ACTIVE Hub 被拒。旧默认 Client 门禁运行于 PREPARING Hub，不能代替当前 v1.4 ACTIVE Client 或 Android 验收。真实 native Runtime、Android、双物理机和公网 HTTPS 当时 **NOT_RUN**。

### 历史独立 Android v1.4 对接提示（当时尚未启动）

当时要求仅在取得该轮冻结 Hub 源码身份、完整 `client-hub-v1.4` 协议包及其 SHA-256 后，在独立 Client 仓库按 [wire v1](client-hub-wire-v1.md)、[OpenAPI](client-hub-v1.openapi.yaml)和 [Owner 合同](android-client-hub-contract.md)实现；先用 `python3 scripts/client-contract.py verify` 核对包，再验证加密 `session.capabilities` 对当前设备的实际授权。v1.3 的 33 项操作、Android/Monitor 证据和固定镜像继续只作历史结果，不当成 v1.4 的兼容或 PASS 证明；v1.4 候选目录有 36 项操作，wire framing 仍是 v1。

对 ACTIVE Hub，从 `topology.snapshot` 的 version 2 视图选择当前 Owner 可见 Network 与 Network-only Endpoint；Network 卡最多 100、Network Endpoint 登记最多 1000，`networks_truncated`/`network_endpoints_truncated` 为真时不得将缺页当作全量空结果。通过 `topology.apply` 的 `group.create` action 显式提交 `network_id`，验证同网父 Group 与 Owner/设备当前权限；NetworkAdmin 或全局管理 bearer 均不能代替 Owner。能力目录和 `can_create_group` 只是提示，不是许可。

Network-only 密封私聊的同意路径：Node 先在其受信 Network/native binding 下公布独立公钥候选；Client 调 `network.key_manifest`，逐字段核验 Hub/Network/Endpoint/Node/原生 Thread 摘要、binding epoch、公钥，并用该 Endpoint 公钥验自签证明；确认本机 Owner 身份后由 Owner 私钥签当前 manifest，以 `network.key_grant` 提交 canonical proof，`network.key_status` 观察 `active/stale`。Node 端须独立 pin 双方 Owner 公钥，不能仅信 Hub 返回的候选。用包内公开合成向量 `cicada-go/internal/e2ee/testdata/network-direct-key-consent-v1.json` 验完整签名字节、摘要和篡改拒绝；该向量不可用于部署。撤权、换 key、binding/登记 revision 改变需重新同意。Client 不持有 Node peer 私钥，也不代 Node 发布候选或发送正文；Network directory 与 direct SEND/ASK/REPLY 分别按当前 grant 验权，不要求伪 Group。

后续验收需单列 Android v1.4 的真实加密 HTTP、错误与响应丢失恢复、Owner 跨 Network 可见性及 key consent 的正反例；真实 native Runtime、双物理 Node 与公网 HTTPS 另列 **NOT_RUN** 直到实测。此提示只移交合同与验收边界，不启动 Client 实施。

> 2026-09-27: frozen v1.3 artifact and disposable TCP gate **PASS**; see the
> [frozen validation record](client-hub-v13-validation.md). Clean source
> `25013b5` also passed full Go/vet, focused race, contract/export, exact-image
> disposable TCP, and the bounded Android/native Monitor chain. Client's 10
> selectors/final strict status, Core's scoped ciphertext scan, Intake's
> independent Hub audit and owned-fixture cleanup all passed. The exact evidence
> and limits are in the [candidate record](client-hub-v13-25013b5-validation.md),
> [native runbook](client-monitor-native-fixture.md), [approval review note](monitor-broadcast-approval-review.md),
> and [Client validation report](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md).
> The prior `81d8f1f` denials remain historical. This bounded run used two logical
> Nodes in one container; full React Native consent UX, physical Android/dual
> Node, and public HTTPS remain **NOT_RUN**. Network M1 started from clean `dev` /
> `0cda61460757246789970782584b1e904173e653`. The bounded Network foundation
> checkpoint at `b0081a0` passed separate disposable Network and default Client
> Docker gates; `f9d3c7e` only fixed a stale migration test assertion. At that
> historical point M1 remained **NOT_COMPLETE**; see the [validation matrix](network-m1-validation.md)
> and [Network contract](network-m1-contract.md). Frozen v1.3 `group.create` has no
> Network selector and is rejected on an ACTIVE Hub. The passing default PREPARING
> Client gate is not an ACTIVE topology test. A Network-only Endpoint without a
> Group cannot DM; different-Group Endpoints may use an authorized sealed Link
> when both Groups map to the same Network and each Owner grants the Link. M1
> native Runtime, Android, physical dual-Node and public HTTPS remain **NOT_RUN**.
> Close M1 entry-point and test gaps before M2; native TUI adapter feasibility is
> a bounded next investigation. The frozen v1.3 Client contract and independent
> Android repository are unchanged.
> Journal/Discussion remain proposed later-stage work.

### 2026-09-27 Monitor v1.3 冻结前候选状态快照

当时共享开发树中的候选目录为 `client-hub-v1.3`，33 项操作，catalog SHA-256
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`。
`python3 scripts/client-contract.py check` 和七项合同/恢复 Python 测试通过。
四项新增 RPC 为 `monitor.broadcast_prepare/confirm/status/recover`；它们通过
已认证的加密设备会话调用，catalog 仅表示操作可用，当前会话角色与每次服务端
Guard 才是授权依据。

Hub v34 将新的 live preview intake 限为 16 条/owner-device、64 条/owner；只统计
未过期的 `PREPARED`、`APPROVED`、`DISPATCH_AUTHORIZED`。新预览五分钟过期，撤销
设备不会立即释放仍有效的旧行；精确 Prepare 重试不消耗新名额。列表每次最多扫描
16 个 owner-wide 候选并使用 per-Node 持久游标，因此客户端/Node 仍需通过周期性
reconciliation 推进积压通知。

两个定向 TCP Monitor HTTP lifecycle/Relay 测试通过；整仓 Go tests/`go vet` 在两项
review 修正前通过。随后 Confirm projection/OpenAPI 与 inactive Group 修正通过受影响的
Control/Server 全包测试、vet 及聚焦 race 复验；五项 Store Monitor race 测试也通过。
最终 disposable Docker
gate 待完成；干净源码 commit、协议包 manifest/hash 与精确 image ID/digest 尚待根
任务提供。开始 Client Android 工作前需取得该元数据。
v1.2.1 Android 模拟器 PASS
只作旧固定镜像的历史证据；v1.3 Android、真实 native Monitor 与公网 HTTPS 均为
**NOT_RUN**。独立 Client 的任务边界和验收清单见
[v1.3 Client 提示词](client-hub-v13-client-prompt.md)。

| 切片 | 交付与退出条件 | 当前状态 |
|---|---|---|
| N1 契约来源 | operation catalog 驱动角色 allowlist；版本与摘要可查询；与真实 dispatch 和 OpenAPI 检查一致 | 已实现；Go 定向与全仓回归通过 |
| N2 可重复环境 | 无 Codex/模型凭据的轻量 Hub 镜像；源码来源可核对；独立临时状态的真实 TCP 加密互操作命令 | 已实现；一次性 TCP 联调和开发启动检查通过 |
| N3 联合验收入口 | 协议包、公开合成密码学向量、CI 检查与分层结果；Client 可固定下载/导入具体版本 | 本仓入口完成；Client 在固定 `967dbd8` 镜像上通过 Kotlin wire/Endpoint 向量；GitHub Actions 未在本轮运行 |
| N4 登记与不确定状态恢复 | 丢失登记响应、Hub 重启后 UNCERTAIN 的明确恢复协议，两端故障测试通过 | Hub 侧 Store/HTTP 测试及固定镜像的 Android 模拟器 201/200 丢响应、三类恢复故障验收均通过 |
| N5 最小产品闭环 | 可信绑定 → 手机 Intent → 真实 Node Worker → 审批 → 结果回手机 | 固定镜像的 Android 模拟器→真实 Node/Codex 审批→`goal.result` 通过；同一固定镜像上的独立 Group key 正向授权亦已通过，属于另一条验收链 |
| N6 发布验收 | 真机录音/前后台、HTTPS、签名 APK；跨用户密钥授权另列功能验收 | 未运行 |

N1–N5 的 Android 管理闭环与独立 Group key 正向授权均已在模拟器通过；它们
不覆盖双物理 Node、双真实 Owner 的 Group 越权验收、真机与公网 HTTPS，
也不表示 Architecture v2 已全部实现。跨 owner 原生 peer RPC 另有
同机双逻辑 Node 的真实 Codex sealed Ask/Reply 验收，边界见
[原生验收记录](architecture-v2-native-validation.md)。

上述 Android 结果来自独立 Client 仓库的
`docs/client-hub-v1.2.1-967dbd-validation.md` 与
`docs/client-group-key-v1.2.1-disposable-validation.md`。固定目标是干净源码
`967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`、合同
`client-hub-v1.2.1`、完整本地镜像 ID
`sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7`。
Android 管理闭环使用的候选 APK 早于 Group 时间戳验签修复；后续 Group
正向验收使用 Client 实现提交 `b676668` 的另一对最终 APK，完成原生 Join、
Endpoint attestation 验签、外部 Owner 签名、手机显式确认、加密 Grant 与
`group.key_status=CURRENT`。两条测试不拼成同一次运行；详情以各自报告为准。

## 契约的唯一来源

- `cicada-go/internal/clientcontract/catalog.json`：操作身份、角色候选集合、
  契约修订、wire 版本与语义引用。运行时 allowlist 从这里读取。
- `docs/client-hub-v1.openapi.yaml`：外层 HTTP 请求/响应与 packet 结构。
- `docs/client-hub-wire-v1.md`：签名、AAD、字节规则，以及加密 operation
  内层请求/结果。内层形状当前尚未全部转为机器校验 JSON Schema，不能
  将 catalog 检查称为完整 schema 或行为兼容性证明。
- `docs/android-client-hub-contract.md`：可信终点、产品边界与授权说明。
- `docs/client-hub-v12-validation.md` 与 `docs/client-hub-v12-client-prompt.md`：
  固定版本、故障验收、真实 Node 缺口和 Client 开发交接。
- `cicada-go/internal/clientwire/testdata/`：公开、仅测试用途的加密互操作向量。

文档与运行代码产生分歧时先修正并补检查，不要求 Client 团队猜服务器实现。
`contract_revision` 标识一次契约修订，`catalog_sha256` 只覆盖 catalog 原始
字节，协议包 manifest 则列出所有随包文件的摘要。任何摘要都不替代可信
来源、设备授权或实际安全测试。

## 本地执行入口

在 CICADA 根目录运行：

```sh
python3 scripts/client-contract.py check
python3 -m unittest discover -s scripts -p test_client_contract.py
python3 scripts/client-contract.py export --output .cicada-data/contracts
./scripts/test-client-hub-interop.sh
```

导出命令打印包的完整路径和 SHA-256；Client 开发者取得文件后先用 CICADA
仓库中的 `python3 scripts/client-contract.py verify <包路径>` 核对清单和所有内容。
这只验证完整性，来源仍须通过双方可信仓库或 CI artifact 确认。包中
`source_dirty=true` 表示包含未提交改动，不能按 HEAD 当成已发布版本。

互操作脚本构建 `docker/Dockerfile.hub`，创建一次性 Hub 和 Go 测试客户端，
使用动态本机端口与独立状态。它检查源码/镜像来源、加密 RPC 重试、三种
恢复故障状态与 owner
隔离，输出 `result.json` 与 `test.log`；可用 `CICADA_INTEROP_OUTPUT` 指定
保留证据的位置。原始临时凭据和数据库不属于交付 artifact。
`CICADA_BUILD_PROXY=''` 显式关闭构建代理。开发者需要长期运行的 Hub 时，
另用 `scripts/run-client-hub-dev.sh`；已有同名容器会被拒绝替换。

`.github/workflows/client-hub.yml` 在 PR、`dev`/`main` push 和手动触发时
运行合同、Go 回归与一次性 Hub 检查。新增 workflow 未推送前只能报告本地
命令结果，不能声称 GitHub Actions 已通过。Hub 镜像不含 Codex、模型密钥
或 Android Runtime，此门禁不触发付费模型调用。

## 两仓版本与变更流程

1. 每个任务先写一条用户闭环及成功、拒绝、断网/重启的验收条件，明确两仓
   责任和阻塞关系。接口有实质变化时先更新契约；不得提前打开尚未实现能力。
2. Hub 与 Client 按同一契约并行实现。Client 锁定完整 CICADA commit、
   protocol revision/catalog hash 和实际 Hub image ID/digest，不能只记 `dev`
   或 `latest`。本地未推送镜像记录 image ID；已发布镜像再记录 registry digest。
3. 分别运行语言/平台测试；共同使用导出的协议包与向量。Client 需把向量放入
   Kotlin 验证测试，不能把 Go 自测结果当作 Kotlin 通过。
4. 使用一次性 Docker Hub 执行协议/权限/故障测试，再执行固定版本 Android
   联调。真实 Node/原生 Runtime、真机与公网 HTTPS 单独列结果。
5. 审阅通过后按用户要求阶段性合入 `main`；发布前必须有对应版本组合的
   联合结果。协议包与镜像可以独立分发，不要求用户安装两个产品。

在开发期允许明确的破坏性协议升级，但要更新契约修订、迁移说明及 Client
锁定版本。新增可选字段要保持已有解析可用；安全字段、加密字节、epoch 或
重放语义改变不能只修改文档版本。开发分支不等于获得发布授权。

## 验收记录

每次记录测试命令、退出码、测试级别、环境、Hub/Node/Client commit、
是否 dirty、镜像 ID/digest、APK SHA-256、契约 revision/hash 及证据路径。
工作树有修改时必须附源码内容摘要，不能宣称镜像等同该 commit。

当前 `source_fingerprint` 使用 `scripts/build-hub-image.sh` 的 v4 输入范围
（域前缀 `cicada-hub-build-inputs-v4\0`）：Git 已跟踪及未忽略的
`cicada-go/`、`docker/Dockerfile.hub`、`.dockerignore`、
`scripts/build-web-panel.sh`、`scripts/write-web-panel-manifest.py`、
`scripts/build-hub-image.sh` 与 `.github/workflows/release.yml`；摘要包含
相对路径、文件权限和内容（符号链接则摘要其目标）。它是受限的构建源码
标识，不包含整个仓库，也不是完整构建可复现性证明。`docker/Dockerfile.hub`
目前使用 `golang:1.27.1-alpine` 与 `alpine:3.24` 版本标签，尚未锁定
registry digest；builder 缓存、基础镜像标签解析及构建参数也会影响最终镜像。
`scripts/build-web-panel.sh` 的本地 WASM/Node 检查另用固定 digest 的
`golang:1.27.1-bookworm` builder，这不代表生产 Hub Dockerfile 的基础镜像已
按 digest 锁定。运行和验收必须锁定本次 Docker build 生成并记录的完整 image
ID，不能用可变 tag 代替。

结果区分 `PASS`、`FAIL`、`NOT_RUN`、`BLOCKED`；模拟 Harness 与真实原生
Runtime 不合并。合同检查通过、构建成功、Hub 协议联调、Android 联调、
真实任务验收和生产验收是不同记录。HTTP 200、Intent DONE、Worker 退出
均不能替代 Goal 的验收结果。

测试仅使用自动生成的合成身份和独立 state；Owner trust 的测试 bootstrap
不是生产登录。保持 resident Hub、现有 Owner/Node 密钥和数据库不变。

## Client 已完成的 Group key 验收与后续边界

Client 已导入 `client-hub-v1.2.1` 固定协议包，完成 Kotlin 向量、加密
`session.capabilities`、N4 与 N5 的上述模拟器验收。随后使用
[一次性 Group-key 夹具](client-group-key-disposable-fixture.md)和真实 leased
Codex Endpoint 完成加密 `group.key_manifest/grant/status` 的正向与失效验证：
最终 APK 的 `CURRENT`、租约到期 `STALE`、证明到期 `PROOF_EXPIRED`，以及
Android 本地篡改签名拒绝均有独立记录。Owner 私钥只在外部签署端，Android
独立验证 Endpoint attestation 并显式确认 Grant。该夹具只有一个合成 Owner；
双真实 Owner 的跨 owner 拒绝、物理设备与公网 HTTPS 尚未运行。

N4 的 Hub 端已进入 `client-hub-v1.2`，v1.2.1 保持相同恢复语义：登记 HTTP 201 丢失时原样重发同一
签名 Grant 和设备身份，Hub 在当前绑定仍有效时返回同一 epoch/key version；
完成的加密 RPC 可将原始请求包发到 `/v2/client/rpc/recover`，获得逐字节相同
的缓存响应。仍在处理中的请求返回 409 `STILL_PROCESSING`；v29 接受后因
崩溃而结果不明的请求返回签名、加密且占用预留响应序号的
`OUTCOME_UNCERTAIN` 通知；历史无预留序号的请求返回 409
`RECOVERY_UNAVAILABLE`。Client 验证通知后只能清除传输 pending，业务
结果仍需查权威 Intent/Goal/Approval 状态。具体字节与拒绝语义见
[wire contract](client-hub-wire-v1.md) 和 [互操作流程](client-hub-interop-v1.md)。
Android 已在固定 v1.2.1 协议包和干净 Hub 镜像下独立完成持久 pending-slot、
Kotlin 向量、丢响应与 Hub 重启故障验收；旧 v1.2 结果仍只作历史记录。
固定镜像无需增加故障 API：仅测试专用的回环代理和标记过的 `/tmp` 下
一次性数据库辅助程序可复现三个 `/rpc/recover` 分支，操作步骤和边界见
[v1.2.1 联调清单](client-hub-v12-validation.md#固定镜像的-android-恢复故障入口仅隔离测试)。

N5 的 `goal.result` 已在 Hub 接受 owner 归属 `intent_id` 后读取 Worker 摘要
和不含正文/本地路径的 Artifact 元数据。`TestClientIntentQueuesWorkForOwnerBoundMachineAgent`
验证加密 Client RPC、Node HTTP claim/snapshot/approval/result 和结果读取；
Node 的模拟 app-server 测试验证用原请求 ID 恢复挂起审批；另有真实
Node Agent/Codex 与加密合成 Client 协议驱动通过隔离闭环；Client 随后在固定
镜像上完成 Android 模拟器发起、审批与结果读取。可复跑步骤与真实验收门槛见
[v1.2 联调清单](client-hub-v12-validation.md)。

用户当前无需提供新凭据或操作。到真机/公网验收阶段才需要 Android 测试
手机和明确的 HTTPS 测试地址；到真实模型验收时使用已授权测试环境，
缺少条件只阻塞对应验收，不停止协议和离线开发。
