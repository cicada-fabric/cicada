# Client 开发者交接：Hub 接口

## 2026-10-01 v1.6 完整交接流程与边界

本次只交接 CICADA 的 Hub/Node/Control 协议与有界验证证据。独立 `../CICADA_CLIENT` 负责 Android 实现、APK、设备密钥保管和 Android 验收；本仓库不修改 Client、不替 Client 声明通过，也不自动 push、发布或替换 resident Hub。最终 clean Git commit、Hub image、bundle 文件及 manifest/hash 由本机固定交付目录 `.cicada-data/v01-finish-20260930T145216Z/client-v1.6-clean-handoff/` 的 `HANDOFF.md` 和 `metadata.json` 给出；本文件说明流程与证据边界，动态产物以该目录为准。dirty 54f 的开发合同包是单独验证证据，不能冒充 clean 交付。

先核对 artifact 的 `source_revision`、`source_dirty`、`contract_revision`、`wire_version`、`catalog_sha256` 和逐文件 hash。Git revision、source fingerprint、软件版本、wire version、contract revision 与 image digest 各自独立；public capabilities 说明服务可用性，实际设备授权仍以加密 `session.capabilities` 与逐请求服务端 Guard 为准。最终 manifest 的保守 coverage 不代替独立 Android/native/物理/公网验收记录。

最小开发步骤：

1. 从最终交付 metadata 取得精确 bundle 路径，用 `python3 scripts/client-contract.py verify <bundle-path>` 验证完整性，再核对独立可信的发布者和 Hub pin；不要从共享 WIP、文档拼凑或仅 URL 下载的 identity 开始 Android 验收。
2. 以机器可读 catalog/OpenAPI/wire 和公开合成 vectors 为唯一字节/字段依据，保留已有 v1.5 恢复和原密文重试语义。v1.6 是 wire v1 的 55-operation contract；相对固定 bd79 的 v1.5 增加九项：`network.directory`、`topology.endpoint_admission_preview`、`space.foreign_endpoint_preview`，`network.collaboration_key_manifest/grant/status` 与 `link.review_policy_preview/grant/status`。未知或当前设备未获授权的操作应隐藏或明确拒绝。
3. 先完成 Hub pin、Owner-signed 设备登记和加密 `session.capabilities`。Node 的设备码配对必须是分别可见的 `nodes.preview` / `nodes.confirm`；Node bearer/private keys 永远留在 Node，不由 Android 或 Hub 保存。
4. 在已有拓扑/目录和 consent UI 中逐项实现新增操作，只有该入口的独立 proof、当前 Guard 和 Client interop 证据完备后才开启；其余保持 gated。展示准确 Network/Group/Endpoint、purpose、版本、当前读者与风险；Preview 不等于批准，Grant 只来自用户显式确认。外部 Endpoint admission、跨 Owner space 与 Link reviewer policy 不自动扩大目录、历史、任务或私聊权限。字段与拒绝结果以本次合同为准，不自造 sender、role、scope 或“已批准”。
5. 在 Client 自己的隔离测试与固定 clean Hub 上验证加密 RPC、丢响应/PROCESSING/OUTCOME_UNCERTAIN 恢复、原包重试、当前权限与撤权、Owner/key/purpose 错配拒绝和跨 Network 可见性；保留 APK/source/catalog/image/device 标签及每个 selector 的真实结果。原 Android v1.5 PASS 不转移给 v1.6。
6. 完成后由独立 Client owner 一次性交付实现、合同 pins、APK/hash 与验证报告。Android v1.6、物理双 Node、公网 HTTPS 在实际记录前仍为 NOT_RUN；无需把物理/公网未运行写成已完成后端框架检查点失败，也不能因此宣称 Architecture v2.3 整体完成。

### Client 已有能力与仍关闭入口

只读互操作审查对应 Client `9b17f8fb` 的干净工作树和其 `docs/cicada-core-handoff.md`。固定 v1.5 的 catalog 为 46 项，Client 只实现并按加密 Session 当前授权开放其中 33 项；七项 cross-Owner Space、三项 delegation/proposal 与三项 Link key 操作仍 gated。Release 的四项 public policy 测试后来 PASS 只证明其离线公共接口行为，不能扩展固定 v1.5 live Hub 结果，更不能算 v1.6 Android PASS。

v1.6 的 55 项 catalog 不意味着 Android 应一次性全部开放。应先导入新 clean 包的独立 vectors，再逐入口补齐 proof/current-authority/Guard/interop 证据；保持已有 13 个 gate，直到该入口的具体依赖满足。Endpoint Owner business role `ENDPOINT` 必须映射签名侧 `SOURCE`，Group Owner `GROUP` 对应 `TARGET`；每位 Owner 独立确认自己的侧，两个提交完成后才验证 complete dual-proof status。Endpoint attestation v1 的签名输入包含末尾 `signature:null`；OwnerLinkKeyGrant v2 的十个 ordered claims 中没有 signature 字段，不得把一种 proof 的编码套到另一种。

已验证的 54f 开发包已有 `cross-owner-group-key-v2.json`（SHA-256 `0cc1f40baf754870f36da1ba0a28be9b60036186ef1c02ed2aa6de64d29d778c`），含完整 candidate attestation、v2 manifest、两个 synthetic Owner proof 与精确 signed inputs；这是 Client 已测过的 candidate vector，不是新 native authority 验收。Network direct production-shape vector 与 TASK-purpose collaboration vector 也已包含。所有公开 fixture 都是 synthetic，不能初始化部署或当成独立可信 Owner。

本轮后端/framework检查点已限定 PASS（final2858 fullGo/vet、contract/Python26/shell20；54f bounded Docker/Browser/native Join 保持原来源）。clean commit/image/bundle 动态标识以固定交付目录为准。

最终冻结前已补齐并通过 Go e2ee 全包、严格合同 check/export/verify 和合同单元测试7项检查（新增3项，整套Python26项）的两份公开 synthetic vectors **AVAILABLE**；它们属于新源，不能归于旧 54f 包：

- `owner-link-review-policy-proof-v1.json`：SHA-256 `aab0a7074fb32523f75bb89f9a61f4725d9f462c2d83eec33d23f79609fc5907`。Policy canonical input 为十一项 claims，不包含 signature 字段。
- `network-collaboration-broadcast-consent-v1.json`：SHA-256 `c18b237047a6963b95844a1a32307794e6b353150313b77ab2ce84393b0ab8ea`。BROADCAST consent 为十二项 claims，包含 `signature:null`；TASK vector 保留，各 purpose 不可互换。篡改与串 purpose 拒绝检查通过。

独立 Client 必须导入最终包并在自身 Kotlin 验证精确 canonical bytes/签名与拒绝用例。公开 vectors 可用不等于 Kotlin、native authority 或 Android 已通过。以下依赖仍 **BLOCKED / NOT_RUN**：

- positive v2 admission/first-Owner confirmation/dual-Owner signing/native current-authority fixture 与相应 Client 联合验收：现有 synthetic complete-status vector、schema 和 backend tests 不证明 Owner 在真实原 Thread/binding 上分别完成了 consent/Join。提案/delegation UI 也需相应精确 scope/expiry/CAS 与拒绝用例后才开启。
- Network key uncertainty 的专用 original-proof/status reconciliation：保持已有 durable Network grant fence。通用 `status.snapshot` 可处理 outer RPC fence，但不能释放 Network grant 业务 fence；profile 切换、trust replacement 或设备 reset 也不能覆盖原 signed ciphertext/counters。完整 live Network consent/reconciliation 仍 BLOCKED / NOT_RUN。

本次证据边界见 [检查点报告](v01-completion-checkpoint-validation.md)。f55 Browser、432f 原生 peer、432f＋测试 overlay 广播/Worker 与 840a joined Docker 各有独立来源；后者使用 recording fake queue。最终源 2858 的 Go/合同结果与 54f Browser/Docker/M5 必须另列，不能把历史 PASS 改写到新源。

读取最终动态标识：

```sh
python3 -m json.tool .cicada-data/v01-finish-20260930T145216Z/client-v1.6-clean-handoff/metadata.json
cat .cicada-data/v01-finish-20260930T145216Z/client-v1.6-clean-handoff/HANDOFF.md
```

以下 v1.3/v1.2 内容保留为有日期的历史交接，不作为本次 v1.6 的现时能力/验收结论。

本文件给独立 Android 仓库的开发者一条最短接入路径。Hub 代码仍在 `CICADA`；不要在 Android 端链接 Go 包、读取 Hub SQLite、保存管理 bearer 或 Node bearer。详细字段、字节级加密规则和错误边界分别见 [最小互操作流程](client-hub-interop-v1.md)、[wire contract](client-hub-wire-v1.md) 和 [OpenAPI](client-hub-v1.openapi.yaml)。

> 2026-09-27: frozen v1.3 artifact and disposable TCP gate **PASS**; exact pins and
> boundaries are in the [validation record](client-hub-v13-validation.md). The dated candidate note below is pre-freeze history.

两仓统一开发、版本固定和验收流程见 [联合开发规范](client-hub-development.md)。
可直接交给独立 Client 开发者的 v1.2 任务书见
[Client 提示词](client-hub-v12-client-prompt.md)。
机器可读 operation 来源为 [`catalog.json`](../cicada-go/internal/clientcontract/catalog.json)，
不要在各份文档中分别维护操作数量。`contract_revision` 与 `catalog_sha256`
用于核对协议修订；实际权限仍由加密 `session.capabilities` 和服务端 Guard 决定。

## 2026-09-27 Monitor v1.3 冻结前候选快照

共享工作树中的候选为 `client-hub-v1.3`，33 个操作，catalog SHA-256
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`；本地
catalog 检查及七项合同/恢复 Python 测试通过。四项新 RPC 是
`monitor.broadcast_prepare`、`monitor.broadcast_confirm`、
`monitor.broadcast_status` 与 `monitor.broadcast_recover`。

先等待 Hub owner 提供干净 source commit、完整协议包及 manifest/hash、实际 Hub
image ID/digest，再导入 Android。两个定向 TCP Monitor HTTP lifecycle/Relay 测试已
通过；整仓 Go tests/`go vet` 在两项 review 修正前通过。之后的 Confirm
projection/OpenAPI 与 inactive Group 修正通过受影响的 Control/Server 全包测试、
vet 及聚焦 race 复验；五项 Store Monitor race 测试也通过。最终 Docker 联合门禁仍待确认。不要从
共享开发 Hub 构建 Android 验收结论。候选功能要求 Client 先验证完整 Endpoint
attestation 与独立可信 Owner 签署的 Group Endpoint grant，再显示 consent scope 与
有序 recipient roster；只有显式用户确认后才以 Monitor key 加密正文并用 Client
device key 签署 envelope v2。精确细节、重试/恢复与验收条件见
[v1.3 Client 任务书](client-hub-v13-client-prompt.md)。

v1.2.1 固定镜像上的 Android 管理、恢复和 Group key 验收只保留为历史证据。此候选
的 Android、真实 native Monitor、物理设备与公网 HTTPS 均为 **NOT_RUN**，不能从旧
APK 或旧镜像结果推导通过。

## 历史 v1.3 最小接入路径

在本仓库根目录运行 `./scripts/run-client-hub-dev.sh`，得到绑定 `127.0.0.1:8787` 的隔离开发 Hub。它会构建 Docker 镜像并保留 `.cicada-data/client-hub-dev` 状态；重复运行前需停止已存在的开发容器。Android 模拟器访问宿主机时须使用其宿主机映射地址，而不是把 `127.0.0.1` 当作 Hub。公网接入另需 HTTPS 与独立可信的 Hub 公钥固定，此脚本不做公网部署。

接入顺序：

1. `GET /v2/client/capabilities` 读取实际开关。`status=partial` 是当前预期；先实现已开放操作，隐藏未开放功能。
2. `GET /v2/client/identity`，通过独立可信渠道核对并固定 `hub_id`、Control ML-KEM/ML-DSA 公钥和版本。仅从将要连接的 URL 下载身份不能证明它可信。
3. 生成手机自己的 ML-KEM-768/ML-DSA-65 设备密钥；取得该 owner 独立签名的 `OwnerDeviceGrant`，调用 `POST /v2/client/devices/enroll`。若 HTTP 201 丢失，原样重发登记请求，Hub 返回已接受的原绑定。开发环境的首次 owner 公钥需要 Hub 本地 `cicada owner-key register` 引导，详见 [owner bootstrap](owner-approval-bootstrap.md)。当前没有手机侧一键登录 UI 或可由管理 bearer 代替的设备批准。
4. 将签名、封装并加密的 Client-Control v1 packet 发到 `POST /v2/client/rpc`。首个 operation 应为 `session.capabilities`，以该设备返回的 `available_rpc_operations` 决定界面。持久保存请求序号、`operation_id` 和待重试的**原始密文包**。丢响应或重启后将原包发到 `POST /v2/client/rpc/recover`：正常缓存原样返回；`OUTCOME_UNCERTAIN` 是可验证的密文通知，清除传输 pending 后仍须保留业务不确定状态。不得创建新 operation 重试副作用。
5. UI 的 Node/Endpoint/Worker/Goal/Group/Task 使用 `status.snapshot`；增量轮询 `status.changes` 并定期用快照对账。语音转写在手机上形成可编辑文本，再以 `intent.submit` 交给 Control；用 `intent.status` 查询派发进度，目标为 Goal 时用 `goal.result` 读取归属校验后的 Worker 摘要及证据引用。画布使用 `topology.snapshot/apply` 的版本化操作；批准使用 `approvals.list/decide`。这些管理操作目前只授予本 Hub 的 manager owner，外部 owner 的会话不会意外取得管家权限。
6. Node 配对时，手机只显示 Node 提供的 user code 并在加密 RPC 中 `nodes.preview`、`nodes.confirm`；Node 凭据始终留在 Node。跨用户 Thread 邀请可先实现 `link.invite_create/preview/accept`、`link.list` 和 `link.key_*` 的**提案与授权界面**，但不能显示为可聊天/可发送。

Hub 从同一 catalog 派生管家 owner 和外部 owner 的操作集合，包括 Group Endpoint 密钥授权操作。两类设备都走同一个 `/v2/client/rpc` 加密入口；区别由已登记设备的 owner 和 Hub 当前权限决定，不能由客户端自填 `role`、`sender`、`group` 或“已批准”。外部 owner 只能读自己的状态、Node、Group/Endpoint 和 Link 元数据，不能提交本 Hub Control 的 Goal、Intent、Approval 管理动作。Client 可以只实现其已验证的操作子集，未知或未实现操作继续关闭。

## 暂不可在 Android 标为已完成

- `status_events=false`：已有可续读的 `status.changes` 轮询，尚无完整 push 事件流，且差异只覆盖快照与有限管理状态。
- `external_thread_links=false`：双方设备可创建一次性邀请、恢复 Link 提案并分别签署当前密钥清单；Node/MCP 密文 SEND/ASK/REPLY 已在两个逻辑 Node/fake Codex 中通过，但真实跨用户原生 Codex 会话、完整 Client 对话体验和广播尚未验收。
- Client 开发者报告当前固定在 `client-hub-v1.1`（实现 `179e0ef`、文档 `b298fd8`）。这些是 v1.1 证据，不能用于 v1.2 结论；请先固定本仓干净 commit、v1.2 协议包摘要和本地 Hub image ID，再重新运行 Kotlin 向量、恢复故障与 Android 验收。交付及复跑清单见 [v1.2 验收流程](client-hub-v12-validation.md)。手机首次简便可信绑定、设备密钥备份/换机、真机录音和公网 TLS 仍须单独验收。请按能力开关实现 UI 降级，不能改用旧 `/v1` bearer API 代替加密入口。

这里的“Client”是用户设备入口，“Node”是承载原生 Thread 的执行设备；两者都主动连 Hub，但权能不同。Client 的管理内容预定由 Control 解密；普通 Endpoint 消息应只由目标 Endpoint 解密。Android 不参与 Node 的 `/v2/relay/nodes/...` 领取和原生注入流程。
