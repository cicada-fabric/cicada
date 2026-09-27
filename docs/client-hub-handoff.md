# Client 开发者交接：Hub 接口

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

## 现在可以接入

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
