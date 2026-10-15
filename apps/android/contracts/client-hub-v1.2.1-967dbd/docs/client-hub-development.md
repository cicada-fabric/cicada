# Client / Hub 联合开发与验收

本规范将两个仓库作为一个产品协作，但分别构建和发布。CICADA 拥有
Hub/Node/Control、权威状态和协议；CICADA_CLIENT 拥有 Android UI、端侧
密钥与手机生命周期。当前由本仓库落实服务端与联调工具，不修改 Client。

## 当前整改顺序

| 切片 | 交付与退出条件 | 当前状态 |
|---|---|---|
| N1 契约来源 | operation catalog 驱动角色 allowlist；版本与摘要可查询；与真实 dispatch 和 OpenAPI 检查一致 | 已实现；Go 定向与全仓回归通过 |
| N2 可重复环境 | 无 Codex/模型凭据的轻量 Hub 镜像；源码来源可核对；独立临时状态的真实 TCP 加密互操作命令 | 已实现；一次性 TCP 联调和开发启动检查通过 |
| N3 联合验收入口 | 协议包、公开合成密码学向量、CI 检查与分层结果；Client 可固定下载/导入具体版本 | 本仓入口完成；本地测试通过，GitHub Actions 与新 Kotlin 向量测试未运行 |
| N4 登记与不确定状态恢复 | 丢失登记响应、Hub 重启后 UNCERTAIN 的明确恢复协议，两端故障测试通过 | Hub 侧已实现并通过 Store/HTTP 故障测试；隔离 Android 故障代理/临时数据库注入入口已提供，Android 三场景尚待运行 |
| N5 最小产品闭环 | 可信绑定 → 手机 Intent → 真实 Node Worker → 审批 → 结果回手机 | Hub 的 `goal.result`、Node 审批桥和真实 Node/Codex 加密合成 Client 闭环已验收；Android 全链仍待验收 |
| N6 发布验收 | 真机录音/前后台、HTTPS、签名 APK；跨用户密钥授权另列功能验收 | 未运行 |

N1–N3 完成及 N4/N5 的 Hub 侧改动不表示跨仓、真实原生与 N6 已完成，也不表示 Architecture v2 已全部实现。

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

当前 `source_fingerprint` 覆盖 Git 已跟踪及未忽略的 `cicada-go/`、
`docker/Dockerfile.hub`、`.dockerignore` 文件内容与权限。它标识源码输入；
构建工具、基础镜像的解析版本和构建参数仍可能改变产物。基础镜像目前使用
版本标签，尚未锁定 registry digest，因此不承诺逐字节可复现构建。运行和
验收必须锁定本次 Docker build 生成的完整 image ID，不能用可变 tag 代替。

结果区分 `PASS`、`FAIL`、`NOT_RUN`、`BLOCKED`；模拟 Harness 与真实原生
Runtime 不合并。合同检查通过、构建成功、Hub 协议联调、Android 联调、
真实任务验收和生产验收是不同记录。HTTP 200、Intent DONE、Worker 退出
均不能替代 Goal 的验收结果。

测试仅使用自动生成的合成身份和独立 state；Owner trust 的测试 bootstrap
不是生产登录。保持 resident Hub、现有 Owner/Node 密钥和数据库不变。

## 下一项交给 Client 开发者的工作

先导入本次协议包、运行 Kotlin 向量验证，再锁定可追溯的 Hub 镜像完成
`session.capabilities` 联调。新增加的 Group key operation 按实际产品需要
接入，不因 operation 被列举就省略 Owner 签署、Endpoint attestation 验证。
已实现的 Android operation 子集可继续使用；未知可选操作保持关闭。

N4 的 Hub 端已进入 `client-hub-v1.2`，v1.2.1 保持相同恢复语义：登记 HTTP 201 丢失时原样重发同一
签名 Grant 和设备身份，Hub 在当前绑定仍有效时返回同一 epoch/key version；
完成的加密 RPC 可将原始请求包发到 `/v2/client/rpc/recover`，获得逐字节相同
的缓存响应。仍在处理中的请求返回 409 `STILL_PROCESSING`；v29 接受后因
崩溃而结果不明的请求返回签名、加密且占用预留响应序号的
`OUTCOME_UNCERTAIN` 通知；历史无预留序号的请求返回 409
`RECOVERY_UNAVAILABLE`。Client 验证通知后只能清除传输 pending，业务
结果仍需查权威 Intent/Goal/Approval 状态。具体字节与拒绝语义见
[wire contract](client-hub-wire-v1.md) 和 [互操作流程](client-hub-interop-v1.md)。
Android 的持久 pending-slot、Kotlin 向量、丢响应与 Hub 重启测试须在固定
v1.2.1 协议包和干净 Hub 镜像下重新验收；旧 v1.2 结果不能算通过。
固定镜像无需增加故障 API：仅测试专用的回环代理和标记过的 `/tmp` 下
一次性数据库辅助程序可复现三个 `/rpc/recover` 分支，操作步骤和边界见
[v1.2.1 联调清单](client-hub-v12-validation.md#固定镜像的-android-恢复故障入口仅隔离测试)。

N5 的 `goal.result` 已在 Hub 接受 owner 归属 `intent_id` 后读取 Worker 摘要
和不含正文/本地路径的 Artifact 元数据。`TestClientIntentQueuesWorkForOwnerBoundMachineAgent`
验证加密 Client RPC、Node HTTP claim/snapshot/approval/result 和结果读取；
Node 的模拟 app-server 测试验证用原请求 ID 恢复挂起审批；另有真实
Node Agent/Codex 与加密合成 Client 协议驱动通过隔离闭环，但没有运行 Android。可复跑步骤与真实验收门槛见
[v1.2 联调清单](client-hub-v12-validation.md)。

用户当前无需提供新凭据或操作。到真机/公网验收阶段才需要 Android 测试
手机和明确的 HTTPS 测试地址；到真实模型验收时使用已授权测试环境，
缺少条件只阻塞对应验收，不停止协议和离线开发。
