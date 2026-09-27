# Client–Hub v1.2 固定版本与联调清单

本清单只使用 CICADA Hub/Node 仓库；Android 实现在独立仓库。每轮联调固定
Hub 的完整 Git commit、协议包 SHA-256、`catalog_sha256`、本地 Docker image
ID，并单独记录 Client commit。`dev` 分支名或可变镜像 tag 不是版本证据。

## 从干净提交准备材料

在没有未提交文件的 CICADA checkout 执行：

```bash
git status --porcelain=v1                       # 必须无输出
git rev-parse HEAD
python3 scripts/client-contract.py check
python3 -m unittest discover -s scripts -p test_client_contract.py
python3 scripts/client-contract.py export --output .cicada-data/contracts
python3 scripts/client-contract.py verify .cicada-data/contracts/client-hub-<SHA256>.tar.gz
./scripts/build-hub-image.sh --image cicada:client-hub-v1.2 \
  --metadata-file .cicada-data/client-hub-v12-build.json
```

导出命令打印实际协议包路径、完整 SHA-256 和 catalog 摘要；以该输出替换上面的
`<SHA256>`。构建元数据的 `source.dirty` 必须是 `false`，`source.revision`
必须等于 `git rev-parse HEAD`，且 `source.catalog_sha256` 等于协议包 manifest
的 `catalog_sha256`。将 `image.id`（完整 `sha256:...`）交给 Client；未推送
镜像没有 registry digest，不能把本地 image ID 当 registry digest。
`docker/Dockerfile.hub` 是无 Codex/模型凭据的轻量镜像。

## v1.2 确定性 Hub 验证

```bash
cd cicada-go
go test -count=1 ./internal/store -run 'TestClientRecovery|TestGroupEndpointKeyGrant'
go test -count=1 ./internal/server -run 'TestClientRPCRecovery|TestClientDockerHubSmoke|TestClientIntentQueuesWorkForOwnerBoundMachineAgent|TestClientGroupEndpointKeyGrant'
cd ..
./scripts/test-client-hub-interop.sh
```

若主机没有 Go，使用仓库规定的 Go 1.27.1 Docker 工具链运行相同测试。一次性
interop 脚本会独立构建并启动真实 TCP Docker Hub，记录自己的 image ID
和 `result.json`，不接触 resident Hub。它覆盖登记精确重试、完成请求的原包
恢复、加密 RPC、Node 设备码和 owner 隔离。Store/HTTP 测试另外覆盖重启后
`OUTCOME_UNCERTAIN`、409 `STILL_PROCESSING`、409 `RECOVERY_UNAVAILABLE`、
错包、撤权、单调响应序号和 `goal.result` 归属。每项以实际退出码为准；Go
测试不等于 Kotlin/Android 或真实 Node Runtime 已通过。

Client 在固定镜像上应至少重放：登记响应丢失后原样重发同一 Grant；已完成
RPC 的 `/rpc/recover` 返回原密文；处理中返回 409 `STILL_PROCESSING`；
Hub 重启后的不确定 RPC 返回使用原预留响应序号的密文
`OUTCOME_UNCERTAIN`；旧无标记请求返回 409 `RECOVERY_UNAVAILABLE`；
错密文与撤销设备被拒绝。每个响应均核对签名、Hub/owner/device/epoch、
原 operation ID 和响应序号；不因 409 创建第二个业务 operation。

## 真实 Node Worker、审批与结果验收

当前可复跑的 Hub HTTP 协议链为
`TestClientIntentQueuesWorkForOwnerBoundMachineAgent`：加密 Client Intent →
持久 Goal/Worker → owner 绑定 Node 的 heartbeat/jobs/claim → Workspace
snapshot → fenced result → 加密 `goal.result`。测试还覆盖 Node 已认证地
持久提交 Codex 审批、加密 Client `approvals.list/decide`、Node 在原 attempt
读取决定，以及旧 attempt、终态和撤权拒绝。它使用合成 Node bearer 和
HTTP 测试客户端，**没有启动真实 Agent/Codex**。

真实 Node Agent 的 Codex Worker 现在通过同一原生 app-server 进程接收
`item/commandExecution/requestApproval` 和 `item/fileChange/requestApproval`，
向 Hub 的 `/v2/relay/nodes/{node_id}/jobs/{worker_id}/approvals` 持久提交
`{attempt,request_id,method,request}`。响应丢失后以相同 `request_id` 与原始
请求重试；Hub 返回 `approval_id` 后 Node 对
`.../approvals/{approval_id}?attempt=N&wait_ms=20000` 长等待。Client 的决定
只经现有加密 `approvals.decide` 产生；Node 用原 app-server 请求 ID 回复，
让尚在运行的 turn 继续。Node 的 409、撤权和不匹配决定均失败关闭。
`TestRemoteCodexApprovalReturnsToOriginalAppServerTurn` 使用模拟 app-server
验证这条 Node 桥和原请求 ID；它**不能证明真实 Codex 的原生会话连续性**。
`TestMachineAgentBinaryRemoteApprovalEndToEnd` 进一步启动真正的
`cicada machine agent --once` 二进制，对真实 Hub HTTP Handler 执行
加密 Client Intent → Node 领取 → 审批列表/决定 → 原请求 ID 回答 →
Node 提交结果 → 加密 `goal.result`。该测试的 app-server 是协议模拟器；
在隔离的 Hub/Node 工作目录下连续运行三次通过。Node 按授权的
`workspace_id` 将 Workspace 定位到本机 `CICADA_WORKSPACE_ROOT/workspaces/<id>`；
Hub 的绝对工作目录不作为 Node 执行路径。
审批请求参数会由 Node 经 HTTPS 交给 Hub，并在 Hub 的 Approval 表中保存；
Hub 可读取这份管理审批正文。此路径不能称为 Node→Client 端到端盲密文，
也不代表普通 Endpoint 间的 sealed peer 消息经过 Control 解密。

完整验收须在隔离的 Hub 与 Node 上按以下顺序执行并记录脱敏 ID/状态：

1. 从上方固定 image ID 启动隔离 Hub；用独立可信渠道固定 Hub ID/公钥，
   本地登记测试 owner 公钥，再让测试 Client 签署设备 Grant 和入网。Node
   使用单独 StateDir 启动 `cicada machine agent --id NODE_ID --state-dir
   NODE_STATE --control-url HUB_URL`，由 Client 加密调用 `nodes.preview`、
   `nodes.confirm`；验证真实 Agent 心跳与 Node 凭据不进入 Client。
2. Client 发送 `intent.submit`，指定该 Node/workspace/Codex 的有界 Goal；
   持久保存原请求包、operation ID 和返回的 `intent_id`。轮询
   `intent.status`，核对 Goal/Worker 已排队，随后由**真实 Agent 进程**
   领取、执行并回报；检查 Worker attempt、原生 Session ID、Workspace
   snapshot digest 与 Goal 归属。
3. 在 Worker 发起一项确需批准的受控动作时，Client 通过
   `approvals.list` 读取同一 Goal/Worker 的 pending approval，明确调用
   `approvals.decide` accept/decline；验证旧 attempt、异 owner、重复和
   伪造“用户已批准”均不能放行。最后查询 `intent.status` 与
   `goal.result {"intent_id":"..."}`，比较 Worker 终态、摘要和 Artifact
   元数据；不将 `intent.status=DONE` 当作 Worker 成功。

**真实验收门槛**：上述 HTTP 与模拟运行时测试不能替代真实 Node Agent 与
Codex 联合运行。2026-09-24 的隔离联合测试已通过：使用真实
`cicada machine agent --once`、Hub HTTP Handler、Codex CLI 0.156.1、
`gpt-5.6-luna` 与加密合成 Client 协议驱动。Client 提交 Goal，Node 领取
Worker；原生 Codex 请求命令审批，Client 读取并接受，Node 用原 app-server
请求 ID 回复；受控动作产生的文件内容经核对，Node 提交结果，Client 从
`goal.result` 读到 `completed` Worker 和 `resolved` Intent。审批请求的原生
`threadId` 与最终 Worker 记录的 Thread ID 完全相同，attempt 保持 1。
Hub 与 Node 分处隔离的状态目录，Node 和 Codex 是独立进程/容器；Hub 使用
真实 HTTP Handler，但运行在测试进程中。该测试不证明 Android 真机操作、
公网 HTTPS 或双物理机。另一个下方的探针独立证明跨进程原生
`thread/resume` 与上下文延续，不能把两个独立 Thread 拼作一次跨机恢复。
app-server 重启不保证恢复挂起的审批 turn；旧 attempt 不得借 resume
假装它已继续。

复跑联合测试（隔离 provider env 文件仅供测试容器读取，权限必须为 0600）：

```bash
python3 scripts/test-real-node-codex-approval.py \
  --env-file /path/to/private-test-provider.env \
  --output .cicada-data/real-node-codex-approval-result.json
```

脚本要求本机 Docker socket、`cicada-codex:client-hub-dev` 中的 Codex CLI
0.156.1、Go 1.27.1 Docker 镜像、可用的 `gpt-5.6-luna` 凭据；不使用 npm，
不把凭据写入输出或 Hub 镜像。实际运行的退出码为 0，脱敏结构化证据在
`.cicada-data/real-node-codex-approval-fec06fa.json`（测试源码提交
`fec06fa79ec8941cc26f6b15ffe8b6ce717fdeb4`）：
`native_session_exact=true`、`approved_action_verified=true`、
`worker_attempt=1`、`worker_status=completed`、
`goal_result_intent_status=resolved`。该本地文件不在协议包中；接收方应复跑。
Android 真机和公网 HTTPS 仍须分别记录结果。

若 Node 在用户接受远端命令审批后离线，或 Hub 此时重启，Worker 被标为
`outcome_uncertain`，不自动领取第二次；需要先核对原生运行结果。
原来的 Node 若仍持有同一 attempt 和当前授权，可以读回已接受的决定并提交
迟到结果；Hub 按原 attempt 验收并拒绝重复结果，其他 Node 不能重领该 Worker。
Hub 重启时旧 turn 尚未决议的审批会取消，不能授权新 attempt。
未接受审批的普通离线请求仍按现有排队恢复。该保护只覆盖有持久接受审批的
动作，不能替代所有自动执行动作的原生注入对账。

2026-09-24 使用隔离 Docker、Codex CLI 0.156.1、`gpt-5.6-luna` 和一次性
`CODEX_HOME`，第一进程在原生 Thread
`01a0d412-700c-79e1-a72d-2efbb18a5b1a` 收到真实
`item/commandExecution/requestApproval`，以原请求 ID `accept` 后，受控文件
写入成功、turn 为 `completed`，最终消息与随机标记一致。关闭该进程后，
第二进程以同一 `CODEX_HOME` 执行 `thread/resume`，返回完全相同的 Thread ID；
下一轮不访问文件，仅凭历史准确回答前一轮的随机标记，turn 同样为
`completed`。此探针直接驱动 Codex app-server，**没有**经过 Cicada Hub、
Node Agent 或 Android，因而不能记作产品全链 PASS。早先使用 Python
`select` 读取文本缓冲流的探针误判为超时，已经以持续读取队列重跑纠正。
本机结构化结果为 `.cicada-data/native-codex-v12-04feff1.json`；该文件不在
协议包中，接收方应在自己的环境独立复跑。

可在已安装 Codex CLI 0.156.1 的测试镜像上复跑：

```bash
python3 scripts/test-native-codex-approval.py \
  --env-file /path/to/private-test-provider.env \
  --image cicada-codex:client-hub-dev \
  --output .cicada-data/native-codex-approval-result.json
```

环境文件须为 `0600`，包含 `API_KEY=...`；脚本只挂载该文件到一次性 Docker
容器，不把 key 放进输出、仓库或镜像。结果只记录原生 Thread ID、审批方法、
两个 turn 状态、原生恢复与随机上下文匹配，不记录模型正文。

## Group Endpoint 公钥签署门槛

`group.key_manifest` 的 `candidate_attestation` 必须给 Client 提供完整
Endpoint 自签 JSON 证明；只有摘要和公钥不能独立验签。Client 先核对该
证明的 SHA-256 与 `candidate_proof_digest`，再验证 ML-DSA-65 签名、
Endpoint/Principal/Node/SessionBinding ID 与 epoch、公钥 ID/指纹、Group/
Membership/Join revision、候选 binding digest 和 manifest digest，最后才用
owner key 签名。完整字段顺序、域分离字节和拒绝条件见
[wire contract](client-hub-wire-v1.md#complete-group-endpoint-key-evidence)。
自签名只证明 Endpoint 持有私钥；Hub 返回的当前关系和用户的独立批准仍须
分别验证。缺失证明字节时直接拒绝，不以展示指纹代替验签。
