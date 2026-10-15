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
snapshot → fenced result → 加密 `goal.result`。它使用合成 Node bearer 和
HTTP 测试客户端，**没有启动真实 Agent/Codex，也没有审批环节**。

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

**当前阻塞点**：远端 Node Agent 的 Codex Worker 走 `codex exec`，尚未把原生
审批回调通过 Node-authenticated、attempt-fenced 通道交给 Hub。Control
本地 app-server Worker 虽有 `requestApproval` 回调，却不是远端 Node Worker。
因此步骤 3 目前只能作为待实现的验收流程，不能报告真实远端审批闭环 PASS；
也不能用合成 `CreateApproval` 行冒充 Worker 真正等待批准。下一项后端工作是
Node→Hub 审批请求/决议桥、旧 attempt fencing 与真实 Codex app-server
测试。真实 Agent/Codex、Android 真机和公网 HTTPS 结果分别记录。

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
