# v0.1 Node PQ transport：产品接入检查点

## Main combined integration status (2026-10-02)

Main integrates retained-certificate lifetime checks and the recovery metadata
query over `06d0a58` (runtime source `648162e…`). Focused receipts retain their
tested sources; the query keeps quarantine held and never re-executes work.
Current integrated Main source is `e64f2449…`. Full Go QA passed on the
pre-policy-fix source `97a008…`, with explicit skips retained; its separate
799-input proof connects only `97a008…` to the pre-policy-fix shipping baseline
`bab6569…`, and does not cover the later policy fix. Focused shipping script
checks retain their `bab6569…` attribution, with artifact skips retained. Clean package/image and
exact-image acceptance are NOT_RUN. Its real Agent observation covers startup/poll/RSS only;
ASK/heartbeat/revoke ran in the driver context. Historical `fec658…` is retained.

Client contract `client-hub-v1.6.1`, wire 1, 55 operations and Hub schema v55
are unchanged; Architecture v2.3/v0.1 remain PARTIAL. The [status table](architecture-v2-status.md)
owns source inventories, focused receipts and independent device-layer limits.

The retained-certificate lifetime layer supersedes the standalone snapshot's
retained-expiry limitation below; see the [lifetime record](v01-node-pqtls-lifetime-validation.md).
Automatic issuance/rotation and independent certificate revocation remain outside
that result. The metadata [recovery query](node-recovery-query.md) does not complete
restore reconciliation or certificate lifecycle. All standalone counts, source
hashes and failures below retain their original attribution.

## Standalone delivery snapshot (2026-10-01)

At that delivery time the bounded product implementation, deterministic gates
and disposable Docker validation passed in the isolated worktree, but the
overlay had not yet been integrated into Root's Main worktree. This was not a
v0.1 completion, automatic certificate lifecycle, Android/browser pure TLS or
public deployment result.

## 源码与权属

工作树 `/home/zyf/CICADA_pqtls_runtime`，detached base `fe565b41bb1aa86d400a0ec98c528c856d0b9579`，dirty overlay；没有 commit、push、merge、release、替换常驻部署、全局安装 OpenSSL 或真实密钥轮换。软件版本仍为 `0.1.0-dev`、wire `1`、Client 合同 `client-hub-v1.6.1`、catalog `55` 项。catalog 原始字节 SHA-256 为 `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b`，这些身份不与 Git revision、源码 fingerprint、二进制 SHA 或 image digest 混用。

最终 Go 子树有 779 个文件，其 fingerprint 定义为按路径排序的 `SHA256(file) + 两个空格 + path + 换行` 再作 SHA-256：`8a4748c04c040cf414572efdff2c71f01964948f458c02a5c6a3a960b58d22a1`。这是包括测试在内的 Go 子树身份，不是 Root release 脚本的全仓 fingerprint。

原完整五包回归属于关闭顺序修复前的 Go 子树 fingerprint `5c01548f281139d90692aab2af054b492a2c781a33fc29c887cd0becc3bc8997`；本检查点保留该归属，并对最终受影响的 cmd、产品 transport、Guard 与 lifecycle 重新验证。不把此前 783 个顶层测试改标到后续源码。

最终文件 SHA 清单、完整包含新文件的 patch、全部 gate 结果及日志 SHA 均在本机 `.cicada-data/node-pqtls-runtime-20261001/` 的 `final-manifest.json`、`final-runtime.patch`、`RESULTS.json` 与各 `.jsonl/.log/.exit`。这些私有证据不含真实密钥、凭据或完整敏感业务正文。

在独立交付时，没有修改 Client、authoritative Client 合同、当时七份既有架构检查点文档、backup/recovery 实现、`mcp_network.go`、`local_network_join_bridge.go` 或 `machine_network_direct.go`。`local_join_bridge.go` 仅换了一处 HTTP client 构造。**该 standalone snapshot 中，两个 Network Join bridge HTTP 构造仍待 Root 后续接入 helper**；当时 strict 前门会安全拒绝其普通 peer 请求，所以不能把该 snapshot 的 native Network Join 宣称为完整接通。Main 后续已接入两处 Join/renew 构造；当前状态见上方 integration note。

## 实际产品边界

- [serve_pqtls.go](../cicada-go/cmd/cicada/serve_pqtls.go) 在同一进程和数据库上开原 Client/bootstrap 前门及可选 Node listener；两个 listener 均取得后才启动 HTTP 服务。Node listener 使用 `internal/pqtls`，`ConnContext` 保留真实 verified state，`Request.TLS` 仍为 nil。不伪造 Go TLS state、HTTP/2 支持或标准 TLS fallback。
- `serve --node-pqtls-config <private.json>` / `CICADA_HUB_NODE_PQTLS_CONFIG` 在 managed 与 `--fabric-only` 两种模式生效。没有配置时保留既有入口；配置后两个入口都装 [Node Guard](../cicada-go/internal/server/node_pqtls.go)，普通入口上的 Fabric、Artifact、Relay、已配对 Node RPC/key-upgrade 请求拒绝，即使带合法 Manager/Node/Session bearer。
- Client、Node public identity、未配对 device-code/status 留在原前门。Node listener 不承接 Client/bootstrap/Manager API；其只读 health/Node identity 与已入网路径有明确范围。Client availability/catalog 不扩大授权，原 encrypted device session 与业务 Guard 保持权威。
- [machine_pqtls.go](../cicada-go/cmd/cicada/machine_pqtls.go) 的 `machineNodeHTTPClient(ctx, timeout) (*http.Client, error)` 为 Agent、Node-Control、snapshot、SSE、Group/Link/space/regroup bridge、peer CLI/MCP 选择 per-Hub transport。独立命令读取 `CICADA_NODE_PQTLS_CONFIG`，配置错误直接失败；共享 `networkHTTPClient()` 保留旧签名，但错误以 failing RoundTripper 返回。Agent 保留 pool，独立命令关闭单次响应的连接。
- `machine agent --pqtls-config <private.json>` / `CICADA_NODE_PQTLS_CONFIG` 启用该 Hub 的 Node 配置。Multi-Hub registry 的每项 `pqtls_config` 指向对应 private 配置；Hub ID、Node ID 和逻辑 origin 必须匹配该 Hub context，不通过全局 transport/token 替换实现。
- Node 仍只出站连接，SSE 只传提示，密文和 durable claim/reconciliation 走原 Router/Relay/Store；Control 不解释或转发 peer 正文。
- 关闭顺序经修复：`serveManagedProductHTTP` 等待两 HTTP 入口 drain、Close 和 Serve goroutine join，再同步、限时关闭 Control/Store；listener 初始化错误也关闭 Control。实际 TCP 测试验证 signal 后在途 handler 仍可读 Store、响应完成后 Store 才关闭，不把并发关闭误称为 graceful drain。

## 私有审批与 CURRENT Store 关系

[private config](../cicada-go/internal/nodetransport/config.go) version 为 `1`。配置及 TLS private key 必须是无 symlink 的 regular file，权限不向 group/other 开放；相对证书路径相对配置文件。JSON 拒绝未知字段、尾随值、空/错误 pin、重复 Node/pin、跨 Hub 和缺失的权威坐标。最多 64 个 Node，单 Node 当前仅一个批准的 TLS pin。

Hub peer approval 包含 `identity(kind, hub_id, node_id, dns_name, tls_epoch)`、`pin_kind`、`pin_sha256`、`owner_id`、`owner_key_id`、`binding_id`、`binding_version`、`credential_version`。pin 类型仅 `certificate-sha256` 或 `spki-sha256`。明确 CA、SAN 与 pin 不使用 OS roots、TOFU 或 hybrid/classical profile 降级；TLS private key 必须独立生成，不能导出或复用 Node/Owner/Endpoint 的 E2EE key。

**operator private approval 是此次有界证书配置的信任输入，不是产品自动 enrollment、CSR 签发、rotation、独立证书撤销或 monotonic TLS epoch 数据库。** TLS pin 选定连接身份，再与 Store CURRENT 权威相交，不能用 pin 代替 Owner 同意。

每个已入网 HTTP 请求先检查实际 PQ state 的 TLS 1.3、MLKEM768、ML-DSA-65、TLS_AES_256_GCM_SHA384、ALPN http/1.1、CA verify/SAN 成功，再由 [Fabric transport authority](../cicada-go/internal/fabric/node_transport.go) 从真实 credential 导出 Node：

| credential | Node 来源 | 后续关系 |
| --- | --- | --- |
| CicadaNode | 当前 digest-backed Owner-bound credential | 与 active Owner binding 同 Node/Hub/Owner/key、ID/version、credential version 对照 |
| CicadaSession | 通过既有 Group Guard 的 SessionBinding | 校验实际 binding ID/epoch，读取其 Node，不采信请求自填 Node/sender |
| Cicada-Network-Session | 通过既有 Network Guard 的 access session | 校验实际 access ID/epoch，读取其 Node，不把 Network grants 当 Group/native authority |

[CurrentNodeTransportBinding](../cicada-go/internal/store/node_transport.go) 每次查询 active Node credential、精确 digest/version 的 active Owner binding、当前 Hub、active human Owner 和 active Owner approval key。Guard 逐请求比较批准的 Store 元数据、verified peer 与实际证书/SPKI hash；原业务 Guard/transaction 仍继续运行。不同 Node 证书不能借另一个 Node、Group Session 或 Network Session 的 token。

`identity.tls_epoch` 映射到旧 transport API 的 `pqtls.Identity.BindingEpoch`，只表示 operator 批准的 TLS 连接身份。它不等于 Store Owner binding version、credential version、Node-Control key epoch/version、native SessionBinding epoch 或 Network access epoch。测试使用 TLS epoch 17/29 与独立业务版本及 renewed access epoch，证明没有因名字相近而混用。

strict SSE 有一秒的独立 CURRENT transport-policy 重验，并保留既有 credential/keepalive 重验。撤销后旧 stream 结束、重新请求被拒；不宣称离线分区中瞬时全局撤权。Owner key、Owner binding/credential 更换后需重新检查、批准当前配置；旧配置不会自动跟随扩权。

**有效期限制：** OpenSSL 在 handshake 检查证书有效期。本次 State 没有证书 NotAfter 字段；已建立连接上的独立证书过期、CRL/OCSP 与自动关闭尚未实现/验收。TLS epoch/pin 的 CURRENT 配置在进程启动时固定；替换 private approval 需受控重启，不能将文件 rollback 说成数据库 fencing。Store Owner/key/credential revocation 的逐请求/stream 重验已测试，但不扩大成全部证书生命周期保证。

## application_origin 与已有状态

Node 配置的 `origin` 必须是明确的 PQ HTTPS origin。可选 `application_origin` 保留已有 Node-Control、MCP 和 Network state 所绑定的逻辑 Hub origin；未设置时二者相同。public application origin 需 HTTPS；仅显式隔离 loopback fixture 可保留原 HTTP 逻辑 origin。

每次请求先检查精确逻辑 origin、无 userinfo/fragment、Host 一致；只有 shared enrolled-path classifier 选中的请求才 clone URL/Host 到已批准的 PQ 目的地址。Client/bootstrap/Manager 不 remap，redirect 拒绝。这个选择发生在拨号前，不是 PQ 失败后的标准 TLS/HTTP fallback；PQ 错误直接返回。bootstrap frontdoor 的普通 transport 不被称为 pure PQ TLS。

示意配置，值与证书均须为独立批准材料，不能直接初始化部署：

```json
{
  "version": 1,
  "role": "node",
  "origin": "https://node-transport.example.invalid:9443",
  "application_origin": "https://hub.example.invalid",
  "certificate_file": "node-tls-chain.pem",
  "private_key_file": "node-tls-private.pem",
  "trust_file": "tls-ca.pem",
  "identity": {
    "kind": "node", "hub_id": "SYNTHETIC-HUB-ONLY",
    "node_id": "SYNTHETIC-NODE-ONLY", "tls_epoch": 17,
    "dns_name": "node.synthetic.invalid"
  },
  "peers": [{
    "identity": {"kind": "hub", "hub_id": "SYNTHETIC-HUB-ONLY", "dns_name": "hub.synthetic.invalid"},
    "pin_kind": "certificate-sha256",
    "pin_sha256": "REPLACE_WITH_EXPLICITLY_APPROVED_64_LOWERCASE_HEX"
  }]
}
```

示例 pin 故意不合法，不能被误当作可用 deployment fixture。运行时 Node 的 Hub context 仍绑定原逻辑 origin；不编辑 state.HubOrigin、不重置 counters、不重建应用密钥来迁就新端口。

## 验收范围与终端结果

全部运行使用本机一次性 Docker，pinned `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`、UID 1000、`--network none`、offline module cache；source 只读。现有常驻 Hub/Android 容器不作 fixture。启用 gate 复用已接受的 OpenSSL 3.5.9 runtime/Apache license，未 rebuild/install，原树挂 `/repo`、本树挂 `/src`。

| gate | 顶层 PASS | subtests PASS | SKIP | FAIL | process exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| 关闭顺序修复前：default 五包完整标准 | 783 | 398 | 11 | 0 | 0 |
| 最终修复源码：default cmd 完整标准 | 284 | 104 | 7 | 0 | 0 |
| 最终修复源码：default unavailable/lifecycle race | 4 | 0 | 0 | 0 | 0 |
| 最终修复源码：enabled 产品/Guard/lifecycle 标准 | 12 | 48 | 0 | 0 | 0 |
| 最终修复源码：enabled 产品/Guard/lifecycle race | 12 | 48 | 0 | 0 | 0 |
| 同源未变的 pqtls module：完整 race | 23 | 36 | 0 | 0 | 0 |
| default/enabled vet 与 CLI build | — | — | — | 0 | 各 0 |
| Client contract check / Python contract tests | — / 8 | — | 0 | 0 | 各 0 |

五包范围为 `./cmd/cicada ./internal/server ./internal/fabric ./internal/store ./internal/nodetransport`，不是全仓 Go。11 个环境 gate skip 包括 native Runtime/Android、既有独立 Docker interop fixture；它们不是 PASS，不与这里新跑的产品 Docker gate混同。最终 cmd 7 skip 是 native/Client 原生演示条件未提供。

真实边界证据包括：

- Fabric-only Hub 没有构造 Control；真实 pure PQ HTTPS Router/Relay 处理密文 Ask、重复提交的幂等、目标 Node 离线后的 durable claim，绑定实际目标与原 native ID。Hub SQLite/WAL 不含测试的 private plaintext marker。没有 fake echo handler 代替业务。
- 独立 relay-only Node Agent 子进程执行实际 flag、私有 state/lock、授权探测、heartbeat、reconciliation，exit 0；观察 HTTP pool 连接复用、出站 SSE 断开重连与 Store 撤销后的拒绝。没有调用 native 模型或把 claim 记为 consumption。
- 独立 managed Node Agent 子进程及实际加密 Node-Control RPC，exit 0；TLS 启用前 Node-Control state/key 文件逐字节不变；之后保留原 HubOrigin、原应用 identity，正常推进原 sequence/replay state。Owner/Node pairing 使用现有真实 cryptographic proof 和 Owner-granted device 权威的合成 fixture；不是 Android UI enrollment 验收。Control 对象未 Start planner/scheduler，队列中没有 Worker job/provider/model。
- 借其他 Node bearer/Session/Network credential、旧 TLS epoch/证书、错误 pin/SAN/CA/origin、classical Go TLS、plain HTTP 均拒绝；profile/peer/origin mismatch 不能降级后发送 Node HTTP authentication。此处 HTTP 观测不夸大成每一种情况下 TLS client certificate 从未发送。
- 严格普通前门拒绝 enrolled peer，同时 Client v1.6.1 capabilities/frontdoor 与 bootstrap 路径保留。default 不可用 build 明确报 `ErrUnavailable`：Hub 不初始化 identity/state，Node 不发请求/auth header。
- 所有 product Serve/Node worker 和子进程有终端/清理等待；最后没有 `synthetic-*` 私有 TLS fixture 目录或本任务 Docker 容器残留。子进程 stdout 仅保留 hash/长度与退出结果，不保留真实凭据正文。

## 可复现命令

在一次性 pinned Go 容器中：source 挂 `/src:ro`、原 OpenSSL worktree 挂 `/repo:ro`、本机私有 evidence 挂 `/evidence`，module cache `/home/zyf/CICADA/.cicada-data/m1-gomodcache` 挂 `/modcache:ro`，build cache `/home/zyf/.cache/go-build` 挂 `/gocache`。设置 `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMODCACHE=/modcache GOCACHE=/gocache`，working directory `/src/cicada-go`，UID `1000:1000`，network none。

```bash
# default：两类生命周期/不可用负例；完整 cmd
go test -race -count=1 -json -timeout=3m -run '^(TestProductHTTP.*|TestProductNodePQUnavailable.*)$' ./cmd/cicada
go test -count=1 -json -timeout=5m ./cmd/cicada

# enabled：只复用 runtime，不运行 build-pqtls-runtime.sh
source /repo/.cicada-data/pqtls-openssl-accepted-build/cgo-runtime.env
export PQTLS_TEST_ARTIFACT_DIR=/evidence CGO_ENABLED=1
pattern='^(TestProductHTTP.*|TestProductNodePQ.*|TestNodeCertificateCannotBorrowOtherNodeAndCurrentAuthorityFencesReuse|TestStrictNodeTransportKeepsClientBootstrapAndBlocksOrdinaryPeerRoutes|TestNetworkSessionTransportDerivesNodeAcrossIndependentAccessEpochs|TestPrivateNodeTransport.*|TestNodeTransportOriginRejectsDowngradeAndCredentials|TestApplicationOriginSelectionDoesNotChangePeerAuthority)$'
go test -tags cicada_pqtls -count=1 -p=2 -json -timeout=4m -run "$pattern" ./cmd/cicada ./internal/server ./internal/nodetransport
go test -race -tags cicada_pqtls -count=1 -p=2 -json -timeout=4m -run "$pattern" ./cmd/cicada ./internal/server ./internal/nodetransport
go test -race -tags cicada_pqtls -count=1 -json -timeout=3m ./internal/pqtls
go vet -tags cicada_pqtls ./cmd/cicada ./internal/server ./internal/fabric ./internal/store ./internal/nodetransport ./internal/pqtls
go build -trimpath -tags cicada_pqtls -o /evidence/cicada-pqtls ./cmd/cicada
```

仓库根目录另运行 `python3 scripts/client-contract.py check` 与 `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_client_contract.py`。每条命令以真实 process terminal exit 加 JSON 结果计数为证据，不只看测试 body PASS。二进制为 validation artifact，没有 clean release/image 或 sole-HEAD attribution。

## 失败记录与未完成范围

失败均保留，不合并成最终 PASS：首次 snapshot client 迁移有返回值编译错误；首次 Ask claim fixture 漏 `consumer_id` 返回 500；Network invitation fixture 少于 32 字符被既有 Guard 拒绝；一次恢复 shared client signature 前的 MCP 编译失败；过宽 regex 选入其他 Client tests 导致三分钟超时；同次 default 全 race 在编译失败后终止，exit 137；managed RPC fixture 的 status DTO 少字段被 strict decoder 拒绝；启用 vet 指出测试重连 CancelFunc 重赋值，改为独立 context/cancel/done 并重新验证。关闭顺序由只读 reviewer 找出并修复，最终 lifecycle gates 单独记录。旧失败、旧源码 fingerprint 和旧 package 测试数量不重标。

自动 Owner-approved TLS issuance/rotation/revocation、TLS epoch 持久单调与恢复对账、已建立连接独立证书有效期检查、arm64 pure PQ、Android/browser TLS、真实 native/model consumption、双物理 Node、互隔离多容器网络/public HTTPS 均没有新增验收。底层 pure PQ 实现目前仅 Linux amd64/CGo/`cicada_pqtls`；其他 build 不可用且 fail closed。

后续生命周期的固定顺序：

1. 保留现有 Node credential、Owner approval key、Node-Control、Endpoint E2EE identity 与全部 replay/writer 状态，盘点 bootstrap、current Owner binding/credential、key epoch 和恢复水位。
2. Node 在本地 private state 独立生成 TLS key/CSR；CSR 的 TLS proof-of-possession 与现有已批准 Node-Control identity 对 Hub/Node/binding/公钥摘要的证明分开，不把 E2EE key 转成 TLS key。
3. 先定义 authoritative contract、限制与检查，再设计对应 Owner-approved encrypted Client 操作；现有 Owner device/grant、candidate digest/CAS 与 Node proof 是可复用的身份原语。本 patch 未新增 Client operation，不能将 private pin 文件算作 Owner UI approval。
4. Hub 在 CURRENT Owner/Node binding、credential、Owner key、candidate version 的同一事务内保存独立、monotonic TLS epoch 与 scoped cert/pin grant、失效时间/状态和审计；只收窄原权限。
5. listener/client 从该 authority 获取 active certificate profile；先验证 Hub 再发 Node auth，逐请求与长连接重验 certificate epoch/expiry/Owner authority，撤销或替换旧连接时 fail closed；不靠普通前门兜底。
6. rotation/cutover 明确新旧 epoch 顺序、有限过渡、失败重试和重连；恢复需包含独立 TLS grants/keys 与版本水位，不能通过 restore/配置 rollback 重新启用旧批准。
7. 单独运行失联、活跃 SSE/keepalive 到期/撤销、旧与新 cert/key竞争、恢复 fencing、arm64、Client/native 与公网 HTTPS 验收，分别记录；完成后再更新架构实施证据与发布来源。
