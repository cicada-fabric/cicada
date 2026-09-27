# v2 原生 MCP 验收记录

2026-09-23，已通过 **旧架构 G1 的同机双容器原生验收**：真实模型经 MCP Join/Ask/Reply，双方原生 ID 不变，A 保留原上下文并收到 B 的结果。旧架构 MA→MB→B1 的 G2 也已通过，但它不是根目录 v2.1 要求的直接授权连线。此前失败保留在下文；这些结果不能推广为双物理机、无人值守 Adopt、同 Node 零 Hub Relay、Hub-blind PQ E2EE 或新版 G1–G5 全部完成。

下列 `scripts/native-group-demo.py` 命令是当时的实测记录；脚本依赖现已退役的服务器明文 Node token 下发入口，已从当前可执行脚本中删除。它们不能作为现版本的复验命令；要复验须先用 owner 确认的 Node 设备码流程重建演示夹具。历史证据和会话 ID 保留在本记录。

## v2.1 同一原生 Thread 加入两个 Group 的真实闭环

2026-09-23，Docker 中两个隔离的 Codex HOME/Workspace/Node 状态（同一物理主机），官方 shell 安装的 `codex-cli 0.155.1`、`gpt-5.5`。实际运行命令退出码 **0**：

```bash
python3 scripts/native-group-demo.py --multi-group \
  --resume-setup /tmp/cicada-native-multigroup-evidence \
  --binary /tmp/cicada-native-multigroup-build/cicada \
  --api-env-file /gpu1-share/data/cicada/secrets/cicada.env \
  --image cicada-codex:updated
```

首次运行因 MCP 持久 outbox 遗漏 `Cicada-Group-Scope`，服务端正确返回 404；首次运行没有被接受的 Ask。修复后用 `--resume-setup` 保留同一原生 Session 与 Endpoint，复用已有两个 Group 再跑。二进制 SHA-256：`4a2f2e846202548b7a1857d816e5d2eef8e535b41cdcf601db6f098d5fbac627`；受限证据在 `/tmp/cicada-native-multigroup-evidence/evidence.json`、原生 JSONL 与 SQLite。

| 对象 | 身份/状态 |
|---|---|
| A | Native Session `01a0cc5d-6614-70c3-82d9-622b7534ecad`；Endpoint `ep_614bd8e4205e737d` |
| B | Native Session `01a0cc5d-b3d4-7741-a2b7-79ace17ad18c`；Endpoint `ep_2d83b20b1e470374` |
| Group | 第一组 `grp_bb447a815d565179`；第二组 `grp_95ac3bc94f38ce2b`；A/B 各有两条 active Endpoint Membership |
| Request | `rq_bd04e11c80b44980`；状态 `REPLIED`；`sender_group_id` 和 `receiver_group_id` 均为第二组 |
| MCP | A/B 模型各自调用 `cicada_join` 加入两组；B 先 `cicada_use_group` 选回第一组；A `cicada_find`/`cicada_ask`；B 原线程唤醒后 `cicada_use_group` 选第二组并 `cicada_receive`/`cicada_reply`。 |
| 连续性 | 两端 context→join→第二组 join→ask/reply→continue 的 `thread.started` 均等于各自原 Session ID；A 的继续回合同时给出原私有标记 `ALPHA-7421`、B 的 `83.7` 和 `SAMPLE-BETA`。 |
| 投递 | 两条 Relay 消息均有 `RELAY_ACCEPTED`、`NODE_RECEIVED`、`RUNTIME_INJECTED`、`CONSUMPTION_UNCONFIRMED` 回执；没有伪称可验证模型消费 ACK。 |
| Control | 建组和 Principal 授权后关闭完整服务；协作期间只运行 `serve --fabric-only`，管理 `/v1/goals` 返回 503，没有 Control 业务实例。 |

该测试证明选定第二组的原生 MCP Ask/Reply、Node 投递、精确 Session 恢复和 Control 业务隔离；不证明双物理机、同 Node 零 Hub Relay、授权跨 Group 直达、无人值守前台安全或 Hub-blind PQ E2EE。队列使用官方 Codex queue 与受控安全点的显式 resume。

## 后续真实通过记录

实际命令（退出码 0）：

```bash
python3 scripts/native-group-demo.py \
  --binary /tmp/cicada-native-build-next/cicada \
  --api-env-file /gpu1-share/data/cicada/secrets/cicada.env \
  --trace-tools
```

本次证据目录 `/tmp/cicada-native-mcp-7iicrguf`，包含受限的 `evidence.json`、
`verification.json`、原生 JSONL 和仅含工具名称/类型的 trace。
二进制 SHA-256：`138b3fd3150ffc03ca5270f9e66cbec841742b2980dbfad47d88a5564f2965bf`。
这对应本批次配额/outbox 修改前的已编译快照；后续 Go 修改有独立测试记录。

| 观察 | 原生/持久证据 |
|---|---|
| A | Session `01a0c984-26a2-7d72-9e69-d430b01d00c3`；Endpoint `ep_0c39a68ac103d137` |
| B | Session `01a0c984-5039-7911-96bd-60c4902755f3`；Endpoint `ep_af7d820560560364` |
| Group | `grp_cef3aca8cd8b3a62` |
| Request | `rq_874bd0118f6ee40a`；消息 `msg_3d0a4e51783aab8b` |
| Reply | `msg_dae808e61ed3dea5`；请求状态 `REPLIED` |
| 模型调用 | A/B 各自 `cicada_join`/`cicada_whoami`；A `find`/`ask`；B `reply`。驱动未提交 peer Ask/Reply。 |
| 连续性 | context、join、ask/reply、continue 的 `thread.started` ID 分别相同；A 返回原始 `ALPHA-7421` 和 B 的 `83.7 GFLOPS`、`SAMPLE-BETA`。 |
| 回执 | 两条消息均有 `RELAY_ACCEPTED → NODE_RECEIVED → RUNTIME_INJECTED → CONSUMPTION_UNCONFIRMED`。正文结果可被观察到不代表 Runtime 提供了通用消费 ACK。 |
| Control | 拓扑准备后管理进程停止，实际仅运行 `serve --fabric-only`；管理接口 503，未构造 Control 业务对象。 |

实际暴露配置为 `[mcp_servers.cicada] omit_tools_from = ["deferred"]`，
只作用于隔离演示容器。本次没有替换模型目录，仍是 `gpt-5.5`。
模型曾尝试重复/错误方向回复，服务拒绝且数据库只保存一条有效回复。
A 最后通过已注入的 reply 继续原上下文；其随后 MCP 查询失败暴露了
“任意 403 清除有效 session”问题。因此本次通过不证明错误操作后的 MCP 可用性。
该问题列入后续修复和回归，不从原始证据中隐藏。

## 旧 MA→MB G2 的真实模型证据（历史路径）

同一物理主机上的隔离逻辑 Node、`serve --fabric-only` 和真实 Codex/MCP 完成 A1→MA→MB→B1→MA→A1；五个原生 Session 的前后 ID 保持不变，未 Join 的 U 没有 Endpoint。受限证据为 `/tmp/cicada-native-mcp-7iicrguf/g2-1790127100096979128/evidence-resume-1790128951106967458.json`。本节只用于说明现有能力与保留数据的必要性，不计入新版跨 Group 直达的退出条件。

| 参与者 | 原生 Session ID | Endpoint ID |
|---|---|---|
| MA | `01a0cbe3-d2fb-75d1-a432-815a4c63a77e` | `ep_207804b897539dd7` |
| B1 | `01a0cbe4-089e-7722-b7d3-e8a6940468fb` | `ep_d492167a55a009c6` |
| MB | `01a0cbe4-6882-7352-ac3a-d14b31c7ed70` | `ep_cb58ba54e95e3682` |
| U | `01a0cbe4-77e3-7f52-afe7-187ef7aaca1d` | 无 |

原请求 `rq_0267d5bc98f827cb`、B 组内请求 `rq_3562e229506e4645` 与旧代表请求 `frequest_72bc94d10c765e25` 各自关联；管理 API 在 Fabric-only 进程返回 503，未构造 Control 业务对象。A1 的身份与 G1 记录相同。该演示使用旧强制代表转发，**不能**证明新版 CommunicationLink、Monitor 可选、跨用户单 Hub、组内广播或 Hub 失明；新路径须重跑原生验证。

## 工具暴露诊断

失败请求实际只包含 `tool_search`，没有直接声明 Cicada 工具。官方本地源码
`core/src/mcp_tool_exposure.rs` 和 `core/src/tools/spec_plan.rs` 表明：支持搜索的
模型默认把 MCP 工具延迟加载。`tools/list` 返回 21 个工具不能证明模型已经看到它们。
Codex 的 `omit_tools_from = ["deferred"]` 会让这一服务器的工具直接暴露；
源配置定义在 `config/src/mcp_types.rs`，矩阵测试在 `core/tests/suite/code_mode.rs`。
先前模型目录 override 只用于诊断，已由更小的服务器配置替代。

Trace 转发不改请求/响应正文，不保存 header、prompt、参数、工具结果或错误正文；
`scripts/test_native_tool_trace.py` 验证记录白名单不保留这些内容。

## 早期失败记录

## 环境与命令

- Codex：官方 shell 安装的 `codex-cli 0.155.1`，Docker 镜像 `cicada-codex:dev`。
- 模型：用户指定的 `gpt-5.5`；provider upstream 为 `https://basil.xin/v1`。
- 同一物理主机，两个独立 Codex HOME、Workspace 和 Node 状态目录；非双物理机。
- 已有受限 runtime env 文件只交给模型容器，未写入仓库或打印。
- MCP 配置与 Tool 预授权仅位于演示容器；没有修改用户全局 CLI 配置。

构建和运行方式：

```bash
cd cicada-go
go build -o /tmp/cicada-v2 ./cmd/cicada
cd ..
python3 scripts/native-group-demo.py \
  --binary /tmp/cicada-v2 \
  --api-env-file /path/to/protected-runtime.env
```

本机实际构建在 Docker Go 1.22 中完成，二进制为
`/tmp/cicada-native-build-next/cicada`；其 SHA-256 为
`ab4365d58c2a890eaac9e524836202e3f760004bba8aaf3f1f35910db3e6bc75`。
实际 env 文件是既有 `/gpu1-share/data/cicada/secrets/cicada.env`。
再次诊断时使用 `--resume-setup /tmp/cicada-native-mcp-tcig81fh` 保留同一原生会话；
该选项会拒绝重跑已经有 accepted Ask 的演示，避免静默重放业务请求。

## 已观察到的事实

| 项目 | 实际结果 |
|---|---|
| A 原生 Session | `01a0c95f-1f59-7433-a4e8-ad2d1b125bf7` |
| B 原生 Session | `01a0c95f-479f-7bf2-9e6d-a8597cf1c2f2` |
| Group | `grp_64542f45dfe6c5d2` |
| A Endpoint | `ep_99af368deb9776f2` |
| B Endpoint | 未创建 |
| A 实际 MCP 调用 | 曾成功调用 `cicada_join`、`cicada_whoami`；原生 JSONL 有完成事件 |
| 后续恢复 | 模型没有稳定发出 Join；出现“client bridge 未声明工具”的答复，并调用资源列表而非 Cicada Join |
| 独立协议检查 | 相同容器环境手动初始化 MCP、读取 `tools/list` 成功，返回 21 个工具；这只证明协议暴露，不证明模型执行 |
| Ask 数量 | 数据库 `relay_v2_requests` 为 0 |
| Ask/Reply 自主闭环 | 未通过，没有 request/reply ID，也没有脚本代替模型回复 |
| Control 业务 | 拓扑准备后停止管理进程，启动 `serve --fabric-only`；健康响应 `cicada-fabric`，管理 API 返回 503 |
| 进程与凭据清理 | 测试服务器与模型容器已结束；临时 manager/Node/session 明文凭据已删除；用户已有 API env 文件保留 |

第一轮另一个临时目录中的 Join 被 Codex 非交互审批策略拒绝。依据用户对本次
演示的授权，在隔离配置中限制 `enabled_tools` 为八个通信工具并预授权后，A 才真实
调用成功。随后测试了 Codex 已存在的 per-server 非前缀工具兼容选项，仍未完成
闭环。原生 ID 均来自真实 `thread.started`，没有编造或用新会话替代恢复成功。

## 证据边界与下一步

运行脚本的这几次退出码为 1。失败摘要和脱敏身份记录位于上述临时目录的
`evidence.json`、`previous-evidence-*.json`；原始日志受目录权限保护，仅含测试上下文。
后续必须检查实际发送给 provider 的工具声明与恢复时的工具加载，采集时只记录
工具名/类型，禁止保存认证 header、API key 或完整用户上下文。现有证据不足以把
原因确定归于 provider、模型或 Cicada 的适配器。

脚本只使用原生 `queue` 和受控安全点的 `exec resume`，不注入 tmux/Enter。
即使未来 G1 通过，也不能据此宣称已验证无人值守唤醒、并发前台输入保护、
真实 Monitor 跨组推理或双物理机网络。这些路径继续单独验收。
