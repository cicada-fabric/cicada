# v2 原生 MCP 验收记录

## 2026-09-25 同 Group 三 Thread 广播：协议通过，原生闭环未通过

新增 opt-in `TestMCPSealedSameGroupBroadcastNative`，使用同一逻辑 Node 的三个
真实 Codex Thread、显式 MCP Join、发送者 `cicada_broadcast`，并要求两名接收者
分别在原 Thread 通过 `cicada_receive` 取得各自的 sealed child message 和原有
上下文。默认未设置 `CICADA_BROADCAST_NATIVE_E2E=1` 时明确 SKIP。
无模型的路径/结构化结果解析向量、`TestMCPBroadcastLocalAndRemoteSealedFullChain`
及现有 Group Broadcast/Store/Hub 定向测试通过。完整原生测试仍 **未通过**：

| 隔离尝试 | 结果 | 到达的可信阶段与失败边界 |
|---|---|---|
| 1 | exit 1，236.06 秒 | 三 Thread Join，发送者广播 MCP 调用完成且两条本地子消息持久接受；测试夹具误读 MCP outbox 路径，尚未验证 Node queue/接收。 |
| 2 | exit 1，223.89 秒 | 三 Thread Join，outbox `SENT/complete/2`，Hub 当前成员快照、两条 exact-session Node inbox 与 queue 均有证据；第一接收者原 Thread 的 `cicada_receive` 工具事件完成，但夹具错误解析 wrapper/`omitempty` 字段，未确认消息体或上下文，也未运行第二接收者和最终 Hub/Control 断言。此后无模型解析向量已修正。 |
| 3 | exit 1，187.68 秒 | 从干净 `c4eb00664a238eee8344044bfcbc1f4275c1ddb6` 冻结二进制；三条初始 native Thread/session record 成立，第一个发送者的 `cicada_join` 因 Codex 自动审批等待超过 deadline 失败，未到广播。该错误不是 HTTP 403，也没有 CICADA Guard 拒绝证据。未作第四次真实重试。 |

第三轮使用 Go 1.27.1 编译的 app/test 二进制 SHA-256 分别为
`049ec226d7b02a976b864a1964e89c522e2aa405cc7888fdd8bf63e67ac486e6` /
`8e163f32b13e63bb916468ade85cb87312dd0cf13ac7b76e2f52546e015d29e5`，
Codex CLI `0.156.1`，本地隔离镜像
`sha256:6dd50c3c2494b20853a5a8ab7c8bfe53ece3873cf5d647c903402004cc45de2f`。
三条初始 native Session 仅记录 SHA-256 短标签：发送者
`4262c2eac3bd28cf`，接收者一 `872fb86db0da34f2`，接收者二
`bcef16299093c7a8`。第三轮没有成功 Join，故不存在可报告的 Endpoint、
broadcast 或 child message ID。第一、二轮的部分阶段不能拼成一条完整 PASS；
三轮均不能证明两名接收者消费、双物理机、无人值守唤醒或用户经 Monitor 广播。
容器使用临时 `CODEX_HOME`，退出后一次性 Node/Hub/MCP 状态已删除；测试凭据
仅经隔离容器环境文件注入，不写入仓库或验收记录。

## 2026-09-25 Codex 0.157 冷 Thread 与 MCP ID 协议核验

核验使用官方 Codex CLI `0.157.0`（本机二进制 SHA-256
`138b3fd3150ffc03ca5270f9e66cbec841742b2980dbfad47d88a5564f2965bf`）。在隔离
`CODEX_HOME` 中运行 `codex app-server generate-ts --experimental --out <temp>`，生成的
0.157.0 协议类型显示：`thread/queue/add` 有 `clientUserMessageId`；队列项包含自己的
`id`、`input` 和 `clientUserMessageId`；`thread/queue/start` 接受 `threadId` 与可选
`queuedSubmissionId`，返回 `{turn}`；`thread/resume` 必须带 `threadId`，响应含 Thread
及配置/历史页字段。resume 文档注明按 ID 从盘加载；若该 ID 已运行则重新加入运行中的
Thread。`thread/loaded/list` 只列当前载入的 Thread IDs；Thread 状态为 `notLoaded`、
`idle`、`systemError` 或带 flags 的 `active`，没有 Node owner、前台租约或 generation
字段。上述 API 没有 expected-owner/expected-generation CAS，读取 `notLoaded` 与后续
resume 之间也没有原子保护；resume 的响应不提供队列消费或模型完成回执，调用超时/进程
退出后的执行结果仍可能未知。可选 `queuedSubmissionId` 是精确队列项定位字段，不是
`queue/add` 的去重保证；隔离协议探针曾观察到相同 `clientUserMessageId` 再次 add 会产生
重复项。

此前一次 0.157.0 隔离只读冷队列观察得到 `thread/read=status.notLoaded`、精确 Thread 的
`thread/queue/list` 返回一个与持久提交见证唯一匹配的条目；该观察未调用 resume 或
queue/start。Codex 维护者在 [issue #44491](https://github.com/openai/codex/issues/44491)
中解释，CLI queue 对未加载 Thread 只持久排队而不自动恢复；issue 的实测版本为 0.154，
因此仅作为与本地 0.157 协议观察一致的上游背景，不替代本版本 wake 验收。

MCP ID 探针也在临时 `CODEX_HOME` 中运行同一 `codex app-server --listen stdio://`，配置
只指向受控 fake stdio MCP 子进程；完成 app-server `initialize`、一次
`thread/start(ephemeral=true)` 与 `mcpServerStatus/list`，没有凭据、模型调用或 queue 操作。
初始化、ephemeral Thread 和 MCP status 请求均成功，app-server/探针退出码均为 `0`；两个
fake MCP 子进程实例的环境都没有 `CODEX_THREAD_ID`/`CODEX_SESSION_ID`，两次 MCP
`initialize` 参数键都只有 `capabilities`、`clientInfo`、`protocolVersion`，未暴露
native ID。隔离目录在结束后删除。该结果只证明 Codex 0.157 app-server 的这条启动方式；
没有测试 TUI、IDE 或未来 Runtime，不能据此推断所有客户端。当前官方
[Codex MCP 配置文档](https://developers.openai.com/codex/mcp)只记载 stdio 子进程的静态
`env` 和从 local/remote executor 转发的 `env_vars`，没有文档化的 Thread-derived 来源。
仓库 `detectCodexMCPJoinSession` 仅接受 `CODEX_THREAD_ID`/`CODEX_SESSION_ID`，原生测试
由驱动显式设置，因此本探针不能证明普通全局 MCP 安装具备自动 Join 的 ID 来源。

生产自动 cold resume 暂判 **UNSUPPORTED**：唯一队列见证与 `notLoaded` 快照仍无法证明
执行 resume 时 Thread 未被前台所有者重新载入；官方接口没有 owner/generation 条件，且
resume 的崩溃/超时窗口没有可查询的执行回执。现有 Node queue 成功只表示
`CODEX_QUEUE_ACCEPTED`，不表示 Thread 已 wake 或模型已消费。原生模型测试使用受控安全点
显式绑定 Session 后执行 `codex exec resume`；那不是 Node 无人值守恢复，也不能覆盖前台
竞争。生产路径继续 fail closed，不会因 queue 成功就自行 resume、queue/start 或重投。

## 2026-09-25 跨 owner CommunicationLink 原生验收：PASS

`TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative` 在一次性
`cicada-codex:updated` Docker 容器中以 Codex CLI `0.156.1`、`gpt-5.6-luna`
和 Go `1.27.1` 通过，退出码 `0`，耗时 `228.02` 秒。两个不同 owner 的真实
Codex Thread 在各自原 Thread 完成 MCP Join 与 Endpoint 公钥候选发布；A 调用
密封 CommunicationLink Ask，B 在原 Thread 收到并调用 Reply，A 恢复原 Thread
后同时保留了原上下文与 B 的回复。测试检查了 Hub HTTP 边界和 SQLite 中没有
测试正文，并断言 Control business call 计数为 `0`，未访问
`/v2/fabric/send`、`/v2/fabric/ask`、`/v2/fabric/reply`、
`/v2/fabric/receive` 或 `/v2/control/`；必经的 Link authorization、sealed
ASK、sealed REPLY 和 sealed claim 路径断言均通过。成功日志中的合成身份为 A
owner `owner_source` / Endpoint `ep_source`、B owner `owner_target` / Endpoint
`ep_target`，request `rq_1755face8d1ac24a5f7932ae04e02d89`，reply
`msg_70f0dbdadad3a7ccc9585e25cc93db91`。两个 native Thread 仅以 SHA-256 短标签
记录：A `sha256:2c92c5c747033b13`，B `sha256:d0e77867f62c75ec`。

这次验收中发现并修正了两个测试夹具问题。其一，预设 Endpoint Membership 只给
`message.ask`，但真实 Join 后候选发布先调用 WhoAmI，需要 `directory.read`；
opt-in 合成成员现在显式具有 `directory.read`、`message.ask`、`message.reply`
和 `message.receive`。其二，旧夹具在 Join 前签署 owner key grant；真实 Join 会
轮换 SessionBinding 并重新发布候选，授权 manifest 因而必须按 Join 后的当前
binding 和候选重新生成。opt-in 路径现在保留 Link、延后两侧 synthetic owner
grant，直到双方实际 Join 和发布候选之后再签署，不修改生产 Guard。新增的
`TestSyntheticCrossOwnerLinkAuthorizationAfterJoin` 不调用模型；它通过真实 Hub
HTTP 流程完成两个 synthetic Node Join 和 Endpoint key 发布，然后验证两侧 owner
grant 绑定当前 manifest，Store 检查以及两个 Node 凭据的 HTTP authorization
bundle 均通过 `200`。这项检查是合成夹具证据，不是原生 Codex 证据。

修正前的真实 FAIL 路径诊断保留：一次尝试在两侧 Node Join 均返回 `201` 后，
`GET /v2/fabric/whoami` 返回 `403`；当时 Membership 仅含 `message.ask`。仅补足
该权限后的下一次尝试中，两侧 WhoAmI 和候选发布均返回 `200`，但 A 的
`GET /v2/relay/nodes/node_source/links/<synthetic-link>/authorization` 返回
`404`，没有进入 sealed ASK。原因为夹具已用 Join 前 manifest 记录双侧 owner
grant；当前授权 bundle 按新 SessionBinding/候选 fail closed。这两个 FAIL 均未
运行完整 Ask/Reply。相关失败 Thread 标签仅保留为散列：WhoAmI 轮 A
`sha256:daf3d2fbe5f9ca75`、B `sha256:078cfd4002f3b45e`；旧 grant 轮 A
`sha256:31bbcd22fec5538e`、B `sha256:d6ce3b72fa95d667`。

原生测试仍是 opt-in；未设置 `CICADA_CROSS_OWNER_NATIVE_E2E=1` 时明确 SKIP，
不能计通过。真实验收在容器内使用隔离 tmpfs `CODEX_HOME`，通过本机 provider
env 文件注入 API key，配置 MCP child 使用同一 `CODEX_HOME`，并用
`omit_tools_from=["deferred"]` 直接公开 Cicada 工具。Go 构建与合成 preflight
命令为：

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -v /home/zyf/go/pkg/mod:/go/pkg/mod:ro \
  -v cicada-go-buildcache:/root/.cache/go-build \
  -v /tmp/cicada-cross-owner-native-build:/out \
  -w /workspace/cicada-go -e GOPROXY=off golang:1.27.1-bookworm \
  sh -c 'gofmt -w cmd/cicada/communication_link_native_test.go cmd/cicada/machine_sealed_receive_test.go && \
    go test -count=1 -run "^TestSyntheticCrossOwnerLinkAuthorizationAfterJoin$" ./cmd/cicada && \
    go build -buildvcs=false -o /out/cicada-native ./cmd/cicada && \
    go test -c -o /out/cicada.test ./cmd/cicada'
```

原生运行在 `cicada-codex:updated` 内执行等价于以下命令的有界单次测试：

```bash
docker run --rm --network host \
  --env-file /gpu1-share/data/cicada/secrets/cicada.env \
  -e HTTPS_PROXY=http://127.0.0.1:7890 -e HTTP_PROXY=http://127.0.0.1:7890 \
  -e NO_PROXY=127.0.0.1,localhost \
  -e CODEX_HOME=/tmp/cicada-cross-owner-codex-home \
  -e CICADA_CROSS_OWNER_NATIVE_E2E=1 \
  -e CICADA_NATIVE_MODEL=gpt-5.6-luna \
  -e CICADA_CODEX_BIN=/usr/local/bin/codex \
  -e CICADA_NATIVE_CICADA_BIN=/tmp/cicada-native \
  --tmpfs /tmp/cicada-cross-owner-codex-home:rw,size=1g \
  -v "$PWD/docker/codex-config.toml:/tmp/cicada-codex-config.toml:ro" \
  -v /tmp/cicada-cross-owner-native-build/cicada-native:/tmp/cicada-native:ro \
  -v /tmp/cicada-cross-owner-native-build/cicada.test:/tmp/cicada.test:ro \
  -w /workspace/cicada-go --entrypoint /bin/sh cicada-codex:updated \
  -c 'cp /tmp/cicada-codex-config.toml "$CODEX_HOME/config.toml" && \
    /tmp/cicada.test -test.v -test.timeout=25m \
    -test.run "^TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative$"'
```

该原生运行使用的 `/tmp/cicada-cross-owner-native-build/cicada.test` SHA-256 为
`49bea5863d646fd3547b16a352ea0bbc8827075c0ee7dd80559601eab3b91829`。测试结束后，
Go 测试源只发生了上述 opt-in 注释的文字编辑；运行二进制中的测试逻辑和当前
工作树一致，但二进制不是由注释编辑后的字节级源码重新构建。没有生产二进制
或部署镜像参与该验收。

该结果证明同一物理主机上两个逻辑 Node、一个 disposable Hub 和两条真实 Codex
Thread 的跨 owner 消费闭环；不证明双物理机、公网隔离或无人值守冷 Thread 唤醒。

2026-09-24 **真实同组跨 Node 原生 ASK/REPLY PASS**：opt-in `TestMCPSealedCrossNodeGroupAskReplyNative` 在一次性 `cicada-codex:updated` Docker 容器中使用官方 shell 安装的 Codex CLI `0.156.1` 与 `gpt-5.6-luna`，退出码 0，耗时 171.22 秒。两个独立逻辑 Node 状态目录、两个真实原生 Codex Thread 和一个测试 Hub 完成显式 Join、A MCP Ask、B 原 Thread MCP Receive/Reply、A 原 Thread 收到关联回复并继续保留初始上下文。A Endpoint `ep_f217f9c04b362396` / native Session `01a0d2c8-ca08-7410-8bad-495462b7d1b1`；B Endpoint `ep_bcc822a880296304` / native Session `01a0d2c8-b243-7481-9a98-2fbde67e36ba`；请求 `rq_e77d87511d94c05784e564f1ae427894`，回复消息 `msg_c8325c7dbbc96fdd2bad1aa79e1fee2b`。测试从真实 `thread.started` 和本地 Session record 验证前后原生 ID 相同，Hub HTTP/SQLite 均不含测试正文，method/path whitelist 未见旧明文 Fabric 路由或 Control 业务调用。Control 业务对象未构造。测试驱动显式绑定 Session ID，在安全点调用官方 `codex exec resume`；这证明两个逻辑 Node 的真实模型消费，不证明无人值守唤醒、两个独立物理主机或公网网络隔离。

首次运行其实完成了原生 A→B→A，但测试白名单遗漏正常 Node `/claim` 而退出码 1；之后一次测试把合成标记误写成 private，自动审批合理地拒绝 B `cicada_reply`；另两次模型直接结束回合而未调用 Ask/Join 工具。最终测试只在确认回合完全没有 MCP 工具调用时于同一原 Thread 补一次指令，不对已尝试或不确定的操作自动重试。提供方最初对 `gpt-5.6-luna` 返回无权限 403，用户开通后最小模型探针与上述最终原生运行均通过。

## 2026-09-24 新同 Node 密文路径的验收边界

`TestMCPSealedSameNodeGroupAskReplyFullChain` 在 Docker Go 1.22 中通过：真实 Store/Fabric、一个 owner-bound Node、两条显式 Join 的 Codex 记录与当前公钥候选、MCP/Node 本地桥、持久密文 ASK/REPLY 和原生 `queue --thread` 参数均进入同一测试；Hub 请求正文没有 peer 明文，调用路径只有 Directory/Guard，没有 Hub 消息 Relay 或 Control 业务实例。该测试的 `codex` 是记录 argv 的替身，**没有真实模型消费**，原生连续性只验证了参数和持久绑定。本轮含同组跨 Node 与 inbox 增量的 Docker Go 1.22 全仓 `go test -count=1 ./...`、`go vet ./...` 与新增收件路径的聚焦 `-race` 均已通过；真实原生验收另见下文。

旧的独立 provider 探针在 `codex-cli 0.155.1` 下使用 `gpt-5.5` 成功返回 `READY`，产生真实新 Session `01a0d16e-181f-7b11-951b-e1d1b17071fa`。2026-09-24 用官方 shell 安装器更新一次性 `cicada-codex:updated` 镜像后，当前镜像报告 `codex-cli 0.156.1`，没有使用 npm 或更改宿主机全局 Codex 配置。该旧探针只确认 CLI/model 可用，没有 Join、ASK/REPLY 或唤醒任何旧 Session，**不计入**新 G1 原生验收。

另在一次性 `cicada-codex:updated` 容器中，使用 `gpt-5.5` 的真实 CLI 独立验证了队列与恢复：`codex exec --json` 创建原生 Session `01a0d18e-9760-7363-85a7-59c6d7ce9b23`，`codex queue --thread <原 ID> --message <测试标记>` 退出 0；随后 `codex exec --skip-git-repo-check --json resume -m gpt-5.5 <原 ID> <安全点提示>` 退出 0，恢复事件中的 `thread.started` 等于原 ID，模型答复同时包含初始上下文标记和队列标记。两次 `exec` 的标准输入均显式指向 `/dev/null`，避免 CLI 等待额外输入。该独立探针证明所用 CLI 具备精确队列/原会话恢复能力，**尚未**调用 Cicada Join、Node Guard、密文账本或 MCP Ask/Reply，不能代替新 G1 全链验收。

新增 `TestMCPSealedSameNodeGroupAskReplyNative` 作为 opt-in 真 Codex 测试，默认跳过；它会在一次性容器和隔离 Cicada StateDir 中建立两条真实 Thread，以受控安全点推进 MCP Join/Ask、Node 本机密文交接、原生 queue 和 Reply。初期提供方曾对 `codex-auto-review` 返回 403 和价格未配置；用户修正后，`codex-cli 0.156.1` + `gpt-5.5` 的正常自动审批已允许真正执行 MCP 工具。未绕过审批。

2026-09-24 一次运行实际走到：A Endpoint `ep_914eaa6833bf042f`、B Endpoint `ep_389cf082e288534b`；请求 `rq_08f770058ed55c46687fd789bc8b4fdf`，原生 B Session `01a0d21d-2ae1-7923-8d0b-2e5ac03cf594`，原生 A Session `01a0d21d-7efc-79c0-a65c-7461045bb792`。A 的 ASK 持久密封后由 Node 向 B 的原 Session queue 注入；B 在原 Session 的恢复回合调用 `cicada_reply`，回复消息 `msg_c7ce43362fe006cfb9a59a76ac7004d5` 被密封并向 A 原 Session queue 注入；A 恢复回合中的回答同时含原上下文标记与 B 私有回复标记。两条消息的记录达到 `CONSUMPTION_UNCONFIRMED`；B 的实际回复与 A 的回答是本次应用层观察，不能推广成 Runtime 通用消费 ACK。测试最终因 Hub 路径白名单出现 1 条未识别请求而退出码 1；白名单只报数量，尚不能证明这条请求是只读 Fabric 查询还是错误的 Relay/Control 调用。测试在结论上仍为 **未通过**。

随后增加了仅记录 method/path 的失败诊断并重跑两次，但提供方分别在创建 A 和 B 的初始原生 Thread 时超时（均未进入 Cicada 路径），尚未获得额外路径。新的测试源码把每回合等待由 150 秒提高至 210 秒，待跨 Node 切片完成后重编再跑。测试驱动从真实 `thread.started` 事件取原生 ID、核对 CODEX_HOME Session 记录，再为这个一次性 MCP 进程显式设置 `CODEX_THREAD_ID`；不能据此宣称普通全局 MCP 安装能自动发现 Thread ID。`codex queue --thread` 后的恢复由受控安全点的驱动调用 `codex exec resume`；本测试也不证明无人值守唤醒或真实双物理机。Docker Go 测试中的 fake queue 全链继续独立验证协议与 Guard。

路径诊断最终把此前唯一的额外 Hub 请求确认成 `POST /v2/fabric/receive`：sealed-capable Thread 的 MCP `cicada_receive` 曾落到 legacy Hub receive。该调用不是同 Node 的密文 ASK/REPLY 路径。实现已改为经受信 Node 本机桥读取同 Node inbox 与跨 Node crypto inbox 的 Group/native-session scoped 注入记录，使用只读 SQLite handles；没有 sealed capability 的旧 Session 才保留 legacy receive。Node inbox 增量 Group 索引不会猜测旧行属于哪个 Group，缺少可信映射的历史行保持不可见。Node Agent 已补齐显式 Link 收件 normal/recovery `Save` 的可信 GroupID，并覆盖最终注入前精确 attempt recheck；Node inbox 与跨 Node fake full-chain 定向测试通过。未映射的历史行仍只保留数据、不猜测 Group。

当前同 Group 跨 Node fake full-chain `TestMCPSealedSameGroupCrossNodeAskReplyFullChain` 使用两个隔离逻辑 Node 和 fake Codex queue 通过；最终授权复查返回 404 时不会 queue。它证明 Hub/Node route、密文、相关回复和 fail-closed 注入边界，不证明物理网络或真实跨 Node 模型消费。

2026-09-24 修复后的真实原生运行 **PASS**：`TestMCPSealedSameNodeGroupAskReplyNative` 在一次性 `cicada-codex:updated` 容器中使用 `codex-cli 0.156.1` 与 `gpt-5.5`，耗时 738.65 秒、进程退出码 0。request `rq_da0e6864af4065f3e9e2393f0987f1c8`；A Endpoint `ep_1c13164d3eab3789` / native Session `01a0d256-fad3-7470-934b-736b5efe2619`；B Endpoint `ep_efe659c1f38a1d0c` / native Session `01a0d256-b314-7f92-ae09-4f102cf43dae`。A 在其原 Thread Ask；B 的原生 Session 收到投递并实际调用 MCP `cicada_reply`；A 的原生 Session 收到相关回复，最终模型恢复后断言保留原上下文。Hub path whitelist 通过，只记录 method/path 元数据，未出现 `/v2/fabric/receive`。此验收是同一物理主机、一个 Node、两个真实 Codex Thread；使用测试驱动显式绑定 Session ID 和受控 `codex exec resume`，不证明全局 MCP 自动发现、无人值守唤醒、真实跨 Node 消费或双物理机链路。

复验命令在已构建 `cicada.test` 的 Docker 容器内运行：

```bash
docker run --rm --network host \
  --env-file /gpu1-share/data/cicada/secrets/cicada.env \
  -e HTTPS_PROXY=http://127.0.0.1:7890 \
  -e HTTP_PROXY=http://127.0.0.1:7890 \
  -e CICADA_NATIVE_E2E=1 \
  -e CICADA_NATIVE_MODEL=gpt-5.5 \
  -e CICADA_NATIVE_CICADA_BIN=/tmp/cicada-current \
  -v /tmp/cicada-native-build/cicada:/tmp/cicada-current:ro \
  -v /tmp/cicada-native-build/cicada.test:/tmp/cicada.test:ro \
  cicada-codex:updated /tmp/cicada.test -test.v -test.timeout=25m \
  -test.run '^TestMCPSealedSameNodeGroupAskReplyNative$'
```

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
