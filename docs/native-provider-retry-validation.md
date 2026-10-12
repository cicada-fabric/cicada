# Native Provider 重试边界验证（CLI 0.162.1）

当前已验证官方 CLI 0.162.1 的有限 HTTP 重试与断流拒绝边界；这不是 Native Board、MCP、Owner 授权或 auto-review 整体验收。真实 Board A7 为 FAIL_OR_UNKNOWN：第一个 Journal 返回 SENT，但整段工具序列未完成；A8 仅修测试 prompt 解包后实际 PASS_NATIVE_BOARD_SCOPED，不能由本页合成测试推导 PASS。产品 Hub/Node 工件仍归 clean `d86e214829db16fc7fe1df34ab6dcfca6df23b93`；A7 测试准备时文档 HEAD 为 `9898f0ea75c0ab163bc5d7f1e623a4d30193027b`，辅助授权 helper 仍归 c292，不互相替代。Client、合同、wire、catalog、软件版本均未改。

## 确切版本与官方来源

[官方 rust-v0.162.1 release](https://github.com/openai/codex/releases/tag/rust-v0.162.1) 的 annotated tag object 为 `7a078f6bb4ce0dc2a81408b334ce52979d92c603`，指向 `092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`。实装 CLI binary 为 294,415,048 bytes，SHA-256 `628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1`，含该完整 commit stamp；官方安装记录和 package manifest 的版本为 0.162.1。此 tag 未签名，不声称构建可重复或签名认证。旧 untagged 临时 checkout 不作为本版本语义证据。

限定官方源码缓存位于 `../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/official-cli01621-retry-source/`；`SOURCE-MANIFEST.NONAUTH.json` SHA-256 `4cb7ca226505fe2292103f7276576f6500edd0d24b33004f43944ff7e04e0418` 固定各文件 raw-byte SHA、官方 commit URL 与本地路径。

## 三层边界

[HTTP retry.rs](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/codex-client/src/retry.rs#L93) 的 `0..=max_attempts` 表示 request retry 1 是初始请求加一次重试。[provider 配置](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/model-provider-info/src/lib.rs#L454) 对 5xx 和部分 transport 错误采用这一层预算；不是仅针对 500。prepared request 在同一 HTTP 调用内复用；此层不重新注入 Native turn 或调用 MCP。

[HTTP transport](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/http-client/src/transport.rs#L215) 先检查非 2xx，再向上暴露成功的 SSE stream。因此已收到 HTTP 500 与 HTTP 200 后消费事件再断流是不同失败。后者由 [responses_retry.rs](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/core/src/responses_retry.rs#L96) 的 stream/connection/fallback 分支处理。该版本 [feature 定义](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/features/src/lib.rs#L1381) 的 `unbounded_connection_retries` 默认 true，可以越过 stream retry 0；WebSocket fallback 也有独立路径。新的限定测试显式设 `features.unbounded_connection_retries=false`、custom provider `supports_websockets=false`、`stream_max_retries=0`，不能仅凭总 POST cap 称所有 SDK 重试已关闭。

Guardian review 的 [固定上限](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/ext/guardian-reviewer/src/lib.rs#L40) 为最多三次 review attempt 与 90 秒 review budget；[reviewer retry](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/ext/guardian-reviewer/src/retry.rs) 包括部分 transport/stream/解析恢复。[review session](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/core/src/guardian/review_session.rs) 能看到 provider clone，但最终 ReviewerConfig 完整继承仍 UNKNOWN。本次合成 gate 没有工具审批，不能证明全部 Guardian 行为。A7 的 32 总实际 POST cap 仍覆盖 main、Guardian、HTTP retry、partial 和 failure；不关闭审批以省请求。

exec JSON 的 [Error 映射](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/exec/src/event_processor_with_jsonl_output.rs#L447) 不保留 `will_retry`。现有业务 parser 继续拒绝 fatal、未知 error 和断流；没有加入“忽略所有 error”的豁免。

## 实际零外部 Runtime 验证

固定 Runtime image `sha256:7d5c8ef4288772fae4f43eafef1cfdd5c0644d2fe29b9b94d1c025d6837ae45e`，network none、UID 1000、readonly root、cap-drop ALL、no-new-privileges、1 CPU、768 MiB、pids 96，仅私有 controller/home 挂载。provider 在同容器 loopback 合成 Responses SSE；没有外部连接、真实模型凭据、Node、Hub、MCP、真实模型或 auto-review 接受。内部 180 秒工作加 60 秒清理；Root 接受外层 TERM 245 秒加 KILL 5 秒，总硬上限 250 秒。

| 场景 | 实际 HTTP / CLI | 严格结果 |
| --- | --- | --- |
| request retry 0，500 | `[500]` / exit 1 | 唯一 failed turn，无 completed turn |
| request retry 1，500 后 200 | `[500,200]` / exit 0 | 两次 body SHA 相同；唯一 completed turn，无 error |
| 200 后完整 item 已消费再截断，stream retry 0 | `[200]` / exit 1 | 真实 `item.completed` 先被 CLI 消费；唯一 failed turn，无 completed turn，无 item 重放 |

实际 3/3 PASS，8.588124657 秒；每个场景 stdout/stderr EOF、exact CLI PG absence、provider 关闭均核验。精确 container CID/name/label 清理 CONFIRMED，六 resident canonical 指纹前后相同，source pins unchanged。此 PASS 只归合成传输范围。

实际结果：`../.cicada-data/v01-next-gates-20261011/native-direct-audit/cli01621-synthetic-retry-a1/cases-v2/cli-retry01621-20261012c/RESULT.NONAUTH.json`，SHA-256 `ca703dd530ac5cf4ff755d20ae8fa1d9ddf1e5121b5725c42a49232a0a67a868`。同批纯 QA 9/9 PASS：`cases-v2/QA.NONAUTH.json` SHA-256 `e693dba2146b135d6e25a6735ab314fdb01d2f41ee048c8e93bf61c076df45cb`；纯测试不冒充 Runtime PASS。

## 保留的启动失败与最小修正

A1 启动失败结果 SHA-256 `bbd9ebd809eacfdc43727fb60b4cdf477bc245d3e947fa3ffaf0472d0bd98c49` 原样保留。旧 host 只留 stderr hash，随后 guest-result 缺失覆盖为 FileNotFoundError，原 stderr 不能追回。独立 image import 诊断实际 Python 3.14.4、stdlib operator 未预缓存；controller 内 `operator.py` 遮蔽标准库并产生 AttributeError。

诊断结果 SHA-256 `56374fdbdaaa6910344d6222f12f4e3e345da47e683cd70d109ab1fffe770615`。新诊断 stderr 1313 bytes，仅删除唯一 39-byte `<string>` traceback frame 后，派生 1274 bytes 的 SHA-256 精确等于旧 stderr 记录 `694435241a8b13c77fd8881423302d4322857dd71380b71256f3430fcce05c21`。这是新派生证据，不伪写原输出；`cases-v2/SHADOW-DERIVATION.NONAUTH.json` SHA-256 `31444d67fe9b315b8e1a225d69999800cd8d513bba000955a61439aa150aecac`。

后继 host 更名为 `synthetic_retry_host.py`，同次 bounded stdout/stderr 以私有 0600/O_EXCL 留存，typed START_NONZERO 在 guest-result 读取之前记录。guest/SSE 原字节、三场景 oracle、审批、隔离与预算不变。

## Native Board A7：保留真实失败与已发送首条

A7 对新 fresh 业务批次采用 request retry 1、stream retry 0、unbounded false、WebSocket false；原六 manual、零 automatic business turn、32 总实际 POST、900 秒工作加 60 秒清理及 exact SID/CWD、Owner consent、Board、Control 隔离 oracle 保持。没有 whole-turn 或 proxy retry，不重投旧 uncertain 操作，也不以 HTTP 重试推断 Join/candidate 未提交。

实际 A7 为 FAIL_OR_UNKNOWN / MCP_ORDER_COUNT：五个 attempted manual turn，四份已保存 completed CLI exec receipt；第五 CLI exit 在既有阶段解析失败时未留存，必须写 UNRECORDED。实际 18 POST 为 17 HTTP 200 加一个 codex-auto-review HTTP 500，随后同批已有 HTTP 200；不是再次上游失败。cleanup CONFIRMED / errors []，六 resident 不变。

严格 parser 预期 author 的 `journal_append → journal_append → discussion_topic_create → discussion_reply` 四项完成，实际只观察第一 `cicada_journal_append` completed、isError=false，业务返回 SENT / attempts=1 / retryable=false。实际 code-mode 代码照测试 prompt 读取 `first.payload.result.record.record_id`；同一次返回对象与 MCP result 精确相同，只有 content+structuredContent，没有 payload。随后发生 undefined / reading result，后三项未调用，parser 拒绝正确。这不是业务 Guard 拒绝，也不是合法 CLI event 被错误计数；首条 Journal 不能视为未执行或重投。

[A7 原始结果](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a7/board-native20261012h/RESULT.NONAUTH.json) SHA-256 `f240b0f25da3e6fcadd7dd6c5cde67147cd7a2820d2bca9b4a3e5d2b2ade901c`；[仅闭集诊断](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a7/AUTHOR-FAILURE-DIAG.NONAUTH.json) SHA-256 `43d5f0b2e2a38dd39282656da3282ac615160b53c064fbc788898d2ffc5cdee4`，保存工具名/顺序/状态、原 SID/CWD match 及源行 SHA，不公开正文或密钥。

A8 是唯一 prompt-only 修正：structuredContent 优先、text JSON fallback、同时存在须严格一致；拒绝 error/缺失/未知形状后才能读取真实 normalized.result.record、cursor、seq。严格 parse_turn、author/reader witness、Owner callback、Guard、SDK retry、隔离和预算不变。16 项 source-bound 纯 QA PASS（含用 visibly synthetic CallToolResult 执行两段实际 JavaScript prompt），不是 Native PASS。新 run board-native20261012i 使用全新 Endpoint/State/SID，不复用 A7 已 SENT Journal。A8 实际结果为 PASS_NATIVE_BOARD_SCOPED / cleanup CONFIRMED：六 manual、零 automatic business turn，六 CLI exit-0/EOF/reaped，30 总 POST（15 main/15 auto-review，29 HTTP 200、一个 main HTTP 500 后 200）。原 SID/cwd 上的规定顺序 code-mode 写/读、五条 committed record、十条 reader ciphertext、unread 5→0 完成；不是自然语言自主决策、长期历史 Thread/cold 自动唤醒、Android、物理公网或全 G1–G5 PASS。trace detail overflow 2、space-sync 119 HTTP 403 的因果 UNKNOWN 均保留，不称全路由完整/全 2xx/性能验收。

[A8 实际结果](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a8/board-native20261012i/RESULT.NONAUTH.json) SHA-256 `ced365497a7637a53e91c928e2213aaaf81036ae988c29ec6e5a774b346e4913`；具体原生工具/Owner/加密链路范围见 [Native Board 当前记录](native-board-current-validation.md)。Frozen audit 的 C292 serve-fabric-only 字符串是旧测试 label，产品归属依 d86 preflight/image/source，不伪改结果。

产品仍为 d86 Node 与 A1 Hub candidate c536 / archive 5099；不是已无 archive 的 A2 d6 镜像。helper 仍 c292 AUX。所有历史 FAIL 和原始 SHA 归属不变，文档后继 HEAD 不替代任何工件 producer。
