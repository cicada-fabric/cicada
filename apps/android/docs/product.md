# CICADA Android Client：产品与交互

状态：手机 Client 的 Android 产品需求与当前实现边界；未来支持 iOS 与原生鸿蒙，技术边界见 [stack-decision.md](stack-decision.md)。核心目标架构仍以 `../../CICADA/CICADA.md` 为准。**当前已接真实开发 Hub 的 Client-Control v1 加密会话和部分管理 API。** 未登录不显示开发 fixture；没有服务端确认的管理动作不得显示成功。

## 第一版的五件事

1. **随手看状态。** 首页展示需要用户注意的 Goal、审批与异常；可按 Node 查看在线新鲜度、Worker 的运行/等待/结束状态、Goal 的 running/paused/finished/failed 状态，以及 Group 的任务和可选 Monitor。Node 在线不代表 Worker 正在运行；Worker 退出不代表 Goal 验收完成。每项状态显示来源和观察时间，未知保持未知。
2. **快速说给 Control。** 首页底部固定一个显眼、单手可触达的语音按钮和文字入口。用户主动开始/停止录音；端侧模型把语音转成可编辑文本，用户检查后才提交。无模型时仍可打字，并可进入模型管理。第一版不做后台常听或自动发送原始音频。
3. **可选安装多个本地模型。** 用户自己选择下载、安装、切换和删除语音转文字模型，看到语言、能力、下载大小、来源和许可；应用私有目录分别保存模型并校验下载完整性。允许 GB 级端侧模型，未来可扩展文字、图像或其他能力，但每种能力须有实际平台推理适配和验收，不能把任意 Hugging Face 仓库当成可直接运行。模型在第一版没有管理权限，也不直接决定 Goal/审批。若以后启用联网转写，必须另行告知音频将交给谁并由用户选择；当前阶段不启用。
4. **手机控制 Hub 面板。** 手机上的管理面板是 Hub 权威状态的移动操作界面。用户可浏览 Node/Worker/Goal/Group/审批，并按加密会话能力调用现有 `topology.*`、`nodes.*` 和 `approvals.*`。选 Node/Workspace/Agent 的自然语言需求交给 `intent.submit` 后由 Control 决定；手机离线时显示空状态或上次观察时间，不把本地拖动当成授权。
5. **与他人的 Thread 对接。** 用户可发起限定目标、方向、动作、数据范围、有效期和共同 Hub 的连接请求；对方用户独立批准相同范围后才生效。Contact、Group 父子关系、Monitor 建议和画布连线都不自动提供授权。

## Control 请求与结果

Android App 发给 Control 的是用户确认过的请求，不是直接给 Worker 的指令。Control 可能直接查询获授权 Worker，也可能向 Group 的 Monitor 请求汇总；具体路径由 Control/Guard 和可用能力决定，Monitor 是可选的。Control 可选择 Node、Workspace、Agent 创建或推进 Goal，也可要求澄清或用户批准。App 显示请求已持久接受、处理进度、结果及证据来源；`HTTP 200/202` 不等于 Worker 已执行或 Goal 已完成。

## 状态和导航

- **概览**：正在运行的 Goal、需处理事项、最近有证据的结果、离线或状态过期提示；它不是按日期筛选的页面。
- **节点**：每个已授权 Node 的连接新鲜度、所在 Worker 与 Endpoint，按需查看详情。
- **工作**：Goal → Worker/Group → Task/结果的层级视图，区分暂停、完成、失败、等待和未知。
- **管理**：Hub 面板的手机布局，Group/Thread/角色/连线分类型展示；跨用户对接有独立审阅页。
- **设置**：Hub/设备身份与加密状态、端侧语音模型、隐私和存储。

管理动作预览必须说清影响对象和范围。成功以 Hub 返回的加密业务结果及新版本为准；`409`、撤权、断网时刷新权威状态并解释失败。大图按需加载，手机屏幕优先列表与详情，不强迫用户在小屏上操作复杂全图。`status_events=false` 时没有完整实时推送；`status.changes` 只是部分增量，仍定期读取完整快照。`external_thread_links=false` 时不显示跨用户 Thread 消息入口。

## 手机 ↔ Hub 安全边界

手机与 Hub 上受授权的 Control 服务之间的业务 RPC 采用 Client-Control v1：ML-KEM-768、ML-DSA-65、HKDF-SHA256 和 AES-256-GCM。Android 独立固定 Hub ID/完整公钥，Owner 另行签发设备 Grant，手机私钥由 Android Keystore 包裹，精确密文包与序号持久保存后发送；真实 Android 模拟器与 Docker Hub 的互操作记录见 [测试记录](client-hub-interop-results.md)。发布版仅接受 HTTPS；本地 debug HTTP 仅限模拟器到回环映射，业务正文仍由应用层保护。NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) 定义 ML-KEM、[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) 定义 ML-DSA；采用标准原语仍需审阅完整协议。Android 私钥不进入模型、日志或 Hub 页面。

这里的受授权 Control 是用户请求的**明文业务终点**，可以读取用户交给它的指令；这与普通 peer 消息要求 Hub 盲转发的目标不同。App 不使用旧 `/v1` 管理 bearer；端侧转写本身也不构成手机到 Hub 的加密证明。

普通 peer 的明文当前仍可能经过旧 Fabric/Contact 路径；App 不宣称盲 Hub 已上线，不拉取完整敏感 Thread 历史。设备绑定不自动 Join Thread，也不授予 peer 正文解密权。
