# CICADA Android Client 开发约束

用户最新任务：**只在本仓库开发 Android 手机 Client；保留简洁 UI 与多模型本地 STT，并接入真实 Hub 的 Client-Control v1 后量子加密 `/v2/client/rpc`。** 设备须有独立可信 Hub 公钥固定、OwnerDeviceGrant 和加密 `session.capabilities` 授权；状态、Intent 与现有管理操作使用真实服务端契约，不走旧 `/v1` bearer。重放、撤权、断线恢复与互操作必须由真实 Docker Hub 验证。以后支持 iOS，并迁移到原生鸿蒙应用；当前不要用 Ark 开发。主工程选 TypeScript + React Native，新增 Android 安全与设备适配用 Kotlin。鸿蒙界面需要 ArkUI/ArkTS 重写，不得宣称 TSX 可直接编译成原生鸿蒙应用。模型由用户选择下载、安装、切换和删除；当前只启用经过真实适配和测试的转写，用户也可直接文字输入。模型调研见 `docs/model-selection.md`。

开始前阅读 `README.md`、`docs/`、相邻核心仓库 `../CICADA/CICADA.md` 与 `../CICADA/docs/architecture-v2-status.md`，并核对真实服务端路由与测试。核心规格优先于旧交接内容，用户最新指令优先于两者。核心仓库不在相邻目录时先定位版本。

## 本地阶段的目标与持续验收要求

- 建可复现 React Native 工程并生成 Android 包；保留 iOS 工程入口但不虚报 iOS 验证。实现概览、Node/Worker/Goal/Group 状态、Control 输入、手机管理面板与设置；跨用户 Thread 对接只有经双方授权且后端路由可用时才能作为真实能力显示。未连接时不展示开发 fixture，也不能显示真正发送、批准、完成或连线成功。
- 首页语音入口便捷、清晰且只在用户操作后录音。转写文字可编辑，文字输入始终可用。模型中心支持多个可实际运行的模型分别下载、安装、切换、删除，说明来源、许可、大小，下载后校验完整性并存 App 私有目录。只有权重格式、推理运行时和手机资源测试均成立时才开放模型；Hugging Face 候选不得冒充已支持。录音、转写结果和模型不进日志/分析/不必要缓存；第一阶段不上传音频。
- 真实运行小模型对语音样本转写，记录模型/样本/设备或宿主环境、命令、退出码、输出、耗时及局限。宿主机测试不能冒充 Android 真机测试；缺少真机就明确记 `NOT_RUN`。
- 在 Docker 中开发、构建和测试。先核实 `docker info` 的数据根目录；本环境预期为 `/gpu1-share/data/docker-root`。项目构建缓存、测试下载与临时容器挂载优先放 `/gpu1-share/data/cicada-client`，不改动 `/gpu1-share/data/cicada` 的现有数据或用户全局 Docker 配置。

## 当前 Hub 对接与继续开发的边界

- 顶层部署角色是 Node（原生 Thread）、Hub（Control/Directory/Relay/权威状态）、Client（用户入口）。Thread 是原生 Session；Endpoint 是显式 Join 后的稳定身份，可参加多个 Group；Group 嵌套不继承权限。Worker/Monitor 是按范围授予的角色，Monitor 可选，不能替 User 审批。
- 手机是 User 入口；Control 通常在 Hub。App 发出用户确认的文字请求，由 Control 决定查询 Worker、通过授权 Monitor 汇总 Group，或选择 Node/Workspace/Agent 创建和启动 Goal。App 不直连原生 Thread 注入输入。
- 手机上的管理面板是 Hub 权威面板的移动操作面；所有真实写入必须走服务端 Guard、预期版本和幂等处理。409/撤权/断网时恢复权威状态。跨用户 Thread 连线须双方独立同意精确范围，Monitor 不能代 User 批准。
- 组内广播必须固定单一 Group 与成员快照，保留逐收件人状态；父子 Group 和同 Thread 所在其他 Group 不自动扩散。设备码绑定由 Node 显示短时码，Client 登录并核对 Node 指纹后批准；绑定不授予 peer 解密权。未有真实后端契约时相关按钮关闭。
- **手机 ↔ Hub/Control 的用户内容、状态及管理请求必须经验证的 NIST 后量子端到端加密与相互认证，无明文/传统 TLS 降级。** 明文终点是手机和受授权 Control；这不意味着普通 peer 正文已对 Hub 失明。当前已完成开发 Hub 的独立 Android 互操作；公网 TLS、真机密钥边界和完整生命周期仍未验收，不能把开发验证写成生产验收。
- 核心当前 Fabric 与旧 Contact API 有 Hub/Control 可见明文路径；不得把敏感 peer 正文放进无端点密钥的 Hub 页面、缓存或日志，也不宣称盲 Hub 已上线。`/v2/fabric/*` 和 Node Relay 凭据只属于其可信调用方，Android UI 不得冒充。

## 工程与交付

- 所有提交的 author 和 committer 必须直接使用服务器 `git config --global user.name` 与 `user.email`。提交前读取并核对有效身份；不得以仓库配置、`git -c`、环境变量、`--author` 或共同作者 trailer 添加或覆盖身份。当前全局配置为 `DaiVernon <205618093@qq.com>`；今后以服务器实际全局配置为准。提交和推送前都须检查历史身份，发现不一致立即修正，未经用户明确授权不改写已发布历史。
- 以完整、可验收的关键节点提交；同一节点的实现、修复、测试和文档合并为一个清晰提交，不为每次小改动单独提交。推送前可整理尚未发布的提交，保留验收来源与本地恢复引用；未经明确授权不得改写已发布历史。只推送用户指定的分支，不顺带推送归档引用或合并其他分支。
- 持续维护真实接口清单、阶段计划和未对接项，见 `docs/backend-contract.md` 与 `docs/development-plan.md`。不发明生产 URL/JSON 字段；开发 fixture 只供 UI 测试，不能进入真实运行路径。后端能力标志和加密 `session.capabilities` 均须允许，才显示实际操作。
- 依赖用锁文件固定；页面、状态模型和请求语义与 Android SDK 隔离，设备能力使用窄适配接口。模型选型记录来源和许可。大列表按需加载，显示状态时间与来源；HTTP 接受、Node 接收、Runtime 注入、模型消费未知、业务结果各自区分。
- 不在仓库、APK、测试快照或持久缓存保存真实 API key、长期 bearer、私钥、完整敏感消息或模型测试的个人录音。
- 保留用户未提交修改；不自动推送、发布、部署生产、轮换密钥或修改全局 CLI/Docker 配置。交付列出已完成界面、实际模型测试、真实 Hub API、构建/测试命令与退出码、未对接能力及安全边界。
