# Owner 账户、可信设备与首次接入设计

产品要求：**用户已确定**普通 Owner 账户、内置本地密钥生成/导入及简单安全的
设备接入；此前“Owner 只能依赖外部工具生成密钥”的普通体验决策已被修正。
实现状态：**PROPOSED / NOT_IMPLEMENTED**。本文记录 2026-10-13 的流程与
下一实现边界，不修改 [已采纳规格](../CICADA.md)、软件版本、已发布 Client
合同或现有部署。下一检查点推荐采用密钥认证的单 Owner 人类账户，不增加
密码/SSO 服务；这是实施方案，不把新账号或 API 写成已经可用。

产品应让用户部署 Hub 后创建一个属于自己的 Owner 账户，选择 Android 或
可信 Windows 本地 CICADA 组件作为首批准设备，自动生成或选择导入本地密钥，
在认证并完成初始信任建立后登记公钥；Node 同样内置本地密钥生成及安全登记。
用户通过“账户与设备”管理已连接电脑、手机
和 Node，查看待确认请求、权限、最近活动、撤销和恢复。正常流程不要求安装
OpenSSL、手写公钥 JSON、查询 Owner ID、复制 Base64 Grant 或执行签名命令。

[现有 OpenSSL 工具](owner-windows-openssl.md)是可选高级/开发兼容路径。它已经
取得的 Linux、生产 handler、原镜像 TCP 与交叉构建证据保留原来源；这些结果
不证明本文的账户产品、Windows 安全存储或普通手机接入已经实现。

## 1. 已有基础与缺口

本次只读审查的 Core 起点为 `dev` / `1b9d5856d5b2d147e71fb3292c4b27345a9a688c`。
规划不能给该来源或旧候选新增运行 PASS。

| 范围 | 当前事实 | 本次拟议增量 |
|---|---|---|
| Owner | [本地登记公钥](../cicada-go/internal/store/owner_approval_keys_v2.go)与独立 Owner 签名已有实现 | 人类账户创建、登录、账号到 Owner 的持久映射与安全首 claim，**NOT_IMPLEMENTED** |
| Control 与人类 | [初始化](../cicada-go/internal/control/control.go)以 Control identity ID 建 human；[RPC](../cicada-go/internal/server/client_rpc_v2.go)用相等判断 manager | 明确的 Hub manager/account 关联，逐步解除密码学 ID 与人类账户耦合，**NOT_IMPLEMENTED** |
| Android 设备 | [createDeviceIdentity](../../CICADA_CLIENT/android/app/src/main/java/ai/cicada/client/hub/ClientHubSession.kt)本地生成 PQ identity，使用 Android Keystore AES 包裹私钥；当前 UI 要求外部 Grant | 登录、扫码/短码、自动传递公开登记材料与本地确认的普通入口，**NOT_IMPLEMENTED**；已有设备 keygen 不重复建设 |
| Client enrollment | [OwnerDeviceGrant 验证和设备登记](../cicada-go/internal/server/client_v2.go)、精确重试与加密 session 已有实现 | 把协议材料隐藏于受审查的接入流程；账号登录不取代 Owner 授权 |
| Node | [设备码](../cicada-go/internal/control/node_device_bindings.go)、本地凭据/密钥及加密 `nodes.preview/confirm` 已有实现 | 账户设备页、可信公开 pins 的传递、引导与恢复 UI，**NOT_IMPLEMENTED** |
| Windows | OpenSSL public SPKI 适配与独立签名兼容工具已有实现 | CICADA 内置生成/私钥导入、本地持久保护及签名交互，**NOT_IMPLEMENTED**；原生 Windows/ACL 验收 **NOT_RUN** |

Android PQ 私钥使用软件密码库，并由 Keystore 密钥包裹；不能宣称 PQ 私钥本身
已经在硬件安全模块中不可导出。Node 设备码存在也不表示已有浏览器批准页面。
现有 `/client/device` 是 Client 导航入口。

## 2. 账户和授权对象

| 对象 | 用户理解 | 权威及密钥边界 |
|---|---|---|
| 人类 Owner 账户 | “我的 CICADA 账户” | Hub 管理稳定账户记录，关联一个 human Owner Principal；不是 Control key ID、邮箱、显示名或 Network |
| 账号认证会话 | “我已登录” | 已受信设备在本地解锁后签挑战，用于确认账户及允许的 metadata/接入操作；不自动授予签名权或加密管理权 |
| Owner 批准签名者 | “可以批准新设备/具体授权的可信设备” | 对应显式注册的 Owner approval key，私钥由用户本地持有；签名资格、范围与生命周期独立管理 |
| Client 设备 | “这台电脑/手机已连接” | 持有自己的 Client identity 与 session/replay 状态；由精确 OwnerDeviceGrant 登记，普通 Client 权限不自动成为批准签名者 |
| Node | “这台机器可以运行我的工作” | 本地生成并持有自己的凭据、Node-Control/Endpoint 私钥与状态；Owner 确认准确候选，不上传私钥 |
| Thread Join | “让这个原生会话参与协作” | 仍由本地真实 session owner 显式完成；设备登记、Node 批准和 Network 成员关系均不代替 Join |

首版目标是单 Hub 的一个部署者 Owner 账户，不开放任意公网注册。存量已登记
external humans、设备和双 Owner 连线仍保留；“单 Owner 首次设置”不能成为删除
或提升既有其他 Owner 权限的理由。其他用户账户、组织账号、一般 RBAC 和多
Hub 账户同步不放入本检查点。

Owner 私钥、Client 私钥、Node 私钥、Endpoint 私钥和 Hub 管理通道私钥分别
承担既有职责。Hub 可保存账户记录、公钥、受权绑定及必要审计；不能替 Owner
制造批准签名，也不能取得普通 peer 解密材料。密码重置或网站管理员权限不
等于 Owner 签名授权。公开 capability 只描述可用性，当前加密 session
capabilities、Owner proof 和服务端 Guard 共同裁决具体操作。

默认账号稳定 ID 与密码学 key ID 分离，可有用户名/显示名作为便于识别的
标签。一个账户可关联多个独立、可撤销的设备 key，更换设备不更换人类账户。
本检查点不新增服务端密码、SSO 或邮件找回服务；若以后需要这些登录方式，
另行设计密码 KDF、认证会话和恢复政策，也不能取代签名接入或 Owner 恢复。

## 3. 首次设置闭环

1. 部署完成后，部署者通过独立受信的安装/本地控制渠道取得首设置入口。
   该入口绑定稳定 Hub ID、准确的 Client-Control 与 Node-Control public pins，
   带短期、单次且仅服务首次设置的 claim 授权。服务端只保存该授权的校验摘要。
   实际发放、过期和尝试上限须在实现合同中固定。公开访问页面不能抢占 Owner。
2. 用户打开经过验证的 HTTPS Hub 或受信 Android Client，选择“创建 Owner
   账户”，输入可选显示名/用户名标签，验证独立初始化码。账户暂处于
   `SETUP_PENDING`，未提交准确 key/device proofs 前不能获得 Owner 权限。
   创建与 claim 支持中断恢复并拒绝重复首 Owner，首个公开公钥上传者不获权。
3. 用户选择“用手机作为首批准设备”或“用这台可信电脑”，由独立安装的
   Android Client 或可信 Windows 本地 CICADA 组件生成 Owner/Client 密钥，
   也可选择受支持的本地密钥导入。检查算法、密钥匹配及本地存储保护；Hub
   只接收公开候选和证明。Owner signer 的手机存储/签名集成仍须实现，现有
   Android Client keygen 不表示其已能生成 Owner grant。导入格式/Windows
   安全存储方案须单独审定，当前 JSON reader 不是 PEM/PKCS#8 产品导入器。
4. 本地组件显示 Hub、账户、首设备名称及“可批准新设备”的效果，验证受信
   pins、claim audience 和当前挑战，再用本地 Owner key 签首设备的准确
   OwnerDeviceGrant。候选 Client 必须用现有 Seal/Open 完成反向随机加密
   挑战并签署回应，证明签名与 KEM 两类私钥持有；绑定同一 Hub/account/
   device/request/purpose/expiry，挑战不可重放，未完成不得激活。现有签名
   proof 中绑定 KEM 公钥不表示其已经证明 KEM 私钥 possession。
5. Hub 在事务边界校验部署者 claim、可信 Owner/account 关联、公开候选、
   签名和设备证明，原子消费 claim 并记录首批准 key、设备、账户关联和审计。
   原子激活账户。完成响应丢失后查询/精确恢复原操作，不能再造另一个 Owner
   或覆盖根密钥。
6. 界面显示“Owner 设置完成”“当前批准设备”“添加手机/Node”“设置恢复”。
   本地组件提供受保护备份与第二批准设备的明确引导；其具体恢复协议尚须
   完成实现设计和验收。设置成功不使任何原生 Thread 自动 Join。

账号认证与部署者首 claim 共同建立人类关联，但都不代替本地签名。Hub 返回
的公钥候选只是 discovery；不能将“获取 `/v2/client/identity` 后点击固定”
当成独立信任检查。二维码/短链接只能携带严格限定的公开身份和临时挑战，
不得含私钥、账号长期凭据、Node bearer 或可无限复用的批准授权。
初始化秘密、恢复秘密及签名器材料不得进入普通日志、URL query/referrer 或
诊断导出；初始化授权仅在受控本地显示/受保护渠道中短期传递，不放入公网
可发现链接。它与用于查找候选的设备码、公开核对码分别处理。

若采用浏览器作为签名界面，必须先审查 ML-DSA 支持、私钥持久保护、页面来源
及本地授权确认。Hub 下发的 JavaScript 属于受信代码边界，可能接触浏览器内
密钥，不能宣传为隔离于服务器软件的原生签名器。默认 Web 面板负责管理与
流程协调；在独立可信资产来源及加密本地持久保护通过审查前，不把它作为高
信任首 Owner signer。Android 与 Windows 本地组件均可作为首批准设备。
网页到本地组件的 origin、消息范围与确认交互须显式设计，不能
默认开放任意网页请求签名。此组件复用本仓 Go 核心，不另建协调项目。
Web 确认页须校验可信顶层 origin、显式用户手势、frame protection 与 CSRF；
本地签名组件只接受限定来源和操作。扫描二维码或打开链接仅导航/预览，不能
自动完成批准。具体 HTTP/bridge 防护进入同一合同和拒绝测试。

## 4. 添加手机与批准设备

新手机输入/扫描受信 Hub 入口，创建或读取已有的本地设备 identity，并选择
“连接到我的账户”。身份候选和设备名由 App 提交；服务器绑定账户 scope，
不要求用户手填 Owner ID。账号登录可开始待确认请求，不使手机立即获得
加密管理 session。

已有受信设备登录时在本地解锁，以当前 key 签服务端挑战；验证 audience、
Hub/account/device、操作目的、随机 nonce、期限、一次性挑战和撤销状态后取得
相应会话；登录签名与 enrollment 签名必须有独立 purpose，不能互换。本地解锁
PIN/生物识别不是 Hub 登录密码。未登记的设备提示“由批准设备确认”，普通
Client 需要签署 Owner proof 时显示 `NEEDS_OWNER_SIGNER`，不能伪造自动 Grant。

在已受信的批准设备上，用户打开“待确认设备”，核对 Hub、账户、手机名、
有效期和两端显示的核对码，查看将授予的具体能力，点击“批准”。本地签名器
核验当前公开 manifest 后签现有准确 OwnerDeviceGrant，App/Hub 自动传递
公开 proof；手机独立验证受信 Owner key、Hub pin 和自身公开 identity，
提交登记并建立加密 session。后台传递不能省掉独立信任建立或本地批准。
双端核对码必须绑定当前候选公开 identity/manifest 摘要、Hub 和账户，不能
仅显示可查找请求的随机 user code。新设备同样完成上述两类私钥挑战证明。

批准结果必须区别“Client 设备已登记”与“可以批准其他设备”。当前
`CLIENT_CONTROL` 目的不含 signer delegation，不能静默升级其含义。若允许
手机成为批准设备，要新增显式 signer 授权状态及版本化合同，并由当前有效
Owner 批准 signer 精确授权，设备登记可采用独立 `DEVICE_ENROLL` scope；
不能据此批准 Link、TLS 或其他操作。授权限定 Hub/account、期限与撤销关系，
最多一层委托，受委托 signer 不得再委托 signer、轮换 Root 或取得 Root 权限。
委托使用新的独立 scope 状态、有效期和可撤销 lineage，不能简单登记为现有
`owner_approval_keys` 的 unrestricted Root；通用 Link/TLS/grant 路径必须拒绝
越 scope 委托 key。没有该能力时界面显示普通管理设备，转到现有
批准设备完成签名；Node 不自动成为批准设备，模型也不持有 Owner 私钥。

## 5. 添加 Node

Node 引导只需要 Hub 入口和可选机器显示名。本地组件读取现有状态或首次生成
自己的凭据与 Node-Control identity，输出待确认短码/二维码。现有 Node
请求/本地 proof 路径继续复用，不复制手机或 Owner 密钥。
现有 Node proof 只证明 signing possession 并绑定两个公开 key；下一检查点
的完整 Node possession 还须加入反向 KEM 加密挑战与签名回应，不能将其
写为已有能力或仅凭 key 字段认为完成证明。

Owner 在已授权的 Client 打开“添加 Node”，输入/扫描短码，使用已有
`nodes.preview` 核对准确 Node、Hub、公开 identity、期限和预期用途，再
独立确认。设备码是查找特定候选的入口，既不是登录凭据，也不是 Owner 签名。
节点密钥配对、严格 PQ TLS leaf/安装批准等现有独立 proof 必须保留本地签署，
界面隐藏其编码但展示真实影响，不能因点击“连接”便同时批准全部 transport。

结果区分“Owner 绑定有效”“Node-Control 配对有效”“PQ TLS 已安装/待处理”
和“原生 Thread 已 Join”。Node 仍只主动出站。连接成功后再由用户本地选择
准确 Thread、Network/Group 并显式 Join；不扫描后自动开放全部历史会话。
当前 Node 管理依赖批准 Client 的有效状态；撤销该手机可能阻断它批准的
Node 管理能力。设备页须显示这一关联并预览影响；有效的剩余 Owner 设备可
经明确 reapproval/rebind 恢复关联，不能静默解除 fence。

## 6. 普通界面的最少信息

| 界面 | 默认输入/展示 | 用户操作 |
|---|---|---|
| 首设置 | Hub 名称、初始化码、可选账号标签/设备名、首批准设备与生成/导入选择 | 建立 Owner、确认本地 key、保存恢复材料 |
| 登录 | 选定 Hub/账户与可信设备、本地解锁 | 签挑战登录；新设备进入扫码/短码确认 |
| 账户与设备 | 设备类型/名称、当前设备、批准资格、真实状态/新鲜度、最近活动 | 添加、重命名、查看权限、撤销 |
| 待确认 | 请求设备、Hub/账户、核对码、期限、将获权限和关联影响 | 批准、拒绝、取消 |
| Node | 短码/二维码、机器显示名、连接/配对/安装/Join 各自状态 | 预览、确认、查看待处理步骤 |
| 恢复 | 仍可使用的批准设备与受保护备份状态、受影响设备/Node | 使用备份、另机确认或开始重新建信任 |

稳定 IDs、完整公钥、fingerprints、manifest/Grant 编码、版本和日志保留在
“高级详情/诊断导出”；默认确认仍要有足够公开身份和权限摘要让人核对准确
对象。用户不需要把协议内容当作表单逐项录入。诊断不包含私钥、完整敏感
授权载荷或可复用凭据，最近活动也不能被展示为在线或任务消费证明。

## 7. 取消、过期、重试与恢复

下列状态为拟议产品状态；不能据此改写现有 Store/API 枚举。

| 情况 | 产品行为与服务端要求 |
|---|---|
| 取消/拒绝未完成请求 | 服务端使对应请求不可再消费并保留必要审计；本地保留已生成密钥供后续选择，不偷偷删除或重建 identity |
| 过期 | 信任 claim、请求和 Grant 各自检查期限；准确显示需重新开始的步骤；旧码/挑战/签名不可用于扩大期限 |
| 丢响应/断网/重启 | 持久保存原操作身份、公开 manifest、精确 proof 和状态；恢复同一操作，区分 PENDING、完成、失败、结果不明；不重新签名掩盖 uncertainty |
| 重试 | 同操作同内容返回同一记录；同身份不同内容冲突；重新开始必须显示旧操作已经过期/取消或已对账，遵循固定限流 |
| 撤销设备/批准 key | 事务检查 actor、预期版本与关联影响；拒绝新的 enrollment/签名资格及受影响 session，传播当前 revocation/epoch；不能只隐藏 UI |
| 手机丢失但仍有批准设备 | 使用另一受信 signer 撤销旧手机并批准替代手机；旧设备数据不能被承诺远程擦除；需要处理它批准的 Node 的独立关联 |
| 唯一在线批准设备丢失但有离线备份 | 默认恢复来源是用户离线保存的加密备份；在新本地设备恢复 Owner 材料，证明 possession，核验当前 Hub trust/撤销状态，按显式协议重新登记；不能直接恢复陈旧 session/counter |
| 全部 signer 和备份丢失 | 账号可恢复与密码重置不复活旧 Owner trust。受影响授权 fail closed；只有独立部署者控制渠道能按显式恢复方案重新建立新信任 epoch，并撤销/重新确认受影响设备和授权；具体协议 **NOT_IMPLEMENTED** |

恢复同一 Owner key 与重新建立 trust 是不同操作。后者不伪造旧 Grant，不
无声复活 revoked key，不重置 replay counters，不保证恢复不可用的历史
peer 密文。新 key、bilateral Link、Node-local Owner trust 和新加密材料的
重新确认须分别处理。没有可信恢复来源时显示限制，保留原数据和证据，不用
删除数据库或初始化新部署来表现为“修复”。

## 8. 保留现有安装的迁移

新增账户映射和设置状态应采用可重试、可审阅的增量迁移。现有 Hub ID、
Control/Client-Control/Node-Control identity、Owner approval keys、human
Principal、Client/Node/Endpoint IDs、现有 Grant、Link、消息、session epoch
和 replay 水位全部保留。账号是新的关联记录，不重编码已签名 claims，也不
重新生成密钥来匹配新的账号 ID。

先清点当前 Control crypto ID 对应的 manager human、已登记 Owner keys 和
其他 humans；只给已有 manager 建立准确候选关联，由部署者与现有受信 signer
在独立流程确认。无匹配、多个候选、revoked owner 或可能扩权时保持待确认，
不能挑第一行或让远程首设置占有旧部署。迁移不会把 existing external owner
自动升级为 manager，也不把旧 ownerless 业务按名字推断归属。

代码逐步从 `ownerID == Control.Identity().ID` 转为明确的当前 Hub manager
human/account 关联和对象 scope checks；同时更新初始化、能力 projection、
dispatch 与 `ValidateClientOwnerScope` 等真实写/读入口。旧稳定 Principal ID
可暂时保留历史值；它与 key ID 字符串曾经相等不继续成为授权依据。取消耦合
不能顺便开放多 manager、跨账户目录或 general RBAC。

迁移先在合成 StateDir dry-run，核对对象数量、关系、key/epoch/counter 与
旧 Client 精确恢复行为；明确备份、停 writer、恢复/向前修复边界。现有部署
只制定方案，不执行迁移、替换镜像、注册真实 key 或轮换真实身份。

## 9. 下一主要检查点的边界

下一检查点以“一个新 Hub、一个人类 Owner、一个本地批准 signer、一个合成
Client 登记、一个合成 Node 确认”的可重复闭环为目标；统一公开 setup/pairing
API 和状态机先在本仓实现，原生平台 Client 按固定合同分开实现。Core 完成后
再向独立 Android 仓库交接，分别实现普通手机体验；本文不授权 Client 编辑。

| 顺序 | 本仓模块与责任 | 退出条件 |
|---|---|---|
| A 设计固定 | `docs/owner-onboarding-design.md`、安全 ADR/迁移设计 | 固定密钥挑战认证、session/恢复政策、首 claim、公钥 possession、本地 custody、首次/后续 signer 权限及协议 byte 边界；不引入密码服务 |
| B 账户与迁移 | `internal/store`、`internal/control`、`internal/server` | account/manager mapping、一次性首 claim、共同 Guard、原子记录及存量 dry-run；移除 crypto ID 相等授权，拒绝重复 claim/guest 扩权 |
| C 本地接入 | `cmd/cicada`、`internal/e2ee`、既有 Web 面板 | 内置本地生成/受支持导入与 manifest 签名，统一首设置/设备配对 API；Web 协调及待确认/恢复交互；Windows 原生 custody 单独验收，不依赖 mandatory OpenSSL |
| D 协议与门禁 | `internal/clientcontract`、Client/OpenAPI/wire 文档、公开合成 vectors、既有 contract scripts 与 Docker gate | 实现、权威合同与检查同一有意义检查点更新；选定修订后输出精确来源协议包/Hub 工件；旧合同不回填新能力 |
| E 独立 Client 工作 | `../CICADA_CLIENT` Owner 的后续单独任务 | 导入固定 Core commit/合同/包/镜像；复用本地 keygen/Keystore 和精确 pending/recover，新增扫码/短码与本地确认 UI；Android 自己验证合同及拒绝/恢复 |

Core 的针对性确定性测试至少覆盖：两调用竞争首 claim 的单胜者、重放/过期/
错 Hub/错 account/错误公开 pin、未证明私钥、同操作不同内容、Owner key 或
设备撤销、签名资格与普通 Client 分离、账号会话不得签 Grant/扩权、跨账号
枚举/批准、限流、丢响应/重启原样恢复、旧 manager/guest 数据迁移、all-signer
loss 不绕过 proof、日志不泄密。Windows keygen/import/storage 的实际运行与
ACL/密钥保护需要原生 Windows 证据，交叉编译不能代替。

安全负例还包括登录/enrollment wrong-purpose、委托过期/撤销/递归/Root
轮换及其他 grant 越权、KEM challenge 重放/错误 recipient、外来 origin/
嵌入 frame/CSRF/无用户手势请求、二维码不自动批准，以及 sponsoring phone
撤销后的 Node 继续保持 fenced、明确受权 rebind 后才恢复。保持原有
OwnerDeviceGrant canonical bytes；新增委托 proof 另定 scope 与版本。

性能边界：密钥生成只在首次本地创建或明确导入/替换时执行，日常复用已有
密钥；这些额外挑战集中于 bootstrap、登录和批准，不对每条 peer 消息重复
keygen 或账户认证。复用既有 Go、SQLite、出站通知与服务层，不增加 SSO、
消息 broker 或常驻协调平台；仍保留既有消息加密与实时 Guard。

使用既有一次性 Docker Hub 门禁，准备隔离状态与明显合成 identities，验证
真实 HTTP/encrypted handler、原 claim/Grant 精确恢复和 Node preview/confirm，
包括 Hub 重启与撤销。不得使用 resident/shared Hub 作为 fixture。Android、
真实 native Runtime、物理手机/双机器、公网 HTTPS 与严格 PQ TLS 的结果
各自记录；本规划没有执行这些测试，均未据本文新增 PASS。

本检查点不发布、不 push、不改 main、不替换现有部署、不处理真实密钥，
不通过文档完成宣称新账号或接入产品已经可用。具体软件版本、wire version、
contract revision、Git source/dirty fingerprint 与 image digest 各自记录。
