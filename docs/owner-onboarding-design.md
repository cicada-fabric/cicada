# Owner 账户、可信设备与首次接入设计

产品要求：**用户已确定**普通 Owner 账户、内置本地密钥生成/导入及简单安全的
设备接入。**先独立部署并初始化 Linux 服务器 Hub，再让 Node/Client 以同一
扫码/配对串体验加入**；手机只承担 Client，不作为 Hub；Hub 初始化不依赖
任何已注册 Client。此前“外部工具
是普通接入前提”和“首手机参与创建 Owner”的流程均已被修正。
实现状态：**PROPOSED / NOT_IMPLEMENTED**。本文记录 2026-10-13 的流程与
下一实现边界，不修改 [已采纳规格](../CICADA.md)、软件版本、已发布 Client
合同或现有部署。已连接设备以自身私钥挑战认证；Hub 初始管理授权另来自
独立部署者控制渠道，本次不宣称新密码/SSO 或远程 admin 登录已经实现。

产品应先在 Hub 设置中建立属于用户的 Owner/admin 账户、管理入口与连接策略，
然后在面板选择“添加设备 → Client / Node”。设备扫描二维码或输入配对串，
自动在本地生成或选择导入密钥，上传公钥并按当前权限完成准确批准与连接。
用户通过“账户与设备”管理已连接电脑、手机
和 Node，查看待确认请求、权限、最近活动、撤销和恢复。正常流程不要求安装
OpenSSL、手写公钥 JSON、查询 Owner ID、复制 Base64 Grant 或执行签名命令。

[现有 OpenSSL 工具](owner-windows-openssl.md)是可选高级/开发兼容路径。它已经
取得的 Linux、生产 handler、原镜像 TCP 与交叉构建证据保留原来源；这些结果
不证明本文的账户产品、Windows 安全存储或普通手机接入已经实现。

## 1. 已有基础与缺口

初稿只读审查的 Core 起点为 `dev` / `1b9d5856d5b2d147e71fb3292c4b27345a9a688c`；
本次顺序/交互文档修正基于 `fd61459124d6944b1683033363b6be660cc2c53b`。
规划不能给该来源或旧候选新增运行 PASS。

| 范围 | 当前事实 | 本次拟议增量 |
|---|---|---|
| Owner | [本地登记公钥](../cicada-go/internal/store/owner_approval_keys_v2.go)与独立 Owner 签名已有实现 | Hub 独立账户初始化、管理入口/连接策略、Owner 映射与有限首 signer bootstrap，**NOT_IMPLEMENTED** |
| Control 与人类 | [初始化](../cicada-go/internal/control/control.go)以 Control identity ID 建 human；[RPC](../cicada-go/internal/server/client_rpc_v2.go)用相等判断 manager | 明确的 Hub manager/account 关联，逐步解除密码学 ID 与人类账户耦合，**NOT_IMPLEMENTED** |
| Android 设备 | [createDeviceIdentity](../../CICADA_CLIENT/android/app/src/main/java/ai/cicada/client/hub/ClientHubSession.kt)本地生成 PQ identity，使用 Android Keystore AES 包裹私钥；当前 UI 要求外部 Grant | 登录、扫码/短码、自动传递公开登记材料与本地确认的普通入口，**NOT_IMPLEMENTED**；已有设备 keygen 不重复建设 |
| Client enrollment | [OwnerDeviceGrant 验证和设备登记](../cicada-go/internal/server/client_v2.go)、精确重试与加密 session 已有实现 | 把协议材料隐藏于受审查的接入流程；账号登录不取代 Owner 授权 |
| Node | [设备码](../cicada-go/internal/control/node_device_bindings.go)、本地凭据/密钥及加密 `nodes.preview/confirm` 已有实现 | 与 Client 同格式的 Hub 发起配对授权、CLI 粘贴/文件接入和恢复 UI，**NOT_IMPLEMENTED** |
| Windows | OpenSSL public SPKI 适配与独立签名兼容工具已有实现 | CICADA 内置生成/私钥导入、本地持久保护及签名交互，**NOT_IMPLEMENTED**；原生 Windows/ACL 验收 **NOT_RUN** |

Android PQ 私钥使用软件密码库，并由 Keystore 密钥包裹；不能宣称 PQ 私钥本身
已经在硬件安全模块中不可导出。Node 设备码存在也不表示已有浏览器批准页面。
现有 `/client/device` 是 Client 导航入口。

## 2. 账户和授权对象

| 对象 | 用户理解 | 权威及密钥边界 |
|---|---|---|
| 人类 Owner 账户 | “我的 CICADA 账户” | Hub 管理稳定账户记录，关联一个 human Owner Principal；不是 Control key ID、邮箱、显示名或 Network |
| Hub 管理授权 | “服务器 Hub 已设置好” | 独立部署控制渠道建立已有 Owner/admin 关联与初始管理入口；不要求已连接手机，不代替批准签名者 |
| 已连接设备认证 | “我已登录” | 已绑定设备在本地解锁后签挑战，按当前角色取得会话；不能用于解释首设备存在前的 Hub admin 认证 |
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
本规划不新增服务端密码、SSO 或邮件找回服务；若需要首设备前的远程 admin 登录，
另行设计密码 KDF、认证会话和恢复政策，也不能取代签名接入或 Owner 恢复。

## 3. 先完成服务器 Hub 初始化

Hub 部署在 Linux 服务器，以 Docker 或 binary 常驻运行，先完成它自己的
初始化，再接受 Node/Client。手机只承担 Client，不作为 Hub；Hub 初始化不
依赖任何已注册 Client。Node 当前以 Linux 工作空间主机为基线；Linux/macOS/
Windows 的 CLI/本地组件与平台适配边界见[部署与界面设计](deployment-interface-design.md)。
Client 可以是 Android、Windows 本地入口或浏览器。一个物理主机可同时运行独立 Hub 与 Node 实例，分别保存
状态、密钥与权限，不因同机而共用身份或自动加入。

通过任意浏览器操作 Hub 配置不等于在该设备托管 Hub；手机浏览器也可作为
设置界面。初始化由已认证本地 CLI 或受保护 Web wizard 操作，写入服务器
Hub 状态，先于普通设备登记。Web wizard 的认证沿用下述独立部署者授权
边界，具体方案仍须实现；普通手机 App enrollment 在 `HUB_READY` 后进行。

部署者通过独立受信的服务器安装/本地管理渠道完成以下 Hub 设置：

1. 创建稳定的人类 Owner/admin 账户，选定显示标签并记录管理权限关联。
   账号 ID 不使用服务器密码学 key ID；不是等首手机上传公钥才创建 Owner。
2. 配置管理入口、服务器身份、受信 HTTPS 入口与连接策略，包括允许的设备
   类型、配对有效期/一次使用、精确候选确认、限流与恢复规则。初始化授权
   来自部署者控制的受保护渠道，拒绝公开页面抢占和重复初始化。
3. 原子提交 Hub 账户、管理入口和策略，令 Hub 服务状态成为 `HUB_READY`。
   该操作不要求手机或其他 Client 在场；退出设备接入、配对失败或没有设备
   在线，都不回退已完成的 Hub 设置。现有部署不得重新初始化或覆盖原账户。
4. 管理入口显示独立的批准签名者状态：`OWNER_SIGNER_READY` 或
   `NEEDS_OWNER_SIGNER`。初始化管理授权允许其明确范围内的 Hub 设置/账户
   metadata/配对准备，不代替 Owner 批准签名，也不是 Node 凭据。

这些名称是拟议状态，并未成为当前 Store/API 枚举。Hub 的初始 admin 认证
来自独立部署者控制渠道；其登录/会话与后续设备挑战认证的准确合同仍须固定，
不凭空宣称已有服务端密码、SSO 或第一台设备尚未存在的签名登录服务。

如果尚无外部 Owner signer，当前 OwnerDeviceGrant 协议无法自动完成普通
设备登记。新增实现需在已完成 Hub 设置时单独预置有限、短期、单次、准确
Hub/Owner/purpose 绑定的首 signer bootstrap authority；由可信 Android/
Windows 本地组件或独立 Owner/operator 签名器生成/导入外部 Owner key，并
证明 possession。Hub 验证准确候选与该独立授权后，原子消费授权并登记公开
signer authority；随后由本地 signer 签准确设备 Grant。首 Client 不创建或
claim Owner 账户，Hub 不生成/持有 Owner 私钥或代签。初始授权不能被普通
bearer、公钥首上传、Node 或模型取得，也不能用于覆盖既有 Root。
允许条件必须是持久 `ROOT_NEVER_ESTABLISHED`，而非“当前 active Root 数为零”；
所有 Root 已撤销/丢失或恢复后仍是历史已建立状态，必须走明确恢复/新 epoch，
不能重开首次 bootstrap。仅登记服务器自己的加密 identity 不建立人类 signer。

这一首 signer 绑定的公开协议、授权发放/恢复、PoP、候选核对及 signer+设备
登记的原子/分步恢复边界属于**尚须固定并实现的安全决策**，不是现有 API。
没有合法 signer 或独立预置授权时显示 `NEEDS_OWNER_SIGNER`，保留完成的 Hub
设置，不能显示“自动批准”。没有手机的 Node-only 场景仍需独立合格 signer；
部署者可使用用户控制的外部本地组件，Owner 私钥不进入 Hub state/volume，
不能把常驻 Hub/Node 变成 Owner signer。现有 `nodes.preview/confirm` 还要求
已登记 ACTIVE 管理 Client actor，只有外部 Root signer 本身不足以调用确认。
无手机最小复用方案是独立 Owner/operator CLI 作为 headless management
Client，用自身独立 Client identity 登记并关联外部 signer；这套产品入口仍
**NOT_IMPLEMENTED**。其他 operator proof 入口须另行设计，不能把 bootstrap
票或 Node identity 当成已有管理 Client actor。

## 4. Node 与 Client 共用“添加设备”流程

正常心智模型统一为：Hub 面板选择“添加设备 → Client / Node”，获得二维码
或配对串；设备扫描或手动输入同格式凭证，在本地生成/读取密钥并连接。
配对串是临时接入授权，不是设备私钥、Owner 私钥或日常登录密码。

1. 已授权的 Hub 管理入口按当前连接策略发出短期、单次配对授权，绑定准确
   Hub、已有 Owner、设备类型、操作 scope、随机请求 nonce 和期限，服务端保存其
   校验摘要。二维码/配对串采用紧凑的公开 origin、稳定 Hub ID、版本化公开
   identity bundle 的完整密码学 fingerprint，以及受保护传递的有限授权；
   不假定两类 Control PQ 公钥的完整 JSON 能放进一个二维码。二维码与手动
   配对串使用同一格式，不为 Node/Client 创建两套账号/配对系统。
   后端仍须区分首 signer `ROOT_BOOTSTRAP`、普通 `CLIENT_ENROLL` 和
   `NODE_BINDING` 类型/purpose 与发行者权限；Node 票不能登记 Root/Client，
   普通 Client 票不能建立 Root 或扩大 scope。界面同型不能合并授权类别。
2. Client 扫码或手动输入；无摄像头 Node 默认使用 CLI 粘贴配对串或读取
   私有配对文件，不要求扫码硬件。敏感配对串不作普通命令行参数进入进程
   列表/历史，也不进 URL query/referrer、普通日志、诊断导出或公开链接。
   默认通过交互隐藏输入或受保护文件读取，不以 secret flags/env 传入。
3. 设备获取完整公开 identity bundle，再按受信二维码/配对串中的完整摘要
   校验准确 Client-Control/Node-Control 公钥和 Hub ID；不以短 key ID、显示
   核对码或首次获取即信任替代该检查。复用既有审查过的 hash 库/算法；bundle
   version、canonical bytes、hash purpose 和测试向量须在实现合同中固定，
   本文不新增 API，也不宣称未测的二维码容量/性能。当前 Android
   完整 JSON pin UI 保持现状，新 reader 在后续 Client 检查点实现。
   核验后设备在本地创建或读取自己的 identity/凭据，只上传公开候选。完整 possession
   使用现有 Seal/Open 的反向随机加密挑战和签名回应，证明签名与 KEM 两类
   私钥；绑定 Hub/Owner/device/request/purpose/expiry，未完成不得连接。
4. 授权若未事先绑定实际候选密钥，Hub 显示“待确认”。用户在合格 Owner
   本地签名组件核对设备类型/名称、Hub/账户、当前候选摘要、期限、权限与
   双端核对码，明确批准准确 manifest。核对码绑定候选与 scope，不能只
   显示查找请求的随机 user code。替换公钥、类型或范围须重新审查，扫码/
   打开链接本身不批准；配对授权不能替代精确 Owner 签名 proof。
5. 合格 Owner signer 在本地签当前 Client Grant 或相应 Node 授权 proof，
   产品自动传递公开材料，设备与 Hub 独立验证。Hub 原子校验并消费对应配对
   授权、建立准确角色绑定和审计；同操作同内容精确恢复，同身份不同内容
   冲突。签名者缺失/无资格时停在 `NEEDS_OWNER_SIGNER`，不伪造自动 Grant。
6. 设备显示“已连接”及实际角色/能力，Hub 保持独立 `HUB_READY`。用户不
   需要抄 Owner ID、JSON、Base64 或执行签名命令。设备退出只影响自身接入
   请求/连接，不撤销 Hub 初始化或其他设备的独立权限。

两类设备共用“待确认、已连接、已过期、已取消、恢复中、结果不明”的展示，
不把这些拟议标签写为已有协议枚举。两者的 proof purpose、设备能力和当前
Guard 仍分别校验。现有 Node 自身生成设备码、由已授权 Client preview/confirm
的流程是可复用基础，尚未实现上述 Hub 发起的统一配对授权；不能静默改变
已有设备码或 Grant 的安全语义。

## 5. 连接后角色、登录与批准资格

Client 管理设备持有自己的 identity/session/replay 状态。已登记设备再次
连接时在本地解锁，用自己的私钥签挑战，绑定 Hub/account/device/operation/
nonce/expiry 并检查撤销；该登录 purpose 与 enrollment 分离。PIN/生物识别
是本地解锁方式，配对串和公钥都不能充当长期登录身份。

Owner signer 私钥也只在用户受信本地组件中生成/导入和持有。Android 当前
Client keygen/Keystore 包裹不证明其已能签 Owner Grant；Windows 受支持导入/
secure storage 与本地签名交互也仍须实现。默认 Web 面板只负责管理与协调；
浏览器 Root custody 需独立资产信任、加密本地持久保护与本地确认通过审查，
不能因 Hub 下发 JavaScript 就宣称 signer 独立可信。Web/本地 bridge 校验
可信顶层 origin、frame protection、CSRF 与显式用户手势，拒绝任意网页签名。

普通 Client 登记不自动成为批准设备。当前 `CLIENT_CONTROL` 不含 signer
委托；可选设备登记 signer 需新的独立 `DEVICE_ENROLL` scope、有效期、
撤销 lineage 与版本化合同，最多一层委托，不能再委托、轮换 Root 或批准
Link/TLS/其他操作，不能登记成现有 unrestricted Owner Root。无相应资格时
转到合格 Owner signer，不能绕过检查。

Node 持有自己的 Node-Control、Endpoint keys 与工作凭据，永不成为 Owner
signer 或 Client manager。当前 Node proof 只证明 signing possession 并
绑定两个公开 key；完整 KEM PoP 是下一检查点增量。Owner 绑定、Node-Control
配对、PQ TLS leaf/安装和原生 Thread Join 分别显示真实状态，所有特定签署
与 Guard 保留。Node 只主动出站；连接后本地 owner 再选择准确 Thread/
Network/Group 显式 Join，不开放全部历史会话。

当前 sponsoring Client 撤销可能阻断它批准的 Node 管理能力。统一设备页须
预览这一关联；有效的剩余 Owner 设备经明确 reapproval/rebind 才恢复关联，
不静默解除 fence。同一配对体验不意味着同一权限或移除既有撤销边界。

## 6. 普通界面的最少信息

| 界面 | 默认输入/展示 | 用户操作 |
|---|---|---|
| Hub 初始化 | 服务器管理入口、Owner 标签、HTTPS/受信 pins、连接策略 | 独立完成账户/服务设置，显示 Hub 与 signer 各自就绪状态 |
| 添加设备 | Client/Node 类型、二维码与同格式配对串、期限/范围 | 设备扫码或粘贴/文件读取，本地 keygen/公开候选上传、准确批准后连接 |
| 已连接设备登录 | 选定 Hub/账户与可信设备、本地解锁 | 用自身私钥签挑战；新设备进入统一配对流程 |
| 账户与设备 | 设备类型/名称、当前设备、批准资格、真实状态/新鲜度、最近活动 | 添加、重命名、查看权限、撤销 |
| 待确认 | 请求设备、Hub/账户、核对码、期限、将获权限和关联影响 | 批准、拒绝、取消 |
| Node | CLI 配对串/私有文件、机器显示名、连接/配对/安装/Join 各自状态 | 使用同一添加设备流程，默认无需摄像头 |
| 恢复 | 仍可使用的批准设备与受保护备份状态、受影响设备/Node | 使用备份、另机确认或开始重新建信任 |

稳定 IDs、完整公钥、fingerprints、manifest/Grant 编码、版本和日志保留在
“高级详情/诊断导出”；默认确认仍要有足够公开身份和权限摘要让人核对准确
对象。用户不需要把协议内容当作表单逐项录入。诊断不包含私钥、完整敏感
授权载荷或可复用凭据，最近活动也不能被展示为在线或任务消费证明。

## 7. 取消、过期、重试与恢复

下列状态为拟议产品状态；不能据此改写现有 Store/API 枚举。

| 情况 | 产品行为与服务端要求 |
|---|---|
| 取消/拒绝未完成请求 | 服务端使对应请求不可再消费并保留必要审计；本地保留已生成密钥供后续选择，不偷偷删除或重建 identity；保持 Hub 已完成的账户/策略 |
| 过期 | Hub 初始化授权、首 signer bootstrap、设备配对和 Grant 分别检查期限；准确显示需重新开始的步骤；旧码/挑战/签名不可用于扩大期限 |
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
不能挑第一行或让远程首设备占有旧部署。迁移不会把 existing external owner
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

下一检查点以“独立初始化 Linux Hub 与已有 Owner/admin、分别展示 signer
就绪状态，再用相同配对格式连接一个合成 Client 与一个 headless Node”的
可重复闭环为目标；不依赖手机完成 Hub 设置。统一公开 setup/pairing
API 和状态机先在本仓实现，原生平台 Client 按固定合同分开实现。Core 完成后
再向独立 Android 仓库交接，分别实现普通手机体验；本文不授权 Client 编辑。

| 顺序 | 本仓模块与责任 | 退出条件 |
|---|---|---|
| A 设计固定 | `docs/owner-onboarding-design.md`、安全 ADR/迁移设计 | 固定 Hub 先初始化、独立 admin 授权来源、统一 typed 配对、首 signer bootstrap/历史 fence、完整 PoP、session/恢复与 signer scope；无外部 signer 的 Node-only 边界明确 |
| B 账户与迁移 | `internal/store`、`internal/control`、`internal/server` | account/manager mapping、独立 Hub ready/signer ready/设备状态、原子初始化及存量 dry-run；移除 crypto ID 相等授权，拒绝首设备抢占/guest 扩权，配对取消不回退 Hub |
| C 本地接入 | `cmd/cicada`、`internal/e2ee`、既有 Web 面板 | Add device [Client/Node] 共用格式与状态，headless CLI paste/私有文件，内置 keygen/受支持导入、准确 manifest 签署及恢复；Windows 原生 custody 单独验收 |
| D 协议与门禁 | `internal/clientcontract`、Client/OpenAPI/wire 文档、公开合成 vectors、既有 contract scripts 与 Docker gate | 实现、权威合同与检查同一有意义检查点更新；选定修订后输出精确来源协议包/Hub 工件；旧合同不回填新能力 |
| E 独立 Client 工作 | `../CICADA_CLIENT` Owner 的后续单独任务 | 导入固定 Core commit/合同/包/镜像；复用本地 keygen/Keystore 和精确 pending/recover，新增扫码/短码与本地确认 UI；Android 自己验证合同及拒绝/恢复 |

Core 的针对性确定性测试至少覆盖：无手机 Hub 独立初始化、并发初始化单胜者、
曾建立 Root 不重开首 bootstrap、取消/离线设备不影响 Hub ready、重放/过期/
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
统一配对还须拒绝 Root/Client/Node 类型混用、候选替换或不同候选精确重试、
仅持配对串而无 possession/合格批准、Node 升格 manager/signer，并验证
headless paste/file 与 Client scan/manual 的相同状态、限流/过期/撤销恢复。

性能边界：密钥生成只在首次本地创建或明确导入/替换时执行，日常复用已有
密钥；这些额外挑战集中于 bootstrap、登录和批准，不对每条 peer 消息重复
keygen 或账户认证。复用既有 Go、SQLite、出站通知与服务层，不增加 SSO、
消息 broker 或常驻协调平台；仍保留既有消息加密与实时 Guard。

使用既有一次性 Docker Hub 门禁，准备隔离状态与明显合成 identities，验证
真实 HTTP/encrypted handler、原初始化/配对/Grant 精确恢复和 Node preview/confirm，
包括 Hub 重启与撤销。不得使用 resident/shared Hub 作为 fixture。Android、
真实 native Runtime、物理手机/双机器、公网 HTTPS 与严格 PQ TLS 的结果
各自记录；本规划没有执行这些测试，均未据本文新增 PASS。

本检查点不发布、不 push、不改 main、不替换现有部署、不处理真实密钥，
不通过文档完成宣称新账号或接入产品已经可用。具体软件版本、wire version、
contract revision、Git source/dirty fingerprint 与 image digest 各自记录。
