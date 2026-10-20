# Owner 账户、可信设备与首次接入设计

> 本文保留包括 2026-10-14 两页/浏览器 UI 在内的历史交互方案；这些章节中的
> “当前”按原日期理解。Hub pin、原 Owner 私钥 proof、密钥职责分离和准确授权
> 等安全目标仍须按有效合同保留。当前原生入口看[App 架构](native-app-architecture.md)，
> 受控安装接入看[C0 合同](hub-installation-registration-contract.md)；首次 Root
> 仍遵循[有效 Owner 激活合同](hub-owner-activation-contract.md)，不由普通登记替代。

## 当前用户决定：普通 Owner 首次设置为两页（2026-10-14）

**两页账户设置/登录产品仍 NOT_IMPLEMENTED；阶段 A 已实现并完成限定测试。**
本节取代此前把浏览器设备登记、手工 Owner ID/公钥 JSON/Grant、外部 CLI
步骤作为普通设置入口的设计。当前未发布开发版本保持 0.0.5：`hubidentity` /
`hubowner` 已分离 Hub 密钥与有限 bootstrap，setup/issuer 和 Hub-only handler
不构造 Control/Workspace/Machine；分段 normal/race、vet 及合同检查的边界与
原失败/超时见[提取审计](architecture-v2-audit.md)。已有加密 OpenSSL key helper、
EN/zh-CN 和旧表单的高级入口是有界实现，不代表账户认证或两页 UI 已交付。
暂不推进 0.0.6；没有新的账户/password/claim API 或 migration，也不操作真实
部署、账户或密钥。

### 安装输出：地址与一次性初始化信息

安装器在部署者控制的本地渠道输出 Hub 地址和**一份可复制/扫码的初始化
payload**，携带独立受信的 Hub pin 与高熵、短期、有限初始 claim。
对准确完整公开身份的 canonical bytes 计算 SHA-256 所得指纹就是完整密码学
pin；无须把全部 PQ key JSON 放进二维码。用户端取得完整公开身份后，必须
按合同固定的编码重新计算并匹配这一受信摘要，不能只比较短 key ID、显示名
或页面自报值。payload 编码及二维码容量仍须验证。它只准备受保护的
初始化资格，不生成 Owner 私钥，也不令公开页面的第一个访客成为 Owner。
旧部署保留已有 Hub/account/Owner、全部密钥和历史，不能用安装重试重开
初始 claim。尚未配置账户时，Hub 的设置/认证服务可独立运行，不能调用
`Control.New` 来创造兼容 human、工作空间或本地 Machine。

### 第一页：核验正确的 Hub 和部署者资格

用户打开安装器给出的地址并导入这一份 payload。浏览器先取得准确完整公开
身份，重算 SHA-256 与安装器独立受信 pin 匹配，并核对 origin/Hub scope；
**核验完成前不发送 claim code 或密码**。code、密码、proof 与结果均保持
Client↔Hub NIST 应用层加密，独立 typed purpose/scope；HTTPS 是运输边界，
不能代替该 PQ 应用保证。核验后才提交一次性初始化资格。服务端核验
Hub/入口、用途、期限与未消费状态，签发只用于第二页的短期 claim session。公开访问、页面自报“这是你的 Hub”、只有 URL 或
上传一个公钥都不能获得该资格。claim 不放进可复用公网 query/referrer、
日志或浏览器长期存储；GET/预取不消费它。错误 Hub、过期、重放、并发抢占
以及已经配置的账户必须得到真实拒绝，不能让前端标签代替权威检查。

### 第二页：用户名、账户密码、已有公钥

默认只显示用户名、账户密码及确认、**已有 ML-KEM/ML-DSA 公钥文件**上传与提交。
已确定密码策略为 10+ 字符，前提是每次登录都完成可信已登记设备的 PQC
挑战。设备 ID、独立设备密钥与本地 vault 由程序在内部管理，盐、用途与
Hub/account scope 各自隔离；不把这些技术字段转成设置表单。
完整指纹可以展开核验，但用户不填写 technical ID、不创建浏览器设备，
也不设置 browser vault。账户密码由 Hub 账户认证服务校验；已有私钥 PEM、
加密私钥 PEM 和 OpenSSL passphrase 均不能上传或进入该表单。

在第一页面向该 Hub 的有效 claim session 下，核验首个独立 ACCOUNT_LOGIN
设备自身的 KEM/签名 proof，再原子创建/关联稳定 human Owner/account、用户名
密码 verifier、该登录设备及准确的待证明公开候选关联，消费初始化资格并
留下可恢复结果。这一步不插入 ACTIVE Root 或永久 Root history。
用户已有 0.0.5 account/Root 时，只能通过明确受控本地渠道给其**原账户**
附加账户凭据与获准登录设备；这与首次 Root 激活是不同操作，不要求清空
既有 Root，也不能改变/重开 Root。不得开放旧 volume 的匿名认领入口或在
安装重试时默认发行新 claim。不重建 human、不换 Hub key、不修改已签 Grant；
若已有批准 key，提交的公钥必须与既有准确关联一致，不能借设置密码替换 Root。

“账户已创建，可登录”与“公钥已关联”不等于“Owner 批准签名者 ACTIVE”。
未证明私钥时，显示“公钥已关联，批准功能待本地验证”，不在
`owner_approval_keys_v2` 插入 ACTIVE 行，不提前触发永久 Root history。
用户名/密码与本机已登记设备 PQC 挑战均成功后，可进入自己 Hub/account
的受限账户与设备页面；签 Grant、建立
Client/Node 管理授权、读取 Endpoint 私钥/历史等仍须相应 proof 与 Guard。
Root 丢失/撤销、密码重置或备份恢复不能重开首次 Root。

### 每次登录的自动设备 MFA

10+ 密码不是 password-only 登录政策。初始 claim 只用于第一次设置，
不是持续 MFA。第一次设置在其准确有限范围内登记本机独立的登录设备候选，
核验设备自身 PQC challenge；随后每次登录由程序自动完成用户名/密码
校验与已登记设备私钥挑战，检查当前绑定、撤销及期限。账户 session 只能
在两项均完成后签发；cookie/session hint 本身不构成账户 actor。后续账户
请求仍需已认证设备的 NIST 应用 envelope、当前 credential/device epochs 和
nonce/sequence 检查；它与旧 Client 管理和 Root purpose 分开。未知新设备
即使知道密码也不能自动登记，必须经 Owner 批准；不能把初始 code、密码重置或普通 cookie 当成新设备 grant。

账户登录设备、Owner Root signer 与现有 `CLIENT_CONTROL` enrollment 分别
有准确 purpose/权限。初始部署 claim 可以批准首个 ACCOUNT_LOGIN 候选，
不使其成为 Root 或自动取得旧 Client 管理角色。Owner Root 仍须本地证明其
已有 signing/KEM 私钥，后续新设备批准使用真实 signer proof。正常界面
隐藏协议细节，服务端仍能区分每一个可信 actor，不伪造旧 device/session。

当前 Hub/UI build 和宿主管理员按用户部署边界明确受信；本检查点不新增
强制签名桌面 UI、enclave 或 VM。既有四个 OpenSSL 公私钥文件必须保留。
标准新密钥生成可作为将来的本地可选功能，不能为完成此流程重建已有 identity。

### 隐藏协议材料，复用本地证明

最短桥接是第二页生成准确、有限的待验证请求，由已有 Owner 本地 helper
读取受保护请求文件，核验安装器独立 Hub pin/account/候选，使用**已有**
加密 PEM 完成 reverse KEM challenge 和签名回应，再返回原样 receipt。
普通界面只显示“本地验证密钥”及真实结果；公钥、pairing/manifest/IDs/
proof/base64 在组件间传递，不要求用户逐项抄录。当前 helper 的 TTY 审查和
文件流程可先封装成一次明确启动；不新增通用网页 sign RPC、常驻 localhost
签名服务或上传/转换私钥。若本地 helper/原生平台尚不可用，账户及公钥关联
保留，批准状态保持待验证，不能伪造就绪或强迫重建已有密钥。

现有 `owner-bootstrap-v1` PoP、有限候选绑定、原样恢复和历史 fence 可以
复用。新 claim/account 服务如何受限地准备这一准确候选 authority 必须在
后续独立 Hub setup/auth 合同固定；现行“只有本地 issuer、没有公共 issuer”
合同不因这份规划自动变化。不能仅打开旧公共 accept 路由让其签发新候选。

### 账户认证属于 Hub，Control 是后续业务服务

账户、用户名密码、claim/session、Owner public association 和 Hub 身份
归 Hub/Identity/Authorization 负责，仅依赖 Store、密钥生命周期和确定性
Guard。它们不依赖 Control 的模型、Workspace、Goal、scheduler 或某个
Controller 的 key ID；停用 Control 或未来更换/添加 Controller 不改变登录
账户或人类 Owner。Controller 只通过明确授权的 adapter 使用 Hub actor。

Hub 登录认证、本地设备 vault 保护、OpenSSL 私钥 passphrase 是三种
不同职责。账户密码可以由程序用于本地设备保护的独立 KDF，但必须使用
独立 salt/purpose/scope，不能复用服务器 verifier 或把本地 vault 密文当登录凭据。前端 PBKDF2/AES-GCM vault 不是服务器 password verifier，更不能
把其密文当登录凭据。服务器只存带独立 salt、版本及固定成本策略的密码
verifier；其算法/参数、会话撤销、输入/并发限制和迁移仍是待合同审查的选择，
不是已实现的政策。账户 actor 始终来自设备 envelope 与当前 Guard，而非
cookie 单独授权。账户会话不伪造旧 Client device/session，不用密码入口旁路现有 NIST
管理加密、Owner proof 或业务 Guard。登录后的 Node/Client 接入、Network
membership 与准确 Endpoint/Thread Join 仍各自授权。

## 历史有界实现与后续设备目标（保留原来源）

产品要求：**用户已确定**普通 Owner 账户、内置本地密钥生成/导入及简单安全的
设备接入。**先独立部署并初始化 Linux 服务器 Hub，再让 Node/Client 以同一
扫码/配对串体验加入**；手机只承担 Client，不作为 Hub；Hub 初始化不依赖
任何已注册 Client。此前“外部工具
是普通接入前提”和“首手机参与创建 Owner”的流程均已被修正。
完整产品实现状态：**PROPOSED / NOT_IMPLEMENTED**。软件 0.0.4 已增加有限的
[无手机管理 Client](owner-headless-client.md)：在 Hub 已初始化、独立 Owner
批准 key 已登记的前提下，复用独立本地 Client identity、准确 Grant 登记和
加密 Node 首次配对预览/确认/恢复。当前 worktree 增加了独立的 Hub 本地
Owner/account setup 与有限首 signer bootstrap。独立 Hub Docker A2 协议、恢复、
no-reset、新 Root 后的 Client/Node INITIAL 路径和清理通过。Normal 与 selected
race coverage 在两个 Store test-fixture-only 修正后分段通过；原 A7、R3 aggregate
失败/超时仍保留。Vet/build 与 Python 检查通过。真实人工 TTY review、Android、
Native、physical device 和 public HTTPS 仍 NOT_RUN；Windows custody 与 lost-Root
recovery 仍 NOT_IMPLEMENTED。现有升级预览缺少准确目标绑定/version，
该 CLI 因而拒绝升级确认；账户界面、Android 首次 bootstrap 与统一扫码仍未实现。
本文保留 2026-10-13 的产品流程与验收来源，并补充 2026-10-14 的接入交互目标；
有限 CLI 检查点更新软件版本，不改变 [已采纳规格](../CICADA.md)、已发布 Client 合同或现有部署。
已连接设备以自身私钥挑战认证；Hub 初始管理授权另来自
独立部署者控制渠道，本次不宣称新密码/SSO 或远程 admin 登录已经实现。

产品应先在 Hub 设置中建立属于用户的 Owner/admin 账户、管理入口与连接策略，
然后在面板选择“添加设备 → Client / Node”。设备扫描二维码或输入配对串，
自动在本地生成或选择导入密钥，上传公钥并按当前权限完成准确批准与连接。
用户通过“账户与设备”管理已连接电脑、手机
和 Node，查看待确认请求、权限、最近活动、撤销和恢复。正常流程不要求安装
OpenSSL、手写公钥 JSON、查询 Owner ID、复制 Base64 Grant 或执行签名命令。

**2026-10-13 bounded checkpoint — SCOPED PASS:** a separate
`owner-bootstrap-v1` contract specifies local Hub setup and the finite first
external Owner-signer bootstrap, with reuse of the existing signed Client
enrollment and Node INITIAL path.
See the [bootstrap contract](hub-owner-bootstrap-contract.md),
[operator guide](hub-owner-bootstrap.md), and
[validation record](hub-owner-bootstrap-validation.md) for the implementation
boundary and evidence. Docker A2, segmented normal and selected race runs,
vet/build, and Python checks passed; full normal A7 and selected race R3 retain
their aggregate failures/timeouts. This is a bounded protocol checkpoint, not accepted
end-to-end onboarding.
The full account product, login, web setup panel,
unified QR pairing, Android bootstrap UI, Windows custody, lost-Root recovery,
and deployment UX remain **PROPOSED / NOT_IMPLEMENTED**.

[现有 OpenSSL 工具](owner-windows-openssl.md)是可选高级/开发兼容路径。它已经
取得的 Linux、生产 handler、原镜像 TCP 与交叉构建证据保留原来源；这些结果
不证明本文的账户产品、Windows 安全存储或普通手机接入已经实现。

<a id="headscale-owner-onboarding-target"></a>

## 2026-10-14：参考 Headscale 的“先创建 Owner，再批准设备”交互

Headscale 的官方流程先通过 `headscale users create` **明确创建用户**；
设备输入服务器地址运行 `tailscale up --login-server`，取得浏览器说明和
Auth ID，再由服务器管理渠道执行 `headscale auth register` 批准归属。
另一路径是预先签发接入 key，默认一次使用、有效一小时。它不是匿名首访者
自动成为 Owner；这里参考交互顺序，不引入 Headscale/Tailscale 依赖，也不
照搬其凭据语义。[官方 Getting started（2026-10-14 核对）](https://headscale.net/stable/usage/getting-started/)

CICADA 的**目标产品流程（PROPOSED / NOT_IMPLEMENTED）**如下：

1. 部署 Hub 后，由部署者控制的本地设置或受保护设置向导显式创建稳定
   Owner/admin 账户，得到管理入口。已有部署保留原账户、状态与密钥；
   普通设备访问和公钥首上传不能创建、抢占或重置 Owner。
2. 首个管理设备上的本地 signer，或独立 Owner 本地组件，选择**已有 PQ
   密钥**并通过有限、一次性的首 signer 授权证明 signing/KEM possession。
   Owner 批准凭据与管理设备自己的 Client identity 分开；不重新生成已有
   密钥、不上传私钥，也不把 Hub/Node 身份当 Owner 签名资格。
3. 其他 Node/Client 只需输入 Hub 地址，发起设备接入，再扫码/输入短期
   一次性码，或打开待批准页面。页面可以展示公开请求 ID；接入凭据不是
   Owner Grant。设备本地复用已有身份；仅在没有身份且用户选择创建时生成。
4. 已授权入口显示准确候选、设备类型、权限和期限；合格 Owner 本地 signer
   批准当前 scope，设备证明自身私钥，Hub 验证并消费对应有限授权，完成
   **有限权限 enrollment**。扫码、打开链接、知道 Hub 地址或只持 bearer
   join code 都不能代替 Owner 签名或私钥 proof。
5. 面板显示待批准/已连接设备及实际角色、权限、撤销和恢复状态。Owner
   账户、Owner 批准凭据、Client/Node identity、Network 成员关系及准确
   Endpoint/Thread Join 各自成立；设备接入不自动加入 Network 或开放会话。

**当前手动 CLI 桥接**是 `hub setup` → 本地有限 challenge issue → 重启同一
Hub → `owner-signer bootstrap` → 现有 Client Grant/enrollment → Node INITIAL。
已有加密 OpenSSL PEM 可通过[本地兼容 helper](owner-windows-openssl.md)参与
相同 proof，验证记录见[单独检查点](windows-owner-openssl-validation.md)。
这些命令是目标交互尚未交付时的桥接，不是已经实现的“输入地址即可接入”。
本小节最初只固定产品目标；其后阶段 A 的 Hub-only 提取已按上文实施并测试，
没有新增账户/claim API 或 schema，不改已部署 0.0.5 Hub，也不将本地 helper
交叉构建或 Linux PTY 结果写成 Windows 原生验收。

## 1. 已有基础与缺口

初稿只读审查的 Core 起点为 `dev` / `1b9d5856d5b2d147e71fb3292c4b27345a9a688c`；
本次顺序/交互文档修正基于 `fd61459124d6944b1683033363b6be660cc2c53b`。
规划不能给该来源或旧候选新增运行 PASS。

| 范围 | 当前事实 | 本次拟议增量 |
|---|---|---|
| Owner | [本地登记公钥](../cicada-go/internal/store/owner_approval_keys_v2.go)与独立 Owner 签名已有实现 | 有界本地账户映射与有限首 signer bootstrap 已实现；独立 Hub Docker A2 与分段 normal/selected-race、vet/build、Python 检查通过，A7/R3 原始 aggregate failure/timeout 保留；管理入口 UI、连接策略 UI 和普通设备入口仍 **NOT_IMPLEMENTED** |
| Control 与人类 | 旧路径以 Control identity ID 作为兼容 manager；有界新路径持久化 Hub setup→human Owner 映射 | 保持旧 Owner ID 的 `LEGACY_COMPAT` 与显式本地 adopt；不把 crypto ID 本身当成新 manager grant；完整账户管理 UI 仍 **NOT_IMPLEMENTED** |
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
| Network 成员关系 | “允许参与这个私有协作范围” | 依各 Network 的准确授权建立；Owner 账户或设备接入不自动授予成员权限 |
| Endpoint / Thread Join | “让这个原生会话参与协作” | 仍由本地真实 session owner 显式完成；设备登记、Node 批准和 Network 成员关系均不代替 Join |

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
最新两页目标新增独立 Hub 用户名/密码登录，须先固定 password verifier、
短期会话与撤销合同；SSO、邮件找回和一般 RBAC 不进入这个最小检查点。
账户恢复仍不能取代私钥 proof、签名接入或 Owner trust 恢复。

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

有界实现已把 `HUB_READY` 与 `LEGACY_COMPAT` 用作本地持久状态；
`OWNER_SIGNER_READY` / `NEEDS_OWNER_SIGNER` 是签名者状态，
`ROOT_NEVER_ESTABLISHED` 是历史条件，不是远程登录会话。Hub 的初始 setup
仍来自独立部署者控制渠道；其登录/会话与后续设备挑战认证不是同一合同，
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

首 signer 的有限授权、PoP、精确候选绑定、响应丢失恢复与根历史边界见
[独立协议合同](hub-owner-bootstrap-contract.md)。这一协议不是普通设备
enrollment 或统一 QR 产品；它不替代现有 signer 对准确设备 Grant 的签名。
没有合法 signer 或独立预置授权时显示 `NEEDS_OWNER_SIGNER`，保留完成的 Hub
设置，不能显示“自动批准”。没有手机的 Node-only 场景仍需独立合格 signer；
部署者可使用用户控制的外部本地组件，Owner 私钥不进入 Hub state/volume，
不能把常驻 Hub/Node 变成 Owner signer。现有 `nodes.preview/confirm` 还要求
已登记 ACTIVE 管理 Client actor，只有外部 Root signer 本身不足以调用确认。
无手机最小复用方案是独立 Owner/operator CLI 作为 headless management
Client，用自身独立 Client identity 登记并关联外部 signer。0.0.4 的有限
[headless CLI](owner-headless-client.md)已复用现有 Grant/encrypted RPC 完成这段
协议入口；它仍要求独立预置公钥/Signer，不完成账号设置或普通统一配对产品。
其他 operator proof 入口须另行设计，不能把 bootstrap
票或 Node identity 当成已有管理 Client actor。

## 4. 账户设置之后的 Node 与 Client“添加设备”目标

目标心智模型统一为：Node/Client 输入 Hub 地址并发起接入，或者由 Hub 面板
选择“添加设备 → Client / Node”准备邀请；通过短期一次性二维码/配对码或
待批准页面核对同一请求，设备复用本地已有密钥并按准确授权连接。
没有本地身份时才按用户选择生成/导入。地址、公开请求 ID 与受保护配对凭据
分别展示；配对凭据是有限接入材料，不是 Owner Grant、私钥或日常登录密码。

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
| 添加设备 | Hub 地址、Client/Node 类型、短期一次性二维码/码或待批准页、期限/范围 | 复用本地身份，按需创建/导入；设备 proof 与准确 Owner 批准后连接 |
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

## 9. 下一有界检查点：纯 Hub 账户与两页设置

先完成“安装 claim → 核验 Hub → 用户名密码与公钥关联 → 登录 → 本地 PoP
真实状态”的合成闭环；不同时建设 SSO、跨 Hub 账户同步、多 Controller
平台、普通设备二维码全产品或 Root-loss recovery。后续设备入口复用这些
稳定 Hub/account actor；本次不授权修改独立 Android 仓库。

| 顺序 | 最小模块改动（均未实现） | 退出条件 |
|---|---|---|
| A 纯 Hub composition | 下沉 `Control.loadIdentity` 的已测文件生命周期；抽出仅 Store+现有 Hub key 的 setup/bootstrap service，旧 Control/CLI facade 委托 | 相同 StateDir 三组 Hub key、Owner ID 和全部业务数据不变；无 Control/Workspace/machines/model 也能准备设置与校验 PoP |
| B claim 与账户 | 新小型 Go Hub account/auth service 和增量 Store 数据：claim 摘要/期限/消费、稳定账户 credentials、登录设备 PQC 绑定、短期 session、独立 pending public association | 原子单胜者；无匿名首访认领；密码只存 verifier；每次登录同时验证已登记设备 challenge，未知设备不能密码自动登记；公钥未 PoP 不成为 ACTIVE Root；存量账户不重建、Root history 不清零 |
| C 两页与本地 helper | 安装器受控输出 trust/claim；受保护 setup/auth HTTP adapter 与两页 UI；复用严格 public SPKI/parser 和 existing-key OpenSSL PoP 文件桥接 | 普通设置只需地址/claim、用户名密码和公钥；错误输入/私钥文件拒绝；没有 browser-device 表单；本地验证显示真实状态和原样恢复 |
| D 合同与门禁 | 独立 Hub setup/auth 合同、密码/会话和 claim 限额、restore/schema inventory、迁移与一次性 Docker/平台证据 | Control 缺席的合成两页闭环、重启/并发/丢响应/撤销/无私钥/旧 Root 负例通过；原密码学协议和现有 Client/Node 门禁不回归 |

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
