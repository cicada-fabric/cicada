# 部署方式与跨平台界面设计

状态：**PROPOSED / NOT_IMPLEMENTED**。用户要求 Linux/macOS/Windows 的 CLI
与图形入口，并要求先完成服务器 Hub 设置，再以同一配对体验接入 Node/Client。
本设计复用现有 Go、Hub Web 面板与协议，不表示已完成跨平台原生运行验收，
也不选择新的 GUI 框架、密码认证方案或改变已发布合同。

## 1. 推荐交付形态

| 部署职责/入口 | 产品形态 | 责任与限制 |
|---|---|---|
| Hub | 当前目标为 Linux amd64/ARM64 的 Docker 镜像或本机 binary/package，服务器/常驻电脑运行 | 先完成 Owner/admin、管理入口、连接策略和持久状态；内嵌一份权威 Web UI；手机不承担 Hub；未来 macOS/Windows Hub 角色需平台能力验收 |
| 图形管理 | 浏览器打开 Hub 的受信 HTTPS Web UI | Chrome/Firefox/Edge 等现代浏览器的响应式适配是目标；复用已有面板/画布，完整无限画布体验按现有计划增量验收 |
| 平台 CLI/本地组件 | 同一 Go 核心的 Linux/macOS/Windows 包 | 以显式角色提供 Hub 本地管理、Node 配对/运行、Owner 本地生成/导入/签名；同一 binary 不使这些身份互相继承 |
| Node | 默认运行在拥有真实 native Runtime/Workspace 的宿主机 | Linux 为现有基线；macOS/Windows 要验证各自 native 适配与存储。容器仅为明确选定的 Runtime 隔离选项，不假装访问宿主原 Thread |
| Android Client | 独立 Android 仓库交付 APK | 本地 device keys、管理与批准交互；按固定 Core 合同实现，不要求手机完成 Hub 初始化 |
| 桌面图形程序 | 可选薄启动器/托盘/OS 安全存储适配 | 打开/嵌入相同 Web UI，并调用同一 API/Go 本地组件；不重复后端/UI，默认不打包浏览器或 Node.js Runtime；暂不选择 GUI 框架 |

用户有两种图形使用方式：只打开浏览器进行远程管理，或安装本地组件以运行
Node、保护本地批准密钥并获得桌面入口。Node 本机 native wake、Workspace
读写和独立安全存储属于本地受权组件；浏览器页面不能凭远程 GUI 权限完成
这些工作，也不能凭服务器下发 JS 自动成为独立可信 Owner signer。

一台物理主机可运行独立的 Hub 和 Node 实例，分别保存身份/state。面板部署在
Hub 中，不需要另起 UI 服务；桌面壳不带新的业务数据库、账号服务或消息中间件。
GUI、CLI、APK、后台重试都调用同一服务/API 和当前核心 Guard。

“一份 Web UI”指一套维护的前端代码；每个 Hub 分别提供自己的面板、origin
和 state，不建立全局 SaaS 或中央账户。既有多 Hub/profile 边界仍要求分别
保存 pins、设备 keys、session 和 counters；桌面/其他前端直接调用明确选定
的 Hub，不通过 Hub-to-Hub 转发器。这是已有架构边界，不是新增能力声明。

当前优先维护一个 Go CLI binary 的不同角色入口；共享代码/API 不要求所有
平台永远打包完整 Hub 面板与未用的 server 依赖。只有测量表明有价值时才做
角色专用 build/package，不另建项目、插件体系或协调 daemon。Hub native/
Docker state/volume 持久保留；同机 Hub 与 Node 分别运行、分开 state/key/
access policy。Node 绑定准确机器、Workspace/cwd 与原 Runtime session，
不能把容器/VM 内的 Runtime 假装成宿主原 Thread。

建议 Linux/macOS 使用可校验的程序包/`tar.gz`，Windows 使用 `zip`/`exe`
和可选本地启动器，Android 单独提供 APK。安装先核对来源、版本与 digest，
更新保留各角色状态与身份。以上是交付目标，当前包仍是开发候选，未据此
发布新 installer 或承诺所有功能在五个构建 target 可用。

## 2. 用户第一次使用的顺序

1. 在 Linux 服务器选择 Docker 或本机包，检查依赖/权限、选定持久目录与受信
   HTTPS 入口。通过已认证本地 CLI 或受保护 Web wizard 设置服务器上的
   Owner 人类账户、管理凭据/入口和连接策略，然后明确显示 Hub 已就绪。
   不依赖已注册 Client；任意浏览器包括手机浏览器可操作设置界面，这不
   表示该设备托管 Hub。普通手机 App 接入发生在 Hub 就绪后。
2. 如需首设备之前的远程 admin 登录，管理凭据种类、存储/会话/恢复政策是
   实现前须固定的认证设计；本次不宣称已实现密码、SSO 或未绑定设备签名登录。
   账号就绪和外部 Owner signer 就绪分开，后者遵守有限独立 bootstrap 授权。
3. 在同一 Hub Web UI/CLI 选择“添加设备 → Client / Node”，获得二维码与
   同格式配对串。Client 扫码或手动输入；headless Node 默认交互粘贴或读取
   私有文件，不要求摄像头，不把 secret 放进 flags/env、URL 或普通日志。
4. 设备自动读取/生成当地 key，仅上传公开候选，完成完整 PoP、准确候选批准
   与角色绑定。Root bootstrap、Client enrollment、Node binding 的后台
   authority/purpose 不混用，具体流程见[Owner 接入设计](owner-onboarding-design.md)。
5. 已连接设备以后以自身私钥挑战认证；Node 再由用户显式 Join 原 Thread。
   Pairing key 是临时接入授权，不是密码学私钥，也不赋予 Node 管理者/Owner
   signer 权限。设备离线或取消不使已经初始化的 Hub 失去账户/连接策略。

配对凭证默认一次用、短期、限定角色与操作，不是长期共享网络 master secret，
也不是 Hub 的持久根密钥。文中菜单/步骤是目标语义，没有新增可运行 CLI
命令或公开 API；实现命名须由当前代码与合同固定。

PQ 公钥体积较大，二维码/配对串只携带紧凑 origin、稳定 Hub ID、版本化
公开 identity bundle 的完整密码学 fingerprint 与一次用授权。获取公开
正文后按受信凭证的完整摘要校验，不用短 key ID/显示码或 TOFU；canonical
bytes、hash purpose/算法与向量在实现合同固定，不预设二维码容量或性能。
当前 Android 完整 JSON pin UI 仍是现状，新读取方式须后续 Client 实现。

配置页默认提供“Hub 状态、添加设备、已连接设备、待确认、权限/撤销、恢复”。
本地 CLI 返回同样的类型化状态和错误；密钥编码、ID、manifest 和 transport
细节放在高级诊断，普通流程保留准确对象和权限摘要。安装/升级仍遵守原有
备份、受控停 writer、来源核对和显式恢复规则，不替换现有部署或轮换密钥。

## 3. 平台支持与验证必须分别记录

已有 [release 构建入口](../scripts/build-release.sh)覆盖标准包的
Linux amd64/ARM64、macOS amd64/ARM64 与 Windows amd64；历史包验证见
[候选记录](v00-candidate-d86-validation.md)。跨编译或包存在只证明对应构建
范围，不证明新 Hub 初始化、配对 UX、OS key custody 或原生 Runtime 可以运行。

当前严格 PQ TLS 包是 Linux amd64/ARM64 的独立变体，依赖匹配的 CGo/glibc/
OpenSSL stage；见[PQ transport](pqtls-openssl-transport.md)与
[IP/ARM64 验证](docker-ip-arm64-validation.md)。不能把它宣传为任意 OS 的
通用静态包，或因标准 Windows/macOS 包已构建就推定 PQ/native 适配通过。

| 新流程验证域 | 对新产品的证据状态 | 当前范围与后续门槛 |
|---|---|---|
| 代码/合同/确定性状态测试 | **NOT_IMPLEMENTED / NOT_RUN** | 新初始化、typed 配对、权限/拒绝、恢复尚待实现；这次文档不新增 PASS |
| Linux Hub Docker/包 | 新流程 **NOT_RUN** | 既有实际结果保持原来源；新账户/配对需一次性 Docker gate 单独验证 |
| Linux ARM64 | 新流程/native 硬件 **NOT_RUN** | 已有显式 QEMU scoped package/PQ 结果不等于 native ARM 物理机或新 UX 验收 |
| macOS amd64/ARM64 | 包证据 **BUILD_ONLY**；新原生流程 **NOT_RUN** | 标准构建与原生执行分开；新 CLI、权限、key storage、native Runtime/foreground 适配另验 |
| Windows amd64 | 包/helper **BUILD_ONLY**；新原生流程 **NOT_RUN** | 新 CLI/GUI、keygen/import、ACL/storage/native 适配另验 |
| 浏览器 | 新流程 **NOT_RUN** | 现有 Chromium 记录不升级为所有浏览器通过；按 Chrome/Firefox/Edge 单独验证设置/配对 |
| Android | 新流程 **NOT_RUN** | 复用 keygen/Keystore/恢复；新扫码/手动配对/签名资格需 Client 自身测试与固定镜像验收 |
| 真实 Runtime/设备/公网 | 新流程 **NOT_RUN** | 原 Thread 连续性、物理手机/双机器、public HTTPS/PQ TLS 独立记录，SKIP 不计 PASS |

表中 BUILD_ONLY 描述包证据对新平台产品的有限支持，不降低或升级历史
producer 的原有构建/协议 PASS；任何原生平台结论须有对应运行证据。

每条证据记录 source commit/dirty fingerprint、合同/wire、binary/APK 或 image
身份、实际 OS/Runtime 版本、命令、失败和未运行范围。此设计没有运行上述
软件验收，也不推断现有 five-target 包实现了新跨平台产品。

## 4. 同类产品可复用原则

2026-10-13 核对的官方资料只支持下列交付/交互原则；没有运行这些产品或审计
其密码学实现，也不把他人的平台声明当作 CICADA 验收。

| 官方来源 | 可复用经验 | CICADA 的取舍 |
|---|---|---|
| [Syncthing 架构/CLI](https://docs.syncthing.net/users/syncthing.html) | 后台程序可同时提供 CLI、内嵌 HTML/JS GUI 和 API，让外部 GUI wrapper 复用核心 | 最贴近已有 Go Hub/面板；共享一份管理 UI 与 API，原生壳只做启动/OS 适配 |
| [Headscale 首次使用](https://headscale.net/stable/usage/getting-started/) | 服务先配置运行、创建用户，再通过浏览器或有限 preauth key 登记归属该用户的 Node | 借鉴 server/account 先于设备、一次接入授权；不照搬其 credential 或网络权限，也不采用其社区容器文档作生产认可 |
| [RustDesk Server OSS 安装](https://rustdesk.com/docs/en/self-host/rustdesk-server-oss/install/)及[客户端配置](https://rustdesk.com/docs/en/self-host/client-configuration/) | 自建服务器与跨平台客户端分开交付，客户端可导入 server/public-key 配置 | 借鉴公开连接配置导入；CICADA 保留自己的角色/批准协议，不复制其服务器拆分与密码学 |
| [Happy quick start](https://happy.engineering/quick-start/)及[CLI 文档](https://happy.engineering/docs/) | 当前桌面入口覆盖三 OS，并有手机扫码接入；旧 CLI 处于维护模式，新功能转向 Desktop | 借鉴 desktop/mobile 接入交互；不引入其 npm/Runtime，也不推断原 Thread/密钥协议兼容 |
| [MeshCentral 官方仓库](https://github.com/Ylianst/MeshCentral) | Web 管理服务与本机 agents 分工 | 管理页和本地能力分开，Node 自己执行受权本机操作；不引入第二套管理平台 |

浏览器扫码需安全 origin 和用户摄像头许可，见
[MDN getUserMedia](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)。
手动配对串始终是同等入口；文件选择/网页权限不等于任意 Workspace、进程或
native Runtime 控制，也不建立独立 Owner Root trust。

只借鉴交付和接入交互，不复制代码、账号制度、密码学协议或授权 scope。
CICADA 继续使用既有 Go binary、SQLite、Client 契约、Hub 内嵌面板与 Node
出站连接，不为桌面外壳、两仓协作或 QR 配对新增基础设施。
