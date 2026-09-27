# Architecture v2.1：后量子传输与解密边界

> **状态：应用层端点加密覆盖跨 owner 显式 Link 和 sealed-capable 同 owner、同 Group 的本地/跨 Node SEND/ASK/REPLY；PQ-only 传输仍是设计目标。** 当前 `dev` 实现用 Node 本地 Owner 公钥信任和 key-bound Grant，连接 MCP、本机密文 outbox、Hub-blind `SEALED_V1` Relay、两侧 Node 密文 inbox 和精确 native queue；两个逻辑 Node/fake Codex 的 ASK/REPLY 全链测试及一个 Node 两真实 Codex Thread 的本机 ASK/REPLY 验收已通过。v28 同 Group 广播采用固定成员快照和逐人 sealed SEND，已通过两个逻辑 Node/fake Codex 全链；旧无 sealed capability 的 Session 仍可走明文 Fabric。同组跨 Node 的真实 Codex ASK/REPLY 已在两个逻辑 Node 上通过；跨 owner native 与广播 native 验收单独见 [状态矩阵](architecture-v2-status.md)。Node→Hub 当前仍使用 Node bearer 和普通 HTTPS/TLS，协议层 ML-KEM/ML-DSA Node 认证与纯 PQ TLS 协商未实现，不能宣称整条网络符合 PQ-only 要求。本设计遵守 [CICADA.md §22](../CICADA.md#chapter-22)、[§24](../CICADA.md#chapter-24)、[§25](../CICADA.md#chapter-25) 的信任终点、原子状态和恢复要求。

## 1. 决策

默认本地路径不依赖任何中心服务：同一 Node 上的 Endpoint 经本机授权适配器进入本地 Codex queue，队列负责持久化、claim/receipt 和恢复；没有 Relay 才能完成的信任或路由步骤。Group 是可嵌套的组织/权限范围，Monitor 是可选 Endpoint/服务。面板显式配置 Endpoint、Thread 与 Group 的多对多 Membership、连接边及每条边授予的能力；Group 嵌套本身不自动授予成员资格、路由权或解密权。

跨 Node 或跨用户时，双方必须在面板中显式批准同一个 Hub Relay 及连接/权限边。两端 Node 都只向这个 Hub 发起出站连接，不开入站端口；一条远程路径最多经过一个双方共同选定的 Hub，不做 Hub 链式转发或隐式中心目录路由。Hub 可持久化密文 mailbox 并唤醒在线 Node，但不持有 Endpoint 私钥、Group 解密密钥，也不解密或重封装消息。Hub 选择、发现和可达性都不能代替身份验证和授权。DNS/IP 只作为网络 locator；双方通过面板显示的指纹/二维码等已认证方式核对并批准同一个 Hub 身份。无需使用 Tailscale、其他 overlay VPN、NAT hole-punch 或逐台暴露公网端口。

远程节点间的“联系”是：发送 Endpoint 按面板授权向共同 Hub 提交已加密、有明确 scope 和 recipient 的 envelope；Hub 在 durable commit 后沿目标 Node 已建立的出站事件流发无正文 `wake`；目标 Node 用 `claim` 取回不透明密文、持久写入本地 inbox 并回执。断线重连后先对账，低频 claim 兜底。SSE 只减少唤醒延迟，不能代表消息、投递或执行成功；本地同 Node 路径不经 Hub。

所有新公共密钥认证和密钥交换固定使用 NIST FIPS 203 ML-KEM 与 FIPS 204 ML-DSA。传输配置只接受 TLS 1.3、纯 ML-KEM-768 key exchange、ML-DSA-65 客户端和服务端证书、`TLS_AES_256_GCM_SHA384`；拒绝 X25519/ECDH/RSA/ECDSA/Ed25519、任何 classical/PQ hybrid、TLS 1.2 及未知 suite。TLS 应检查实际协商结果，不能只看 `supported_groups` 配置或宣称“启用了 PQ”。AES/GCM 使用 FIPS 197 和 NIST SP 800-38D；ML-KEM 的应用方式遵循 NIST SP 800-227。参数集和实现按 FIPS 当前勘误复核。

这一套标准原语的选择不等于当前有符合要求的传输实现。仓库当前使用 Go 1.27.1 工具链和 CIRCL 1.6.5 实现应用层原语；升级工具链并未自动提供纯 PQ TLS。Go 1.24 的官方 TLS 说明列出的默认 PQ key exchange 是 **X25519 + ML-KEM-768 混合组**，它包含经典 X25519，不能满足本设计的纯 PQ 策略。[Go 1.24 发布说明](https://go.dev/doc/go1.24) IETF 的 [TLS 1.3 ML-KEM](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) 与 [TLS 1.3 ML-DSA](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/) profile 截至 2026-09-23 仍处于 RFC Editor 队列、拟为 Informational；它们不是已发布的 TLS 标准。ML-DSA 的 X.509 算法标识已有 [RFC 9881](https://datatracker.ietf.org/doc/rfc9881/)。实现阶段须选定能按明确 profile 禁用所有 classical/hybrid 协商的 TLS 栈，锁定版本，并实际验协商组、签名算法、证书链和 cipher。达不到这些条件时，PQ-only 部署必须 fail closed；不得退回当前 bearer/普通 TLS 路径。

## 2. 当前真实数据与凭据路径

以下是仓库当前路径；“使用 PQ 原语”不等于链路、端点和整体系统已经满足后量子安全。表中 Relay 是当前 v2 实现，不表示目标架构要求本地流量经过中心 Relay。

| 路径 | 当前凭据与传输 | 当前明文/密文终点 |
|---|---|---|
| Node → Relay | Node 本地保存独立 `CicadaNode` bearer，只把摘要提交 `/v2/nodes/device-code`；owner Client 加密确认后才可访问 Node Relay。远程 CLI 强制 `https`，回环开发可用 `http`；HTTPS 仍是普通 Go TLS，不是纯 PQ TLS。 | 旧未 sealed-capable 的同组 `fabric.Delivery.Body` 仍明文；显式 Link 与当前 sealed-capable 同组路径的 `SEALED_V1` 只在 Hub 保存 Endpoint 密文，目标 Node 验权后本地解密。Node→Relay PQ TLS 尚无实现。 |
| Node 唤醒 | 当前工作树已有 Node 主动建立的 `/v2/relay/nodes/{id}/events` SSE 流；Relay 提交后发送 `event: wake`/`data: claim`，不携带消息正文。Node 收到提示后走现有 claim/receipt；断线后周期 ticker 兜底。凭据仍是 `CicadaNode` bearer。代码和 `relay_node_v2_test.go` 覆盖 SSE 认证、事件和 durable claim 路径。 | SSE 提示不是 PQ 认证或 PQ 加密；它不能使明文 claim/body 变成密文。当前测试没有证明 PQ 握手、PQ TLS 或 E2EE。 |
| MCP → Fabric | `mcp.go` 显式 Join 后使用 `CicadaSession` 校验当前 SessionBinding；旧未 sealed-capable Session 仍走 `CICADA_API_URL` 的普通 HTTP/TLS。显式 Link 与 sealed-capable 同组发送经本机 Unix 桥，把当前 Session credential 临时交给 Node 核验，Node bearer 不进入 MCP。 | 旧 `/v2/fabric/send|ask|reply` 的正文仍在 Hub 明文存储；显式 Link 与 sealed-capable 同组 SEND 在本机 Node 封装后，Hub 只见密文和必要路由。 |
| 旧 Contact | `/v1/peer-messages` 与 `/v1/federation/messages` HTTP 写入口已删除；Contact identity、ratchet、replay 和历史 envelope 仍保存在 StateDir/SQLite 供迁移对账。 | 历史 Control 收发逻辑曾接触明文，因此不能将旧记录称作 Hub-blind E2EE；不能靠删除 HTTP 入口改变旧密钥的信任终点。 |

当前 v11 Fabric 已有同一 Thread/Endpoint 的多条 Group Membership，并按选定 Group scope 保存单播请求/收件箱；v12 有不继承权限的父子 Group 管理关系。`fabric_endpoints.group_id` 和 SessionBinding `group_id` 仍是旧主组投影；v22/v26 的双侧授权使指定跨 owner 单收件人 SEND/ASK 与原请求反向 REPLY 获得密文路由，v27 让同组跨 Node 走 sealed 路径，v28 固定同组广播收件人快照。广播正文不在 Hub 快照，来源 Node 按收件人分别封装；旧未 sealed-capable Session 的明文路径仍需迁移。

旧 Contact 目前使用 Cloudflare CIRCL 1.6.5 的 ML-KEM-768、ML-DSA-65、HKDF-SHA256 和 AES-256-GCM；固定 Contact public identity、签名 envelope、ratchet epoch/counter 和 replay 状态在 `internal/e2ee/{pq,ratchet,directory}.go` 与 Store 中。私有 identity 文件位于 `e2ee/identity.json`（0600）；peer ratchet key/counter 在 SQLite。`docs/e2ee.md` 描述了这些路径。不能重生或替换身份、清空 Contact/session/replay 状态，也不能把旧 Control API 说成端到端不可见。旧 Contact 在 Control 解密是待处理迁移缺口，不是新协议的兼容条件；必须迁移并保全可验证的身份、密钥、序号与证据后退役旧 API，无法安全迁移时阻断相关路径，不能静默丢数据或降级。

NIST 明确指出，FIPS 算法标准本身不保证具体实现或整体系统安全。当前代码没有证据表明 CIRCL 是经过验证的 FIPS 140 模块，也没有独立审计当前 Contact 组合协议；这里仅确认代码使用了这些标准原语，不宣称模块验证、系统认证或审计通过。[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

## 3. 目标建联、发现与重连

### 3.1 本地发现、Hub 选择和信任

1. 本地-only Node 不查 Directory、不申请 RelayCard、不需公网网络服务。面板在本机列出可用 Endpoint/Thread，由 owner 显式建立 Membership 和连接边。Endpoint、Thread、Group 和 Node 是不同标识；同一个 Endpoint/原生 Thread 可以有多条 Group Membership。
2. 配置跨 Node/跨用户连接时，双方在面板核对并批准同一个签名 `HubCard`（Hub ID、origin、ML-DSA-65 公钥/证书指纹、协议版本、有效期）。卡片可通过二维码、文件或既有受认证管理流程交换；DNS/IP、网页发现结果和 HubCard locator 字段只提供地址，不能成为信任根。Hub 不能替任何一方增加成员、连接边、recipient 或能力。
3. Node 在本机生成独立 ML-DSA-65 transport key。Hub 连接需要两端分别以自己的 Node key 做 PQ-only mTLS；Enrollment/轮换由 owner 签名、限时且一次性的 ML-DSA-65 委托记录授权，并在既有 PQ-only 通道提交，不以长期 bearer 作为身份。双方 Node 身份和 Hub 身份 pin 相符之后，才可使用 mailbox。Hub 不签发 Endpoint 身份，也不能单方面登记远端 Endpoint。
4. 每个 Endpoint 在其原生 Thread 边缘持有独立 ML-DSA-65 签名身份和 ML-KEM-768 解封身份，或绑定到由该 Endpoint owner 控制的本地 adapter。owner 签署显式 Membership、ConnectionEdge 和 Permission revision；参与方校验签名、有效期、撤销状态和 revision。Hub、DNS、对端提供的自报 `group_id` 均不作为授权证据。MCP/原生 Thread 通过本机授权 adapter 使用 Node 的 local queue；Endpoint 证书与 Node transport identity 分离。

Group 的嵌套只组织配置和策略引用，不隐式继承 Membership、reader 权、跨组路由权或密钥。面板保存可审计的连接图及每条边的允许消息类型、recipients、能力和到期条件；跨用户/跨 Group 的边须由双方对应 owner 对同一 scope、权限和 revision 分别签名授权，任何一侧拒绝或撤销即不成立；缺失或歧义边默认拒绝。Monitor 可选，只有作为明确 recipient/受托 adapter 并获得相应 scope 权限时才能解密。

### 3.2 PQ TLS 与 SSE/claim 生命周期

本地与远程路径分开。相同 Node 内的流量直接进入该 Node 的本地 Codex queue；只有显式授权的远程边才启用 Node 到双方共同批准 Hub 的持久出站 HTTP/2 SSE：

```text
同 Node：Thread/Endpoint → 本机授权 adapter → local Codex queue → 目标 Thread/Endpoint
          （无中心 Directory/Relay）

Node A -- outbound PQ-only mTLS / HTTPS·HTTP/2 SSE --> 共同批准的 Hub
                                                       （只存密文）
Node B -- outbound PQ-only mTLS / HTTPS·HTTP/2 SSE --> 同一个 Hub

Endpoint A === ML-KEM envelope + ML-DSA signature ===> Endpoint B
                     经过至多一个 Hub；Hub 不解密
```

TLS profile 有一个版本化的精确 allow-list：`TLS_AES_256_GCM_SHA384`、纯 ML-KEM-768 key exchange（无 X25519、无 hybrid）、ML-DSA-65 服务端和客户端身份。Node 证书只授权该 Node 对应 mailbox 的 claim/receipt，不授予 Endpoint 解密权。Hub 从 PQ 客户端证书识别 Node key；Endpoint 的消息签名和当前 Membership/ConnectionEdge 仍须独立核验。模型不能提供 sender/group/recipient/role/approval 身份字段。证书、Node 绑定或授权边撤销/过期时，拒绝新操作并关闭对应 SSE 流。该 TLS 组合当前没有可声称已标准化且已实现的仓库 profile，见 §1 与 §8；没有实际验证协商时远程路径 fail closed。

具体步骤：

1. 每个远程 Node 只连接面板中为相关连接边配置且双方均 pin 的 Hub origin，以 Node ML-DSA 证书打开 `/v3/hubs/{hub_id}/nodes/{node_id}/events` 出站 SSE。校验证书链、Hub ID、服务 ID、公钥 pin、协议版本和实际 PQ 协商结果；任一不符就断开，不尝试 v2 bearer、普通 TLS 或另一个未批准 Hub。
2. 发送 Endpoint 在本机先验证本地 owner 签署的 ConnectionEdge/Permission revision、自己的 Membership、目标 recipients 的各自 Membership/Endpoint key 与消息 scope。它为每个 recipient 生成独立 envelope，签署绑定 scope/recipient/AAD 的头部，再交给本机 queue。无远程连接边时不得从本地路径自动转发到 Hub。
3. 两端均通过共同 Hub 的 PQ mTLS mailbox 上传/claim opaque envelope。Hub 校验 Node mailbox 能力和必要的格式/大小限制，但不代替端侧做 Group 授权，不解密或重新封装。只有 delivery 与必要的 mailbox metadata durable commit 后，Hub 才沿目标 Node 的现有 SSE stream 发可合并的 `wake`。事件不包含 message ID、body、密文、用户内容或可直接触发副作用的命令；它只提示检查 mailbox。若 Hub 在 commit 后、发事件前崩溃，重连扫描和低频兜底仍可找到 durable delivery。
4. Node 收到 `wake` 后通过同一 PQ mTLS `claim`，将 immutable message ID、opaque ciphertext 和 digest 写入本地 durable inbox，再提交 `NODE_RECEIVED` receipt。接收 Endpoint 在解密前重新验证签名、AAD、当前 Membership/ConnectionEdge revision 和 recipient。Node 重连时先扫描本地 inbox/journal 并向 Hub 对账、处理 durable claims；随后恢复 SSE。低频 timer 周期性 claim/receipt，覆盖丢失或合并的 wake、进程重启和网络代理空闲超时。
5. SSE 断开后，Node 使用有 jitter 的指数退避持续重连。旧 stream、撤销证书或已过期授权边不再可消费。连接建立后立即 reconcile，不依赖用户重发，也不另开 Node 入站端口。同 Node 的 MCP/Thread 仍调用本机授权 adapter 和 local queue；它不直接连接 Hub，也不依赖远程在线状态。

Hub 内部可以把 durable queue 与 SSE handler 部署在一起，但不得拥有 Endpoint 解密密钥，也不得将应用消息明文写入数据库、日志、指标或错误信息。公网 L7 反向代理若只能用传统证书或 classical/hybrid TLS 终止，则不满足此 profile；应让 Hub 自己终止通过验证的 PQ TLS，或仅用不终止 TLS 的 L4 转发。不能只在 Hub 与代理之间使用 PQ 链路就声称 Node→Hub 连接是 PQ。Relay/Hub 不负责全局强制 Directory 或 Monitor 中介。

## 4. 密钥边界与消息解密点

| 身份/密钥 | 谁持有私钥 | 用途 / 可见内容 |
|---|---|---|
| Hub ML-DSA-65 identity | Hub 运维密钥库 | 仅证明双方 pin 的网络服务身份；不签发 Group 授权、不代表 Endpoint，也不解密 envelope。Hub 证书签名 key 与消息加密 key 不混用。 |
| Node ML-DSA-65 transport key | Node 受保护密钥库/OS key store；优先 TPM/安全硬件 | mTLS 证明某出站连接代表该 Node，且只能操作被授予的 mailbox。它不是 Endpoint 发件人身份，也不解密 Fabric 内容。 |
| Group/Connection owner ML-DSA-65 | 相应 Group/连接 owner 的受控密钥库 | 对 Membership、ConnectionEdge、Permission 和 revision 变更签名。Hub 不能代签或扩大权限。嵌套 Group 不产生隐式继承。 |
| Endpoint ML-DSA-65 + ML-KEM-768 | 本 Endpoint 的原生 Session 边缘 adapter/受控本地服务 | ML-DSA 签署来源；ML-KEM 派生只给该 Endpoint 的 envelope key。与 Node transport key、Principal、Membership 和当前 Binding 分离；模型不得接触私钥。相同 Thread 可有多个 Group Membership，但密钥身份不因此合并。 |
| TLS traffic keys | TLS 两端内存，仅单连接 | 仅保护 Node→Hub 远程链路；每次新连接重新协商，不备份、不跨连接复用。同 Node local queue 不经过 TLS/Hub。 |
| Contact identity/ratchet | 现有 Control state（当前实现） | 当前代码中 Control 是旧 Contact 信任/明文终点。迁移前保持原始 key material、Contact pins、ratchet epoch/counter、发送序号和接收 replay 状态。 |

Fabric 业务 body 必须是面向接收者的 Endpoint envelope，不能因 TLS 已加密就把 cleartext body 存进 Hub。初期按发送时授权的 Endpoint reader fan-out，为每个 recipient 单独用 ML-KEM-768 共享秘密和版本化、具域分离的 KDF 派生 AES-256-GCM key，并由发送 Endpoint 的 ML-DSA-65 签名；Hub mailbox 仅接受 opaque envelope。密钥派生及 KEM 使用按 NIST SP 800-227 的最终 profile 实现，不把 KEM shared secret 直接用作 AES key。不要建立可由 Hub 持有的共享 Group 解密 key。每条逻辑消息只能声明一个 `scope_group_id`；canonical AAD 至少绑定协议/算法版本、message/transport ID、发送 Endpoint ID、完整有序 recipient Endpoint 集合、该 scope 下发送者和每个 recipient 的 Membership revision、`ConnectionEdge ID/revision`（远程时）、Binding ID/epoch、消息类型、request/reply correlation、deadline、nonce/sequence。签名覆盖 canonical header、KEM encapsulation、nonce 和 ciphertext digest；ciphertext digest 由 AEAD 生成后签入外层签名结构，不塞进自身 GCM AAD，避免循环定义。接收者必须确认自己在签名 recipient 集合中、该集合与消息 scope 的授权一致、所用 Membership/edge revision 当前有效，再验证 signature、AAD 和 GCM tag。Hub 仍可看到路由目标 Node、包长、时间及签名外层必要字段，不应宣称隐藏了这些元数据。

同一个原生 Thread/Endpoint 可以同时属于多个 Group，但每条消息/API 请求必须明确指定且只指定一个 Group scope，依据该 scope 的 Membership、连接边和权限进行检查，不能让模型自报 `group_id`。该 Thread 在不同 Group 中仍是同一模型会话，共享其会话记忆；加密、AAD 或切换 `group_id` 都不能擦除或隔离已经进入模型上下文的信息。面板可以为敏感 Group 强制使用 dedicated Thread，并拒绝绑定到共享 Thread；这是必要的策略边界，不能只靠提示词要求保密。

组内明文点是接收 Endpoint 的本地 crypto adapter：只在验证当前 SessionBinding、单一 scope、Membership/edge revision、签名、recipient、AAD、nonce/replay 后，在注入正确原生 Thread 前短暂解密。Node 本地 inbox 和 Hub 持久队列只保存 envelope。运行 Endpoint 的本机管理员/操作系统仍属于该 Endpoint 的物理信任边界。需要组内日志可读时，显式把日志 reader 加入 recipient fan-out；新增 Membership 不追溯获旧文，不声称撤权能删除已读取的明文。Monitor 是可选的：只有面板把它列为该消息的授权 recipient/adapter 时才解密；一旦授予该权限，它就是明文可信点。

跨 Group 不强制经 Monitor/GroupGateway。若面板建立双方同意的 `CommunicationLink`（本文早期草案称 `ConnectionEdge`），获准 Endpoint A 直接为 Endpoint B 创建一条 envelope，头部同时绑定 A 的来源 Group、B 的目标 Group、连线 ID/revision 和双方当前 Membership revision；B 解密前按自己的目标 Group 和该连线重新授权。这里的两个 Group scope 是**同一条消息的双端授权坐标**，不要求先把正文发给 A 组另一接收者、再生成 B 组消息。Monitor 可被明确列为附加审阅 recipient，也可完全不参与；未授权时不得收到正文。跨 Group 的每条连线独立授权，不因共同 Hub、嵌套关系或同一 Thread 的多重 Membership 自动开通。任何远程路径仍最多经过一个共同 Hub，Hub 只转发密文。

Group 广播固定一个 Group ID 和发送时的有效成员快照，以一份不可变 `broadcast_id` 关联多份逐收件人 envelope。发送 Thread 必须有该 Group 的广播权限；User 经 Monitor 广播时，可信用户发起/批准记录与 Monitor 实际发送身份分别签名/记录，不能接受模型自称“用户已批准”。每份 envelope 绑定相同广播 ID、Group scope、快照版本和唯一目标 Endpoint；每个收件人单独 ML-KEM 封装、独立 nonce/Delivery/receipt。远端收件人各自最多走一个共同 Hub，本机收件人不走中心 Relay；整个广播有多个收件人不等于单条路径经过多个 Relay。父子 Group、其他 Group 和撤权成员不会因同一 Thread 多组加入而自动收到。广播的部分失败、限流、重试和撤权均按收件人报告。

## 5. nonce、重放、重试与备份恢复

- TLS traffic keys 仅属于一个新鲜 PQ TLS session。每个方向使用独立 TLS traffic key/sequence；按 TLS 1.3 record nonce 规则保护记录，不自行复用 GCM nonce。进程重启、断线或状态恢复后废弃旧 session 与旧 key，重新 PQ mTLS。SSE event 是 hint，可重复、合并或丢失；`claim`/receipt 状态是权威事实。
- Endpoint E2EE 使用不同的发送/接收方向 key、ML-KEM session/ratchet epoch 和 AES-GCM 记录；AEAD AAD 覆盖上一节列出的所有身份和关联字段。接收方在成功验证签名及 GCM 标签后，才原子提交 replay 状态/接收计数与 durable ciphertext record；相同 ID + 相同 digest 返回已有状态，相同 ID + 不同 digest 报冲突。旧 ID/计数或旧 Binding epoch 不进入 Runtime。
- Sender 先原子持久化 message ID、ciphertext、digest 和 outbound counter，再网络发送。超时、断线、Hub 已提交但 ACK 丢失时，复用同一 ID/同一密文重试，不能重新 Seal 成另一个 envelope 或创建第二个业务消息。Hub durable commit 后回复 `HUB_ACCEPTED`；Node inbox durable commit 后回复 `NODE_RECEIVED`；原生注入、模型消费确认和业务结果继续按 `CICADA.md §14/§25` 区分。无法确认注入时仍为 `INJECTION_UNCERTAIN`，不得盲目重投高风险动作。
- 备份要形成可恢复的一致点：密钥/证书身份、授权记录、Contact 与 Group/Endpoint public key pins、Store schema、Endpoint ratchet send/receive counters、replay 状态、消息/receipt/outbox/inbox ID 与 ciphertext/digest 同步备份。明文旧 Fabric rows 按真实状态记录，不能声称备份中已加密。
- 恢复身份时保留同一 key identity 与 Contact 信任；废弃所有 TLS traffic keys、SSE stream 和临时 challenge，显式重新握手。恢复后检查 epoch 和 durable counter 不回退；若可信单调性无法证明，则锁定相关 Endpoint、完成显式密钥恢复/撤销流程，不能 reset counter、沿用旧 key nonce，不能自动生成新 key 冒充旧身份。新增密钥存 OS key store/TPM 或加密 state root；现有 0600 文件和 SQLite key columns 只是当前保护，不能默认等同硬件密钥保护。

## 6. 无降级与分期改造

| 阶段 | 改造范围 | 必须保持的约束 |
|---|---|---|
| P0：本地优先与远程传输门槛 | 让同 Node Thread/MCP → 本地 Codex queue 能离线工作；面板持久化可嵌套 Group、Endpoint/Thread 多对多 Membership 和显式 Permission/ConnectionEdge。并行验证纯 ML-KEM-768 + ML-DSA-65 TLS profile、Go toolchain、证书/密钥存储及实际互操作。 | 本地路径无公网 Directory/Hub 依赖。当前 Go 1.27.1 工具链仍使用默认 hybrid/standard TLS；传统 reverse-proxy TLS 和 bearer 认证不满足远程 PQ-only 要求；profile 未验证前远程 Hub 功能不可启用，不能回退旧 `/v2`。 |
| P1：Endpoint 身份与消息 scope | 在 `internal/e2ee` 扩展并审阅 Endpoint ML-DSA/ML-KEM envelope；为 `internal/fabric` / `internal/store` 建立多对多 Membership、ConnectionEdge revision、单消息 scope、完整 recipient/AAD 及 replay schema；实现本地 adapter 解密。 | 当前单 `GroupID` schema 不冒充多 Membership。授权必须按每消息 scope、签名 recipient set 和当前 revision 重查；Endpoint 私钥不交给模型或 Hub。敏感 Group 可由面板强制 dedicated Thread。 |
| P2：可选 Hub 与 PQ SSE | 将 `cmd/cicada/machine_agent.go`、`machine_fabric.go`、`internal/server/relay_node_v2.go`、`internal/fabric` 的远程路径重做为双方批准的 HubCard、Node PQ mTLS、Hub opaque mailbox、持久 SSE wake、claim/receipt 和重连对账。 | Hub 仅被显式 ConnectionEdge 使用；两端出站、最多一跳、无隐式 relay chain。当前 `CicadaNode` bearer 路径只视为待退役实现；新路径未就绪时保持远程连接关闭，不兼容降级。 |
| P3：面板授权与 Fabric 迁移 | 将 `cmd/cicada/mcp.go`、`mcp_outbox.go`、`mcp_session_state.go` 的 Actor 来源绑定到 Endpoint identity 和 owner-signed Membership/Binding；改 `internal/server/fabric_v2.go`、`internal/fabric/model.go|service.go`、`internal/store/fabric_v2.go|relay_v2.go` 为 per-recipient envelope，Node inbox 只持久化密文。面板实现可选 Monitor 和逐边权限。 | Join/连接显式；撤权在 claim、解密、Artifact 读取和执行前重查。旧明文 Fabric rows 明确标为 plaintext 并安全迁移；旧 API 不是长期兼容条件，无明文 fallback。 |
| P4：Contact 单向迁移与恢复 | 一次性迁移旧 Contact Endpoint、pin、身份、ratchet/replay counter、待处理消息、receipt 和 evidence；扩展 `internal/store/state_backup.go`、恢复 CLI/UI、`docs/distribution.md` 与 `docs/e2ee.md`。迁移验证后退役旧 `/v1/peer-messages` Control 明文终点及旧双代表路由。 | 不重生或静默替换既有身份/信任/序号，不静默丢弃无法解码记录。无法安全映射的数据标为 `MIGRATION_BLOCKED`，保留受保护的源记录供显式恢复；禁止回退旧 API/明文路径。Git 可保留代码历史，不要求新协议兼容旧运行路径。 |

本文件是方案，不是已经完成的迁移步骤；不表示 v3 API、证书系统、E2EE 或 key store 存在。实现期间只增加支持精确 PQ profile 所需依赖，并记录仓库级 ADR、许可证、版本、平台支持和安全审阅结果。

## 7. 最低测试清单

**TLS/profile 与密钥 Enrollment**：NIST ML-KEM-768/ML-DSA-65 KAT；HubCard pin、过期、替换和签名校验；Node/Endpoint/Hub key ID 绑定；mTLS 客户端/服务端证书验证。通过抓取实际 `tls.ConnectionState`/握手记录确认协商 TLS 1.3、纯 ML-KEM-768、ML-DSA-65 和 AES-256-GCM；构造只有 X25519、hybrid、ECDSA、RSA、TLS 1.2、未知 version/suite、错 pin 的端点，逐个确认 fail closed。验证反代不做 classical TLS terminate 后冒称 PQ。Hub 未经双方批准、双方 Hub ID/pin 不同或授权边缺失时，消息不得提交。

**本地 queue 与 Node stream**：本地同 Node 通信在无 Hub URL、无公网连通时仍可持久排队、claim/receipt 和恢复。远程仅 Node PQ 证书可建立 SSE；撤销/轮换关闭旧流；commit 前无 wake，commit 后 wake；wake 内容无 MessageID/body/正文；断线、丢 wake、重复 wake、Hub 重启、Node 重启后低频扫描/重连对账能取到 durable delivery；重复 claim/receipt 同 ID 幂等、不同 digest 冲突；绑定与 Node epoch 过期时拒绝；保持已有层级回执及注入崩溃语义。尝试 Hub-of-Hubs/两跳连接必须失败。

**多 Group、scope 与解密边界**：同一 Endpoint/原生 Thread 同时加入多个 Group；每条消息仍需一个显式 `scope_group_id` 和有效 Membership。篡改 Group scope、recipient set、Membership/ConnectionEdge revision、Binding epoch、AAD、签名、密文/tag、nonce/sequence/replay 均拒绝；嵌套 Group 不自动授予 Membership/读权。未授权的 Monitor 不可解密；Monitor 缺席时授权的跨组 endpoint 路径仍工作；显式授权 Monitor 后它可解密。检查 Hub DB、SSE、日志、错误和 Node inbox 没有正文，只有授权 Endpoint recipient 可解密。面板必须拒绝把敏感 Group 绑定到共享 Thread（若启用 dedicated-Thread 要求）；同时在文档/UI 明示加密无法隔离同一 Thread 已共享的模型记忆。

**跨 Group 授权与旧路由退役**：跨 Group 只有显式 ConnectionEdge + 分别签署的 A/B scope 消息可以通过；无边、过期边、权限缩减或试图继承嵌套权限都拒绝。旧 `MA→MB` 双代表路由不作为新协议必要环节，测试确保无需 Monitor 即可走授权边，并确认旧运行 API 在迁移后关闭。

**重试/恢复/迁移**：outbox 先写密文和 counter，丢 ACK 重传相同 ID/密文；在 Hub commit、Node inbox commit、Runtime injection 前后崩溃分别对账；不把 at-least-once 承诺当 exactly-once。备份/恢复前后核对 identity fingerprint、Contact/Endpoint key binding、epoch、发送计数、replay 状态、message digest、待处理消息、evidence 和 receipts；恢复后旧 stream/session 失效。一次性迁移证明 Contact key/trust/ratchet/counter 与消息身份对应且数据无损；不能安全迁移的数据保留在受保护隔离区并标记阻断。迁移完成后确认旧明文 API 与旧双代表路由不可调用，且系统不会因新协议不可用自动降级。

## 8. 标准与实现参考

- [NIST FIPS 203：ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)；[NIST SP 800-227：KEM 推荐用法](https://csrc.nist.gov/pubs/sp/800/227/final)。
- [NIST FIPS 204：ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)；[RFC 9881：ML-DSA 的 X.509 算法标识](https://datatracker.ietf.org/doc/rfc9881/)。
- [NIST FIPS 197：AES](https://csrc.nist.gov/pubs/fips/197/final)；[NIST SP 800-38D：GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)。
- [Go 1.24 发布说明](https://go.dev/doc/go1.24)：其默认 TLS PQ KEX 是 X25519MLKEM768 混合方式，因此不能单独满足本文件的无 classical/hybrid profile。当前仓库已升级 Go 工具链，仍需另行验证 TLS profile。
- [IETF TLS 1.3 ML-KEM work in progress](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) 与 [ML-DSA work in progress](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)：只用于跟踪 TLS profile；截至 2026-09-23 尚非已发布 RFC。上线前必须复核版本、RFC 状态、Go/TLS 实现和实际握手，不能引用草案把当前部署称为已标准化 PQ TLS。
