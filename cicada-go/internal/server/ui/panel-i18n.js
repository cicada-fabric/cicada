const simplifiedChinese = Object.freeze({
  'Language': '语言',
  'Connection status': '连接状态',
  'Connecting to this Hub…': '正在连接此 Hub…',
  'Unverified': '未验证',
  'Loading secure panel': '正在加载安全面板',
  'Checking the local WebCrypto build…': '正在检查本地 WebCrypto 构建…',
  'Pin this Hub independently': '独立固定此 Hub',
  'The identity below came from this connection and is untrusted. Compare both values with an independent operator source before entering them. This page will not trust a first-seen Hub automatically.': '以下身份来自当前连接，尚不可信。请输入前，请使用独立的运营方信息核对两项内容。本页面不会自动信任首次看到的 Hub。',
  'Origin: {origin}\nHub ID: {hubId}\nHub identity key ID: {keyId}\nSuite: {suite}': '来源：{origin}\nHub ID：{hubId}\nHub 身份密钥 ID：{keyId}\n套件：{suite}',
  'Independently verified Hub ID': '独立核验的 Hub ID',
  'Independently verified Hub identity key ID': '独立核验的 Hub 身份密钥 ID',
  'Pin this exact Hub identity': '固定此 Hub 身份',
  'The typed Hub or Hub identity key does not match. No trust was saved.': '输入的 Hub 或 Hub 身份密钥不匹配。未保存信任信息。',
  'Hub pinned': 'Hub 已固定',
  'Owner account setup is unavailable in this build': '此版本尚未提供 Owner 账户设置',
  'The normal first Owner setup should start with an installer-issued Hub URL and one-time claim code, then create an Owner username and password using existing public keys. That signup flow is not available in this build; this page does not create an account or accept a claim.': '标准的首个 Owner 设置应从安装程序签发的 Hub URL 和一次性认领码开始，然后使用已有公钥创建 Owner 用户名和密码。此版本尚未提供该注册流程；此页面不会创建账户或接受认领码。',
  'OWNER ACCOUNT SETUP': 'OWNER 账户设置',
  'The browser-device form is a separate advanced Client enrollment tool. It is not Owner signup and does not create Owner login credentials.': '浏览器设备表单是单独的高级 Client 注册工具。它不是 Owner 注册流程，也不会创建 Owner 登录凭据。',
  'Advanced technical setup': '高级技术设置',
  'The optional technical path covers Owner-signer bootstrap and browser Client-device enrollment. It requires separate operator and signer steps and does not claim a Hub installation or create an Owner username or password.': '此可选技术流程涵盖 Owner 签名器引导和浏览器 Client 设备注册，需要运营方与签名器分别操作；它不会认领 Hub 安装，也不会创建 Owner 用户名或密码。',
  'I understand this is advanced signer and browser-device setup, not Owner account signup.': '我了解这是高级签名器和浏览器设备设置，不是 Owner 账户注册。',
  'Open advanced signer and browser-device setup': '打开高级签名器和浏览器设备设置',
  'Advanced Owner signer and browser Client setup': '高级 Owner 签名器和浏览器 Client 设置',
  'This technical path does not claim a Hub installation or set Owner login credentials. Its browser-device form creates a Client device key for separate Owner-authorized enrollment.': '此技术流程不会认领 Hub 安装或设置 Owner 登录凭据。浏览器设备表单只会创建 Client 设备密钥，之后须单独通过 Owner 授权注册。',
  'LOCAL TRUST SETUP': '本地信任设置',
  'FIRST OWNER · PUBLIC-FILE GUIDE': '首个 Owner · 公共文件指南',
  'ADVANCED OWNER SIGNER · TECHNICAL FLOW': '高级 Owner 签名器 · 技术流程',
  'Hub setup and Owner signer setup are separate. A public key alone is not approval: the Hub operator must issue one finite pairing locally, then the Owner signer must prove possession of both private-key operations. This page does not contact an issuer or read live Root status.': 'Hub 设置与 Owner 签名器设置相互独立。仅有公钥不代表已获批准：Hub 运营方必须在本地签发一次性配对信息，之后 Owner 签名器须证明其可执行两项私钥操作。本页面不会联系签发方，也不会读取 Root 实时状态。',
  'A local Hub operator runs `cicada hub setup` to create the stable account-to-human-Owner mapping and exports the public Hub connection file.': 'Hub 运营方在本地运行 `cicada hub setup`，创建稳定的账户与人工 Owner 对应关系，并导出 Hub 公共连接文件。',
  'The Owner configures the local signer with the existing encrypted key files and exports its public manifest. Never select a private-key file or enter a passphrase in this page.': 'Owner 使用现有加密密钥文件配置本地签名器，并导出其公共清单。请勿在此页面选择私钥文件或输入口令。',
  'The Hub operator compares the complete candidate fingerprint and runs `cicada hub owner-bootstrap-issue` locally with its interactive approval.': 'Hub 运营方核对完整候选指纹，并在本地通过交互式确认运行 `cicada hub owner-bootstrap-issue`。',
  'The Owner imports the finite pairing into the local signer and runs its bootstrap or exact recovery flow. The signer verifies the Hub receipt.': 'Owner 将一次性配对文件导入本地签名器，并运行首次证明或精确恢复流程。签名器会验证 Hub 回执。',
  'Only afterward, use the existing Owner-signed Client grant to enroll this browser. Node INITIAL enrollment is a separate later flow.': '完成上述步骤后，才能使用现有 Owner 签名的 Client 授权注册此浏览器。Node 的 INITIAL 注册是之后单独进行的流程。',
  'The Hub can be configured (`HUB_READY`) while still needing its first Owner signer (`NEEDS_OWNER_SIGNER`). This page cannot determine or report either live state. A valid public-file draft is not proof of issuance, possession, registration, or manager access.': 'Hub 可以已完成配置（`HUB_READY`），同时仍需要首个 Owner 签名器（`NEEDS_OWNER_SIGNER`）。本页面无法读取或报告这两种实时状态。有效的公共文件草稿不能证明授权已签发、密钥持有权已验证、注册已完成或管理权限已授予。',
  'Independent public Hub connection file': '独立取得的 Hub 公共连接文件',
  'Local Owner signer public manifest': '本地 Owner 签名器公共清单',
  'Check public files and full fingerprint': '检查公共文件和完整指纹',
  'Hub connection file': 'Hub 连接文件',
  'Owner public manifest': 'Owner 公共清单',
  '{label} must be a selected JSON file no larger than 64 KiB.': '请选择不超过 64 KiB 的 {label} JSON 文件。',
  '{label} is not valid JSON.': '{label} 不是有效的 JSON。',
  'A selected file changed while it was being checked. Select both public files again.': '检查期间所选文件发生变化。请重新选择两个公共文件。',
  'Public-file draft only — no Owner state was changed.\nAccount: {accountID}\nOwner: {ownerID}\nHub: {hubID}\nOwner public key: {ownerKeyID}\nOrigin: {origin}\nFull candidate fingerprint: {fingerprint}\n\nThe local Hub operator must still issue finite authority; the local Owner signer must complete proof and verify its receipt.': '仅为公共文件草稿检查——未更改任何 Owner 状态。\n账户：{accountID}\nOwner：{ownerID}\nHub：{hubID}\nOwner 公钥：{ownerKeyID}\n来源：{origin}\n候选完整指纹：{fingerprint}\n\nHub 运营方仍须在本地签发一次性授权；Owner 本地签名器仍须完成证明并验证回执。',
  'Download this validated public candidate': '下载已验证的公共候选文件',
  'Continue to advanced browser Client device enrollment': '继续高级浏览器 Client 设备注册',
  'Public files could not be checked.': '无法检查公共文件。',
  'Choose public JSON files only. The checker accepts only the documented connection and signer-manifest fields; it rejects unknown fields, including private-key, seed, credential, and secret fields. Files are read into page memory for comparison only: they are not sent to the Hub or saved in browser storage.': '仅选择公共 JSON 文件。检查器只接受文档规定的连接文件和签名器清单字段；未知字段（包括私钥、种子、凭据和秘密字段）都会被拒绝。文件仅读入页面内存进行比对，不会发送到 Hub，也不会保存到浏览器存储。',
  'Open advanced browser Client device enrollment': '打开高级浏览器 Client 设备注册',
  'Create an advanced browser Client device': '创建高级浏览器 Client 设备',
  'This form creates only a browser Client device key. The private key is stored as password-encrypted WebCrypto data in this browser profile; the vault password is not an Owner login password. Owner approval remains a separate step.': '此表单只会创建浏览器 Client 设备密钥。私钥以密码加密的 WebCrypto 数据保存在此浏览器配置文件中；保险库密码不是 Owner 登录密码。Owner 批准仍是单独步骤。',
  'Owner ID': 'Owner ID',
  'Owner public key ID': 'Owner 公钥 ID',
  'Device ID': '设备 ID',
  'Vault password (12+ characters)': '保险库密码（至少 12 个字符）',
  'Confirm vault password': '确认保险库密码',
  'This device-enrollment form does not create an Owner account. The Hub does not receive Owner private keys; the exported manifest contains only this browser Client device public identity.': '此设备注册表单不会创建 Owner 账户。Hub 不会收到 Owner 私钥；导出的清单只包含此浏览器 Client 设备的公钥身份。',
  'Create Client device key and public enrollment manifest': '创建 Client 设备密钥并生成公共注册清单',
  'Owner and device identifiers are required.': '必须填写 Owner 和设备标识符。',
  'Vault password confirmation does not match.': '保险库密码确认不一致。',
  'PQ device identity generation failed.': 'PQ 设备身份生成失败。',
  'Device identity fingerprint failed.': '设备身份指纹计算失败。',
  'Unlock the browser device key': '解锁浏览器设备密钥',
  'The device private identity is encrypted in IndexedDB with AES-256-GCM and a PBKDF2-SHA-256 password key. It is decrypted into Go WASM memory for this session only.': '设备私钥身份使用 AES-256-GCM 和 PBKDF2-SHA-256 密码密钥加密后保存在 IndexedDB 中。解密后的数据只在本次会话期间存在于 Go WASM 内存中。',
  'Vault password': '保险库密码',
  'Unlock device key': '解锁设备密钥',
  'Saved device vault or Hub pin changed in another tab. Reload and verify the current state.': '设备保险库或 Hub 固定信息已在另一个标签页中更改。请重新加载并核验当前状态。',
  'Local browser device key could not be restored.': '无法恢复本地浏览器设备密钥。',
  'Restored private key does not match the saved public device identity.': '恢复的私钥与已保存的设备公钥身份不匹配。',
  'Download encrypted device backup': '下载加密的设备备份',
  'Import the offline Owner grant': '导入离线 Owner 授权',
  'The command-line signer approves this exact browser public key for this pinned Hub. Import its public summary and canonical grant bytes; the Hub still performs the authoritative enrollment check.': '命令行签名器为此已固定 Hub 批准这个确切的浏览器公钥。请导入其公共摘要和规范授权字节；最终注册仍由 Hub 权威核验。',
  'Owner: {ownerID}\nOwner key: {ownerKeyID}\nHub: {hubID}\nDevice: {deviceID}\nDevice key: {deviceKeyID}\nFingerprint: {fingerprint}\nPurpose: CLIENT_CONTROL\nExpires within 24 hours': 'Owner：{ownerID}\nOwner 密钥：{ownerKeyID}\nHub：{hubID}\n设备：{deviceID}\n设备密钥：{deviceKeyID}\n指纹：{fingerprint}\n用途：CLIENT_CONTROL\n有效期不超过 24 小时',
  'Signer summary JSON': '签名器摘要 JSON',
  'Canonical Owner grant file': '规范 Owner 授权文件',
  'After the local Owner signer has authenticated its bootstrap receipt, run `cicada owner-signer grant --profile DIR --manifest-file cicada-device-enrollment.json --expires-at UTC_RFC3339Nano --output owner-device-grant.json --summary-output owner-device-grant-summary.json` on that signer machine. Review in the terminal; the command writes a separate public summary file. Import that summary and the grant here. Never paste, upload, or select an Owner private key or passphrase.': '本地 Owner 签名器验证引导回执后，请在签名器所在机器运行 `cicada owner-signer grant --profile DIR --manifest-file cicada-device-enrollment.json --expires-at UTC_RFC3339Nano --output owner-device-grant.json --summary-output owner-device-grant-summary.json`。请在终端中核对；命令会另行写出公共摘要文件。在此处导入该摘要和授权文件。请勿粘贴、上传或选择 Owner 私钥或口令。',
  'Verify grant and enroll exact request': '验证授权并提交准确的注册请求',
  'Select both signer summary and Owner grant files.': '请选择签名器摘要和 Owner 授权文件。',
  'Signer summary and Owner grant files must each be no larger than 64 KiB.': '签名器摘要和 Owner 授权文件都不能超过 64 KiB。',
  'Owner grant signature or scope verification failed.': 'Owner 授权签名或范围验证失败。',
  'Signer summary expiry does not match the authenticated Owner grant.': '签名器摘要的有效期与已认证的 Owner 授权不一致。',
  'Resume the saved device enrollment': '继续已保存的设备注册',
  'A previous attempt may have reached the Hub even if the browser lost its response. This uses the exact saved Owner grant and device identity request; it will not create a new key or nonce.': '即使浏览器未收到响应，先前的请求也可能已到达 Hub。此操作会重用已保存的 Owner 授权和设备身份请求，不会创建新密钥或随机数。',
  'Owner: {ownerID}\nDevice: {deviceID}\nDevice key: {deviceKeyID}': 'Owner：{ownerID}\n设备：{deviceID}\n设备密钥：{deviceKeyID}',
  'Retry the exact saved enrollment request': '重试完全相同的已保存注册请求',
  'Unlock device and inspect saved request': '解锁设备并查看已保存请求',
  'Hub rejected the encrypted operation.': 'Hub 拒绝了加密操作。',
  'Hub {hub} · Owner {owner} · device {device}': 'Hub {hub} · Owner {owner} · 设备 {device}',
  'Endpoint: {name}, presence: {presence}': 'Endpoint：{name}，状态：{presence}',
  'Endpoint state: {presence} · {group}': 'Endpoint 状态：{presence} · {group}',
  'OWNER SESSION': '所有者会话',
  'Active Network changed. Previous action previews and created Group selection intent were discarded.': '当前 Network 已更改。先前的操作预览和新建 Group 选择意图已丢弃。',
  'All networks': '所有 Network',
  'This write became uncertain during the refresh. Refresh again after it resolves before reviewing state.': '刷新期间此写入结果变为不确定。请等待其处理完成后再次刷新，再审核状态。',
  'Authoritative topology and status snapshots refreshed.': '已刷新权威拓扑和状态快照。',
  'PQ Client Wire v1': 'PQ Client Wire v1',
  'Resolve the saved Client request': '处理已保存的 Client 请求',
  'No new operation can be sent while the prior response is unknown. Recovery submits only the exact encrypted packet already stored by this browser.': '在先前操作的结果未知时，不能发送新操作。恢复流程只会提交此浏览器已保存的完全相同的加密数据包。',
  'The server may have applied the operation. A verified recovery result or a fresh authoritative snapshot is required before continuing.': '服务器可能已执行该操作。继续之前，必须取得已验证的恢复结果或新的权威快照。',
  'Recover exact pending operation': '恢复完全相同的待处理操作',
  'Hub confirmed an uncertain outcome. Inspect the refreshed authoritative state before deciding what to do next.': 'Hub 确认该操作结果不确定。请检查更新后的权威状态，再决定下一步。',
  'The encrypted panel needs attention': '加密面板需要处理',
  'No unverified topology is shown. Resolve this message and reload the authoritative snapshots before changing anything.': '不会显示未经验证的拓扑。请先处理此消息并重新加载权威快照，再进行任何更改。',
  'Retry authoritative snapshots': '重新获取权威快照',
  'Untrusted identity · {origin}': '未受信任的身份 · {origin}',
  'Hub identity changed': 'Hub 身份已更改',
  'This browser had pinned a different Hub or Hub identity key for this origin. CICADA refused to replace it automatically. Verify the new identity out of band and use a separate browser profile or site-data reset after reviewing the change.': '此浏览器先前为该来源固定了不同的 Hub 或 Hub 身份密钥。CICADA 拒绝自动替换。请通过其他可信渠道核验新身份，并在审阅变更后使用单独的浏览器配置文件或清除站点数据。',
  'Stored Hub: {storedHub}\nStored Hub identity key: {storedKey}\nObserved Hub: {observedHub}\nObserved Hub identity key: {observedKey}': '已存储的 Hub：{storedHub}\n已存储的 Hub 身份密钥：{storedKey}\n当前 Hub：{observedHub}\n当前 Hub 身份密钥：{observedKey}',
  'Pinned Hub {hub}': '已固定 Hub {hub}',
  'Secure Hub panel unavailable': '安全 Hub 面板不可用',
  'The page does not fall back to a bearer-token UI or another cryptographic implementation.': '页面不会退回到持有者令牌界面或其他密码实现。',
  'Public files could not be checked.': '无法检查公共文件。',
  'Hub connection file is invalid.': 'Hub 连接文件无效。',
  'Owner bootstrap candidate does not match the pinned Hub.': 'Owner 引导候选与已固定的 Hub 不匹配。',
  'Owner device grant is not valid for this exact Client draft.': 'Owner 设备授权不适用于此确切的 Client 草稿。',
  'The browser storage is unavailable.': '浏览器存储不可用。',
  'The browser WebCrypto API is unavailable.': '浏览器 WebCrypto API 不可用。',
  'The secure Hub identity could not be verified.': '无法验证安全 Hub 身份。',
  'Could not open the local browser vault.': '无法打开本地浏览器保险库。',
  'The saved Hub pin is invalid or belongs to another origin.': '已保存的 Hub 固定信息无效或属于其他来源。',
  'This browser already has a different active device.': '此浏览器已有另一台有效设备。',
  'A saved enrollment is already pending. Resume that exact request first.': '已有一个注册请求待处理。请先继续完全相同的请求。',
  'This device draft changed in another tab. Reload before continuing.': '此设备草稿已在另一个标签页中更改。请重新加载后再继续。',
  'The current Hub identity no longer matches the saved pin.': '当前 Hub 身份与已保存的固定信息不匹配。',
  'Owner session': 'Owner 会话',
  'Owner unavailable': 'Owner 不可用',
  'Active Network': '当前 Network',
  'Recover pending request': '恢复待处理请求',
  'Lock device': '锁定设备',
  '{count} preview item(s) waiting for separate confirmation.': '有 {count} 个预览项等待分别确认。',
  'Live status snapshot': '实时状态快照',
  '{scope} · captured {time}': '{scope} · 捕获时间 {time}',
  '{count} Groups': '{count} 个 Group',
  '{count} Endpoints': '{count} 个 Endpoint',
  'unknown': '未知',
  'unknown time': '未知时间',
  'unknown scope': '范围未知',
  'Create Group': '创建 Group',
  'No active Owner-managed Network currently allows Group creation.': '当前没有允许创建 Group 的有效 Owner 管理 Network。',
  'Network': 'Network',
  'Parent Group': '上级 Group',
  'Network root': 'Network 根节点',
  'New Group name': '新 Group 名称',
  'Group creation and its parent relation are one versioned topology action. The Hub validates ownership and Network scope; canvas layout is not authority.': '创建 Group 及其父级关系是一个带版本的拓扑操作。Hub 会验证所有权和 Network 范围；画布布局不代表授权。',
  'Preview Group creation': '预览 Group 创建',
  'Switch the active Network before creating a Group there.': '请先切换到目标 Network，再在那里创建 Group。',
  'Attach selected Endpoints': '关联选中的 Endpoint',
  '{count} Endpoint(s) selected. Each Group admission or reference is previewed and confirmed separately.': '已选择 {count} 个 Endpoint。每项 Group 准入或引用都必须分别预览和确认。',
  'Target Group': '目标 Group',
  'Target locked to the authenticated newly created Group. No Endpoint is added without its own preview and confirmation.': '目标已锁定为经认证的新建 Group。每个 Endpoint 都必须单独预览并确认后才会添加。',
  'Discard created Group selection intent': '放弃新建 Group 的选择意图',
  'Preview next selected Endpoint': '预览下一个选中的 Endpoint',
  'Choose an active Group first.': '请先选择一个有效 Group。',
  'No selected Endpoint needs a new reference in that Group.': '所选 Endpoint 均无需在该 Group 中新增引用。',
  'Opted-in Network directory': '自愿公开的 Network 目录',
  'Read-only Endpoint cards published by current Network members. A card does not add a Group reference, grant access, or authorize a message.': '当前 Network 成员发布的只读 Endpoint 卡片。卡片不会添加 Group 引用、授予访问权限或授权发送消息。',
  'Select an active Network first.': '请先选择有效 Network。',
  'No opted-in Endpoint cards are currently visible.': '当前没有可见的自愿公开 Endpoint 卡片。',
  'Loading directory…': '正在加载目录…',
  'Refresh directory': '刷新目录',
  'Next page': '下一页',
  'Hub returned an invalid Network directory page.': 'Hub 返回了无效的 Network 目录页面。',
  'Directory request failed.': '目录请求失败。',
  'Membership & Monitor settings': '成员关系和 Monitor 设置',
  'No visible Group Memberships.': '没有可见的 Group 成员关系。',
  'Membership': '成员关系',
  'Role': '角色',
  'Preview role update': '预览角色更新',
  'Explicit message.broadcast permission': '显式 message.broadcast 权限',
  'Keep disabled / remove grant': '保持禁用 / 移除授权',
  'Enable for this Membership': '为此成员关系启用',
  'Preview permission change': '预览权限变更',
  'A Monitor role does not grant message.broadcast. That permission is a separate explicit action.': 'Monitor 角色不会授予 message.broadcast。该权限需要单独的显式操作。',
  'Propose a Link': '提议 Link',
  'At least two visible Endpoints are needed.': '至少需要两个可见 Endpoint。',
  'Source Endpoint': '源 Endpoint',
  'Target Endpoint': '目标 Endpoint',
  'Source Group': '源 Group',
  'Target Group': '目标 Group',
  'Common transport Hub (cross-Node only)': '公共传输 Hub（仅跨 Node）',
  'No Hub selected': '未选择 Hub',
  'Select pinned Hub {hub}': '选择已固定的 Hub {hub}',
  'Data scopes (comma separated)': '数据范围（用逗号分隔）',
  'Allowed actions (comma separated)': '允许的操作（用逗号分隔）',
  'Expires in days': '有效期（天）',
  'A Link proposal remains inactive. Endpoint Owners must separately authorize the required key grants and the other side must accept the proposal.': 'Link 提议不会立即生效。Endpoint Owner 必须分别批准所需密钥授权，另一方也必须接受提议。',
  'Preview Link proposal': '预览 Link 提议',
  'The selected Link endpoints are not currently authorized in these Groups.': '所选 Link Endpoint 当前未在这些 Group 中获得授权。',
  'Only a proposal is written; it does not create an active route.': '这里只会写入提议，不会创建有效路由。',
  'Links': 'Links',
  'No visible Link proposals or active Links.': '没有可见的 Link 提议或有效 Link。',
  'Revoke': '撤销',
  'A proposal is not an active cross-Owner Link. Only an accepted, currently authorized Link is active.': '提议并不等于跨 Owner 的有效 Link。只有已接受且当前仍获授权的 Link 才有效。',
  'Shared Thread memory': '共享 Thread 记忆',
  'Endpoints in the same Group may share Thread memory according to Group policy. Review sharing and retention before adding an Endpoint. Canvas position is local presentation and never an ACL.': '同一 Group 中的 Endpoint 可能按 Group 策略共享 Thread 记忆。添加 Endpoint 前请检查共享和保留策略。画布位置仅是本地展示，不代表访问控制列表。',
  'Exact action preview': '准确操作预览',
  '{count} action(s) are queued. Only the first is shown and submitted; each next item requires its own review.': '队列中有 {count} 个操作。这里只显示并提交第一个；后续每项都需单独审核。',
  'Commit this one action': '提交此项操作',
  'Discard preview queue': '放弃预览队列',
  'UNCERTAIN WRITE FENCE': '不确定写入保护',
  'A prior change may have taken effect': '先前的更改可能已生效',
  '{operation} · operation {operationID}': '{operation} · 操作 {operationID}',
  'Legacy sealed-packet SHA-256: {digest}': '旧版密封数据包 SHA-256：{digest}',
  'Submitted JSON body SHA-256: {digest}': '已提交 JSON 正文 SHA-256：{digest}',
  'Scope: {scope}': '范围：{scope}',
  'The authenticated recovery response advanced the Client sequence, but it did not prove whether this change applied. No new topology write is allowed until you inspect fresh snapshots and explicitly authorize one. The old action is never replayed.': '经过认证的恢复响应已推进 Client 序列，但不能证明此更改是否已生效。在检查新快照并明确授权之前，不允许新的拓扑写入。旧操作绝不会重放。',
  'Refresh topology and status for review': '刷新拓扑和状态以供审核',
  'I reviewed this state; authorize a new write': '我已检查此状态；授权新的写入',
  'Refresh after the uncertain operation resolves. The confirmation button unlocks only after both authoritative snapshots finish.': '请在不确定操作结果明确后刷新。只有两个权威快照都已完成，确认按钮才会启用。',
  'Refresh topology and status for this exact write fence before authorizing another write.': '授权其他写入前，请先为此写入保护刷新拓扑和状态。',
  'Authorize new topology writes after reviewing the fresh state?\n\nPrior operation: {operation}\nOperation ID: {operationID}\n{digest}\nScope: {scope}\n\nThis does not retry or repeat the prior action.': '检查最新状态后，是否授权新的拓扑写入？\n\n先前操作：{operation}\n操作 ID：{operationID}\n{digest}\n范围：{scope}\n\n此操作不会重试或重复先前操作。',
  'You authorized a new write after reviewing fresh snapshots. The prior action was not replayed.': '你已检查新快照并授权新的写入。先前操作没有重放。',
  'Resource scope changed. Previous action previews and created Group selection intent were discarded. Prepare a fresh preview.': '资源范围已更改。先前操作预览和新建 Group 的选择意图已清除。请重新预览。',
  'Wait for the current operation or snapshot refresh before preparing another action.': '请等待当前操作或快照刷新完成后，再准备其他操作。',
  'A prior write has an uncertain outcome. Review fresh topology and status, then explicitly authorize a new write.': '先前写入结果不确定。请检查新的拓扑和状态，再明确授权新的写入。',
  'Group scope or version changed during the gesture. Refresh and review again.': '拖动期间 Group 范围或版本已更改。请刷新并重新审核。',
  'This Group already has that parent. No write was prepared.': '此 Group 已有该父级。未准备写入。',
  'Submitting {operation} as one encrypted topology.apply action…': '正在将 {operation} 作为一个加密 topology.apply 操作提交…',
  'Authenticated snapshots refreshed. The created Group target is locked; preview and confirm each selected Endpoint separately.': '已刷新经过认证的快照。新建 Group 目标已锁定；每个选中的 Endpoint 都必须分别预览和确认。',
  'The prior action has an uncertain outcome. The next snapshots are authoritative; review them before making another change.': '先前操作结果不确定。后续快照具有权威性；请先检查，再进行其他更改。',
  'The prior encrypted Client operation was recovered.': '先前的加密 Client 操作已恢复。',
  'Canvas gesture cancelled. No topology action was submitted.': '画布手势已取消。未提交拓扑操作。',
  'Select Endpoints or drag a box.': '选择 Endpoint 或拖动框选。',
  'Drag empty canvas space to pan.': '拖动空白画布区域以平移。',
  'Drag an Endpoint reference onto a Group to preview one join.': '将 Endpoint 引用拖到 Group 上以预览关联。',
  'Drag a Group label onto another Group or Network root to preview nesting.': '将 Group 标签拖到另一个 Group 或 Network 根节点上以预览嵌套。',
  'Drag from an Endpoint reference to another to prepare a Link proposal.': '从一个 Endpoint 引用拖到另一个引用以准备 Link 提议。',
  'Drop over a Group to review an Endpoint join.': '将 Endpoint 放到 Group 上以审核关联。',
  'Drop over another Endpoint reference to review a Link proposal.': '将其放到另一个 Endpoint 引用上以审核 Link 提议。',
  'No Group or Network root was targeted. No action was prepared.': '目标不是 Group 或 Network 根节点。未准备操作。',
  'No Group was targeted. No topology action was prepared.': '没有选中 Group。未准备拓扑操作。',
  'No target Endpoint was selected. No Link proposal was prepared.': '未选择目标 Endpoint。未准备 Link 提议。',
  'Network root · drop Group here': 'Network 根节点 · 将 Group 放置于此',
  'nested under {parent} · v{version}': '嵌套于 {parent} · v{version}',
  'network root · v{version}': 'Network 根节点 · v{version}',
  'presence unknown': '状态未知',
  'unassigned': '未分配',
  'Hub topology canvas': 'Hub 拓扑画布',
  'Network · {name}': 'Network · {name}',
  'Refresh snapshots': '刷新快照',
  'Select': '选择',
  'Pan': '平移',
  'Drag to Group': '拖到 Group',
  'Nest Group': '嵌套 Group',
  'Draw Link': '绘制 Link',
  'Layout is local to this browser. It does not change ownership, ACLs, or Network policy.': '布局仅保存在此浏览器中，不会更改所有权、ACL 或 Network 策略。',
  'Refreshing authoritative snapshots. Previous action previews and created Group selection intent were discarded.': '正在刷新权威快照。先前操作预览和新建 Group 的选择意图已清除。',
  '{outcome} Authoritative topology and status snapshots refreshed.': '{outcome} 已刷新权威拓扑和状态快照。',
  '{prefix}Refresh stopped: {code}{message}': '{prefix}刷新已停止：{code}{message}',
  'Local layout only · {count} endpoint references · zoom {zoom}%': '仅本地布局 · {count} 个 Endpoint 引用 · 缩放 {zoom}%',
  'Wait for the current operation or snapshot refresh before preparing another action.': '请等待当前操作或快照刷新完成后，再准备其他操作。',
  'Endpoint is no longer visible in this Owner snapshot. Refresh before continuing.': '此 Endpoint 已不在当前 Owner 快照中。请刷新后继续。',
  'Only an Endpoint enrolled in the selected Network can be admitted to this Group.': '只有已注册到所选 Network 的 Endpoint 才能加入此 Group。',
  'OWNER ACCOUNT · PAGE 1 OF 2': 'OWNER 账户 · 第 1 页，共 2 页',
  'OWNER ACCOUNT · PAGE 2 OF 2': 'OWNER 账户 · 第 2 页，共 2 页',
  'OWNER ACCOUNT': 'OWNER 账户',
  'EXACT REQUEST RECOVERY': '精确请求恢复',
  'Set up the first Owner account': '设置首个 Owner 账户',
  'Use the installer-issued Hub claim file. The page checks its exact origin and complete Hub fingerprint against the pinned identity before it uses the one-time code. Owner private keys stay in their local encrypted files.': '使用安装程序签发的 Hub 认领文件。本页面会先将精确来源和完整 Hub 指纹与已固定身份核对，再使用一次性代码。Owner 私钥保留在本地加密文件中。',
  'Installer claim file or JSON': '安装程序认领文件或 JSON',
  'Choose claim JSON file': '选择认领 JSON 文件',
  'The installer claim file must be a JSON file no larger than 16 KiB.': '安装程序认领文件必须是大小不超过 16 KiB 的 JSON 文件。',
  'The installer claim file could not be read.': '无法读取安装程序认领文件。',
  'Verify origin and full Hub fingerprint': '核验来源和完整 Hub 指纹',
  'The installer claim does not match this Hub page. No account request was sent.': '安装程序认领信息与此 Hub 页面不匹配。未发送账户请求。',
  'Verified claim scope\nOrigin: {origin}\nFull Hub fingerprint: {fingerprint}\nExpires: {expiresAt}': '已核验的认领范围\n来源：{origin}\nHub 完整指纹：{fingerprint}\n过期时间：{expiresAt}',
  'I independently checked this exact origin and complete fingerprint with the installer.': '我已通过安装程序提供的独立信息核对了此精确来源和完整指纹。',
  'Continue to Owner credentials': '继续设置 Owner 凭据',
  'The claim code is not displayed or saved. The encrypted first request is saved with the generated browser device key before it is sent. Refresh or a lost response resumes that exact request.': '认领代码不会显示或保存。首次加密请求会与生成的浏览器设备密钥一起先保存，再发送。刷新页面或响应丢失后会继续使用完全相同的请求。',
  'Paste or choose the installer claim JSON before verification.': '请先粘贴或选择安装程序认领 JSON，再进行核验。',
  'The claim request could not start. The claim file was not saved; check the page and retry.': '无法启动认领请求。认领文件未保存；请检查页面后重试。',
  'Create Owner credentials': '创建 Owner 凭据',
  'Page 2 of 2. These credentials bind to the installer claim and the existing public ML-KEM and ML-DSA keys. Private PEM files are rejected before their contents are read.': '第 2 页，共 2 页。这些凭据会绑定到安装程序认领和现有 ML-KEM、ML-DSA 公钥。私钥 PEM 会在读取内容前被拒绝。',
  'This browser login device is a separate PQ identity protected by a random non-extractable browser-profile key. The account password does not unlock it. Browser profile cloning or loss can still expose or remove this local device; sign in also requires the account password and PQ device key.': '此浏览器登录设备是独立的 PQ 身份，由随机且不可导出的浏览器配置文件密钥保护。账户密码不能解锁此密钥。克隆或丢失浏览器配置文件仍可能暴露或移除此本地设备；登录还需要账户密码和 PQ 设备密钥。',
  'Owner username': 'Owner 用户名',
  'Owner password (at least 10 characters)': 'Owner 密码（至少 10 个字符）',
  'Confirm Owner password': '确认 Owner 密码',
  'Password strength appears here; the value is checked locally and never saved.': '此处显示密码强度；密码仅在本地检查，绝不保存。',
  'Weak password': '密码强度弱',
  'At least 10 characters required': '至少需要 10 个字符',
  'Password exceeds the byte limit': '密码超过字节数限制',
  'Strong password': '密码强度强',
  'Acceptable password': '密码强度可接受',
  'Existing Owner ML-KEM-768 public SPKI PEM': '现有 Owner ML-KEM-768 公共 SPKI PEM',
  'Existing Owner ML-DSA-65 public SPKI PEM': '现有 Owner ML-DSA-65 公共 SPKI PEM',
  'Only public SPKI PEM files are accepted. Do not select private keys, password files, or a combined private-key bundle.': '仅接受公共 SPKI PEM 文件。请勿选择私钥、密码文件或包含私钥的组合文件。',
  'Create Owner account': '创建 Owner 账户',
  'Owner password confirmation does not match.': 'Owner 密码确认不一致。',
  'Choose a password of at least 10 characters that is not a common or username-based password.': '请选择至少 10 个字符，且不是常见密码或基于用户名的密码。',
  'The selected public PEM pair is invalid. Choose existing ML-KEM-768 and ML-DSA-65 SPKI PUBLIC KEY files.': '所选公共 PEM 密钥对无效。请选择现有的 ML-KEM-768 和 ML-DSA-65 SPKI PUBLIC KEY 文件。',
  'Owner credentials or public keys could not be checked. The claim challenge remains saved.': '无法检查 Owner 凭据或公钥。认领挑战仍已保存。',
  'Owner account sign in': 'Owner 账户登录',
  'Owner account setup is locked': 'Owner 账户设置已锁定',
  'Owner account setup is active in another tab, or this browser cannot provide a safe single-tab lock. Close the other tab or use a supported browser, then reload.': 'Owner 账户设置正在另一个标签页中进行，或此浏览器无法提供安全的单标签页锁。请关闭另一个标签页或使用受支持的浏览器，然后重新加载。',
  'Reload this page': '重新加载此页面',
  'Sign in with this browser PQ device and your Owner account password. A password alone cannot add a new device. This account page does not grant Client manager access.': '使用此浏览器 PQ 设备和 Owner 账户密码登录。仅凭密码不能添加新设备。此账户页面不会授予 Client 管理权限。',
  'Account status: {state}\nRoot signer: {rootState}\nThe Hub accepted the first account claim. Root proof and Client enrollment are separate steps.': '账户状态：{state}\nRoot 签名器：{rootState}\nHub 已接受首个账户认领。Root 证明和 Client 注册是单独步骤。',
  'This browser has an encrypted account login device for {accountId}. Its key remains in this browser profile.': '此浏览器有一个用于 {accountId} 的加密账户登录设备。其密钥保留在此浏览器配置文件中。',
  'Owner password': 'Owner 密码',
  'Sign in': '登录',
  'Enter the Owner account password.': '请输入 Owner 账户密码。',
  'Sign in could not complete. Any sent request remains saved for exact recovery.': '登录未能完成。任何已发送请求仍会以完全相同的形式保存以供恢复。',
  'The Hub challenge is saved as encrypted bytes. Enter the account password to finish sign in.': 'Hub 挑战已作为加密字节保存。请输入账户密码以完成登录。',
  'Refresh account status': '刷新账户状态',
  'Sign in succeeded but the authenticated account status could not be refreshed. Sign in again to continue.': '登录成功，但无法刷新经过认证的账户状态。请重新登录以继续。',
  'Owner account': 'Owner 账户',
  'This page shows authenticated account status only. Root signing and Client manager access require their separate proof and enrollment checks.': '此页面仅显示经过认证的账户状态。Root 签名和 Client 管理权限需要单独的证明与注册检查。',
  'Account: {username}\nAccount state: {state}\nRoot signer state: {rootState}\nRoot active: {rootActive}\nOwner public key: {ownerKeyID}': '账户：{username}\n账户状态：{state}\nRoot 签名器状态：{rootState}\nRoot 已启用：{rootActive}\nOwner 公钥：{ownerKeyID}',
  'Yes': '是',
  'No': '否',
  'Owner signer proof is still required. This account session does not create Root authority or Client manager capabilities.': '仍需要 Owner 签名器证明。此账户会话不会创建 Root 权限或 Client 管理能力。',
  'Sign out': '退出登录',
  'Recover the saved account request': '恢复已保存的账户请求',
  'The Hub may already have accepted this request. Recovery submits only its exact saved encrypted bytes; it never regenerates the device, request ID, or challenge nonce.': 'Hub 可能已经接受此请求。恢复仅提交已保存的完全相同加密字节，不会重新生成设备、请求 ID 或挑战随机数。',
  'Saved step: {phase}\nAccount: {accountId}\nDevice: {deviceId}': '已保存步骤：{phase}\n账户：{accountId}\n设备：{deviceId}',
  'Recover exact encrypted request': '恢复完全相同的加密请求',
  'The saved request could not be recovered. Its exact bytes remain available for retry.': '无法恢复已保存的请求。其完全相同的字节仍可用于重试。',
  'Continue Owner account setup': '继续 Owner 账户设置',
  'The account setup step did not complete. Check the information and retry the saved request.': '账户设置步骤未完成。请检查信息并重试已保存的请求。',
  'Advanced technical setup': '高级技术设置',
  'The browser login device is an account credential, not a Client manager device.': '浏览器登录设备是账户凭据，不是 Client 管理设备。',
  'Fetching an exact Owner-scoped admission preview. No Group membership is being written.': '正在获取范围精确的 Owner 准入预览。不会写入 Group 成员关系。',
  'Preview next selected Endpoint': '预览下一个选中的 Endpoint',
  'No topology action was prepared.': '未准备拓扑操作。',
  'No action was prepared.': '未准备操作。',
  'Enter a Group name before previewing.': '请先输入 Group 名称，再预览。',
  'Choose both Groups for the Link proposal.': '请为 Link 提议选择两个 Group。',
  'Link proposal needs at least one action and data scope.': 'Link 提议至少需要一项操作和一个数据范围。',
  'No Group or Network root was targeted. No action was prepared.': '目标不是 Group 或 Network 根节点。未准备操作。',
  'At least two visible Endpoints are needed.': '至少需要两个可见 Endpoint。',
});

const english = Object.freeze(Object.fromEntries(Object.keys(simplifiedChinese).map(key => [key, key])));
export const catalogs = Object.freeze({ en: english, 'zh-CN': simplifiedChinese });
export const supportedLanguages = Object.freeze(['en', 'zh-CN']);
export const languagePreferenceKey = 'cicada.hub.panel.language.v1';

const token = Symbol('localized-panel-text');
let activeLanguage = 'en';
const localizedValues = new WeakMap();

export function localized(key, values = {}) {
  return Object.freeze({ [token]: true, key, values: Object.freeze({ ...values }) });
}

function resolveValue(value, language) {
  if (value && value[token]) return translate(value.key, value.values, language);
  return String(value ?? '');
}

function interpolate(template, values, language) {
  return template.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(values, name) ? resolveValue(values[name], language) : match);
}

export function translate(key, values = {}, language = activeLanguage) {
  const catalog = catalogs[language] || english;
  const template = Object.prototype.hasOwnProperty.call(catalog, key) ? catalog[key] : String(key);
  return interpolate(template, values, catalogs[language] ? language : 'en');
}

function bindLocalized(element, channel, value) {
  if (!element || !value || !value[token]) return false;
  const record = localizedValues.get(element) || { attributes: new Map() };
  if (channel === 'text') record.text = value;
  else {
    record.attributes.set(channel, value);
    element.setAttribute(`data-i18n-${channel}-key`, value.key);
    element.setAttribute('data-i18n-attributes', [...record.attributes.keys()].join(' '));
  }
  localizedValues.set(element, record);
  if (channel === 'text') {
    element.dataset.i18nTextKey = value.key;
    element.textContent = resolveValue(value, activeLanguage);
  } else {
    element.setAttribute(channel, resolveValue(value, activeLanguage));
  }
  return true;
}

export function setLocalizedText(element, value) {
  if (bindLocalized(element, 'text', value)) return element;
  const record = localizedValues.get(element);
  if (record) delete record.text;
  if (element?.dataset) delete element.dataset.i18nTextKey;
  if (record && record.attributes.size === 0) localizedValues.delete(element);
  if (element) element.textContent = String(value ?? '');
  return element;
}

export function setLocalizedAttribute(element, name, value) {
  if (bindLocalized(element, name, value)) return element;
  const record = localizedValues.get(element);
  record?.attributes.delete(name);
  element?.removeAttribute?.(`data-i18n-${name}-key`);
  if (record?.attributes.size) element?.setAttribute?.('data-i18n-attributes', [...record.attributes.keys()].join(' '));
  else {
    element?.removeAttribute?.('data-i18n-attributes');
    if (record && !record.text) localizedValues.delete(element);
  }
  if (element) element.setAttribute(name, String(value ?? ''));
  return element;
}

export function applyTranslations(language = activeLanguage, documentRef = globalThis.document) {
  // Translate only explicitly marked, currently live DOM nodes. The WeakMap
  // keeps values without retaining removed nodes or their former form values.
  for (const element of documentRef?.querySelectorAll?.('[data-i18n-text-key], [data-i18n-attributes]') || []) {
    const record = localizedValues.get(element);
    if (record?.text) element.textContent = resolveValue(record.text, language);
    for (const [name, value] of record?.attributes || []) element.setAttribute(name, resolveValue(value, language));
  }
}

function safeStorage(storage) {
  if (storage !== undefined) return storage;
  try { return globalThis.localStorage; } catch { return null; }
}

function browserDefault(languages) {
  return languages.some(value => /^zh(?:-|$)/i.test(String(value || ''))) ? 'zh-CN' : 'en';
}

export function initializeLanguageSelector(selector, options = {}) {
  const documentRef = options.documentRef ?? globalThis.document;
  const storage = safeStorage(options.storage);
  const browserLanguages = options.browserLanguages ?? globalThis.navigator?.languages ?? [globalThis.navigator?.language || ''];
  let preferred = '';
  try { preferred = storage?.getItem(languagePreferenceKey) || ''; } catch { preferred = ''; }
  const initial = supportedLanguages.includes(preferred) ? preferred : browserDefault(browserLanguages);
  setPanelLanguage(initial, { ...options, selector, documentRef, storage });
  if (selector && !selector.dataset.i18nBound) {
    selector.addEventListener('change', () => {
      if (supportedLanguages.includes(selector.value)) setPanelLanguage(selector.value, { ...options, selector, documentRef, storage });
    });
    selector.dataset.i18nBound = 'true';
  }
  return initial;
}

export function setPanelLanguage(language, options = {}) {
  if (!supportedLanguages.includes(language)) throw new Error('Unsupported panel language.');
  activeLanguage = language;
  const documentRef = options.documentRef ?? globalThis.document;
  const selector = options.selector;
  if (documentRef?.documentElement) documentRef.documentElement.lang = language;
  if (selector) selector.value = language;
  applyTranslations(language, documentRef);
  const storage = safeStorage(options.storage);
  try { storage?.setItem(languagePreferenceKey, language); } catch { /* Preference storage is optional. */ }
  return language;
}

export function localizedIfKnown(value) {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(english, value) ? localized(value) : value;
}
