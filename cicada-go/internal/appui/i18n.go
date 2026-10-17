package appui

// Locale is a display-only language choice. It is never included in Hub
// requests or application identity state.
type Locale string

const (
	English Locale = "en"
	Chinese Locale = "zh-CN"
)

type messageID string

const (
	msgAppTitle                  messageID = "app.title"
	msgLanguage                  messageID = "app.language"
	msgEnglish                   messageID = "language.english"
	msgChinese                   messageID = "language.chinese"
	msgConnection                messageID = "state.connection"
	msgUnverified                messageID = "state.unverified"
	msgLocked                    messageID = "state.locked"
	msgClaimPending              messageID = "state.claim_pending"
	msgOwnerPending              messageID = "state.owner_pending"
	msgOwnerReady                messageID = "state.owner_ready"
	msgUnavailable               messageID = "state.unavailable"
	msgError                     messageID = "state.error"
	msgHub                       messageID = "section.hub"
	msgAccount                   messageID = "section.account"
	msgCanvas                    messageID = "section.canvas"
	msgNotConnected              messageID = "connection.not_connected"
	msgActivationCode            messageID = "connection.activation_code"
	msgConnect                   messageID = "connection.connect"
	msgVerifyHub                 messageID = "connection.verify_hub"
	msgHealthPublic              messageID = "connection.health_public"
	msgUnlock                    messageID = "account.unlock"
	msgLogin                     messageID = "account.login"
	msgUsername                  messageID = "account.username"
	msgPassword                  messageID = "account.password"
	msgClaim                     messageID = "account.claim"
	msgImportOwner               messageID = "account.import_owner"
	msgOwnerProofPending         messageID = "account.owner_proof_pending"
	msgManagementEnabled         messageID = "account.management_enabled"
	msgManagementDisabled        messageID = "account.management_disabled"
	msgRefresh                   messageID = "account.refresh"
	msgLogout                    messageID = "account.logout"
	msgNoCanvasAuthority         messageID = "canvas.no_authorized_data"
	msgCanvasUnavailable         messageID = "canvas.unavailable"
	msgCanvasPreview             messageID = "canvas.preview"
	msgPreviewBanner             messageID = "canvas.preview_banner"
	msgSelected                  messageID = "canvas.selected"
	msgOperationInProgress       messageID = "operation.in_progress"
	msgTryAgain                  messageID = "operation.try_again"
	msgHubIdentity               messageID = "hub.identity"
	msgHubFingerprint            messageID = "hub.fingerprint"
	msgOrigin                    messageID = "hub.origin"
	msgHealth                    messageID = "hub.health"
	msgNoData                    messageID = "common.no_data"
	msgErrorCode                 messageID = "common.error_code"
	msgRequestFailed             messageID = "common.request_failed"
	msgGenerateOwner             messageID = "account.generate_owner"
	msgSelectOwnerFiles          messageID = "account.select_owner_files"
	msgOwnerFilesUnsupported     messageID = "account.owner_files_unsupported"
	msgSelectKEMPrivate          messageID = "account.select_kem_private"
	msgSelectSigningPrivate      messageID = "account.select_signing_private"
	msgSelectKEMPublic           messageID = "account.select_kem_public"
	msgSelectSigningPublic       messageID = "account.select_signing_public"
	msgCanvasInstruction         messageID = "canvas.instructions"
	msgHubPinned                 messageID = "hub.pinned"
	msgHubUnverified             messageID = "hub.unverified"
	msgAccountUnknown            messageID = "account.state.unknown"
	msgAccountClaimPending       messageID = "account.state.claim_pending"
	msgAccountLoginRequired      messageID = "account.state.login_required"
	msgAccountSessionCheck       messageID = "account.state.session_check"
	msgAccountSession            messageID = "account.state.session_active"
	msgAccountOwnerPending       messageID = "account.state.owner_pending"
	msgAccountOwnerReady         messageID = "account.state.owner_ready"
	msgRootUnknown               messageID = "root.state.unknown"
	msgRootUnavailable           messageID = "root.state.unavailable"
	msgRootPending               messageID = "root.state.pending"
	msgRootActive                messageID = "root.state.active"
	msgLocalKeyPresent           messageID = "account.local_owner_key_present"
	msgLocalKeyMissing           messageID = "account.local_owner_key_missing"
	msgAccountID                 messageID = "account.id"
	msgOwnerID                   messageID = "account.owner_id"
	msgOwnerFingerprint          messageID = "account.owner_fingerprint"
	msgAccountState              messageID = "account.state"
	msgRootState                 messageID = "root.state"
	msgPrepareClaim              messageID = "account.prepare_claim"
	msgCompleteClaim             messageID = "account.complete_claim"
	msgStartLogin                messageID = "account.start_login"
	msgGenerateLocalOwner        messageID = "account.generate_local_owner"
	msgRecoverExact              messageID = "operation.recover_exact"
	msgDiscoverProfiles          messageID = "connection.discover_profiles"
	msgSavedProfiles             messageID = "connection.saved_profiles"
	msgResumeProfile             messageID = "connection.resume_profile"
	msgWelcome                   messageID = "setup.welcome"
	msgWelcomeBody               messageID = "setup.welcome_body"
	msgStepConnect               messageID = "setup.step_connect"
	msgStepKeys                  messageID = "setup.step_keys"
	msgStepAccount               messageID = "setup.step_account"
	msgKeysBody                  messageID = "setup.keys_body"
	msgRecoveryBody              messageID = "setup.recovery_body"
	msgConnectionMaterial        messageID = "connection.material"
	msgSetupReady                messageID = "setup.account_ready"
	msgActivateApp               messageID = "setup.activate_app"
	msgGrantBody                 messageID = "setup.grant_body"
	msgGrantConsent              messageID = "setup.grant_consent"
	msgKeysStored                messageID = "setup.keys_stored"
	msgLoginBody                 messageID = "setup.login_body"
	msgConnectionDetails         messageID = "connection.details"
	msgAccessActive              messageID = "authorization.active"
	msgAccessLogin               messageID = "authorization.login_required"
	msgAccessRecheck             messageID = "authorization.recheck_required"
	msgAccessExpired             messageID = "authorization.expired"
	msgAccessRevoked             messageID = "authorization.revoked"
	msgAccessUnavailable         messageID = "authorization.unavailable"
	msgAccessUnconfirmed         messageID = "authorization.unconfirmed"
	msgAccessUntil               messageID = "authorization.until"
	msgRecoverConnection         messageID = "operation.recover_connection"
	msgRequestUnknown            messageID = "error.request_unknown"
	msgRequestRejected           messageID = "error.request_rejected"
	msgMaterialInvalid           messageID = "error.material_invalid"
	msgLocalUnlockFailed         messageID = "error.local_unlock_failed"
	msgHubTrustFailed            messageID = "error.hub_trust_failed"
	msgOwnerMismatch             messageID = "error.owner_mismatch"
	msgEncryptedOwnerUnsupported messageID = "error.encrypted_owner_unsupported"
	msgReplacementCode           messageID = "setup.replacement_code"
	msgReplacementBody           messageID = "setup.replacement_body"
	msgBackToActivation          messageID = "setup.back_to_activation"
	msgNodeSection               messageID = "node.section"
	msgNodeIntro                 messageID = "node.intro"
	msgNodeCode                  messageID = "node.code"
	msgNodePreview               messageID = "node.preview"
	msgNodeApprove               messageID = "node.approve"
	msgNodeRefresh               messageID = "node.refresh"
	msgNodeRecover               messageID = "node.recover"
	msgNodeReview                messageID = "node.review"
	msgNodeIdentityConsent       messageID = "node.identity_consent"
	msgNodeAccessConsent         messageID = "node.access_consent"
	msgNodeScope                 messageID = "node.scope"
	msgNodeName                  messageID = "node.name"
	msgNodeID                    messageID = "node.id"
	msgNodeFingerprint           messageID = "node.fingerprint"
	msgNodeFingerprints          messageID = "node.fingerprints"
	msgNodeHubFingerprint        messageID = "node.hub_fingerprint"
	msgNodeCandidateUntil        messageID = "node.candidate_until"
	msgNodeAccessUntil           messageID = "node.access_until"
	msgNodeObservation           messageID = "node.observed_at"
	msgNodeLastHeartbeat         messageID = "node.last_heartbeat"
	msgNodeNotBound              messageID = "node.not_bound"
	msgNodeUnknown               messageID = "node.unknown"
	msgNodeOnline                messageID = "node.online"
	msgNodeOffline               messageID = "node.offline"
	msgNodeStale                 messageID = "node.stale"
	msgNodeBound                 messageID = "node.bound"
	msgNodeRecovery              messageID = "node.recovery"
	msgNodeUnavailable           messageID = "node.unavailable"
	msgNodeAccessActive          messageID = "node.access_active"
	msgNodeAccessExpired         messageID = "node.access_expired"
	msgNodeAccessRevoked         messageID = "node.access_revoked"
	msgNodeAccessUnconfirmed     messageID = "node.access_unconfirmed"
	msgNodeCandidateExpired      messageID = "node.candidate_expired"
	msgNodeInitialReviewExpired  messageID = "node.initial_review_expired"
	msgNodeStatusReviewExpired   messageID = "node.status_review_expired"
	msgNodeUnboundSessionEnded   messageID = "node.unbound_session_ended"
	msgInitialAuthorization      messageID = "authorization.initial"
	msgNodeCancelReview          messageID = "node.cancel_review"
	msgNodeEndAccess             messageID = "node.end_access"
	msgNodeReviewStatus          messageID = "node.review_status"
	msgNodeStatusScope           messageID = "node.status_scope"
	msgNodeStatusConsent         messageID = "node.status_consent"
	msgNodeAuthorizeStatus       messageID = "node.authorize_status"
	msgNodeReauthorizeStatus     messageID = "node.reauthorize_status"
	msgNodeAccountRecovery       messageID = "node.account_recovery"
)

const (
	msgNodeUnavailableError messageID = "error.node_unavailable"
	msgNodeCodeInvalid      messageID = "error.node_code_invalid"
	msgNodeCounterConflict  messageID = "error.node_counter_conflict"
	msgNodeSessionEnded     messageID = "node.session_ended"
	msgNodeAccessEnded      messageID = "node.access_ended"
)

var catalog = map[Locale]map[messageID]string{
	English: {
		msgNodeUnavailableError: "This Hub's Node connection service is unavailable. Your saved requests are retained.",
		msgNodeCodeInvalid:      "Enter the current connection code shown on your Node.",
		msgNodeCounterConflict:  "The saved Node conversation could not be reconciled safely. Its state has been retained.",
		msgNodeSessionEnded:     "The sign-in used for this Node access has ended. Sign in and explicitly authorize status again.",
		msgNodeAccessEnded:      "This App's Node access has ended.",

		msgNodeReviewStatus:          "Review status access for this Node",
		msgNodeStatusScope:           "Allow only status reads for this previously approved Node until the displayed expiry. This does not pair the Node again or renew its previous authorization.",
		msgNodeStatusConsent:         "I allow this App to read this Node's status for the shown period.",
		msgNodeAuthorizeStatus:       "Allow status access",
		msgNodeReauthorizeStatus:     "Authorize status again",
		msgNodeAccountRecovery:       "A Node request is also saved. Recover the account request above first; the original Node request will remain available.",
		msgNodeCancelReview:          "Cancel this review",
		msgNodeEndAccess:             "End this App's Node access",
		msgInitialAuthorization:      "Initial setup access",
		msgNodeSection:               "Your Node",
		msgNodeIntro:                 "Start Cicada Node on your Ubuntu computer, then enter the connection code shown there.",
		msgNodeCode:                  "Node connection code",
		msgNodePreview:               "Review this Node",
		msgNodeApprove:               "Approve this connection",
		msgNodeRefresh:               "Check Node status",
		msgNodeRecover:               "Recover saved Node request",
		msgNodeReview:                "Check this exact Node",
		msgNodeIdentityConsent:       "I checked the Node and Hub key fingerprints against the trusted Node screen.",
		msgNodeAccessConsent:         "I approve the limited access shown for this Node.",
		msgNodeScope:                 "Allow this App to approve only the Node shown here and read its connection status until the displayed expiry. Access does not renew automatically.",
		msgNodeName:                  "Computer",
		msgNodeID:                    "Node ID",
		msgNodeFingerprint:           "Node key fingerprint",
		msgNodeFingerprints:          "Key fingerprints",
		msgNodeHubFingerprint:        "Hub Node-Control key fingerprint",
		msgNodeCandidateUntil:        "Approve before",
		msgNodeAccessUntil:           "Node access expires",
		msgNodeObservation:           "Status checked at",
		msgNodeLastHeartbeat:         "Last Node heartbeat",
		msgNodeNotBound:              "No Node connection approved yet.",
		msgNodeUnknown:               "Node status has not been confirmed.",
		msgNodeOnline:                "Node online",
		msgNodeOffline:               "Node offline",
		msgNodeStale:                 "Node status is out of date.",
		msgNodeBound:                 "Node connection approved. Waiting for a current Node observation.",
		msgNodeRecovery:              "The last Node response is unconfirmed. Recover the saved request before approving another connection.",
		msgNodeUnavailable:           "Connect and sign in to review your Node connection.",
		msgNodeAccessActive:          "Limited access to this Node is confirmed.",
		msgNodeAccessExpired:         "This Node authorization has expired. It does not renew automatically.",
		msgNodeAccessRevoked:         "This Node authorization was revoked.",
		msgNodeAccessUnconfirmed:     "Node authorization has not been confirmed.",
		msgNodeCandidateExpired:      "This Node review has expired. Check its saved state or end this review before starting another review.",
		msgNodeInitialReviewExpired:  "This Node connection review has expired. Check its saved state or end this review before using a current Node code.",
		msgNodeStatusReviewExpired:   "This status-access review has expired. Check its saved state or end this review, then explicitly review status access again.",
		msgNodeUnboundSessionEnded:   "The sign-in used for this unfinished Node connection has ended.",
		msgAppTitle:                  "Cicada",
		msgLanguage:                  "Language",
		msgEnglish:                   "English",
		msgChinese:                   "简体中文",
		msgConnection:                "Connection",
		msgUnverified:                "Hub not verified",
		msgLocked:                    "Locked",
		msgClaimPending:              "Account setup pending",
		msgOwnerPending:              "Owner proof pending",
		msgOwnerReady:                "Owner ready",
		msgUnavailable:               "Unavailable",
		msgError:                     "Error",
		msgHub:                       "Hub",
		msgAccount:                   "Account",
		msgCanvas:                    "Canvas",
		msgNotConnected:              "Connect to a Hub to continue.",
		msgActivationCode:            "One-time activation code",
		msgConnect:                   "Connect",
		msgVerifyHub:                 "Verify Hub identity",
		msgHealthPublic:              "Public health does not establish an account or management authority.",
		msgUnlock:                    "Unlock local vault",
		msgLogin:                     "Log in",
		msgUsername:                  "Username",
		msgPassword:                  "Password",
		msgClaim:                     "Create account",
		msgImportOwner:               "Import existing Owner key",
		msgOwnerProofPending:         "The account is ready, but Owner key-possession proof is still required.",
		msgManagementEnabled:         "Management authority is active.",
		msgManagementDisabled:        "General management is not authorized.",
		msgRefresh:                   "Refresh status",
		msgLogout:                    "Log out",
		msgNoCanvasAuthority:         "No authorized canvas data is available.",
		msgCanvasUnavailable:         "Canvas unavailable",
		msgCanvasPreview:             "Open local preview",
		msgPreviewBanner:             "LOCAL PREVIEW — these sample objects are not Hub data and grant no authority.",
		msgSelected:                  "Selected",
		msgOperationInProgress:       "Working…",
		msgTryAgain:                  "Review current state before retrying",
		msgHubIdentity:               "Hub identity",
		msgHubFingerprint:            "Full Hub fingerprint",
		msgOrigin:                    "Origin",
		msgHealth:                    "Public health",
		msgNoData:                    "No data",
		msgErrorCode:                 "Error code",
		msgRequestFailed:             "The operation could not be completed. Review the current state before trying again.",
		msgGenerateOwner:             "Generate Owner identity",
		msgSelectOwnerFiles:          "Import existing Owner identity files",
		msgOwnerFilesUnsupported:     "Native Owner file selection is available on Windows in this build.",
		msgSelectKEMPrivate:          "Select the existing ML-KEM-768 private PEM",
		msgSelectSigningPrivate:      "Select the existing ML-DSA-65 private PEM",
		msgSelectKEMPublic:           "Select the matching ML-KEM-768 public PEM",
		msgSelectSigningPublic:       "Select the matching ML-DSA-65 public PEM",
		msgCanvasInstruction:         "Drag to pan. Use the mouse wheel to zoom. Click an object to select it.",
		msgHubPinned:                 "Pinned Hub identity",
		msgHubUnverified:             "Hub identity is not verified",
		msgAccountUnknown:            "Account not loaded",
		msgAccountClaimPending:       "Claim pending",
		msgAccountLoginRequired:      "Login required",
		msgAccountSessionCheck:       "Session recheck required",
		msgAccountSession:            "Account session active",
		msgAccountOwnerPending:       "Owner proof pending",
		msgAccountOwnerReady:         "Owner ready",
		msgRootUnknown:               "Root status unknown",
		msgRootUnavailable:           "Root unavailable",
		msgRootPending:               "Root proof pending",
		msgRootActive:                "Root active",
		msgLocalKeyPresent:           "Local Owner key present",
		msgLocalKeyMissing:           "Local Owner key not present",
		msgAccountID:                 "Account ID",
		msgOwnerID:                   "Owner ID",
		msgOwnerFingerprint:          "Owner fingerprint",
		msgAccountState:              "Account state",
		msgRootState:                 "Root state",
		msgPrepareClaim:              "Prepare account claim",
		msgCompleteClaim:             "Complete account setup",
		msgStartLogin:                "Start login",
		msgGenerateLocalOwner:        "Generate local Owner identity",
		msgRecoverExact:              "Recover exact saved request",
		msgDiscoverProfiles:          "Find saved connections",
		msgSavedProfiles:             "Your saved connections",
		msgResumeProfile:             "Unlock & continue",
		msgWelcome:                   "Your Cicada, connected.",
		msgWelcomeBody:               "Connect to your trusted Hub. Your private keys stay on this device.",
		msgStepConnect:               "1  Connect your Hub",
		msgStepKeys:                  "2  Keep your identity safe",
		msgStepAccount:               "3  Set up your account",
		msgKeysBody:                  "Already an Owner? Import your existing keys to keep your identity. For a new identity, create keys here and store them securely on this device.",
		msgRecoveryBody:              "The last response is unconfirmed. Cicada has saved your request and will retry the same package. Keep this connection to recover safely.",
		msgConnectionMaterial:        "Activation code or trusted connection card",
		msgSetupReady:                "Your account connection",
		msgActivateApp:               "Activate this App",
		msgGrantBody:                 "Allow this App to read the Node list and check its session permissions for 15 minutes. This does not allow changes or grant general management access. Access does not renew automatically.",
		msgGrantConsent:              "I approve this limited access for this App.",
		msgKeysStored:                "Your Owner keys are stored securely on this device.",
		msgLoginBody:                 "Sign in to your account on this registered device.",
		msgConnectionDetails:         "Connection details",
		msgAccessActive:              "Limited App access is confirmed.",
		msgAccessLogin:               "App activation is confirmed. Log in to use its limited access.",
		msgAccessRecheck:             "Saved access needs a fresh Hub check.",
		msgAccessExpired:             "This 15-minute access period has ended. It will not renew automatically.",
		msgAccessRevoked:             "App access has been revoked.",
		msgAccessUnavailable:         "App access is not available.",
		msgAccessUnconfirmed:         "App access has not been confirmed.",
		msgAccessUntil:               "Access ends at",
		msgRecoverConnection:         "Recover connection",
		msgRequestUnknown:            "The Hub response is unconfirmed. Your saved request is safe; recover this connection to check its result.",
		msgRequestRejected:           "The Hub refused the previous request. Check your details and try again.",
		msgMaterialInvalid:           "This connection code is invalid or expired. Get current material from your Hub operator.",
		msgLocalUnlockFailed:         "This Windows account could not unlock the saved connection.",
		msgHubTrustFailed:            "The Hub identity could not be verified. Check the trusted Hub address before continuing.",
		msgOwnerMismatch:             "Use the original Owner keys for this Hub. The selected identity does not match.",
		msgEncryptedOwnerUnsupported: "This build supports unencrypted PKCS#8 Owner PEM files only. Encrypted PEM import is not supported. Your keys have not been changed.",
		msgReplacementCode:           "Use a new activation code",
		msgReplacementBody:           "Your previous setup did not activate Root. Enter replacement material from your Hub operator to continue with the same local keys.",
		msgBackToActivation:          "Back to activation",
	},
	Chinese: {
		msgNodeUnavailableError: "此 Hub 的 Node 连接服务当前不可用。已保存的请求会继续保留。",
		msgNodeCodeInvalid:      "请输入 Node 当前屏幕上显示的连接码。",
		msgNodeCounterConflict:  "暂时无法安全核对此 Node 会话，原有状态已保留。",
		msgNodeSessionEnded:     "本次 Node 访问所绑定的登录已结束。请登录后明确重新授权查看状态。",
		msgNodeAccessEnded:      "此 App 的 Node 访问已结束。",

		msgNodeReviewStatus:          "核对此 Node 的状态访问",
		msgNodeStatusScope:           "仅允许在显示的截止时间前查看此前已批准 Node 的状态。本次授权不会重新配对 Node，也不会续期此前的授权。",
		msgNodeStatusConsent:         "我同意此 App 在所示期限内查看此 Node 的状态。",
		msgNodeAuthorizeStatus:       "允许查看状态",
		msgNodeReauthorizeStatus:     "重新授权查看状态",
		msgNodeAccountRecovery:       "还有一个 Node 请求已保存。请先恢复上方的账户请求，Node 原始请求会继续保留。",
		msgNodeCancelReview:          "取消此次核对",
		msgNodeEndAccess:             "结束此 App 的 Node 访问",
		msgInitialAuthorization:      "首次设置授权",
		msgNodeSection:               "你的 Node",
		msgNodeIntro:                 "在 Ubuntu 电脑上启动 Cicada Node，然后输入该电脑显示的连接码。",
		msgNodeCode:                  "Node 连接码",
		msgNodePreview:               "查看此 Node",
		msgNodeApprove:               "批准此连接",
		msgNodeRefresh:               "检查 Node 状态",
		msgNodeRecover:               "恢复已保存的 Node 请求",
		msgNodeReview:                "核对此 Node",
		msgNodeIdentityConsent:       "我已与可信 Node 屏幕核对 Node 和 Hub 密钥的完整指纹。",
		msgNodeAccessConsent:         "我同意此 App 在所示范围和期限内批准并查看此 Node。",
		msgNodeScope:                 "允许此 App 在显示的截止时间前，仅批准此处所示 Node 并读取其连接状态。授权不会自动续期。",
		msgNodeName:                  "电脑名称",
		msgNodeID:                    "Node ID",
		msgNodeFingerprint:           "Node 密钥指纹",
		msgNodeFingerprints:          "密钥指纹",
		msgNodeHubFingerprint:        "Hub Node-Control 密钥指纹",
		msgNodeCandidateUntil:        "确认截止时间",
		msgNodeAccessUntil:           "Node 授权截止时间",
		msgNodeObservation:           "状态核对时间",
		msgNodeLastHeartbeat:         "最近 Node 心跳",
		msgNodeNotBound:              "尚未批准 Node 连接。",
		msgNodeUnknown:               "Node 当前状态尚未确认。",
		msgNodeOnline:                "Node 在线",
		msgNodeOffline:               "Node 离线",
		msgNodeStale:                 "Node 状态已陈旧。",
		msgNodeBound:                 "Node 连接已获批准，正在等待当前 Node 状态。",
		msgNodeRecovery:              "上次 Node 响应尚未确认。请先恢复已保存的请求，再批准其他连接。",
		msgNodeUnavailable:           "连接并登录后，可核对 Node 连接。",
		msgNodeAccessActive:          "对此 Node 的有限访问已确认。",
		msgNodeAccessExpired:         "本次 Node 授权已到期，不会自动续期。",
		msgNodeAccessRevoked:         "本次 Node 授权已撤销。",
		msgNodeAccessUnconfirmed:     "Node 授权尚未确认。",
		msgNodeCandidateExpired:      "此次 Node 核对已过期。请先检查已保存的状态或结束此次核对，再开始新的核对。",
		msgNodeInitialReviewExpired:  "此次 Node 连接核对已过期。请先检查已保存的状态或结束此次核对，再使用 Node 当前连接码。",
		msgNodeStatusReviewExpired:   "此次状态访问核对已过期。请先检查已保存的状态或结束此次核对，再明确重新核对状态授权。",
		msgNodeUnboundSessionEnded:   "此次未完成 Node 连接所绑定的登录已结束。",
		msgAppTitle:                  "Cicada",
		msgLanguage:                  "语言",
		msgEnglish:                   "English",
		msgChinese:                   "简体中文",
		msgConnection:                "连接",
		msgUnverified:                "Hub 身份未验证",
		msgLocked:                    "已锁定",
		msgClaimPending:              "账户设置待完成",
		msgOwnerPending:              "Owner 密钥证明待完成",
		msgOwnerReady:                "Owner 已就绪",
		msgUnavailable:               "不可用",
		msgError:                     "错误",
		msgHub:                       "Hub",
		msgAccount:                   "账户",
		msgCanvas:                    "画布",
		msgNotConnected:              "请先连接 Hub。",
		msgActivationCode:            "一次性激活码",
		msgConnect:                   "连接",
		msgVerifyHub:                 "验证 Hub 身份",
		msgHealthPublic:              "公开健康状态不能证明账户或管理权限。",
		msgUnlock:                    "解锁本地保险库",
		msgLogin:                     "登录",
		msgUsername:                  "用户名",
		msgPassword:                  "密码",
		msgClaim:                     "创建账户",
		msgImportOwner:               "导入现有 Owner 密钥",
		msgOwnerProofPending:         "账户已就绪，但仍需完成 Owner 密钥持有证明。",
		msgManagementEnabled:         "管理权限已激活。",
		msgManagementDisabled:        "通用管理权限尚未开通。",
		msgRefresh:                   "刷新状态",
		msgLogout:                    "退出登录",
		msgNoCanvasAuthority:         "当前没有已授权的画布数据。",
		msgCanvasUnavailable:         "画布不可用",
		msgCanvasPreview:             "打开本地预览",
		msgPreviewBanner:             "本地预览——这些示例对象不是 Hub 数据，也不授予任何权限。",
		msgSelected:                  "已选中",
		msgOperationInProgress:       "正在处理…",
		msgTryAgain:                  "重试前请先查看当前状态",
		msgHubIdentity:               "Hub 身份",
		msgHubFingerprint:            "完整 Hub 指纹",
		msgOrigin:                    "来源地址",
		msgHealth:                    "公开健康状态",
		msgNoData:                    "无数据",
		msgErrorCode:                 "错误代码",
		msgRequestFailed:             "操作未能完成。请查看当前状态后再决定是否重试。",
		msgGenerateOwner:             "生成 Owner 身份",
		msgSelectOwnerFiles:          "导入现有 Owner 身份文件",
		msgOwnerFilesUnsupported:     "此版本仅在 Windows 上支持原生 Owner 文件选择。",
		msgSelectKEMPrivate:          "选择现有 ML-KEM-768 私钥 PEM",
		msgSelectSigningPrivate:      "选择现有 ML-DSA-65 私钥 PEM",
		msgSelectKEMPublic:           "选择匹配的 ML-KEM-768 公钥 PEM",
		msgSelectSigningPublic:       "选择匹配的 ML-DSA-65 公钥 PEM",
		msgCanvasInstruction:         "拖动以平移，滚动鼠标滚轮以缩放，单击对象以选中。",
		msgHubPinned:                 "已固定 Hub 身份",
		msgHubUnverified:             "Hub 身份尚未验证",
		msgAccountUnknown:            "账户尚未加载",
		msgAccountClaimPending:       "账户认领待完成",
		msgAccountLoginRequired:      "需要登录",
		msgAccountSessionCheck:       "需要重新验证会话",
		msgAccountSession:            "账户会话已激活",
		msgAccountOwnerPending:       "Owner 证明待完成",
		msgAccountOwnerReady:         "Owner 已就绪",
		msgRootUnknown:               "Root 状态未知",
		msgRootUnavailable:           "Root 不可用",
		msgRootPending:               "Root 证明待完成",
		msgRootActive:                "Root 已激活",
		msgLocalKeyPresent:           "本地存在 Owner 密钥",
		msgLocalKeyMissing:           "本地不存在 Owner 密钥",
		msgAccountID:                 "账户 ID",
		msgOwnerID:                   "Owner ID",
		msgOwnerFingerprint:          "Owner 指纹",
		msgAccountState:              "账户状态",
		msgRootState:                 "Root 状态",
		msgPrepareClaim:              "准备账户认领",
		msgCompleteClaim:             "完成账户设置",
		msgStartLogin:                "开始登录",
		msgGenerateLocalOwner:        "生成本地 Owner 身份",
		msgRecoverExact:              "恢复完全相同的已保存请求",
		msgDiscoverProfiles:          "查找已保存的连接",
		msgSavedProfiles:             "已保存的连接",
		msgResumeProfile:             "解锁并继续",
		msgWelcome:                   "连接你的 Cicada。",
		msgWelcomeBody:               "连接可信 Hub，私钥始终保存在这台设备上。",
		msgStepConnect:               "1  连接你的 Hub",
		msgStepKeys:                  "2  安全保管你的身份",
		msgStepAccount:               "3  设置你的账户",
		msgKeysBody:                  "已有 Owner 身份？请导入原有密钥以保留身份。首次使用可在本机生成密钥，并安全保存在此设备上。",
		msgRecoveryBody:              "上次请求的结果尚未确认。Cicada 已保存请求，将重发同一个包。请保留此连接以安全恢复。",
		msgConnectionMaterial:        "激活码或可信连接卡",
		msgSetupReady:                "你的账户连接",
		msgActivateApp:               "激活此 App",
		msgGrantBody:                 "允许此 App 在 15 分钟内读取 Node 列表、查询会话权限。此授权不允许修改，也不授予通用管理权限；到期不会自动续期。",
		msgGrantConsent:              "我同意向此 App 授予上述有限权限。",
		msgKeysStored:                "Owner 密钥已安全保存在这台设备上。",
		msgLoginBody:                 "在这台已登记的设备上登录你的账户。",
		msgConnectionDetails:         "连接详情",
		msgAccessActive:              "App 有限权限已确认。",
		msgAccessLogin:               "App 激活已确认。登录后可使用有限权限。",
		msgAccessRecheck:             "已保存的授权需要重新向 Hub 核验。",
		msgAccessExpired:             "本次 15 分钟授权已到期，不会自动续期。",
		msgAccessRevoked:             "App 授权已撤销。",
		msgAccessUnavailable:         "App 授权当前不可用。",
		msgAccessUnconfirmed:         "App 授权尚未确认。",
		msgAccessUntil:               "授权截止时间",
		msgRecoverConnection:         "恢复连接",
		msgRequestUnknown:            "Hub 响应尚未确认。请求已安全保存，请恢复连接以核对结果。",
		msgRequestRejected:           "Hub 已拒绝上次请求。请检查输入信息后重试。",
		msgMaterialInvalid:           "连接码无效或已过期，请向 Hub 操作员获取当前连接材料。",
		msgLocalUnlockFailed:         "当前 Windows 账户无法解锁已保存的连接。",
		msgHubTrustFailed:            "无法验证 Hub 身份。请先核对可信的 Hub 地址。",
		msgOwnerMismatch:             "此 Hub 需要原有 Owner 密钥，所选身份不匹配。",
		msgEncryptedOwnerUnsupported: "此版本仅支持未加密的 PKCS#8 Owner PEM 文件，暂不支持加密 PEM。原有密钥未作修改。",
		msgReplacementCode:           "使用新的激活码",
		msgReplacementBody:           "此前设置尚未激活 Root。可输入 Hub 操作员提供的新材料，保留本机原有密钥继续设置。",
		msgBackToActivation:          "返回激活步骤",
	},
}

// NormalizeLocale selects one of the two supported catalogs and falls back to
// English for unknown persisted or system locale values.
func NormalizeLocale(value string) Locale {
	if value == string(Chinese) || value == "zh" || value == "zh-Hans" || value == "zh_CN" {
		return Chinese
	}
	return English
}

func text(locale Locale, id messageID) string {
	if translated, ok := catalog[locale][id]; ok {
		return translated
	}
	return catalog[English][id]
}

// Text returns a reviewed catalog entry or the English fallback. The key is a
// stable app-local label; arbitrary data must be passed separately and is
// never translated or treated as markup.
func Text(locale Locale, key string) string {
	return text(locale, messageID(key))
}

// TranslationCount is intentionally small and exposed only to package tests;
// it lets catalog parity be checked without exporting translation keys.
func translationCount(locale Locale) int {
	return len(catalog[locale])
}
