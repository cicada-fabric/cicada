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
)

var catalog = map[Locale]map[messageID]string{
	English: {
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
		msgManagementDisabled:        "Management is not authorized. No management data is shown.",
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
	},
	Chinese: {
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
		msgManagementDisabled:        "尚未获得管理授权，不会显示管理数据。",
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
