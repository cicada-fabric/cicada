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
	msgHubAddress                messageID = "connection.hub_address"
	msgBootstrapCode             messageID = "connection.bootstrap_code"
	msgSavedHubAddress           messageID = "connection.saved_address_override"
	msgLegacyConnection          messageID = "connection.legacy_input"
	msgDirectConnection          messageID = "connection.direct_input"
	msgTransportVerifying        messageID = "connection.transport_verifying"
	msgTransportVerified         messageID = "connection.transport_verified"
	msgTransportFailed           messageID = "connection.transport_failed"
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
	msgHubCopyAddress            messageID = "hub.address"
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
	msgOwnerKeyID                messageID = "account.owner_key_id"
	msgOwnerPeerFingerprint      messageID = "account.owner_peer_fingerprint"
	msgExportOwnerPublic         messageID = "account.export_owner_public"
	msgExportOwnerPublicFailed   messageID = "account.export_owner_public_failed"
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
	msgHubAddressInvalid         messageID = "error.hub_address_invalid"
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
	msgNodeSavedConnection       messageID = "node.saved_connection"
	msgNodeSavedConnectionBody   messageID = "node.saved_connection_body"
	msgNodeConnectionStatus      messageID = "node.connection_status"
	msgNodeStatusAccess          messageID = "node.status_access"
	msgNodeAwaitingHeartbeat     messageID = "node.awaiting_heartbeat"
	msgNodeSignInForStatus       messageID = "node.sign_in_for_status"
	msgNodeReauthorizeToCheck    messageID = "node.reauthorize_to_check"
	msgNodeCheckAccessToContinue messageID = "node.check_access_to_continue"
	msgNodeCheckAccess           messageID = "node.check_access"
	msgNodeCheckForCurrentStatus messageID = "node.check_for_current_status"
	msgNodeAccountRecoveryFirst  messageID = "node.account_recovery_first"
	msgNodeUpdatingStatus        messageID = "node.updating_status"
	msgNodeCheckingStatusAccess  messageID = "node.checking_status_access"
	msgSavedConnection           messageID = "connection.saved_connection"
	msgCheckSavedSession         messageID = "setup.check_saved_session"
	msgContinueSavedSession      messageID = "setup.continue_saved_session"
	msgPrivateRecoveryBody       messageID = "setup.private_recovery_body"
	msgProfileRecoveryTitle      messageID = "setup.profile_recovery_title"
	msgProfileRecoveryBody       messageID = "setup.profile_recovery_body"
	msgRetrySavedConnection      messageID = "connection.retry_saved_connection"
	msgProfileInUse              messageID = "error.profile_in_use"
	msgPairTitle                 messageID = "pair.title"
	msgPairIntro                 messageID = "pair.intro"
	msgPairLabel                 messageID = "pair.label"
	msgPairPrepare               messageID = "pair.prepare"
	msgPairBootstrapReview       messageID = "pair.bootstrap_review"
	msgPairBootstrapConsent      messageID = "pair.bootstrap_consent"
	msgPairComplete              messageID = "pair.complete"
	msgPairID                    messageID = "pair.id"
	msgPairNode                  messageID = "pair.node"
	msgPairJoinUntil             messageID = "pair.join_until"
	msgPairUntil                 messageID = "pair.until"
	msgPairRefresh               messageID = "pair.refresh"
	msgPairReviewSlots           messageID = "pair.review_slots"
	msgPairSlot                  messageID = "pair.slot"
	msgPairSID                   messageID = "pair.sid"
	msgPairFingerprint           messageID = "pair.fingerprint"
	msgPairSlotConsent           messageID = "pair.slot_consent"
	msgPairApproveSlot           messageID = "pair.approve_slot"
	msgPairRejectSlot            messageID = "pair.reject_slot"
	msgPairRecorded              messageID = "pair.recorded"
	msgPairRevokeConsent         messageID = "pair.revoke_consent"
	msgPairRevoke                messageID = "pair.revoke"
	msgPairSaved                 messageID = "pair.saved"
	msgPairPolicy                messageID = "pair.policy"
	msgPairPrepared              messageID = "pair.state.prepared"
	msgPairWaitingJoin           messageID = "pair.state.waiting_join"
	msgPairWaitingConsent        messageID = "pair.state.waiting_consent"
	msgPairActive                messageID = "pair.state.active"
	msgPairExpired               messageID = "pair.state.expired"
	msgPairRevoked               messageID = "pair.state.revoked"
	msgPairUnavailable           messageID = "pair.error.unavailable"
	msgPairUnknown               messageID = "pair.error.unknown"
	msgPairTargetChanged         messageID = "pair.error.target_changed"
	msgPairFenced                messageID = "pair.error.fenced"
)

const (
	msgCopy            messageID = "common.copy"
	msgCopied          messageID = "common.copied"
	msgAccountDeviceID messageID = "account.device_id"
	msgNodeBindingID   messageID = "node.binding_id"
	msgPairKeyID       messageID = "pair.key_id"
	msgPairTargetHash  messageID = "pair.target_digest"
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
		"local_collaboration.title":          "Local collaboration",
		"local_collaboration.scope":          "Configure collaboration once for registered Threads under this Node's current OS user.",
		"local_collaboration.independent":    "Closing the App or account sign-in expiry does not stop this policy.",
		"local_collaboration.create_network": "Create a private Network",
		"local_collaboration.network_name":   "Private Network name",
		"local_collaboration.network_id":     "Network",
		"local_collaboration.legacy_pair":    "Existing Pair setup (advanced)",
		"local_collaboration.group_name":     "Local collaboration name",
		"local_collaboration.policy":         "Policy",
		"local_collaboration.os_user":        "Node OS-user scope",
		"local_collaboration.group_id":       "Dedicated Group",
		"local_collaboration.until":          "Policy lifetime",
		"local_collaboration.until_revoked":  "Until revoked",
		"local_collaboration.day":            "24 hours",
		"local_collaboration.week":           "7 days",
		"local_collaboration.month":          "30 days",
		"local_collaboration.prepare":        "Review this Node's collaboration",
		"local_collaboration.activate":       "Enable local collaboration",
		"local_collaboration.consent":        "Allow this Node to admit registered Threads into the displayed local collaboration scope.",
		"local_collaboration.review_body":    "This enables local send, ask and reply in the displayed Network and Group. Other Nodes and resource access keep their separate authority checks.",
		"local_collaboration.refresh":        "Read this Node's current configuration",
		"local_collaboration.revoke":         "Revoke this local policy",
		"local_collaboration.revoke_consent": "Stop new collaboration under this exact policy.",
		"local_collaboration.recover":        "Recover the original request",
		"local_collaboration.unchecked":      "The current configuration has not been read from the Hub.",
		"local_collaboration.unavailable":    "This Hub does not provide the required local collaboration feature.",
		"local_collaboration.unconfigured":   "This Node has no current local collaboration policy.",
		"local_collaboration.review":         "Review the exact scope before enabling it.",
		"local_collaboration.review-expired": "This review expired; read the current configuration again.",
		"local_collaboration.active":         "Local collaboration is enabled.",
		"local_collaboration.saved":          "A saved policy is present; its current state needs confirmation.",
		"local_collaboration.expired":        "This local collaboration policy expired.",
		"local_collaboration.revoked":        "This local collaboration policy was revoked.",
		"local_collaboration.pending":        "The original request is retained; reconcile it before starting another operation.",

		"directory.title":                "Threads on this Node",
		"directory.park":                 "Retain the unconfirmed read and continue",
		"directory.park_body":            "This read proof has expired. Retain the complete original request locally as UNKNOWN and release its slot. This does not confirm a Hub outcome.",
		"directory.retained":             "Unconfirmed reads retained locally",
		"directory.retained_body":        "The original read is retained locally as UNKNOWN. Its Hub outcome remains unconfirmed.",
		"directory.history_full":         "The unconfirmed-read history has reached its limit. Original requests are retained and no new directory read can start.",
		"directory.scope":                "Read up to 64 of your own Threads using this App's local Owner key. Registration is separate from communication permission.",
		"directory.read":                 "Read this Node's Threads",
		"directory.next":                 "Read the next page",
		"directory.recover":              "Recover the original directory read",
		"directory.pending":              "A directory request is saved. Recover its original result before starting another operation.",
		"directory.snapshot":             "Snapshot captured",
		"directory.expired":              "This signed read expired. Choose Read to request a new snapshot.",
		"directory.empty":                "No Threads were returned for this Node.",
		"directory.name":                 "Thread name",
		"directory.workspace":            "Workspace",
		"directory.endpoint_id":          "Endpoint ID",
		"directory.harness":              "Runtime",
		"directory.offline":              "Offline at the snapshot time",
		"directory.left":                 "Left",
		"directory.lease_recent":         "Lease recently valid at the snapshot time",
		"directory.unknown":              "Current presence unknown",
		"directory.unavailable":          "This Hub's Owner directory is unavailable. No new directory request was sent.",
		"directory.unknown_result":       "The original directory result is unconfirmed. Its saved request is retained for recovery.",
		"storage.user_root":              "Selected user-file root",
		"storage.vault_root":             "Current identity-vault location",
		"storage.legacy_body":            "The current identity is opened from its original location. It has not been migrated to the selected new-profile root.",
		"workspace.hub_verified":         "Hub verified",
		"workspace.continue_account":     "Complete the next account step to continue.",
		"workspace.continue_operation":   "Continue the original operation",
		"workspace.navigation":           "WORKSPACE",
		"workspace.overview":             "Overview",
		"workspace.devices":              "Devices",
		"workspace.sessions":             "Sessions & communication",
		"workspace.identity":             "Identity & access",
		"workspace.settings":             "Settings",
		"workspace.overview_body":        "Review your device and continue the next step in your workspace.",
		"workspace.devices_unavailable":  "Device access is not available for this connection.",
		"workspace.sessions_unavailable": "Session communication is not available for this connection.",
		"workspace.identity_body":        "Account login, Owner identity and communication permission are separate. Each operation uses its own confirmed authorization.",
		"workspace.settings_body":        "Choose English or Chinese from the language controls. Both use the same account and authorization checks.",
		"workspace.storage_body":         "Existing local identities remain in their original location. Changing the installation root must not recreate or silently move private keys.",
		"workspace.communication_body":   "Review the exact sessions, scope and expiry before separately approving each side. Registration alone does not permit communication.",
		"workspace.review_sessions":      "Review session access",
		"workspace.view_device":          "View device",
		"workspace.connect_device":       "Connect a device",
		"workspace.details":              "Show identifiers and fingerprints",
		"workspace.hide_details":         "Hide technical details",
		msgCopy:                          "Copy",
		msgCopied:                        "Copied",
		msgAccountDeviceID:               "App device ID",
		msgNodeBindingID:                 "Node binding ID",
		msgPairKeyID:                     "Candidate key ID",
		msgPairTargetHash:                "Full target digest",
		msgOwnerKeyID:                    "Local Owner key ID",
		msgOwnerPeerFingerprint:          "Local Owner fingerprint for Node trust",
		msgExportOwnerPublic:             "Save Owner public key JSON to a new file",
		msgExportOwnerPublicFailed:       "The public key could not be saved. Choose a new file in a writable folder; existing files are preserved.",
		msgPairTitle:                     "Two Codex conversations",
		msgPairIntro:                     "Prepare a private conversation between two actual Codex sessions on this Node, then review and approve each session.",
		msgPairLabel:                     "Conversation name",
		msgPairPrepare:                   "Prepare conversation",
		msgPairBootstrapReview:           "Review the two empty slots",
		msgPairBootstrapConsent:          "Create these two empty slots on this Node. Each actual session still needs my separate approval.",
		msgPairComplete:                  "Create reviewed slots",
		msgPairID:                        "Conversation ID",
		msgPairNode:                      "Node",
		msgPairJoinUntil:                 "Sessions must join by",
		msgPairUntil:                     "Permission ends",
		msgPairRefresh:                   "Check conversation",
		msgPairReviewSlots:               "Review both actual sessions",
		msgPairSlot:                      "Slot",
		msgPairSID:                       "Actual session",
		msgPairFingerprint:               "Candidate key fingerprint",
		msgPairSlotConsent:               "Approve this exact session and key for the displayed peer and limits.",
		msgPairApproveSlot:               "Approve this session",
		msgPairRejectSlot:                "Reject this joined session",
		msgPairRecorded:                  "Approval recorded; permission starts only after both approvals.",
		msgPairRevokeConsent:             "End this pair's permissions for both sessions.",
		msgPairRevoke:                    "Revoke this conversation",
		msgPairSaved:                     "Saved observation. Check again for current state.",
		msgPairPolicy:                    "Only these two sessions: up to four questions and four replies, one outstanding question, at most 8 KiB per message. No shared history.",
		msgPairPrepared:                  "Empty slots awaiting approval",
		msgPairWaitingJoin:               "Waiting for two actual sessions to join",
		msgPairWaitingConsent:            "Waiting for separate session approvals",
		msgPairActive:                    "Limited conversation permission is active",
		msgPairExpired:                   "Conversation permission has ended",
		msgPairRevoked:                   "Conversation permission was revoked",
		msgPairUnavailable:               "This Hub does not currently provide the conversation setup service. Saved requests are retained.",
		msgPairUnknown:                   "The saved request is not confirmed. Recover it before starting another operation.",
		msgPairTargetChanged:             "The reviewed target changed or expired. Check the conversation and review it again.",
		msgPairFenced:                    "The request was safely rejected without its proposed change. Check the conversation before trying again.",
		msgProfileRecoveryTitle:          "Saved connection unavailable",
		msgProfileRecoveryBody:           "Retry opening your saved connection before continuing.",
		msgRetrySavedConnection:          "Retry saved connection",
		msgProfileInUse:                  "Your saved connection is in use by another Cicada window. Continue there, or close that window before retrying.",
		msgSavedConnection:               "Saved connection",
		msgCheckSavedSession:             "Verify your saved sign-in to continue.",
		msgContinueSavedSession:          "Continue sign-in",
		msgPrivateRecoveryBody:           "A saved request has an unconfirmed result. Recover it before continuing.",
		msgNodeUnavailableError:          "This Hub's Node connection service is unavailable. Your saved requests are retained.",
		msgNodeCodeInvalid:               "Enter the current connection code shown on your Node.",
		msgNodeCounterConflict:           "The saved Node conversation could not be reconciled safely. Its state has been retained.",
		msgNodeSessionEnded:              "The sign-in used for this status access has ended.",
		msgNodeAccessEnded:               "This App's Node access has ended.",
		msgNodeSavedConnection:           "Saved Node connection",
		msgNodeSavedConnectionBody:       "This saved connection remains when sign-in or status access expires.",
		msgNodeConnectionStatus:          "Current connection status",
		msgNodeStatusAccess:              "Status access",
		msgNodeAwaitingHeartbeat:         "This status record has no recent Node heartbeat yet. Check Node status for an update.",
		msgNodeSignInForStatus:           "Sign in to view this Node's current status. Its saved connection is kept.",
		msgNodeReauthorizeToCheck:        "Continue viewing status to review this App's next limited status access.",
		msgNodeCheckAccessToContinue:     "Check this App's status access before continuing to view this saved Node.",
		msgNodeCheckAccess:               "Check status access",
		msgNodeCheckForCurrentStatus:     "Check Node status to get the latest result.",
		msgNodeAccountRecoveryFirst:      "Recover the saved account request before checking this Node's current status.",
		msgNodeUpdatingStatus:            "Checking for the latest status…",
		msgNodeCheckingStatusAccess:      "Checking current status access…",

		msgNodeReviewStatus:      "Review this status access",
		msgNodeStatusScope:       "Allow only status reads for this previously approved Node until the displayed expiry. This does not pair the Node again or renew its previous authorization.",
		msgNodeStatusConsent:     "I allow this App to read this Node's status for the shown period.",
		msgNodeAuthorizeStatus:   "Allow status access",
		msgNodeReauthorizeStatus: "Continue viewing status",
		msgNodeAccountRecovery:   "A Node request is also saved. Recover the account request above first; the original Node request will remain available.",
		msgNodeCancelReview:      "Cancel this review",
		msgNodeEndAccess:         "End this App's Node access",
		msgInitialAuthorization:  "Initial setup access",
		msgNodeSection:           "Your Node",

		"node_pairing.title":          "Connect a computer",
		"node_pairing.default":        "Use a device pairing code",
		"node_pairing.check":          "Check for confirmation",
		"node_pairing.preparing":      "Preparing this connection",
		"node_pairing.recovery":       "Resume saved pairing",
		"node_pairing.recovery_body":  "The last result is unconfirmed. Recover the original request before pairing again.",
		"node_pairing.ended":          "This pairing has ended. Request a new device code on the computer to try again.",
		"node_pairing.expired":        "This review has expired. Check the saved pairing outcome before starting again.",
		"node_pairing.unavailable":    "Device pairing is not currently available on this Hub.",
		"node_pairing.invalid":        "Enter the complete device pairing code shown by your Node.",
		"node_pairing.trust_mismatch": "This device code does not match your saved Hub connection.",
		"node_pairing.refused":        "Pairing was refused. Check the saved outcome before trying again.",
		"node_pairing.storage_full":   "There is not enough secure local storage to retain this operation safely. The saved request is preserved.",
		"node_pairing.intro":          "Paste the device pairing code shown by Cicada Node on the computer you want to connect.",
		"node_pairing.code":           "Device pairing code",
		"node_pairing.review_title":   "Check this computer",
		"node_pairing.approve":        "Approve and connect",
		"node_pairing.scope":          "Connect this computer to your Hub. Configure work permissions separately after pairing.",
		"node_pairing.waiting_title":  "Waiting for the computer",
		"node_pairing.deadline":       "Pairing deadline reached",
		"node_pairing.deadline_body":  "Check the saved result before starting again. The original approval and request remain saved.",
		"node_pairing.waiting_body":   "Approval was sent. Keep Cicada Node running while it confirms this connection.",
		"node_pairing.connected":      "Computer connected",
		"node_pairing.details":        "Connection details",
		"node_pairing.legacy":         "Advanced: use an older connection code",

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
		msgNodeAccessUntil:           "Status access valid until",
		msgNodeObservation:           "Status checked at",
		msgNodeLastHeartbeat:         "Last Node heartbeat",
		msgNodeNotBound:              "No Node connection approved yet.",
		msgNodeUnknown:               "Current status is unavailable. The saved Node connection is kept.",
		msgNodeOnline:                "Node online",
		msgNodeOffline:               "Node offline",
		msgNodeStale:                 "This status is out of date. Check for an update.",
		msgNodeBound:                 "Node connection approved. Waiting for a current Node observation.",
		msgNodeRecovery:              "The last Node response is unconfirmed. Recover the saved request before approving another connection.",
		msgNodeUnavailable:           "Connect and sign in to review your Node connection.",
		msgNodeAccessActive:          "Limited status access to this Node is confirmed.",
		msgNodeAccessExpired:         "This App's status access has expired. It does not renew automatically.",
		msgNodeAccessRevoked:         "This App's access to this Node was revoked.",
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
		msgHubCopyAddress:            "Hub IP address:port",
		msgBootstrapCode:             "Bootstrap code",
		msgSavedHubAddress:           "New IP address:port (optional; blank keeps the saved address)",
		msgLegacyConnection:          "Use an existing connection card or activation code",
		msgDirectConnection:          "Connect using an IP address",
		msgTransportVerifying:        "Verifying secure connection and Hub identity…",
		msgTransportVerified:         "Secure connection and Hub identity verified",
		msgTransportFailed:           "Secure connection or Hub identity could not be verified",
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
		msgHubAddress:                "Hub IP address:port",
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
		msgHubAddressInvalid:         "Enter a numeric IP address and port, such as 192.0.2.10:8443 or [2001:db8::10]:8443.",
		msgOwnerMismatch:             "Use the original Owner keys for this Hub. The selected identity does not match.",
		msgEncryptedOwnerUnsupported: "This build supports unencrypted PKCS#8 Owner PEM files only. Encrypted PEM import is not supported. Your keys have not been changed.",
		msgReplacementCode:           "Use a new activation code",
		msgReplacementBody:           "Your previous setup did not activate Root. Enter replacement material from your Hub operator to continue with the same local keys.",
		msgBackToActivation:          "Back to activation",
	},
	Chinese: {
		"local_collaboration.title":          "本地协作",
		"local_collaboration.scope":          "为该 Node 当前系统用户下的已登记会话配置一次协作。",
		"local_collaboration.independent":    "关闭 App 或账户登录到期不会停止此策略。",
		"local_collaboration.create_network": "创建私有 Network",
		"local_collaboration.network_name":   "私有 Network 名称",
		"local_collaboration.network_id":     "Network",
		"local_collaboration.legacy_pair":    "已有 Pair 配置（高级）",
		"local_collaboration.group_name":     "本地协作名称",
		"local_collaboration.policy":         "策略",
		"local_collaboration.os_user":        "Node 系统用户范围",
		"local_collaboration.group_id":       "专用 Group",
		"local_collaboration.until":          "策略有效期",
		"local_collaboration.until_revoked":  "持续至撤销",
		"local_collaboration.day":            "24 小时",
		"local_collaboration.week":           "7 天",
		"local_collaboration.month":          "30 天",
		"local_collaboration.prepare":        "核对该 Node 的协作范围",
		"local_collaboration.activate":       "启用本地协作",
		"local_collaboration.consent":        "允许该 Node 将已登记会话接入所示本地协作范围。",
		"local_collaboration.review_body":    "启用所示 Network 与 Group 内的本地发送、提问及回复。其他 Node 与资源访问仍分别核对授权。",
		"local_collaboration.refresh":        "读取该 Node 的当前配置",
		"local_collaboration.revoke":         "撤销此本地协作策略",
		"local_collaboration.revoke_consent": "停止此准确策略下的新协作。",
		"local_collaboration.recover":        "恢复原请求",
		"local_collaboration.unchecked":      "尚未从 Hub 读取该 Node 的当前配置。",
		"local_collaboration.unavailable":    "此 Hub 尚未提供所需的本地协作功能。",
		"local_collaboration.unconfigured":   "该 Node 当前没有本地协作策略。",
		"local_collaboration.review":         "请先核对准确范围，再启用协作。",
		"local_collaboration.review-expired": "本次核对已过期，请重新读取当前配置。",
		"local_collaboration.active":         "本地协作已启用。",
		"local_collaboration.saved":          "已有保存的策略，当前状态尚待确认。",
		"local_collaboration.expired":        "此本地协作策略已过期。",
		"local_collaboration.revoked":        "此本地协作策略已撤销。",
		"local_collaboration.pending":        "原请求已保留，请先对账再开始其他操作。",

		"directory.title":                "此 Node 上的 Thread",
		"directory.park":                 "保留未确认读取并继续",
		"directory.park_body":            "此读取证明已过期。可将完整原请求在本地保留为“未确认”，并释放请求槽；这不代表 Hub 已处理或已结算。",
		"directory.retained":             "本地保留的未确认读取",
		"directory.retained_body":        "原读取已在本地保留为“未确认”，Hub 处理结果仍未知。",
		"directory.history_full":         "未确认读取历史已达到容量上限。所有原请求均继续保留，暂不能创建新的目录读取。",
		"directory.scope":                "使用此 App 本地的 Owner 密钥，一次读取最多 64 个你自己的 Thread。登记与通信权限分别确认。",
		"directory.read":                 "读取此 Node 的 Thread",
		"directory.next":                 "读取下一页",
		"directory.recover":              "恢复原目录读取请求",
		"directory.pending":              "已有一个目录请求已保存。请先恢复它的原始结果，再开始其他操作。",
		"directory.snapshot":             "快照采集时间",
		"directory.expired":              "此次签名读取已过期。可点击读取以获取新快照。",
		"directory.empty":                "此 Node 的目录没有返回 Thread。",
		"directory.name":                 "Thread 名称",
		"directory.workspace":            "工作区",
		"directory.endpoint_id":          "Endpoint ID",
		"directory.harness":              "运行时",
		"directory.offline":              "快照时离线",
		"directory.left":                 "已离开",
		"directory.lease_recent":         "快照时租约近期有效",
		"directory.unknown":              "当前在线状态未知",
		"directory.unavailable":          "此 Hub 的 Owner 目录不可用，尚未发送新的目录请求。",
		"directory.unknown_result":       "原目录请求的结果尚未确认，已保留原包供恢复。",
		"storage.user_root":              "选定的用户文件根目录",
		"storage.vault_root":             "当前身份库的实际位置",
		"storage.legacy_body":            "当前身份继续从原位置打开，尚未迁移到选定的新配置根目录。",
		"workspace.hub_verified":         "Hub 已验证",
		"workspace.continue_account":     "完成当前账户步骤后继续。",
		"workspace.continue_operation":   "继续原操作",
		"workspace.navigation":           "工作空间",
		"workspace.overview":             "概览",
		"workspace.devices":              "设备",
		"workspace.sessions":             "会话与通信",
		"workspace.identity":             "身份与授权",
		"workspace.settings":             "设置",
		"workspace.overview_body":        "查看设备，并继续当前工作空间的下一步。",
		"workspace.devices_unavailable":  "当前连接暂不提供设备访问功能。",
		"workspace.sessions_unavailable": "当前连接暂不提供会话通信功能。",
		"workspace.identity_body":        "账户登录、Owner 身份和通信权限各自独立。每项操作按其已确认的授权执行。",
		"workspace.settings_body":        "通过语言控件选择中文或英文；两种界面使用相同的账户和授权检查。",
		"workspace.storage_body":         "已有本机身份继续使用原保存位置。改变安装根目录不会自动迁移或重建私钥。",
		"workspace.communication_body":   "核对精确会话、范围和期限后，分别确认双方的通信权限。登记本身不授予通信权限。",
		"workspace.review_sessions":      "审阅会话授权",
		"workspace.view_device":          "查看设备",
		"workspace.connect_device":       "连接设备",
		"workspace.details":              "展开标识与指纹",
		"workspace.hide_details":         "收起技术详情",
		msgCopy:                          "复制",
		msgCopied:                        "已复制",
		msgAccountDeviceID:               "App 设备 ID",
		msgNodeBindingID:                 "Node 绑定 ID",
		msgPairKeyID:                     "候选密钥 ID",
		msgPairTargetHash:                "完整目标摘要",
		msgOwnerKeyID:                    "本地 Owner 完整密钥 ID",
		msgOwnerPeerFingerprint:          "用于 Node 信任的本地 Owner 完整指纹",
		msgExportOwnerPublic:             "将 Owner 公钥 JSON 保存为新文件",
		msgExportOwnerPublicFailed:       "公钥保存失败。请在可写目录选择新文件名；已有文件会保留。",
		msgPairTitle:                     "两个 Codex 会话",
		msgPairIntro:                     "在此 Node 上准备两个真实 Codex 会话间的私有对话，再分别审核和同意每个会话。",
		msgPairLabel:                     "对话名称",
		msgPairPrepare:                   "准备对话",
		msgPairBootstrapReview:           "审核两个空席位",
		msgPairBootstrapConsent:          "在此 Node 创建这两个空席位。真实会话加入后，仍须由我分别同意。",
		msgPairComplete:                  "创建已审核席位",
		msgPairID:                        "对话编号",
		msgPairNode:                      "Node",
		msgPairJoinUntil:                 "会话加入截止",
		msgPairUntil:                     "权限截止",
		msgPairRefresh:                   "检查对话状态",
		msgPairReviewSlots:               "审核两个真实会话",
		msgPairSlot:                      "席位",
		msgPairSID:                       "真实会话",
		msgPairFingerprint:               "候选密钥指纹",
		msgPairSlotConsent:               "同意此确切会话和密钥在所示对象与限额内对话。",
		msgPairApproveSlot:               "同意此会话",
		msgPairRejectSlot:                "拒绝此已加入会话",
		msgPairRecorded:                  "已记录同意；两个席位均同意后，权限才会生效。",
		msgPairRevokeConsent:             "结束这对会话双方的权限。",
		msgPairRevoke:                    "撤销此对话权限",
		msgPairSaved:                     "这是已保存的观察记录，请重新检查当前状态。",
		msgPairPolicy:                    "仅限这两个会话：最多四次提问和四次回复，同一时间一个未完成提问，每条消息至多 8 KiB，不共享历史。",
		msgPairPrepared:                  "空席位等待确认",
		msgPairWaitingJoin:               "等待两个真实会话加入",
		msgPairWaitingConsent:            "等待分别同意两个会话",
		msgPairActive:                    "有限对话权限已生效",
		msgPairExpired:                   "对话权限已结束",
		msgPairRevoked:                   "对话权限已撤销",
		msgPairUnavailable:               "此 Hub 当前未提供对话设置服务，已保存请求会继续保留。",
		msgPairUnknown:                   "已保存请求的结果尚未确认，请先恢复后再开始其他操作。",
		msgPairTargetChanged:             "审核对象已变化或过期，请检查对话后重新审核。",
		msgPairFenced:                    "请求已被安全拒绝，未执行该变更。重试前请检查当前对话。",
		msgProfileRecoveryTitle:          "暂时无法打开已保存连接",
		msgProfileRecoveryBody:           "请重试打开已保存连接后继续。",
		msgRetrySavedConnection:          "重试已保存连接",
		msgProfileInUse:                  "已保存连接正由另一个 Cicada 窗口使用。可继续使用原窗口，或关闭原窗口后重试。",
		msgSavedConnection:               "保存的连接",
		msgCheckSavedSession:             "验证已保存的登录后继续。",
		msgContinueSavedSession:          "继续登录",
		msgPrivateRecoveryBody:           "一个已保存请求的结果尚未确认，请先恢复后继续。",
		msgNodeUnavailableError:          "此 Hub 的 Node 连接服务当前不可用。已保存的请求会继续保留。",
		msgNodeCodeInvalid:               "请输入 Node 当前屏幕上显示的连接码。",
		msgNodeCounterConflict:           "暂时无法安全核对此 Node 会话，原有状态已保留。",
		msgNodeSessionEnded:              "本次状态访问所绑定的登录已结束。",
		msgNodeAccessEnded:               "此 App 的 Node 访问已结束。",
		msgNodeSavedConnection:           "已保存的 Node 连接",
		msgNodeSavedConnectionBody:       "登录或状态访问到期后，此 Node 的已保存连接仍然保留。",
		msgNodeConnectionStatus:          "当前连接状态",
		msgNodeStatusAccess:              "状态访问",
		msgNodeAwaitingHeartbeat:         "此次状态记录尚未取得 Node 的最近心跳，可检查状态获取更新。",
		msgNodeSignInForStatus:           "请先登录以查看此 Node 的当前状态。已保存的连接信息仍然保留。",
		msgNodeReauthorizeToCheck:        "请继续查看状态，并确认此 App 下一次有限状态访问。",
		msgNodeCheckAccessToContinue:     "请先检查此 App 的状态访问，再继续查看已保存的 Node。",
		msgNodeCheckAccess:               "检查状态访问",
		msgNodeCheckForCurrentStatus:     "请检查 Node 状态以获取最新结果。",
		msgNodeAccountRecoveryFirst:      "请先恢复已保存的账户请求，再查看此 Node 的当前状态。",
		msgNodeUpdatingStatus:            "正在检查最新状态…",
		msgNodeCheckingStatusAccess:      "正在核对当前状态访问…",

		msgNodeReviewStatus:      "确认此次状态访问",
		msgNodeStatusScope:       "仅允许在显示的截止时间前查看此前已批准 Node 的状态。本次授权不会重新配对 Node，也不会续期此前的授权。",
		msgNodeStatusConsent:     "我同意此 App 在所示期限内查看此 Node 的状态。",
		msgNodeAuthorizeStatus:   "允许查看状态",
		msgNodeReauthorizeStatus: "继续查看状态",
		msgNodeAccountRecovery:   "还有一个 Node 请求已保存。请先恢复上方的账户请求，Node 原始请求会继续保留。",
		msgNodeCancelReview:      "取消此次核对",
		msgNodeEndAccess:         "结束此 App 的 Node 访问",
		msgInitialAuthorization:  "首次设置授权",
		msgNodeSection:           "你的 Node",

		"node_pairing.title":          "接入一台电脑",
		"node_pairing.default":        "使用设备配对码",
		"node_pairing.check":          "检查设备确认",
		"node_pairing.preparing":      "正在准备连接",
		"node_pairing.recovery":       "恢复已保存的配对",
		"node_pairing.recovery_body":  "上次操作的结果尚未确认。请先恢复原请求，再进行新的配对。",
		"node_pairing.ended":          "此次配对已结束。请在电脑上申请新的设备码后重试。",
		"node_pairing.expired":        "此次核对已过期。请先确认保存的配对结果，再开始新的配对。",
		"node_pairing.unavailable":    "此 Hub 暂不可用设备配对。",
		"node_pairing.invalid":        "请输入 Node 显示的完整设备配对码。",
		"node_pairing.trust_mismatch": "此设备码与你保存的 Hub 连接不匹配。",
		"node_pairing.refused":        "配对被拒绝。请先确认保存的结果，再重试。",
		"node_pairing.storage_full":   "本机安全存储空间不足，无法安全保留本次操作。已保存的请求仍会保留。",
		"node_pairing.intro":          "粘贴目标电脑上的 Cicada Node 显示的设备配对码。",
		"node_pairing.code":           "设备配对码",
		"node_pairing.review_title":   "核对这台电脑",
		"node_pairing.approve":        "批准并接入",
		"node_pairing.scope":          "将这台电脑接入你的 Hub。配对完成后，再单独配置工作权限。",
		"node_pairing.waiting_title":  "等待电脑确认",
		"node_pairing.deadline":       "已到配对截止时间",
		"node_pairing.deadline_body":  "请先查询保存的结果，再开始新的配对。原有批准和请求仍然保留。",
		"node_pairing.waiting_body":   "批准已发送。请保持这台电脑上的 Cicada Node 运行，等待它确认连接。",
		"node_pairing.connected":      "电脑已接入",
		"node_pairing.details":        "连接详情",
		"node_pairing.legacy":         "高级：使用旧版连接码",

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
		msgNodeAccessUntil:           "状态访问有效至",
		msgNodeObservation:           "状态核对时间",
		msgNodeLastHeartbeat:         "最近 Node 心跳",
		msgNodeNotBound:              "尚未批准 Node 连接。",
		msgNodeUnknown:               "当前暂无法读取状态，已保存的 Node 连接仍然保留。",
		msgNodeOnline:                "Node 在线",
		msgNodeOffline:               "Node 离线",
		msgNodeStale:                 "状态记录已过期，请检查最新状态。",
		msgNodeBound:                 "Node 连接已获批准，正在等待当前 Node 状态。",
		msgNodeRecovery:              "上次 Node 响应尚未确认。请先恢复已保存的请求，再批准其他连接。",
		msgNodeUnavailable:           "连接并登录后，可核对 Node 连接。",
		msgNodeAccessActive:          "对此 Node 的有限状态访问已确认。",
		msgNodeAccessExpired:         "此 App 的状态访问已到期，不会自动续期。",
		msgNodeAccessRevoked:         "此 App 对此 Node 的访问已撤销。",
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
		msgHubCopyAddress:            "Hub IP 地址:端口",
		msgBootstrapCode:             "安装引导码",
		msgSavedHubAddress:           "新 IP 地址:端口（可选，留空使用保存的地址）",
		msgLegacyConnection:          "使用已有连接卡或旧版激活码",
		msgDirectConnection:          "使用 IP 地址连接",
		msgTransportVerifying:        "正在验证安全连接与 Hub 身份…",
		msgTransportVerified:         "安全连接与 Hub 身份已核验",
		msgTransportFailed:           "未能验证安全连接或 Hub 身份",
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
		msgHubAddress:                "Hub IP 地址:端口",
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
		msgHubAddressInvalid:         "请输入数字 IP 地址和端口，例如 192.0.2.10:8443 或 [2001:db8::10]:8443。",
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
