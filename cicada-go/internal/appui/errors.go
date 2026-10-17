package appui

// ErrorText translates reviewed public codes. Transport/crypto errors, packets,
// private filenames and credentials are never interpolated into user feedback.
func ErrorText(locale Locale, code string) string {
	id := msgRequestFailed
	switch code {
	case "APP_OWNER_PUBLIC_EXPORT_FAILED":
		id = msgExportOwnerPublicFailed
	case "APP_PAIR_UNAVAILABLE":
		id = msgPairUnavailable
	case "APP_PAIR_REQUEST_UNKNOWN", "APP_PAIR_RESPONSE_INVALID", "APP_PAIR_RECOVERY_INVALID", "APP_PAIR_RECOVERY_UNRESOLVED":
		id = msgPairUnknown
	case "APP_PAIR_TARGET_CHANGED":
		id = msgPairTargetChanged
	case "APP_PAIR_REQUEST_FENCED":
		id = msgPairFenced
	case "APP_PAIR_COMMIT_FAILED":
		id = msgLocalUnlockFailed
	case "APP_PROFILE_IN_USE":
		id = msgProfileInUse
	case "APP_NODE_UNAVAILABLE":
		id = msgNodeUnavailableError
	case "APP_NODE_CODE_INVALID":
		id = msgNodeCodeInvalid
	case "APP_NODE_COUNTER_CONFLICT", "APP_NODE_RECOVERY_UNRESOLVED":
		id = msgNodeCounterConflict
	case "APP_NODE_REQUEST_UNKNOWN", "APP_NODE_RESPONSE_INVALID", "APP_NODE_RECOVERY_INVALID":
		id = msgNodeRecovery
	case "APP_NODE_SESSION_REQUIRED":
		id = msgNodeSessionEnded
	case "APP_NODE_AUTHORITY_EXPIRED":
		id = msgNodeAccessExpired
	case "APP_NODE_AUTHORITY_REVOKED", "APP_NODE_ROOT_UNAVAILABLE", "APP_NODE_DEVICE_UNAVAILABLE":
		id = msgNodeAccessRevoked
	case "APP_NODE_CANDIDATE_UNAVAILABLE", "APP_NODE_CANDIDATE_CHANGED", "APP_NODE_PROOF_EXPIRED":
		id = msgNodeCandidateExpired
	case "APP_NODE_CONFIRM_REJECTED", "APP_NODE_SCOPE_MISMATCH", "APP_NODE_REPLAY_CONFLICT", "APP_NODE_AUTHORITY_CONFLICT", "APP_NODE_INVALID_REQUEST":
		id = msgRequestRejected
	case "APP_NODE_STATE_INVALID", "APP_NODE_COMMIT_FAILED":
		id = msgLocalUnlockFailed
	case "APP_NODE_CANDIDATE_EXPIRED":
		id = msgNodeCandidateExpired
	case "ACCOUNT_RESPONSE_UNKNOWN", "ACCOUNT_RESPONSE_INVALID", "APP_RECOVERY_RESPONSE_UNKNOWN", "APP_RECOVERY_RESPONSE_INVALID":
		id = msgRequestUnknown
	case "ACCOUNT_REQUEST_REJECTED":
		id = msgRequestRejected
	case "INVALID_ACTIVATION_CODE", "EXPIRED_CONNECTION_MATERIAL", "ACTIVATION_PROOF_EXPIRED_OR_INVALID":
		id = msgMaterialInvalid
	case "APP_PROFILE_UNLOCK_FAILED", "APP_PROFILE_DISCOVERY_FAILED", "APP_PROFILE_INVALID":
		id = msgLocalUnlockFailed
	case "APP_PROFILE_HUB_UNVERIFIED", "HUB_PIN_MISMATCH", "HUB_IDENTITY_INVALID":
		id = msgHubTrustFailed
	case "OWNER_IDENTITY_SCOPE_MISMATCH", "OWNER_IDENTITY_IMPORT_REJECTED":
		id = msgOwnerMismatch
	case "ENCRYPTED_OWNER_PEM_UNSUPPORTED":
		id = msgEncryptedOwnerUnsupported
	case "APP_DEVICE_REVOKED":
		id = msgAccessRevoked
	}
	return text(locale, id)
}
