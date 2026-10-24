package appui

// ErrorText translates reviewed public codes. Transport/crypto errors, packets,
// private filenames and credentials are never interpolated into user feedback.
func ErrorText(locale Locale, code string) string {
	id := msgRequestFailed
	switch code {
	case "APP_NODE_PAIRING_UNKNOWN":
		id = "node_pairing.recovery_body"
	case "APP_NODE_PAIRING_INVALID", "APP_NODE_PAIRING_CODE_INVALID":
		id = "node_pairing.invalid"
	case "APP_NODE_PAIRING_TRUST_MISMATCH":
		id = "node_pairing.trust_mismatch"
	case "APP_NODE_PAIRING_UNAVAILABLE":
		id = "node_pairing.unavailable"
	case "APP_NODE_PAIRING_EXPIRED":
		id = "node_pairing.expired"
	case "APP_NODE_PAIRING_REFUSED":
		id = "node_pairing.refused"
	case "APP_NODE_PAIRING_STORAGE_FULL":
		id = "node_pairing.storage_full"
	case "APP_LOCAL_COLLABORATION_UNAVAILABLE":
		id = "local_collaboration.unavailable"
	case "APP_LOCAL_COLLABORATION_UNKNOWN", "APP_LOCAL_COLLABORATION_RESPONSE_UNCONFIRMED":
		id = "local_collaboration.pending"
	case "APP_LOCAL_COLLABORATION_REFUSED", "APP_LOCAL_COLLABORATION_READ_INVALID", "APP_LOCAL_COLLABORATION_READ_LIMIT", "APP_LOCAL_COLLABORATION_AMBIGUOUS":
		id = msgRequestRejected
	case "APP_LOCAL_COLLABORATION_COMMIT_FAILED":
		id = msgLocalUnlockFailed
	case "APP_OWNER_DIRECTORY_UNAVAILABLE":
		id = "directory.unavailable"
	case "APP_OWNER_DIRECTORY_REQUEST_UNKNOWN":
		id = "directory.unknown_result"
	case "APP_OWNER_DIRECTORY_RETAINED_UNKNOWN":
		id = "directory.retained_body"
	case "APP_OWNER_DIRECTORY_HISTORY_FULL":
		id = "directory.history_full"
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
	case "INVALID_ACTIVATION_CODE", "HUB_BOOTSTRAP_INVALID", "EXPIRED_CONNECTION_MATERIAL", "ACTIVATION_PROOF_EXPIRED_OR_INVALID":
		id = msgMaterialInvalid
	case "APP_PROFILE_UNLOCK_FAILED", "APP_PROFILE_DISCOVERY_FAILED", "APP_PROFILE_INVALID":
		id = msgLocalUnlockFailed
	case "APP_PROFILE_HUB_UNVERIFIED", "HUB_PIN_MISMATCH", "HUB_IDENTITY_INVALID", "HUB_TLS_UNVERIFIED", "HUB_TRANSPORT_SCOPE_MISMATCH":
		id = msgHubTrustFailed
	case "HUB_ADDRESS_INVALID":
		id = msgHubAddressInvalid
	case "OWNER_IDENTITY_SCOPE_MISMATCH", "OWNER_IDENTITY_IMPORT_REJECTED":
		id = msgOwnerMismatch
	case "ENCRYPTED_OWNER_PEM_UNSUPPORTED":
		id = msgEncryptedOwnerUnsupported
	case "APP_DEVICE_REVOKED":
		id = msgAccessRevoked
	}
	return text(locale, id)
}
