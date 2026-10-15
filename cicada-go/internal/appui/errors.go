package appui

// ErrorText translates reviewed public codes. Transport/crypto errors, packets,
// private filenames and credentials are never interpolated into user feedback.
func ErrorText(locale Locale, code string) string {
	id := msgRequestFailed
	switch code {
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
