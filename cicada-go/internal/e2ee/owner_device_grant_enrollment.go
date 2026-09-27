package e2ee

import (
	"encoding/json"
	"errors"
	"time"
)

// VerifyOwnerDeviceGrantAtRecordedEnrollment verifies an accepted enrollment
// proof against its recorded enrollment time. Older Hub rows recorded only a
// whole second, so such a timestamp represents [recordedAt, recordedAt+1s).
// A subsecond timestamp is exact. The signed grant must overlap that window;
// no proof may be verified at a time later than the current clock.
func VerifyOwnerDeviceGrantAtRecordedEnrollment(
	data []byte,
	trustedOwner PublicIdentity,
	devicePublic PublicIdentity,
	expectedOwnerID, expectedOwnerKeyID, expectedDeviceID, expectedHubID, expectedPurpose string,
	recordedAt time.Time,
) (OwnerDeviceGrant, error) {
	if recordedAt.IsZero() || recordedAt.After(time.Now().UTC()) || len(data) == 0 || len(data) > maxOwnerDeviceGrantBytes {
		return OwnerDeviceGrant{}, ErrInvalidEnvelope
	}
	witness := recordedAt
	if recordedAt.Nanosecond() == 0 {
		// These claims select only a candidate time. VerifyOwnerDeviceGrant below
		// validates canonical JSON, all claims and the Owner signature at it.
		var times struct {
			IssuedAt  string `json:"issued_at"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(data, &times); err != nil {
			return OwnerDeviceGrant{}, err
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, times.IssuedAt)
		if err != nil {
			return OwnerDeviceGrant{}, ErrInvalidEnvelope
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, times.ExpiresAt)
		if err != nil || !expiresAt.After(issuedAt) {
			return OwnerDeviceGrant{}, ErrInvalidEnvelope
		}
		if issuedAt.After(witness) {
			witness = issuedAt
		}
		if !witness.Before(recordedAt.Add(time.Second)) || !witness.Before(expiresAt) ||
			witness.After(time.Now().UTC()) {
			return OwnerDeviceGrant{}, errors.New("owner device grant lifetime does not overlap recorded enrollment second")
		}
	}
	return VerifyOwnerDeviceGrant(data, trustedOwner, devicePublic,
		expectedOwnerID, expectedOwnerKeyID, expectedDeviceID, expectedHubID, expectedPurpose, witness)
}
