package control

import "github.com/cicada-ai/cicada/internal/store"

// Each call requires an accepted encrypted Client request whose persisted
// route operation matches the Store method. The authenticated owner is never
// read from MCP arguments or the plaintext request body.
func (c *Control) AdmitCrossOwnerGroupMemberForClientRequest(requestID, ownerID, groupID, endpointID string,
	grants []string, expiresAt string, expectedGroupRevision, expectedMembershipRevision int64) (*store.CrossOwnerGroupAdmission, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.AdmitCrossOwnerGroupMemberForClientRequest(requestID, ownerID, groupID, endpointID,
		grants, expiresAt, expectedGroupRevision, expectedMembershipRevision)
}

func (c *Control) ConsentCrossOwnerGroupJoinForClientRequest(requestID, ownerID, admissionID,
	bindingID string, bindingEpoch uint64, sharedContextRiskAcknowledged bool) (*store.CrossOwnerGroupJoinConsent, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.ConsentCrossOwnerGroupJoinForClientRequest(requestID, ownerID, admissionID, bindingID,
		bindingEpoch, sharedContextRiskAcknowledged)
}

func (c *Control) RevokeCrossOwnerGroupAdmissionForClientRequest(requestID, ownerID, admissionID string,
	expectedMembershipRevision int64) (*store.CrossOwnerGroupAdmission, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.RevokeCrossOwnerGroupAdmissionForClientRequest(requestID, ownerID,
		admissionID, expectedMembershipRevision)
}

func (c *Control) PreviewCrossOwnerGroupKeyManifestForClientRequest(requestID, ownerID, groupID,
	endpointID string) (*store.CrossOwnerGroupKeyManifest, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewCrossOwnerGroupKeyManifestForClientRequest(requestID, ownerID, groupID, endpointID)
}

func (c *Control) AcceptCrossOwnerGroupKeyProofForClientRequest(requestID, ownerID, groupID,
	endpointID, ownerKeyID, side string, proof []byte) (*store.CrossOwnerGroupKeyProof, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.AcceptCrossOwnerGroupKeyProofForClientRequest(requestID, ownerID, groupID,
		endpointID, ownerKeyID, side, proof)
}

func (c *Control) GetCrossOwnerGroupKeyStatusForClientRequest(requestID, ownerID, groupID,
	endpointID string) (*store.CrossOwnerGroupKeyStatus, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetCrossOwnerGroupKeyStatusForClientRequest(requestID, ownerID, groupID, endpointID)
}
