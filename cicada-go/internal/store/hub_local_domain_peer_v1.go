package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var errLocalDomainCarrierTooLarge = errors.New("local domain complete carrier exceeds bound")

func sameGroupEvidenceManifest(e SameGroupSealedV1EndpointEvidence) GroupEndpointKeyGrantManifest {
	if e.Grant != nil && e.LocalDomainGrant == nil && e.EndpointGroupGrant == nil {
		return e.Grant.Manifest
	}
	var m GroupEndpointKeyGrantManifest
	if e.Grant == nil && e.LocalDomainGrant != nil && e.EndpointGroupGrant == nil {
		raw, _ := json.Marshal(e.LocalDomainGrant.Manifest)
		_ = json.Unmarshal(raw, &m)
	}
	if e.Grant == nil && e.LocalDomainGrant == nil && e.EndpointGroupGrant != nil {
		raw, _ := json.Marshal(e.EndpointGroupGrant.Manifest)
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func sameGroupEvidenceAllowsExpiry(e SameGroupSealedV1EndpointEvidence, end time.Time) bool {
	m := sameGroupEvidenceManifest(e)
	// Only the explicit delegated variant allows an unbounded policy. A missing
	// or malformed legacy grant retains its original fail-closed interval.
	if (e.LocalDomainGrant != nil || e.EndpointGroupGrant != nil) && e.Grant == nil && m.ExpiresAt == "" {
		return true
	}
	deadline, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	return err == nil && !end.After(deadline)
}

func readLocalDomainPeerEndpointTx(tx *sql.Tx, p *hubLocalDomain, endpoint string, at time.Time) (SameGroupSealedV1EndpointEvidence, error) {
	m, err := localDomainEndpointCurrentTx(tx, p, endpoint, at)
	if err != nil || m.member.State != wire.LocalDomainMemberActive || m.grant == "" {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	var grant wire.LocalDomainEndpointKeyGrant
	if json.Unmarshal([]byte(m.grant), &grant) != nil || !reflect.DeepEqual(grant.Member, m.member) {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	// The immutable policy was authenticated at admission. Verify its complete
	// delegated chain again and independently compare the current candidate.
	hub := p.accountHub
	if _, err = wire.VerifyLocalDomainEndpointKeyGrant(grant, hub, p.policy.OwnerID, p.policy.OwnerPublic, at); err != nil {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	k := grant.Manifest
	manifest, err := localDomainProjectedManifestTx(tx, p, m.member, k.IssuedAt, at)
	if err != nil || !reflect.DeepEqual(manifest, k) {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	side, err := readCommunicationLinkKeySide(tx, endpoint, p.policy.GroupID, k.PrincipalID, p.policy.OwnerID, k.NodeID, k.BindingID, k.BindingEpoch)
	if err != nil || side.KeyID != k.CandidateKeyID || side.CandidateVersion != k.CandidateVersion || side.KeyFingerprint != k.CandidateFingerprint || side.ProofDigest != k.CandidateProofDigest || !reflect.DeepEqual(side.PublicIdentity, k.CandidatePublicIdentity) {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	grants, _ := json.Marshal(localDomainGroupGrants())
	var count int
	if tx.QueryRow(`SELECT count(*) FROM memberships gm JOIN network_memberships_v2 nm ON nm.principal_id=gm.principal_id AND nm.network_id=? JOIN endpoint_network_memberships_v2 en ON en.network_id=nm.network_id AND en.endpoint_id=? WHERE gm.group_id=? AND gm.principal_id=? AND gm.status='active' AND gm.role='member' AND gm.grants_json=? AND gm.authorization_json='{}' AND gm.expires_at=? AND nm.status='active' AND nm.grants_json='[]' AND en.status='active' AND en.discoverable=0`, p.policy.NetworkID, endpoint, p.policy.GroupID, m.member.PrincipalID, string(grants), p.policy.ExpiresAt).Scan(&count) != nil || count != 1 {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	return SameGroupSealedV1EndpointEvidence{EndpointID: endpoint, PrincipalID: k.PrincipalID, OwnerID: p.policy.OwnerID, NodeID: k.NodeID, GroupID: k.GroupID, BindingID: k.BindingID, BindingEpoch: k.BindingEpoch, NativeSessionID: m.member.NativeSessionID, GroupRevision: k.GroupRevision, MembershipRevision: k.MembershipRevision, EndpointJoinRevision: k.EndpointJoinRevision, Candidate: EndpointKeyCandidate{EndpointID: endpoint, PrincipalID: k.PrincipalID, OwnerID: p.policy.OwnerID, NodeID: k.NodeID, Public: k.CandidatePublicIdentity, KeyID: k.CandidateKeyID, BindingID: k.BindingID, BindingEpoch: k.BindingEpoch, Proof: append([]byte(nil), k.CandidateAttestation...), ProofDigest: k.CandidateProofDigest, State: EndpointKeyCandidateStateCandidate, Version: k.CandidateVersion}, LocalDomainGrant: &grant}, nil
}

func localDomainPeerCurrentTx(tx *sql.Tx, pair sameGroupEndpointPair, at time.Time) (*wire.LocalDomainCurrent, error) {
	p, err := localDomainForGroupTx(tx, pair.groupID)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	if p == nil {
		if pair.sender.LocalDomainGrant != nil || pair.receiver.LocalDomainGrant != nil {
			return nil, ErrSameGroupSealedV1Denied
		}
		return nil, nil
	}
	if pair.nativeEvidence != nil || pair.sender.Grant != nil || pair.receiver.Grant != nil || pair.sender.LocalDomainGrant == nil || pair.receiver.LocalDomainGrant == nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	a, b := pair.sender.LocalDomainGrant.Member, pair.receiver.LocalDomainGrant.Member
	end := at.Add(30 * time.Second)
	for _, m := range []wire.LocalDomainMember{a, b} {
		var native, access string
		if tx.QueryRow(`SELECT b.lease_expires_at,a.lease_expires_at FROM session_bindings b JOIN network_access_sessions_v2 a ON a.id=? WHERE b.id=?`, m.NetworkAccessBindingID, m.BindingID).Scan(&native, &access) != nil {
			return nil, ErrSameGroupSealedV1Denied
		}
		for _, stamp := range []string{native, access, p.policy.ExpiresAt} {
			if stamp != "" {
				v, e := time.Parse(time.RFC3339Nano, stamp)
				if e != nil {
					return nil, ErrSameGroupSealedV1Denied
				}
				if v.Before(end) {
					end = v
				}
			}
		}
	}
	c := &wire.LocalDomainCurrent{ContractRevision: wire.LocalDomainContractRevision, Selection: a.Selection, State: "CURRENT", Revision: p.revision, Operation: "peer_key", AttemptID: a.EndpointID + ":" + b.EndpointID, Sender: a, Receiver: b, ObservedAt: appNodeStamp(at), ExpiresAt: appNodeStamp(end)}
	if wire.ValidateLocalDomainCurrent(*c, p.policy, a, b, c.Operation, c.AttemptID, at) != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	return c, nil
}

func localDomainCarrierSize(carrier any, current *wire.LocalDomainCurrent) error {
	if current == nil {
		return nil
	}
	raw, err := json.Marshal(carrier)
	if err != nil || len(raw) > wire.MaxLocalDomainCarrierBytes {
		return errLocalDomainCarrierTooLarge
	}
	return nil
}
