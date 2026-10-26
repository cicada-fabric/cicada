package store

import (
	"database/sql"
	"encoding/json"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func readEndpointGroupsPeerEndpointTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) (SameGroupSealedV1EndpointEvidence, error) {
	if endpointGroupsRegistrationLeaseTx(tx, r, at) != nil {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	_, current, source, err := endpointGroupsResolveTx(tx, r, group, at, false)
	if err != nil || current == nil || source == nil {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	var manifest wire.LocalDomainKeyManifest
	if source.LocalDomainGrant != nil {
		manifest = source.LocalDomainGrant.Manifest
	} else if source.EndpointGroupGrant != nil {
		manifest = source.EndpointGroupGrant.Manifest
	} else {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	g, err := endpointGroupsGroupTx(tx, r.anchor.Registration.OwnerID, r.anchor.NetworkID, group)
	if err != nil || g.Revision != manifest.GroupRevision {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	k := manifest
	evidence := SameGroupSealedV1EndpointEvidence{EndpointID: r.anchor.Registration.EndpointID, PrincipalID: r.anchor.Registration.PrincipalID, OwnerID: r.anchor.Registration.OwnerID, NodeID: r.anchor.Registration.NodeID, GroupID: group, BindingID: r.anchor.BindingID, BindingEpoch: r.anchor.BindingEpoch, NativeSessionID: r.anchor.Registration.NativeSessionID, GroupRevision: k.GroupRevision, MembershipRevision: k.MembershipRevision, EndpointJoinRevision: k.EndpointJoinRevision, Candidate: EndpointKeyCandidate{EndpointID: k.EndpointID, PrincipalID: k.PrincipalID, OwnerID: k.OwnerID, NodeID: k.NodeID, Public: k.CandidatePublicIdentity, KeyID: k.CandidateKeyID, BindingID: k.BindingID, BindingEpoch: k.BindingEpoch, Proof: append([]byte(nil), k.CandidateAttestation...), ProofDigest: k.CandidateProofDigest, State: EndpointKeyCandidateStateCandidate, Version: k.CandidateVersion}, LocalDomainGrant: source.LocalDomainGrant, EndpointGroupGrant: source.EndpointGroupGrant}
	return evidence, nil
}

func endpointGroupsPeerCurrentTx(tx *sql.Tx, pair sameGroupEndpointPair, at time.Time) (*wire.EndpointGroupCurrent, error) {
	a, err := endpointGroupsManagedTx(tx, pair.sender.EndpointID)
	if err != nil {
		return nil, err
	}
	b, err := endpointGroupsManagedTx(tx, pair.receiver.EndpointID)
	if err != nil {
		return nil, err
	}
	if a == nil && b == nil {
		if pair.sender.EndpointGroupGrant != nil || pair.receiver.EndpointGroupGrant != nil {
			return nil, ErrSameGroupSealedV1Denied
		}
		return nil, nil
	}
	// A managed conversation requires independent original registration evidence
	// for both sides. It never falls through to a legacy or Pair grant.
	if a == nil || b == nil || pair.nativeEvidence != nil || pair.sender.Grant != nil || pair.receiver.Grant != nil || a.anchor.Registration.OwnerID != b.anchor.Registration.OwnerID || a.anchor.NetworkID != b.anchor.NetworkID {
		return nil, ErrSameGroupSealedV1Denied
	}
	_, ac, as, err := endpointGroupsResolveTx(tx, a, pair.groupID, at, false)
	if err != nil || ac == nil || as == nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	_, bc, bs, err := endpointGroupsResolveTx(tx, b, pair.groupID, at, false)
	if err != nil || bc == nil || bs == nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	if endpointGroupsRegistrationLeaseTx(tx, a, at) != nil || endpointGroupsRegistrationLeaseTx(tx, b, at) != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	end := at.Add(30 * time.Second)
	for _, r := range []*hubEndpointGroupsRegistration{a, b} {
		var native, access string
		if tx.QueryRow(`SELECT b.lease_expires_at,a.lease_expires_at FROM session_bindings b JOIN network_access_sessions_v2 a ON a.id=? WHERE b.id=?`, r.anchor.NetworkAccessBindingID, r.anchor.BindingID).Scan(&native, &access) != nil {
			return nil, ErrSameGroupSealedV1Denied
		}
		for _, stamp := range []string{native, access} {
			v, e := time.Parse(time.RFC3339Nano, stamp)
			if e != nil {
				return nil, ErrSameGroupSealedV1Denied
			}
			if v.Before(end) {
				end = v
			}
		}
	}
	for _, c := range []*wire.EndpointGroupCurrentEndpoint{ac, bc} {
		if c.Relation.ExpiresAt != "" {
			v, e := time.Parse(time.RFC3339Nano, c.Relation.ExpiresAt)
			if e != nil {
				return nil, ErrSameGroupSealedV1Denied
			}
			if v.Before(end) {
				end = v
			}
		}
	}
	current := &wire.EndpointGroupCurrent{Format: wire.EndpointGroupCurrentFormat, HubID: pair.hubID, GroupID: pair.groupID, Sender: *ac, Receiver: *bc, Operation: "peer_key", AttemptID: pair.sender.EndpointID + ":" + pair.receiver.EndpointID, ObservedAt: appNodeStamp(at), ExpiresAt: appNodeStamp(end)}
	if wire.ValidateEndpointGroupCurrent(*current, current.Operation, current.AttemptID, at) != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	return current, nil
}

func endpointGroupsCarrierSize(carrier any, current *wire.EndpointGroupCurrent) error {
	if current == nil {
		return nil
	}
	raw, err := json.Marshal(carrier)
	if err != nil || len(raw) > wire.MaxEndpointGroupCarrierBytes {
		return ErrSameGroupSealedV1Denied
	}
	return nil
}
