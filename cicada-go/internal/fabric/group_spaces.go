package fabric

import "github.com/cicada-ai/cicada/internal/store"

type GroupSpacePrepareInput = store.GroupSpacePrepareInput
type GroupSpaceSnapshot = store.GroupSpaceSnapshot
type GroupSpaceEndpointEvidence = store.GroupSpaceEndpointEvidence
type GroupSpaceCommitInput = store.GroupSpaceCommitInput
type GroupSpaceReaderCiphertext = store.GroupSpaceReaderCiphertext
type GroupSpaceListInput = store.GroupSpaceListInput
type GroupSpaceGetInput = store.GroupSpaceGetInput
type GroupSpaceRecord = store.GroupSpaceRecord
type GroupSpacePage = store.GroupSpacePage
type GroupSpaceHint = store.GroupSpaceHint
type GroupSpaceSyncInput = store.GroupSpaceSyncInput
type GroupSpaceSyncResult = store.GroupSpaceSyncResult
type GroupSpaceReadStateInput = store.GroupSpaceReadStateInput
type GroupSpaceMarkReadInput = store.GroupSpaceMarkReadInput
type GroupSpaceReadState = store.GroupSpaceReadState
type GroupSpaceHistoryManifestInput = store.GroupSpaceHistoryManifestInput
type GroupSpaceHistoryManifest = store.GroupSpaceHistoryManifest
type GroupSpaceHistoryCommitInput = store.GroupSpaceHistoryCommitInput

func (s *Service) groupSpaceActor(nodeToken, sessionToken, groupID string) (store.GroupSpaceActor, error) {
	actor, err := s.AuthenticateForGroup(sessionToken, groupID)
	if err != nil {
		return store.GroupSpaceActor{}, err
	}
	nodeID, err := s.AuthenticateNode(nodeToken)
	if err != nil {
		return store.GroupSpaceActor{}, err
	}
	endpoint, err := s.store.GetEndpointV2(actor.EndpointID)
	if err != nil || endpoint.MachineID != nodeID {
		return store.GroupSpaceActor{}, ErrPermissionDenied
	}
	return store.GroupSpaceActor{Scope: store.NativeActorScope{
		PrincipalID: actor.PrincipalID, EndpointID: actor.EndpointID,
		GroupID: actor.GroupID, NetworkID: actor.NetworkID,
		MembershipID: actor.MembershipID, MembershipRevision: actor.MembershipRevision,
		BindingID: actor.BindingID, BindingEpoch: actor.BindingEpoch,
		LeaseOwner: actor.LeaseOwner,
	}, NodeCredentialDigest: HashSessionCredential(nodeToken)}, nil
}

func (s *Service) PrepareGroupSpaceWrite(nodeToken, sessionToken string,
	in GroupSpacePrepareInput) (*GroupSpaceSnapshot, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.PrepareGroupSpaceWrite(actor, in)
}

func (s *Service) CommitGroupSpaceWrite(nodeToken, sessionToken string,
	in GroupSpaceCommitInput) (*GroupSpaceRecord, error) {
	groupID, err := s.store.GroupSpaceReservationGroupID(in.ReservationID)
	if err != nil {
		return nil, err
	}
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, groupID)
	if err != nil {
		return nil, err
	}
	record, err := s.store.CommitGroupSpaceWrite(actor, in)
	if err == nil {
		for _, nodeID := range store.GroupSpaceReaderNodes(record) {
			s.NotifyNodeSpaceHint(nodeID)
		}
	}
	return record, err
}

func (s *Service) SyncGroupSpace(nodeToken, sessionToken string,
	in GroupSpaceSyncInput) (*GroupSpaceSyncResult, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.SyncGroupSpace(actor, in)
}

func (s *Service) GetGroupSpaceReadState(nodeToken, sessionToken string,
	in GroupSpaceReadStateInput) (*GroupSpaceReadState, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.GetGroupSpaceReadState(actor, in)
}

func (s *Service) MarkGroupSpaceRead(nodeToken, sessionToken string,
	in GroupSpaceMarkReadInput) (*GroupSpaceReadState, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.MarkGroupSpaceRead(actor, in)
}

func (s *Service) ListGroupSpace(nodeToken, sessionToken string,
	in GroupSpaceListInput) (*GroupSpacePage, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.ListGroupSpace(actor, in)
}

func (s *Service) GetGroupSpace(nodeToken, sessionToken string,
	in GroupSpaceGetInput) (*GroupSpaceRecord, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.GetGroupSpace(actor, in)
}

func (s *Service) GetGroupSpaceHistoryManifest(nodeToken, sessionToken string,
	in GroupSpaceHistoryManifestInput) (*GroupSpaceHistoryManifest, error) {
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, in.GroupID)
	if err != nil {
		return nil, err
	}
	return s.store.GetGroupSpaceHistoryManifest(actor, in)
}

func (s *Service) GrantGroupSpaceHistorySealed(nodeToken, sessionToken string,
	in GroupSpaceHistoryCommitInput) (*GroupSpaceRecord, error) {
	groupID, err := s.store.GroupSpaceHistoryManifestGroupID(in.ManifestID)
	if err != nil {
		return nil, err
	}
	actor, err := s.groupSpaceActor(nodeToken, sessionToken, groupID)
	if err != nil {
		return nil, err
	}
	return s.store.GrantGroupSpaceHistorySealed(actor, in)
}
