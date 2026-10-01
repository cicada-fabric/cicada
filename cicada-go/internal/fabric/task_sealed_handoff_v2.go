package fabric

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

type SealedTaskHandoffProposeInput struct {
	HandoffID            string                               `json:"handoff_id"`
	TaskID               string                               `json:"task_id"`
	Target               string                               `json:"target"`
	ExpectedRevision     int64                                `json:"expected_revision"`
	OwnerEpoch           int64                                `json:"owner_epoch"`
	MessageID            string                               `json:"message_id"`
	MessageDigest        string                               `json:"message_digest"`
	ExpiresAt            string                               `json:"expires_at"`
	RequiredArtifactRefs []store.SealedTaskHandoffArtifactRef `json:"required_artifact_refs,omitempty"`
}

// LocalSealedTaskHandoffProposeInput is used only after the Node has durably
// sealed and journaled a same-Node Endpoint SEND. The proof signs route/CAS
// metadata and the ciphertext digest; no payload is sent to Fabric.
type LocalSealedTaskHandoffProposeInput struct {
	HandoffID            string                               `json:"handoff_id"`
	TaskID               string                               `json:"task_id"`
	Target               string                               `json:"target"`
	ExpectedRevision     int64                                `json:"expected_revision"`
	OwnerEpoch           int64                                `json:"owner_epoch"`
	MessageID            string                               `json:"message_id"`
	MessageDigest        string                               `json:"message_digest"`
	ExpiresAt            string                               `json:"expires_at"`
	RequiredArtifactRefs []store.SealedTaskHandoffArtifactRef `json:"required_artifact_refs,omitempty"`
	SenderProof          []byte                               `json:"sender_proof"`
}

type SealedTaskHandoffAcceptInput struct {
	HandoffID       string `json:"handoff_id"`
	ExpectedVersion int64  `json:"expected_version"`
	LeaseSeconds    int    `json:"lease_seconds,omitempty"`
}

func sealedTaskHandoffError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNetworkPermission),
		errors.Is(err, store.ErrSharedTaskNotFound),
		errors.Is(err, store.ErrSealedTaskHandoffNotFound):
		return ErrNotFoundOrNotAuthorized
	case errors.Is(err, store.ErrSealedTaskHandoffPending):
		return ErrConflict
	case errors.Is(err, store.ErrSealedTaskHandoffConflict),
		errors.Is(err, store.ErrSealedTaskHandoffExpired),
		errors.Is(err, store.ErrSealedTaskHandoffMissingArtifact):
		return ErrConflict
	default:
		return err
	}
}

// ProposeSealedTaskHandoff binds a current owner's metadata-only proposal to
// an already-persisted signed same-Group sealed SEND. The target is resolved
// from the current Group directory; sender identity comes from Actor.
func (s *Service) ProposeSealedTaskHandoff(actor Actor,
	input SealedTaskHandoffProposeInput) (*store.SealedSharedTaskHandoff, error) {
	if err := s.Authorize(actor, "task.submit"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.submit"); err != nil {
		return nil, err
	}
	peer, err := s.resolvePeer(actor, input.Target)
	if err != nil {
		return nil, err
	}
	if peer.GroupID != actor.GroupID {
		return nil, ErrCrossGroupDirectDenied
	}
	handoff, err := s.store.ProposeSealedSharedTaskHandoffForActor(nativeActorScope(actor),
		store.SealedSharedTaskHandoffProposal{
			HandoffID: input.HandoffID, TaskID: input.TaskID,
			ExpectedTargetEndpointID: peer.EndpointID,
			ExpectedRevision:         input.ExpectedRevision, OwnerEpoch: input.OwnerEpoch,
			MessageID: input.MessageID, MessageDigest: input.MessageDigest,
			ExpiresAt: input.ExpiresAt, RequiredArtifactRefs: input.RequiredArtifactRefs,
		})
	if err != nil {
		return nil, sealedTaskHandoffError(err)
	}
	s.NotifyNodeClaimHint(handoff.NotifyNodeID)
	handoff.NotifyNodeID = ""
	return handoff, nil
}

// ProposeLocalSealedTaskHandoff publishes only responsibility metadata for a
// SEND already persisted through the Node-local native bridge. Store verifies
// the source Endpoint signature against the exact local route and opaque
// envelope digest before making the metadata visible.
func (s *Service) ProposeLocalSealedTaskHandoff(actor Actor,
	input LocalSealedTaskHandoffProposeInput) (*store.SealedSharedTaskHandoff, error) {
	if err := s.Authorize(actor, "task.submit"); err != nil {
		return nil, err
	}
	peer, err := s.resolvePeer(actor, input.Target)
	if err != nil {
		return nil, err
	}
	source, sourceErr := s.store.GetEndpointV2(actor.EndpointID)
	if sourceErr != nil || source == nil || source.MigrationState != store.EndpointMigrationReady ||
		peer.GroupID != actor.GroupID || source.MachineID == "" || peer.NodeID == "" || source.MachineID != peer.NodeID {
		return nil, ErrCrossGroupDirectDenied
	}
	handoff, err := s.store.ProposeLocalSealedSharedTaskHandoffForActor(nativeActorScope(actor),
		store.LocalSealedSharedTaskHandoffProposal{
			HandoffID: input.HandoffID, TaskID: input.TaskID,
			TargetEndpointID: peer.EndpointID, ExpectedRevision: input.ExpectedRevision,
			OwnerEpoch: input.OwnerEpoch, MessageID: input.MessageID,
			MessageDigest: input.MessageDigest, ExpiresAt: input.ExpiresAt,
			RequiredArtifactRefs: input.RequiredArtifactRefs, SenderProof: input.SenderProof,
		})
	if err != nil {
		return nil, sealedTaskHandoffError(err)
	}
	return handoff, nil
}

func (s *Service) GetSealedTaskHandoff(actor Actor,
	id string) (*store.SealedSharedTaskHandoff, error) {
	if err := s.Authorize(actor, "task.read"); err != nil {
		return nil, err
	}
	handoff, err := s.store.GetSealedSharedTaskHandoffForActor(nativeActorScope(actor), id, "task.read")
	if err != nil {
		return nil, sealedTaskHandoffError(err)
	}
	return handoff, nil
}

// AcceptSealedTaskHandoff rechecks task.claim, current Artifact ACLs and
// immutable Artifact versions inside the same Store transaction as the owner
// epoch/revision change. This guard also applies to direct HTTP callers.
func (s *Service) AcceptSealedTaskHandoff(actor Actor,
	input SealedTaskHandoffAcceptInput) (*store.SharedTask, error) {
	if err := s.Authorize(actor, "task.claim"); err != nil {
		return nil, err
	}
	task, err := s.store.AcceptSealedSharedTaskHandoffForActor(nativeActorScope(actor),
		input.HandoffID, input.ExpectedVersion, input.LeaseSeconds)
	if err != nil {
		return nil, sealedTaskHandoffError(err)
	}
	return task, nil
}
