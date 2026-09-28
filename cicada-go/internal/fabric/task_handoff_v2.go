package fabric

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

type TaskHandoffProposeInput struct {
	TaskID           string   `json:"task_id"`
	Target           string   `json:"target"`
	ExpectedRevision int64    `json:"expected_revision"`
	OwnerEpoch       int64    `json:"owner_epoch"`
	PendingWork      string   `json:"pending_work"`
	WorkspaceState   string   `json:"workspace_state,omitempty"`
	EvidenceRefs     []string `json:"evidence_refs,omitempty"`
	ArtifactRefs     []string `json:"artifact_refs,omitempty"`
	SideEffects      []string `json:"side_effects,omitempty"`
	NoRepeatActions  []string `json:"no_repeat_actions,omitempty"`
}

func (s *Service) ProposeTaskHandoff(actor Actor, input TaskHandoffProposeInput) (*store.SharedTaskHandoff, error) {
	if err := s.Authorize(actor, "task.submit"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.submit"); err != nil {
		return nil, err
	}
	card, err := s.resolvePeer(actor, input.Target)
	if err != nil {
		return nil, err
	}
	if card.GroupID != actor.GroupID {
		return nil, ErrCrossGroupDirectDenied
	}
	handoff, err := s.store.ProposeSharedTaskHandoff(store.SharedTaskHandoff{
		TaskID: input.TaskID, GroupID: actor.GroupID,
		FromPrincipalID: actor.PrincipalID, FromEndpointID: actor.EndpointID,
		ToPrincipalID: card.PrincipalID, ToEndpointID: card.EndpointID,
		FromOwnerEpoch: input.OwnerEpoch, TaskRevision: input.ExpectedRevision,
		PendingWork: input.PendingWork, WorkspaceState: input.WorkspaceState,
		EvidenceRefs: input.EvidenceRefs, ArtifactRefs: input.ArtifactRefs,
		SideEffects: input.SideEffects, NoRepeatActions: input.NoRepeatActions,
	})
	if errors.Is(err, store.ErrSharedTaskHandoffConflict) {
		return nil, ErrConflict
	}
	return handoff, mapRelayError(err)
}

func (s *Service) GetTaskHandoff(actor Actor, id string) (*store.SharedTaskHandoff, error) {
	if err := s.Authorize(actor, "task.read"); err != nil {
		return nil, err
	}
	handoff, err := s.store.GetSharedTaskHandoffForActor(nativeActorScope(actor), id, "task.read")
	if err != nil || handoff.GroupID != actor.GroupID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return handoff, nil
}

func (s *Service) AcceptTaskHandoff(actor Actor, id string, leaseSeconds int) (*store.SharedTask, error) {
	if err := s.Authorize(actor, "task.claim"); err != nil {
		return nil, err
	}
	handoff, err := s.store.GetSharedTaskHandoffForActor(nativeActorScope(actor), id, "task.claim")
	if err != nil || handoff.GroupID != actor.GroupID || handoff.ToPrincipalID != actor.PrincipalID || handoff.ToEndpointID != actor.EndpointID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	var missing []string
	for _, refID := range handoff.ArtifactRefs {
		if _, err := s.ResolveArtifactRefsV2(actor, []string{refID}, nil); err != nil {
			missing = append(missing, refID)
		}
	}
	if len(missing) != 0 {
		if err := s.store.MarkSharedTaskHandoffMissingArtifacts(id, actor.PrincipalID, actor.EndpointID, missing); err != nil {
			return nil, mapRelayError(err)
		}
		return nil, store.ErrSharedTaskHandoffMissingArtifact
	}
	task, err := s.store.AcceptSharedTaskHandoff(id, actor.PrincipalID, actor.EndpointID, leaseSeconds)
	if errors.Is(err, store.ErrSharedTaskHandoffConflict) {
		return nil, ErrConflict
	}
	return task, mapRelayError(err)
}
