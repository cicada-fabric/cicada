package fabric

import (
	"errors"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// Shared Task mutation belongs to the durable collaboration authority. The
// verified session binding supplies actor identity; none of these inputs can
// select a different Principal, Endpoint or Group.
type TaskClaimInput struct {
	TaskID           string `json:"task_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	IdempotencyKey   string `json:"idempotency_key"`
	LeaseSeconds     int    `json:"lease_seconds,omitempty"`
}

type TaskReleaseInput struct {
	TaskID           string `json:"task_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	OwnerEpoch       int64  `json:"owner_epoch"`
}

type TaskRenewInput struct {
	TaskID           string `json:"task_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	OwnerEpoch       int64  `json:"owner_epoch"`
	LeaseSeconds     int    `json:"lease_seconds,omitempty"`
}

type TaskResultInput struct {
	TaskID           string   `json:"task_id"`
	ExpectedRevision int64    `json:"expected_revision"`
	OwnerEpoch       int64    `json:"owner_epoch"`
	Summary          string   `json:"summary"`
	Evidence         []string `json:"evidence,omitempty"`
}

type TaskAcceptInput struct {
	TaskID           string `json:"task_id"`
	ResultID         string `json:"result_id"`
	ExpectedRevision int64  `json:"expected_revision"`
}

func (s *Service) taskForActor(actor Actor, taskID, action string) (*store.SharedTask, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, ErrNotFoundOrNotAuthorized
	}
	task, err := s.store.GetSharedTaskForActor(nativeActorScope(actor), taskID, action)
	if err != nil || task.GroupID != actor.GroupID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	return task, nil
}

func (s *Service) ListTasks(actor Actor, limit int) ([]store.SharedTaskPeerView, error) {
	if err := s.Authorize(actor, "task.read"); err != nil {
		return nil, err
	}
	tasks, err := s.store.ListSharedTasksForActor(nativeActorScope(actor), limit)
	if err != nil {
		return nil, mapRelayError(err)
	}
	views := make([]store.SharedTaskPeerView, 0, len(tasks))
	for i := range tasks {
		view, viewErr := s.store.GetSharedTaskPeerForActor(nativeActorScope(actor), tasks[i].ID, "task.read")
		if viewErr != nil {
			return nil, mapRelayError(viewErr)
		}
		views = append(views, *view)
	}
	return views, nil
}

func (s *Service) GetTask(actor Actor, taskID string) (*store.SharedTaskPeerView, error) {
	if err := s.Authorize(actor, "task.read"); err != nil {
		return nil, err
	}
	task, err := s.store.GetSharedTaskPeerForActor(nativeActorScope(actor), taskID, "task.read")
	return task, mapRelayError(err)
}

func (s *Service) ClaimTask(actor Actor, input TaskClaimInput) (*store.SharedTaskPeerView, error) {
	if err := s.Authorize(actor, "task.claim"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.claim"); err != nil {
		return nil, err
	}
	task, err := s.store.ClaimSharedTaskForActor(nativeActorScope(actor), input.TaskID,
		input.ExpectedRevision, input.IdempotencyKey, input.LeaseSeconds)
	if errors.Is(err, store.ErrSharedTaskConflict) || errors.Is(err, store.ErrSharedTaskDependency) {
		return nil, ErrConflict
	}
	return store.ProjectSharedTaskPeer(task), mapRelayError(err)
}

func (s *Service) ReleaseTask(actor Actor, input TaskReleaseInput) (*store.SharedTaskPeerView, error) {
	if err := s.Authorize(actor, "task.claim"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.claim"); err != nil {
		return nil, err
	}
	task, err := s.store.ReleaseSharedTaskClaimForActor(nativeActorScope(actor), input.TaskID,
		input.ExpectedRevision, input.OwnerEpoch)
	if errors.Is(err, store.ErrSharedTaskConflict) || errors.Is(err, store.ErrSharedTaskStaleOwner) {
		return nil, ErrConflict
	}
	return store.ProjectSharedTaskPeer(task), mapRelayError(err)
}

func (s *Service) RenewTask(actor Actor, input TaskRenewInput) (*store.SharedTaskPeerView, error) {
	if err := s.Authorize(actor, "task.claim"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.claim"); err != nil {
		return nil, err
	}
	task, err := s.store.RenewSharedTaskClaimForActor(nativeActorScope(actor), input.TaskID,
		input.ExpectedRevision, input.OwnerEpoch, input.LeaseSeconds)
	if errors.Is(err, store.ErrSharedTaskConflict) || errors.Is(err, store.ErrSharedTaskStaleOwner) {
		return nil, ErrConflict
	}
	return store.ProjectSharedTaskPeer(task), mapRelayError(err)
}

func (s *Service) SubmitTaskResult(actor Actor, input TaskResultInput) (*store.SharedTaskResult, error) {
	if err := s.Authorize(actor, "task.submit"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.submit"); err != nil {
		return nil, err
	}
	result, err := s.store.SubmitSharedTaskResultForActor(nativeActorScope(actor), input.TaskID,
		input.OwnerEpoch, input.ExpectedRevision, input.Summary, input.Evidence)
	if errors.Is(err, store.ErrSharedTaskStaleOwner) {
		return result, ErrConflict
	}
	return result, mapRelayError(err)
}

func (s *Service) AcceptTaskResult(actor Actor, input TaskAcceptInput) (*store.SharedTaskPeerView, error) {
	if err := s.Authorize(actor, "task.verify"); err != nil {
		return nil, err
	}
	if _, err := s.taskForActor(actor, input.TaskID, "task.verify"); err != nil {
		return nil, err
	}
	task, err := s.store.AcceptSharedTaskResultForActor(input.TaskID, input.ResultID,
		input.ExpectedRevision, nativeActorScope(actor))
	if errors.Is(err, store.ErrSharedTaskConflict) || errors.Is(err, store.ErrSharedTaskStaleOwner) {
		return nil, ErrConflict
	}
	return store.ProjectSharedTaskPeer(task), mapRelayError(err)
}
