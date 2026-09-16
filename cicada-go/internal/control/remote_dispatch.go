package control

import (
	"errors"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// MachineJob is the bounded task description a remote machine agent receives.
// The control database remains authoritative; the agent only executes this
// payload and reports a result back over the authenticated API.
type MachineJob struct {
	WorkerID     string         `json:"worker_id"`
	GoalID       string         `json:"goal_id"`
	MachineID    string         `json:"machine_id"`
	Harness      string         `json:"harness"`
	Workspace    string         `json:"workspace"`
	ResponseFile string         `json:"response_file"`
	ThreadID     string         `json:"thread_id,omitempty"`
	Prompt       string         `json:"prompt"`
	Resources    map[string]any `json:"resources,omitempty"`
	Attempt      int            `json:"attempt"`
}

var ErrWorkerUnavailable = errors.New("worker is no longer available")

func isLocalMachine(machineID string) bool {
	return machineID == "control-local" || machineID == "worker-local"
}

// MachineJobs lists queued work assigned to one remote machine.
func (c *Control) MachineJobs(machineID string) ([]MachineJob, error) {
	if isLocalMachine(strings.TrimSpace(machineID)) {
		return []MachineJob{}, nil
	}
	machine, err := c.store.GetMachine(strings.TrimSpace(machineID))
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, os.ErrNotExist
	}
	workers, err := c.store.ListWorkersForMachine(machine.ID)
	if err != nil {
		return nil, err
	}
	jobs := make([]MachineJob, 0, len(workers))
	for _, worker := range workers {
		job, err := c.remoteJob(worker)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (c *Control) remoteJob(worker store.Worker) (MachineJob, error) {
	goal, err := c.store.GetGoal(worker.GoalID)
	if err != nil {
		return MachineJob{}, err
	}
	if goal == nil {
		return MachineJob{}, os.ErrNotExist
	}
	if permissionErr := c.checkWorkspaceSourcePermission(*goal); permissionErr != nil {
		return MachineJob{}, permissionErr
	}
	commands, err := c.store.ListPendingCommands(goal.ID, worker.ID)
	if err != nil {
		return MachineJob{}, err
	}
	return c.machineJob(*goal, worker, commands), nil
}

func (c *Control) machineJob(goal store.Goal, worker store.Worker, commands []store.Command) MachineJob {
	prompt := strings.TrimSpace(worker.Prompt)
	if prompt == "" {
		prompt = c.initialPrompt(goal)
	}
	if len(commands) > 0 {
		prompt += "\n\nThe monitor has provided the following correction. Apply it to the current goal, verify the result, and continue:\n\n"
		for index, command := range commands {
			if index > 0 {
				prompt += "\n\n"
			}
			prompt += command.Command
		}
	}
	return MachineJob{
		WorkerID: worker.ID, GoalID: worker.GoalID, MachineID: worker.MachineID,
		Harness: worker.Harness, Workspace: worker.Workspace,
		ResponseFile: worker.ResponseFile, ThreadID: worker.ThreadID,
		Prompt:    prompt,
		Resources: goal.Resources, Attempt: worker.Attempt,
	}
}

// ClaimRemoteWorker is the only transition that assigns execution ownership.
// The SQL update is conditional, so two agents polling the same endpoint
// cannot execute one worker concurrently.
func (c *Control) ClaimRemoteWorker(workerID, machineID string) (MachineJob, error) {
	if isLocalMachine(strings.TrimSpace(machineID)) {
		return MachineJob{}, ErrWorkerUnavailable
	}
	worker, err := c.store.GetWorker(strings.TrimSpace(workerID))
	if err != nil {
		return MachineJob{}, err
	}
	if worker == nil || worker.MachineID != machineID {
		return MachineJob{}, os.ErrNotExist
	}
	goal, err := c.store.GetGoal(worker.GoalID)
	if err != nil {
		return MachineJob{}, err
	}
	if goal == nil {
		return MachineJob{}, os.ErrNotExist
	}
	if permissionErr := c.checkWorkspaceSourcePermission(*goal); permissionErr != nil {
		return MachineJob{}, permissionErr
	}
	if worker.Harness == "shell" {
		argv, argvErr := shellArgv(goal.Resources["argv"])
		if argvErr != nil {
			return MachineJob{}, argvErr
		}
		if _, permissionErr := c.CheckPermission("goal", goal.ID, "shell.execute", argv[0]); permissionErr != nil {
			return MachineJob{}, permissionErr
		}
	}
	claimed, err := c.store.ClaimWorker(worker.ID, machineID)
	if err != nil {
		return MachineJob{}, err
	}
	if claimed == nil {
		return MachineJob{}, ErrWorkerUnavailable
	}
	commands, err := c.store.ClaimPendingCommandsForWorker(claimed.GoalID, claimed.ID)
	if err != nil {
		_, _ = c.store.TransitionWorkerStatus(claimed.ID, machineID, "running", "queued")
		return MachineJob{}, err
	}
	job := c.machineJob(*goal, *claimed, commands)
	_ = c.store.SetMachineStatus(machineID, "busy")
	_, _ = c.store.UpdateGoal(claimed.GoalID, "running", "")
	_, _ = c.store.AppendEvent(claimed.GoalID, claimed.ID, "WorkerStarted", map[string]any{
		"attempt": claimed.Attempt, "remote": true, "machine_id": machineID,
	})
	return job, nil
}
