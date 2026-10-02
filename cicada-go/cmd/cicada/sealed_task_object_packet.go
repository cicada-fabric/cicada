package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// This is local application content inside an ordinary exact-Endpoint sealed
// SEND. It creates no Node kind, reserved route or Task authority by itself.
type sealedTaskObjectPacket struct {
	Version            int                           `json:"version"`
	TaskID             string                        `json:"task_id"`
	GroupID            string                        `json:"group_id"`
	Purpose            string                        `json:"purpose"`
	AssignmentVersion  int64                         `json:"assignment_version"`
	ContentVersion     int64                         `json:"content_version"`
	TaskRevision       int64                         `json:"task_revision"`
	OwnerEpoch         int64                         `json:"owner_epoch"`
	SenderEndpointID   string                        `json:"sender_endpoint_id"`
	ReaderEndpointID   string                        `json:"reader_endpoint_id"`
	ArtifactRefs       []store.SharedTaskArtifactRef `json:"artifact_refs"`
	Objective          string                        `json:"objective,omitempty"`
	AcceptanceCriteria string                        `json:"acceptance_criteria,omitempty"`
	Summary            string                        `json:"summary,omitempty"`
}

func decodeSealedTaskObjectPacket(body string) (*sealedTaskObjectPacket, error) {
	if len([]byte(body)) > 60*1024 {
		return nil, errors.New("sealed Task body exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(body))
	decoder.DisallowUnknownFields()
	var p sealedTaskObjectPacket
	if decoder.Decode(&p) != nil {
		return nil, errors.New("sealed Task body is not a typed Task object")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || p.Version != 1 || !validTaskHandoffToken(p.TaskID) || !validTaskHandoffToken(p.GroupID) || !validTaskHandoffToken(p.SenderEndpointID) || !validTaskHandoffToken(p.ReaderEndpointID) || p.SenderEndpointID == p.ReaderEndpointID || p.AssignmentVersion <= 0 || p.ContentVersion <= 0 || p.TaskRevision <= 0 || p.OwnerEpoch < 0 || len(p.ArtifactRefs) > 32 {
		return nil, errors.New("sealed Task body coordinates are invalid")
	}
	switch p.Purpose {
	case store.SharedTaskDefinitionPurpose:
		if strings.TrimSpace(p.Objective) == "" || strings.TrimSpace(p.AcceptanceCriteria) == "" || p.Summary != "" {
			return nil, errors.New("sealed Task definition requires objective and criteria only")
		}
	case store.SharedTaskResultPurpose:
		if strings.TrimSpace(p.Summary) == "" || p.Objective != "" || p.AcceptanceCriteria != "" || len(p.ArtifactRefs) == 0 || p.OwnerEpoch <= 0 {
			return nil, errors.New("sealed Task result requires summary and exact Artifact references only")
		}
	default:
		return nil, errors.New("sealed Task purpose is invalid")
	}
	return &p, nil
}
func matchSealedTaskObjectPacket(p *sealedTaskObjectPacket, ref store.SharedTaskSealedRef) bool {
	return p != nil && p.TaskID == ref.TaskID && p.GroupID == ref.GroupID && p.Purpose == ref.Purpose && p.AssignmentVersion == ref.AssignmentVersion && p.ContentVersion == ref.ContentVersion && p.TaskRevision == ref.TaskRevision && p.OwnerEpoch == ref.OwnerEpoch && p.SenderEndpointID == ref.SenderEndpointID && p.ReaderEndpointID == ref.ReaderEndpointID && reflect.DeepEqual(p.ArtifactRefs, ref.ArtifactRefs)
}
