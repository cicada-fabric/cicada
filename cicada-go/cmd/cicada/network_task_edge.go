package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// The task identifier and claimant epoch are repeated inside Endpoint-sealed
// plaintext. Hub route metadata alone cannot prove what a recipient decrypted.
type networkTaskSealedPayload struct {
	Kind       string `json:"kind"`
	TaskID     string `json:"task_id"`
	OwnerEpoch int64  `json:"owner_epoch,omitempty"`
	Body       string `json:"body"`
}

func validNetworkTaskID(id string) bool {
	if len(id) < 24 || len(id) > 96 || !strings.HasPrefix(id, "ntask_") {
		return false
	}
	for _, b := range []byte(id) {
		if b != '_' && b != '-' && (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

func marshalNetworkTaskSealedPayload(kind, taskID string, ownerEpoch int64, body string) (string, error) {
	if !validNetworkTaskID(taskID) || body == "" || len(body) > 60*1024 ||
		(kind != "offer" && kind != "result") || kind == "offer" && ownerEpoch != 0 ||
		kind == "result" && ownerEpoch <= 0 {
		return "", errors.New("invalid Network Task sealed content")
	}
	encoded, err := json.Marshal(networkTaskSealedPayload{Kind: kind, TaskID: taskID, OwnerEpoch: ownerEpoch, Body: body})
	if err != nil || len(encoded) > 64*1024 {
		return "", errors.New("Network Task sealed content exceeds limit")
	}
	return string(encoded), nil
}

func validateNetworkTaskSealedPayload(messageID string, plaintext []byte) error {
	_, err := decodeNetworkTaskSealedPayload(messageID, plaintext)
	return err
}

func decodeNetworkTaskSealedPayload(messageID string, plaintext []byte) (*networkTaskSealedPayload, error) {
	if !strings.HasPrefix(messageID, "ntask_") {
		return nil, nil
	}
	if len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return nil, errors.New("Network Task sealed content is missing or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var value networkTaskSealedPayload
	if err := decoder.Decode(&value); err != nil || decoder.Decode(new(any)) != io.EOF ||
		!validNetworkTaskID(value.TaskID) || value.Body == "" || len(value.Body) > 60*1024 {
		return nil, errors.New("Network Task sealed content is invalid")
	}
	if value.Kind == "offer" && value.OwnerEpoch == 0 && strings.HasPrefix(messageID, value.TaskID+":offer:") &&
		len(messageID) > len(value.TaskID)+len(":offer:") && len(messageID) <= 256 {
		return &value, nil
	}
	if value.Kind == "result" && value.OwnerEpoch > 0 &&
		strings.HasPrefix(messageID, value.TaskID+":result:"+strconv.FormatInt(value.OwnerEpoch, 10)+":") &&
		len(messageID) > len(value.TaskID)+len(":result:")+len(strconv.FormatInt(value.OwnerEpoch, 10))+1 && len(messageID) <= 256 {
		return &value, nil
	}
	return nil, errors.New("Network Task plaintext ID or epoch differs from its signed route")
}
