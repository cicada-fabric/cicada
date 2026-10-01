package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const networkBroadcastMessagePrefix = "nbroadcast_"

type networkBroadcastSealedPayload struct {
	Version     int    `json:"version"`
	BroadcastID string `json:"broadcast_id"`
	Body        string `json:"body"`
}

func validNetworkBroadcastID(id string) bool {
	if len(id) < 24 || len(id) > 96 || !strings.HasPrefix(id, networkBroadcastMessagePrefix) {
		return false
	}
	for _, b := range []byte(id) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') &&
			(b < '0' || b > '9') && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

func networkBroadcastIDFromMessageID(messageID string) (string, bool) {
	if !strings.HasPrefix(messageID, networkBroadcastMessagePrefix) {
		return "", false
	}
	separator := strings.IndexByte(messageID, ':')
	if separator < 0 || separator+1 >= len(messageID) || len(messageID) > 256 {
		return "", true
	}
	id := messageID[:separator]
	suffix := messageID[separator+1:]
	if !validNetworkBroadcastID(id) || !strings.HasPrefix(suffix, "reader:") ||
		len(suffix) <= len("reader:") {
		return "", true
	}
	return id, true
}

func marshalNetworkBroadcastSealedPayload(broadcastID, body string) (string, error) {
	if !validNetworkBroadcastID(broadcastID) || body == "" || len([]byte(body)) > 64*1024 {
		return "", errors.New("invalid Network Broadcast sealed content")
	}
	encoded, err := json.Marshal(networkBroadcastSealedPayload{Version: 1,
		BroadcastID: broadcastID, Body: body})
	if err != nil || len(encoded) > 68*1024 {
		return "", errors.New("Network Broadcast sealed content exceeds limit")
	}
	return string(encoded), nil
}

func decodeNetworkBroadcastSealedPayload(messageID string, plaintext []byte) (*networkBroadcastSealedPayload, error) {
	broadcastID, reserved := networkBroadcastIDFromMessageID(messageID)
	if !reserved {
		return nil, nil
	}
	if broadcastID == "" || len(plaintext) == 0 || len(plaintext) > 68*1024 {
		return nil, errors.New("Network Broadcast sealed content is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var payload networkBroadcastSealedPayload
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(new(any)) != io.EOF ||
		payload.Version != 1 || payload.BroadcastID != broadcastID || payload.Body == "" ||
		len([]byte(payload.Body)) > 64*1024 {
		return nil, errors.New("Network Broadcast sealed content differs from its authorized message ID")
	}
	return &payload, nil
}
