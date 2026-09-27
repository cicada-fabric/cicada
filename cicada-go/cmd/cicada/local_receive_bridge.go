package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

// localReceiveCursor fences both independent Node inbox positions to the
// current native Session and Group. It is only a pagination token; every read
// revalidates the live binding before opening either inbox.
type localReceiveCursor struct {
	Version int    `json:"version"`
	Scope   string `json:"scope"`
	Local   int64  `json:"local"`
	Relay   int64  `json:"relay"`
	Turn    int    `json:"turn"`
}

func receiveScope(request localGroupRequest) string {
	value := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s",
		request.EndpointID, request.NativeSessionID, request.BindingID,
		request.BindingEpoch, request.GroupID)
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func decodeLocalReceiveCursor(raw string, request localGroupRequest) (localReceiveCursor, error) {
	cursor := localReceiveCursor{Version: 1, Scope: receiveScope(request)}
	if raw == "" {
		return cursor, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(data) > 1024 || json.Unmarshal(data, &cursor) != nil ||
		cursor.Version != 1 || cursor.Scope != receiveScope(request) ||
		cursor.Local < 0 || cursor.Relay < 0 || (cursor.Turn != 0 && cursor.Turn != 1) {
		return localReceiveCursor{}, errors.New("inbox cursor does not match the current native Session and Group")
	}
	return cursor, nil
}

func readScopedNodeInbox(ctx context.Context, path string, request localGroupRequest, after int64, limit int) ([]nodeinbox.VisibleMessage, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return []nodeinbox.VisibleMessage{}, nil
	} else if err != nil {
		return nil, err
	}
	inbox, err := nodeinbox.OpenReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer inbox.Close()
	return inbox.ListInjectedForSession(ctx, request.EndpointID,
		request.NativeSessionID, request.BindingEpoch, request.GroupID, after, limit)
}

func (b *machineAgentJoinBridge) receiveLocalGroup(request localGroupRequest) (*localGroupResult, error) {
	cursor, err := decodeLocalReceiveCursor(request.Cursor, request)
	if err != nil {
		return nil, err
	}
	limit := request.Limit
	if limit == 0 {
		limit = 8
	}
	local, err := readScopedNodeInbox(b.ctx, machineLocalGroupInboxPath(b.stateDir, b.nodeID), request, cursor.Local, limit)
	if err != nil {
		return nil, fmt.Errorf("read local Group inbox: %w", err)
	}
	relay, err := readScopedNodeInbox(b.ctx, machineNodeInboxPath(b.stateDir, b.nodeID), request, cursor.Relay, limit)
	if err != nil {
		return nil, fmt.Errorf("read cross-Node Group inbox: %w", err)
	}
	messages := make([]nodeinbox.VisibleMessage, 0, limit)
	localIndex, relayIndex := 0, 0
	for len(messages) < limit && (localIndex < len(local) || relayIndex < len(relay)) {
		if (cursor.Turn == 0 && localIndex < len(local)) || relayIndex >= len(relay) {
			item := local[localIndex]
			messages = append(messages, item)
			cursor.Local = item.Sequence
			localIndex++
			cursor.Turn = 1
		} else {
			item := relay[relayIndex]
			messages = append(messages, item)
			cursor.Relay = item.Sequence
			relayIndex++
			cursor.Turn = 0
		}
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return nil, err
	}
	return &localGroupResult{
		State: "READY", Messages: messages,
		NextCursor: base64.RawURLEncoding.EncodeToString(encoded),
	}, nil
}
