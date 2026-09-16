package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const eventStreamPollInterval = time.Second

func (h *Handler) goalEventStream(response http.ResponseWriter, request *http.Request, goalID string) {
	after, err := parseEventOffset(request.URL.Query().Get("after"))
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	goal, err := h.control.Goal(goalID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if goal == nil {
		writeError(response, http.StatusNotFound, errors.New("goal not found"))
		return
	}
	flusher, ok := response.(http.Flusher)
	if !ok {
		writeError(response, http.StatusInternalServerError, errors.New("event streaming is unavailable"))
		return
	}
	response.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	response.Header().Set("Cache-Control", "no-cache, no-store")
	response.Header().Set("Connection", "keep-alive")
	response.Header().Set("X-Accel-Buffering", "no")
	response.WriteHeader(http.StatusOK)
	flusher.Flush()

	poll := time.NewTicker(eventStreamPollInterval)
	defer poll.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		events, listErr := h.control.Events(goalID, after)
		if listErr != nil {
			writeSSEError(response, listErr)
			flusher.Flush()
			return
		}
		for _, event := range events {
			if err := writeSSEEvent(response, event); err != nil {
				return
			}
			after = event.ID
		}
		if len(events) > 0 {
			flusher.Flush()
		}
		select {
		case <-request.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprint(response, ": keep-alive\n\n")
			flusher.Flush()
		case <-poll.C:
		}
	}
}

func parseEventOffset(raw string) (int64, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	after, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || after < 0 {
		return 0, errors.New("after must be a non-negative event id")
	}
	return after, nil
}

func writeSSEEvent(response http.ResponseWriter, event store.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	typeName := strings.NewReplacer("\r", "_", "\n", "_").Replace(event.Type)
	if _, err := fmt.Fprintf(response, "id: %d\nevent: %s\n", event.ID, typeName); err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if _, err := fmt.Fprintf(response, "data: %s\n", line); err != nil {
			return err
		}
	}
	_, err = fmt.Fprint(response, "\n")
	return err
}

func writeSSEError(response http.ResponseWriter, err error) {
	message, _ := json.Marshal(map[string]string{"error": err.Error()})
	_, _ = fmt.Fprintf(response, "event: error\ndata: %s\n\n", message)
}
