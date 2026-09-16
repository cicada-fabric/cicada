package server

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestGoalEventStreamReplaysDurableEvents(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	goal, err := controlPlane.CreateGoal(control.GoalInput{Objective: "stream test", MonitorOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(controlPlane))
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/goals/"+goal.ID+"/events/stream?after=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected stream response: status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	scanner := bufio.NewScanner(response.Body)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "event: GoalCreated") {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("durable GoalCreated event was not streamed")
	}
}
