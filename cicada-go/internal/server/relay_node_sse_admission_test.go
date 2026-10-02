package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

func relayNodeSSESubscriberCount(t *testing.T, service *fabricpkg.Service, field, nodeID string) int {
	t.Helper()
	value := reflect.ValueOf(service).Elem().FieldByName(field)
	if !value.IsValid() || value.Kind() != reflect.Map {
		t.Fatalf("Fabric subscription map %q is unavailable", field)
	}
	subscribers := value.MapIndex(reflect.ValueOf(nodeID))
	if !subscribers.IsValid() {
		return 0
	}
	return subscribers.Len()
}

func TestRelayNodeSSEAdmissionBoundsStreamsAndReleases(t *testing.T) {
	service, persistence, _ := newRelayNodeTestService(t)
	const nodeID = "node-sse-admission"
	token, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, nodeID, digest)
	server := httptest.NewServer(NewFabricHandler(service, ""))
	defer server.Close()
	open := func(auth string) (*http.Response, error) {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/v2/relay/nodes/"+nodeID+"/events", nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", auth)
		return http.DefaultClient.Do(request)
	}
	unauthenticated, err := open("CicadaNode invalid")
	if err != nil {
		t.Fatal("send unauthenticated stream request", err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream status=%d", unauthenticated.StatusCode)
	}

	streams := make([]*http.Response, 0, 4)
	defer func() {
		for _, stream := range streams {
			_ = stream.Body.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		response, err := open("CicadaNode " + token)
		if err != nil {
			t.Fatalf("open admitted stream %d: %v", i+1, err)
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
			_ = response.Body.Close()
			t.Fatalf("stream %d status=%d type=%q", i+1, response.StatusCode, response.Header.Get("Content-Type"))
		}
		streams = append(streams, response)
	}

	rejected, err := open("CicadaNode " + token)
	if err != nil {
		t.Fatal("send over-limit stream request", err)
	}
	body, readErr := io.ReadAll(rejected.Body)
	_ = rejected.Body.Close()
	if readErr != nil {
		t.Fatal("read bounded capacity response", readErr)
	}
	if rejected.StatusCode != http.StatusTooManyRequests || rejected.Header.Get("Retry-After") != "1" ||
		rejected.Header.Get("Content-Type") != "text/plain; charset=utf-8" || len(body) == 0 {
		t.Fatalf("capacity response status=%d retry=%q type=%q body=%q", rejected.StatusCode,
			rejected.Header.Get("Retry-After"), rejected.Header.Get("Content-Type"), body)
	}

	for _, stream := range streams {
		_ = stream.Body.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for time.Now().Before(deadline) {
		releases = make([]func(), 0, 4)
		for i := 0; i < 4; i++ {
			release, admitted := service.AdmitNodeSSEStream(nodeID)
			if !admitted {
				break
			}
			releases = append(releases, release)
		}
		if len(releases) == 4 {
			break
		}
		for _, release := range releases {
			release()
		}
		releases = nil
		time.Sleep(5 * time.Millisecond)
	}
	if len(releases) != 4 {
		t.Fatal("closing admitted streams did not release all four Node slots")
	}
	if relayNodeSSESubscriberCount(t, service, "nodeEvents", nodeID) != 0 ||
		relayNodeSSESubscriberCount(t, service, "spaceEvents", nodeID) != 0 {
		t.Fatal("closing admitted streams retained their wake subscriptions")
	}
	for _, release := range releases {
		release()
	}
}

func TestRelayNodeSSEAdmission429UsesBoundedFrameWrite(t *testing.T) {
	service, persistence, _ := newRelayNodeTestService(t)
	const nodeID = "node-sse-deadline"
	token, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, nodeID, digest)
	releases := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		release, admitted := service.AdmitNodeSSEStream(nodeID)
		if !admitted {
			t.Fatal("could not prepare full Node stream capacity")
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	writer := &relayDeadlineWriter{}
	writer.Header()
	request := httptest.NewRequest(http.MethodGet, "/v2/relay/nodes/"+nodeID+"/events", nil)
	NewFabricHandler(service, "").(*Handler).relayNodeEvents(writer, request, nodeID, token)
	if writer.status != http.StatusTooManyRequests || writer.Header().Get("Retry-After") != "1" {
		t.Fatalf("bounded rejection status=%d retry=%q", writer.status, writer.Header().Get("Retry-After"))
	}
	if writer.writes != 1 || writer.flushes != 1 || len(writer.deadlines) != 4 ||
		writer.deadlines[2].IsZero() || !writer.deadlines[3].IsZero() ||
		!writer.flushDeadline.Equal(writer.deadlines[2]) {
		t.Fatalf("429 response did not use one bounded frame write: writes=%d flushes=%d deadlines=%v",
			writer.writes, writer.flushes, writer.deadlines)
	}
	if writer.deadlines[2].After(time.Now().Add(relayNodeStreamWriteTimeout)) {
		t.Fatal("429 response write deadline exceeded the existing stream timeout")
	}
	if relayNodeSSESubscriberCount(t, service, "nodeEvents", nodeID) != 0 ||
		relayNodeSSESubscriberCount(t, service, "spaceEvents", nodeID) != 0 {
		t.Fatal("rejected stream registered event subscriptions")
	}
}
