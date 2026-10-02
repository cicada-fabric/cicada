package fabric

import (
	"strconv"
	"sync"
	"testing"
)

func TestNodeSSEAdmissionPerNodeLimitReleaseAndFairness(t *testing.T) {
	service := &Service{}
	releases := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		release, admitted := service.AdmitNodeSSEStream("node-a")
		if !admitted || release == nil {
			t.Fatalf("Node slot %d was not admitted", i+1)
		}
		releases = append(releases, release)
	}
	if _, admitted := service.AdmitNodeSSEStream("node-a"); admitted {
		t.Fatal("fifth stream for one Node was admitted")
	}
	otherRelease, admitted := service.AdmitNodeSSEStream("node-b")
	if !admitted {
		t.Fatal("one Node reaching its limit denied another Node")
	}
	otherRelease()

	releases[0]()
	releases[0]() // release is idempotent
	for _, release := range releases[1:] {
		release()
	}
	for i := 0; i < 4; i++ {
		release, admitted := service.AdmitNodeSSEStream("node-a")
		if !admitted {
			t.Fatalf("Node slot was not reusable after release: %d", i+1)
		}
		release()
	}
	if service.nodeSSEStreamCount != 0 || len(service.nodeSSEStreams) != 0 {
		t.Fatalf("stream accounting leaked: total=%d nodes=%d", service.nodeSSEStreamCount, len(service.nodeSSEStreams))
	}
}

func TestNodeSSEAdmissionGlobalLimitAndRelease(t *testing.T) {
	service := &Service{}
	releases := make([]func(), 0, 256)
	for node := 0; node < 64; node++ {
		nodeID := "node-" + strconv.Itoa(node)
		for slot := 0; slot < 4; slot++ {
			release, admitted := service.AdmitNodeSSEStream(nodeID)
			if !admitted || release == nil {
				t.Fatalf("global slot %d was denied", len(releases)+1)
			}
			releases = append(releases, release)
		}
	}
	if len(releases) != 256 || service.nodeSSEStreamCount != 256 {
		t.Fatalf("did not reach the global limit: releases=%d total=%d", len(releases), service.nodeSSEStreamCount)
	}
	if _, admitted := service.AdmitNodeSSEStream("node-new"); admitted {
		t.Fatal("stream was admitted beyond the global limit")
	}
	releases[0]()
	newRelease, admitted := service.AdmitNodeSSEStream("node-new")
	if !admitted {
		t.Fatal("released global capacity was not available to another Node")
	}
	newRelease()
	for _, release := range releases[1:] {
		release()
	}
	if service.nodeSSEStreamCount != 0 || len(service.nodeSSEStreams) != 0 {
		t.Fatalf("global stream accounting leaked: total=%d nodes=%d", service.nodeSSEStreamCount, len(service.nodeSSEStreams))
	}
}

func TestNodeSSEAdmissionConcurrentPerNodeLimit(t *testing.T) {
	const attempts = 128
	service := &Service{}
	start := make(chan struct{})
	releases := make(chan func(), attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if release, admitted := service.AdmitNodeSSEStream("node-race"); admitted {
				releases <- release
			}
		}()
	}
	close(start)
	workers.Wait()
	close(releases)
	accepted := make([]func(), 0, 4)
	for release := range releases {
		accepted = append(accepted, release)
	}
	if len(accepted) != 4 || service.nodeSSEStreamCount != 4 {
		t.Fatalf("concurrent admission accepted %d streams; total=%d", len(accepted), service.nodeSSEStreamCount)
	}
	var releasers sync.WaitGroup
	for _, release := range accepted {
		releasers.Add(1)
		go func(release func()) {
			defer releasers.Done()
			release()
			release()
		}(release)
	}
	releasers.Wait()
	if service.nodeSSEStreamCount != 0 || len(service.nodeSSEStreams) != 0 {
		t.Fatalf("concurrent idempotent release leaked: total=%d nodes=%d", service.nodeSSEStreamCount, len(service.nodeSSEStreams))
	}
}
