package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func syntheticNodeHubView(i int) LocalNodeHubView {
	return LocalNodeHubView{ConnectionID: fmt.Sprintf("%032x", i+1), HubID: fmt.Sprintf("synthetic-hub-%d", i), NodeID: "synthetic-shared-node", Alias: fmt.Sprintf("Synthetic %d", i), HubAddress: fmt.Sprintf("127.0.0.1:%d", 9876+i), NodeName: "Synthetic Node", DesiredState: "ENABLED", PairingState: "READY", RuntimeState: "RUNNING", HubOnline: "UNKNOWN", LocalFence: 1}
}

func TestNodeHubContractListClosedAndBounded(t *testing.T) {
	for _, n := range []int{0, 1, 8, 9} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			v := LocalNodeHubList{Format: LocalNodeHubsFormat, Revision: 1, ManagerState: "RUNNING", Connections: []LocalNodeHubView{}}
			for i := 0; i < n; i++ {
				v.Connections = append(v.Connections, syntheticNodeHubView(i))
			}
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeLocalNodeHubList(raw)
			if (err == nil) != (n <= 8) {
				t.Fatal("wrong bounded list result")
			}
		})
	}
	base := LocalNodeHubList{Format: LocalNodeHubsFormat, Revision: 1, ManagerState: "RUNNING", Connections: []LocalNodeHubView{syntheticNodeHubView(0)}}
	raw, _ := json.Marshal(base)
	for name, changed := range map[string][]byte{
		"unknown":   []byte(strings.Replace(string(raw), `"format":`, `"token":"SYNTHETIC-REJECTED","format":`, 1)),
		"duplicate": []byte(strings.Replace(string(raw), `"format":`, `"revision":1,"format":`, 1)),
		"trailing":  append(append([]byte(nil), raw...), []byte(`{}`)...),
		"null":      []byte(`{"format":"cicada.local-node-hubs.v1","revision":1,"manager_state":"RUNNING","connections":null}`),
		"oversized": []byte(strings.Repeat(" ", MaxLocalNodeHubListBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalNodeHubList(changed); err == nil {
				t.Fatal("non-closed list accepted")
			}
		})
	}
	for _, kind := range []string{"alias", "hub", "id", "address", "unready", "stopped", "online"} {
		t.Run(kind, func(t *testing.T) {
			v := base
			v.Connections = append([]LocalNodeHubView(nil), base.Connections...)
			if kind == "unready" {
				v.Connections[0].PairingState = "UNKNOWN"
			} else if kind == "stopped" {
				v.ManagerState = "STOPPED"
			} else if kind == "online" {
				v.Connections[0].HubOnline = "ONLINE"
			} else {
				next := syntheticNodeHubView(1)
				switch kind {
				case "address":
					next.HubAddress = v.Connections[0].HubAddress
				case "alias":
					next.Alias = strings.ToUpper(v.Connections[0].Alias)
				case "hub":
					next.HubID = v.Connections[0].HubID
				case "id":
					next.ConnectionID = v.Connections[0].ConnectionID
				}
				v.Connections = append(v.Connections, next)
			}
			b, _ := json.Marshal(v)
			if _, err := DecodeLocalNodeHubList(b); err == nil {
				t.Fatal("ambiguous or false readiness accepted")
			}
		})
	}
}

func TestNodeHubContractRemovalCannotClaimRemoteRevocation(t *testing.T) {
	v := LocalNodeHubRemoval{Format: LocalNodeHubRemovalFormat, ConnectionID: strings.Repeat("a", 32), HubID: "synthetic-hub", NodeID: "synthetic-node", LocalFence: 2, State: "LOCAL_STOPPED", RemoteRevocation: "NOT_REQUESTED"}
	for _, state := range []string{"LOCAL_STOPPED", "STOP_PENDING"} {
		v.State = state
		b, _ := json.Marshal(v)
		if _, err := DecodeLocalNodeHubRemoval(b); err != nil {
			t.Fatal(err)
		}
	}
	v.RemoteRevocation = "REVOKED"
	b, _ := json.Marshal(v)
	if _, err := DecodeLocalNodeHubRemoval(b); err == nil {
		t.Fatal("local removal fabricated remote fact")
	}
}

func TestNodeHubContractRegistryAndIPCRejectAuthorityExpansion(t *testing.T) {
	r := nodeHubRegistry{Format: LocalNodeHubRegistryFormat, Revision: 1, NodeID: "synthetic-node", NodeName: "Synthetic", WriterRoot: "/synthetic/original", Connections: []nodeHubRegistryEntry{}}
	for i := 0; i < 8; i++ {
		r.Connections = append(r.Connections, nodeHubRegistryEntry{ConnectionID: fmt.Sprintf("%032x", i+1), Alias: fmt.Sprintf("Hub %d", i), HubID: fmt.Sprintf("synthetic-hub-%d", i), NodeID: r.NodeID, NodeName: r.NodeName, HubAddress: fmt.Sprintf("127.0.0.1:%d", 9876+i), Origin: "https://synthetic.invalid", StateDir: fmt.Sprintf("/synthetic/state-%d", i), WriterRoot: r.WriterRoot, MCPSessionStateFile: fmt.Sprintf("/synthetic/mcp-%d/sessions.json", i), MCPOutboxStateFile: fmt.Sprintf("/synthetic/mcp-%d/outbox.sqlite3", i), DesiredState: "ENABLED", LocalFence: 1})
	}
	b, _ := json.Marshal(r)
	if _, err := decodeNodeHubRegistry(b); err != nil {
		t.Fatal(err)
	}
	original := r.Connections[1].MCPSessionStateFile
	r.Connections[1].MCPSessionStateFile = r.Connections[0].MCPSessionStateFile
	b, _ = json.Marshal(r)
	if _, err := decodeNodeHubRegistry(b); err == nil {
		t.Fatal("cross-Hub MCP session path reuse accepted")
	}
	r.Connections[1].MCPSessionStateFile = original
	r.Connections[0].WriterRoot = "/synthetic/replacement"
	b, _ = json.Marshal(r)
	if _, err := decodeNodeHubRegistry(b); err == nil {
		t.Fatal("replaced shared WriterRoot accepted")
	}
	q := nodeHubControlRequest{Format: "cicada.node-hub-control.v1", Operation: "RECONCILE", Nonce: strings.Repeat("a", 32), InstanceID: strings.Repeat("b", 32), Revision: 2}
	b, _ = json.Marshal(q)
	if _, err := decodeNodeHubControlRequest(b); err != nil {
		t.Fatal(err)
	}
	q.Operation = "owner.root.activate"
	b, _ = json.Marshal(q)
	if _, err := decodeNodeHubControlRequest(b); err == nil {
		t.Fatal("IPC became arbitrary remote RPC")
	}
	q.Operation = "STATUS"
	b, _ = json.Marshal(q)
	b = []byte(strings.Replace(string(b), `"operation":`, `"command":"SYNTHETIC-REJECTED","operation":`, 1))
	if _, err := decodeNodeHubControlRequest(b); err == nil {
		t.Fatal("IPC accepted executable injection")
	}
	reply := nodeHubControlReply{Format: "cicada.node-hub-control-reply.v1", Operation: q.Operation, Nonce: q.Nonce, InstanceID: q.InstanceID, Revision: 2, Result: LocalNodeHubList{Format: LocalNodeHubsFormat, Revision: 2, ManagerState: "RUNNING", Connections: []LocalNodeHubView{}}}
	b, _ = json.Marshal(reply)
	if _, err := decodeNodeHubControlReply(b, q); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nonce", "instance", "revision"} {
		changed := reply
		switch field {
		case "nonce":
			changed.Nonce = strings.Repeat("c", 32)
		case "instance":
			changed.InstanceID = strings.Repeat("d", 32)
		case "revision":
			changed.Revision = 1
		}
		b, _ = json.Marshal(changed)
		if _, err := decodeNodeHubControlReply(b, q); err == nil {
			t.Fatal("stale IPC response target accepted")
		}
	}
}

func TestNodeHubContractManagedPinEpochIsPairedAndNotInterchangeable(t *testing.T) {
	p := syntheticLocalNodePin(t, privateLocalNodeRoot(t), "managed-node")
	if err := validateLocalNodePin(p); err != nil {
		t.Fatal(err)
	}
	managed := p
	managed.ConnectionID = strings.Repeat("a", 32)
	if err := validateLocalNodePin(managed); err == nil {
		t.Fatal("connection ID without epoch accepted")
	}
	managed.ConnectionEpoch = 1
	if err := validateLocalNodePin(managed); err != nil {
		t.Fatal(err)
	}
	if sameLocalNodeAuthority(p, managed) {
		t.Fatal("legacy and managed authority interchanged")
	}
	next := managed
	next.ConnectionEpoch++
	if sameLocalNodeAuthority(managed, next) {
		t.Fatal("retired epoch borrowed current connection")
	}
	next.ConnectionID = ""
	if err := validateLocalNodePin(next); err == nil {
		t.Fatal("epoch without connection ID accepted")
	}
}
