package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestEndpointGroupsFreshOperatorProofDoesNotExtendOrRetargetOldTicket(t *testing.T) {
	var authority localCodexContextAuthority
	issue := syntheticCodexContextIssue()
	issue.ToolName = "codex.operator.endpoint_leave"
	profile := syntheticEndpointGroupsContext()
	profile.Harness = issue.Harness
	profile.NativeSessionID = issue.NativeSessionID
	profile.Workspace = issue.Workspace
	binding, err := codexContextBinding(profile)
	if err != nil {
		t.Fatal(err)
	}
	q := syntheticLocalEndpointRequest("endpoint_leave")
	q.APIOrigin = issue.APIOrigin
	q.Harness = issue.Harness
	q.NativeSessionID = issue.NativeSessionID
	q.Workspace = issue.Workspace
	q.Name = ""
	q.codexEndpointGroupsBinding = binding.codexEndpointGroupsBinding
	issue.ArgumentsDigest, _ = codexArgumentsDigest(map[string]any{"operation": q.Operation, "name": q.Name, "pair_label": q.PairLabel, "slot": q.Slot})
	oldTime := time.Now().Add(-31 * time.Second)
	old, err := authority.issueVerified(issue, "synthetic-node-binding", oldTime, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.consume(syntheticCodexContextConsume(issue, old.Ticket), "synthetic-node-binding", oldTime); err != nil {
		t.Fatal(err)
	}
	q.endpointGroupsOperatorContextProof = endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(old.Ticket, ".")[0], ContextConnectionNonce: issue.ConnectionNonce}
	if authority.consumeEndpointGroupsOperator(q, nil, time.Now()) == nil {
		t.Fatal("old consumed ticket lifetime was extended")
	}
	digest := codexOperatorDigest(q, false)
	issue.ConnectionNonce = strings.Repeat("b", 64)
	issue.ArgumentsDigest, _ = codexArgumentsDigest(map[string]any{"operation": q.Operation, "name": q.Name, "pair_label": q.PairLabel, "slot": q.Slot, "original_request_id": q.RequestID, "original_intent_digest": digest})
	fresh, err := authority.issueVerified(issue, "synthetic-node-binding", time.Now(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.consume(syntheticCodexContextConsume(issue, fresh.Ticket), "synthetic-node-binding", time.Now()); err != nil {
		t.Fatal(err)
	}
	proof := &endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(fresh.Ticket, ".")[0], ContextConnectionNonce: issue.ConnectionNonce}
	for _, change := range []func(*localEndpointRequest){func(x *localEndpointRequest) { x.RequestID = strings.Repeat("c", 32) }, func(x *localEndpointRequest) { x.Name = "synthetic-retarget" }, func(x *localEndpointRequest) { x.RegistrationBindingEpoch++ }} {
		other := q
		change(&other)
		if authority.consumeEndpointGroupsOperator(other, proof, time.Now()) == nil {
			t.Fatal("fresh invocation proof authenticated a different original intent/anchor")
		}
	}
	if err := authority.consumeEndpointGroupsOperator(q, proof, time.Now()); err != nil {
		t.Fatal("fresh exact original invocation proof rejected", err)
	}
	q.InvocationProof = proof
	if codexOperatorDigest(q, false) != digest {
		t.Fatal("transient proof changed frozen business intent")
	}
}

// Original registration/key receipts are produced by the real existing Hub
// service. Only the new Describe projection is scripted and sealed with this
// disposable fixture's existing synthetic Hub-Control key. This does not claim
// the production Hub Endpoint-Groups/lease Guard gate.
func endpointGroupsOriginalFixture(t *testing.T) (*nativePairTCPConsumerFixture, machineEndpointGroupsRegistration) {
	t.Helper()
	f := newNativePeerTCPConsumerFixture(t, false)
	activateLocalDomainConsumer(t, f)
	q := localDomainEndpointCommand(t, f, 0)
	accepted, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil {
		t.Fatal(err)
	}
	r, enrolled, err := f.client.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || enrolled {
		t.Fatal("fixture original candidate", err)
	}
	j, d := accepted.Join, accepted.LocalDomain
	m, p, k := d.Member, d.Description.Policy, d.Grant.Manifest
	registration := e2ee.EndpointGroupRegistration{HubID: p.HubID, OwnerID: p.OwnerID, NodeID: m.NodeID, Harness: m.Runtime, NativeSessionID: m.NativeSessionID, Workspace: m.Workspace, EndpointID: m.EndpointID, PrincipalID: m.PrincipalID}
	digest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	if err != nil {
		t.Fatal(err)
	}
	r.Anchor = wire.EndpointGroupsRegistrationAnchor{Profile: wire.EndpointGroupsNativeProfile, RegistrationSource: wire.EndpointGroupsRegistrationSource, Registration: registration, RegistrationDigest: digest, RegistrationRevision: 1, LocalUserScope: m.LocalUserScope, NetworkID: p.NetworkID, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, NodeKeyEpoch: p.Node.NodeKeyEpoch, LeaseOwner: m.LeaseOwner, NetworkAccessBindingID: m.NetworkAccessBindingID, NetworkAccessEpoch: m.NetworkAccessEpoch, NetworkMembershipRevision: m.NetworkMembershipRevision, EndpointNetworkRevision: m.EndpointNetworkRevision, CandidateVersion: m.CandidateVersion, CandidateKeyID: k.CandidateKeyID, CandidatePublic: k.CandidatePublicIdentity, CandidateFingerprint: k.CandidateFingerprint, CandidateProofDigest: k.CandidateProofDigest, State: "REGISTERED", LeaseExpiresAt: j.LeaseExpiresAt}
	if wire.ValidateEndpointGroupsRegistrationAnchor(r.Anchor, f.hub) != nil {
		t.Fatal("fixture anchor differs from real original receipts")
	}
	if err := f.client.saveEndpointGroupsRegistration(r); err != nil {
		t.Fatal(err)
	}
	return f, r
}

func endpointGroupsOperatorCommand(t *testing.T, f *nativePairTCPConsumerFixture, r machineEndpointGroupsRegistration, operation string) localEndpointRequest {
	t.Helper()
	issue := localDomainConsumerIssue(t, f, 0)
	issue.ToolName = codexOperatorContextTool(operation)
	name := ""
	if operation == "endpoint_register" {
		name = "Synthetic original registered Thread"
	}
	issue.ArgumentsDigest, _ = codexArgumentsDigest(map[string]any{"operation": operation, "name": name, "pair_label": "", "slot": ""})
	ticket, err := requestMachineAgentCodexContextIssue(f.bridge.path, issue)
	if err != nil {
		t.Fatal("actual original native-context issue", err)
	}
	consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := codexContextBinding(consumed.Context)
	if err != nil || binding.EndpointGroupsVersion != 1 {
		t.Fatal("explicit profile missing", err)
	}
	now := time.Now().UTC()
	id, err := newLocalEndpointRequestID(now)
	if err != nil {
		t.Fatal(err)
	}
	return localEndpointRequest{Version: 1, Operation: operation, RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: r.Anchor.Registration.NativeSessionID, Workspace: r.Anchor.Registration.Workspace, Name: name, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding, endpointGroupsOperatorContextProof: endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(ticket.Ticket, ".")[0], ContextConnectionNonce: issue.ConnectionNonce}}
}

func TestEndpointGroupsLocalLeavePersistsAndKeepsOriginalReceipts(t *testing.T) {
	f, r := endpointGroupsOriginalFixture(t)
	_, joined, completed, err := f.client.endpointGroupsOriginal(r)
	if err != nil {
		t.Fatal(err)
	}
	identityBefore, err := os.ReadFile(filepath.Join(machineNodeStateDir(f.nodeRoot, f.nodeID), "node-control-identity.bin"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	postsBefore := f.posts["/v2/fabric/leave"]
	joinsBefore := len(f.nodePackets[wire.OperationLocalDomainNodeJoin])
	f.mu.Unlock()
	q := endpointGroupsOperatorCommand(t, f, r, "endpoint_leave")
	result, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || result.State != "COMPLETED" || !result.EndpointGroupsLocalOffline || result.Join != nil || result.Registration.EndpointID != r.Anchor.Registration.EndpointID {
		t.Fatal("actual private leave failed to stop only original local registration", err)
	}
	if err := validateCodexOperatorResult(codexOperatorPending{Request: q, IntentDigest: codexOperatorDigest(q, false), NodeID: f.nodeID}, result, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(f.client.statePath)
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
	if err != nil {
		t.Fatal(err)
	}
	saved, enrolled, err := f.client.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || !saved.LocallyOffline || !sameEndpointGroupsAnchor(saved.Anchor, r.Anchor) {
		t.Fatal("restart forgot durable local stop", err)
	}
	if _, err := f.bridge.renewEndpointGroupsRegistration(context.Background(), f.client, saved); !errors.Is(err, errEndpointGroupsOffline) {
		t.Fatal("offline registration renewed after restart", err)
	}
	if err := endpointGroupsLocalNativeOnline(f.ctx, f.nodeRoot, f.nodeID, r.Anchor.Registration.EndpointID, r.Anchor.BindingID, r.Anchor.BindingEpoch, nil); !errors.Is(err, errEndpointGroupsOffline) {
		t.Fatal("offline registration admitted native injection after restart", err)
	}
	issue := localDomainConsumerIssue(t, f, 0)
	issue.ToolName = "cicada_groups"
	issue.TurnID = "synthetic-original-turn"
	issue.ToolUseID = "synthetic-actual-tool"
	if _, err := requestMachineAgentCodexContextIssue(f.bridge.path, issue); err == nil {
		t.Fatal("offline registration issued an MCP business context")
	}
	replay, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || !replay.EndpointGroupsLocalOffline {
		t.Fatal("original Leave was not exactly recoverable without a replacement Hook", err)
	}
	_, currentJoin, currentComplete, err := f.client.endpointGroupsOriginal(saved)
	if err != nil || currentJoin.SessionToken != joined.SessionToken || currentJoin.Member.BindingID != joined.Member.BindingID || currentJoin.Member.BindingEpoch != joined.Member.BindingEpoch || !bytes.Equal(currentComplete.Grant.NodeProof, completed.Grant.NodeProof) {
		t.Fatal("local stop changed original encrypted key/token/binding receipt", err)
	}
	identityAfter, err := os.ReadFile(filepath.Join(machineNodeStateDir(f.nodeRoot, f.nodeID), "node-control-identity.bin"))
	if err != nil || !bytes.Equal(identityBefore, identityAfter) {
		t.Fatal("local stop replaced Node identity", err)
	}
	f.mu.Lock()
	changed := f.posts["/v2/fabric/leave"] != postsBefore || len(f.nodePackets[wire.OperationLocalDomainNodeJoin]) != joinsBefore
	f.mu.Unlock()
	if changed {
		t.Fatal("local stop invoked global Leave or a new Join")
	}
}

func TestEndpointGroupsExplicitJoinKeepsG1DenyAndG2WithoutAutoSelection(t *testing.T) {
	f, r := endpointGroupsOriginalFixture(t)
	_, original, completed, err := f.client.endpointGroupsOriginal(r)
	if err != nil {
		t.Fatal(err)
	}
	r.LocallyOffline = true
	if err := f.client.saveEndpointGroupsRegistration(r); err != nil {
		t.Fatal(err)
	}
	anchor := r.Anchor
	group1 := completed.Description.Policy.GroupID
	group2 := "zz-synthetic-independent-G2"
	head1 := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "REMOVED"}
	policy := strings.Repeat("c", 32)
	head2 := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "NONE", PolicyID: policy, PolicyEpoch: 1}
	nativeDigest, _ := e2ee.EndpointGroupNativeIdentityDigest(wire.EndpointGroupsNativeIdentity(anchor))
	headDigest, _ := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, group2, head2)
	relation := wire.EndpointGroupRelation{HubID: anchor.Registration.HubID, OwnerID: anchor.Registration.OwnerID, NodeID: anchor.Registration.NodeID, LocalUserScope: anchor.LocalUserScope, NetworkID: anchor.NetworkID, GroupID: group2, EndpointID: anchor.Registration.EndpointID, PrincipalID: anchor.Registration.PrincipalID, RegistrationDigest: anchor.RegistrationDigest, RegistrationRevision: anchor.RegistrationRevision, Source: "OWNER_EXPLICIT", AuthorityID: policy, AuthorityEpoch: 1, ContributionRevision: 1, State: "ACTIVE", DecisionRevision: 1, OwnerControlDigest: headDigest, PolicyID: policy, PolicyEpoch: 1, BindingID: anchor.BindingID, BindingEpoch: anchor.BindingEpoch, MembershipRevision: 1, EndpointJoinRevision: 1, CandidateVersion: anchor.CandidateVersion, CandidateKeyID: anchor.CandidateKeyID, CandidateFingerprint: anchor.CandidateFingerprint, CandidateProofDigest: anchor.CandidateProofDigest}
	ref := wire.EndpointGroupSourceReference{Source: relation.Source, AuthorityID: policy, AuthorityEpoch: 1, ContributionRevision: 1}
	description := wire.EndpointGroupsNodeDescribeResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: anchor, Relations: []wire.OwnerEndpointGroupsRelationCard{{GroupID: group1, GroupName: "Synthetic removed G1", NetworkID: anchor.NetworkID, State: "REMOVED", RelationRevision: 1, DecisionRevision: 1, ManualDeny: true, OwnerControl: head1, KeyState: "REVOKED"}, {GroupID: group2, GroupName: "Synthetic independent G2", NetworkID: anchor.NetworkID, State: "ACTIVE", RelationRevision: 1, DecisionRevision: 1, OwnerControl: head2, Contributions: []wire.OwnerEndpointGroupsContributionCard{{Source: relation.Source, AuthorityID: policy, AuthorityEpoch: 1, ContributionRevision: 1, State: "ACTIVE", KeyState: "CURRENT", Effective: true}}, SelectedSource: &ref, KeyState: "CURRENT"}}, Authorities: []wire.EndpointGroupCurrentEndpoint{{OwnerControl: head2, Relation: relation}}, RelationsRevision: 2, Complete: true}
	keyRaw, err := os.ReadFile(filepath.Join(f.root, "hub", "e2ee", "node-control-identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.UnmarshalIdentity(keyRaw)
	if err != nil {
		t.Fatal(err)
	}
	binding := f.client.approvedBinding()
	f.mu.Lock()
	prior := f.handler
	f.mu.Unlock()
	var mu sync.Mutex
	receipts := map[string][]byte{}
	f.mu.Lock()
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == wire.OwnerEndpointGroupsCapabilitiesPath {
			caps, _ := wire.NewOwnerEndpointGroupsCapabilities(f.hub)
			caps.Available = true
			caps.NativeSelfGroups = true
			raw, _ := json.Marshal(caps)
			_, _ = w.Write(raw)
			return
		}
		if request.URL.Path != "/v2/node/control/rpc" {
			prior.ServeHTTP(w, request)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(request.Body, wire.MaxEndpointGroupsNodeOriginalBytes+1))
		packet, decodeErr := nodewire.DecodePacket(raw)
		if decodeErr == nil && !endpointGroupsNodeBusinessOperation(packet.Route.Operation) {
			request.Body = io.NopCloser(bytes.NewReader(raw))
			prior.ServeHTTP(w, request)
			return
		}
		opened, err := nodewire.OpenRequest(hubKey, binding.NodeKey, binding, raw)
		if err == nil && opened.Route.Operation == wire.OperationEndpointGroupsNodeKeyPrepare {
			// The ordinary managed worker may tick during a race build. This
			// scripted snapshot has no new Owner key proof: refuse it explicitly
			// instead of fabricating a grant or disabling the real worker.
			sealed, sealErr := nodewire.SealResponse(hubKey, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, false, nil, "KEY_NOT_READY"))
			if sealErr != nil {
				t.Error(sealErr)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(sealed)
			return
		}
		if err != nil || opened.Route.Operation != wire.OperationEndpointGroupsNodeDescribe {
			t.Error("scripted projection received unexpected/new business operation", err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		digest := nodewire.RecoveryDigest(raw)
		if receipt := receipts[digest]; receipt != nil {
			_, _ = w.Write(receipt)
			return
		}
		stateRaw, _ := os.ReadFile(f.client.statePath)
		var durable machineNodeControlState
		_ = json.Unmarshal(stateRaw, &durable)
		if !bytes.Equal(durable.PendingPacket, raw) {
			t.Error("new Describe POST preceded durable exact packet")
			w.WriteHeader(500)
			return
		}
		description.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := wire.ValidateEndpointGroupsNodeDescribeResult(description, f.hub, time.Now().UTC()); err != nil {
			t.Error("invalid scripted G1/G2 projection", err)
			w.WriteHeader(500)
			return
		}
		sealed, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, description, ""))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		receipts[digest] = sealed
		_, _ = w.Write(sealed)
	})
	f.mu.Unlock()
	capabilityRaw := f.http(t, http.MethodGet, wire.OwnerEndpointGroupsCapabilitiesPath, "", "", nil, http.StatusOK)
	if _, err := wire.DecodeOwnerEndpointGroupsCapabilities(capabilityRaw, f.hub); err != nil {
		t.Fatal("scripted capability must use canonical shared DTO", err)
	}
	q := endpointGroupsOperatorCommand(t, f, r, "endpoint_register")
	result, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || result.State != "COMPLETED" || result.Join != nil || result.EndpointGroups == nil || result.EndpointGroupsLocalOffline {
		t.Fatal("G1 deny blocked independent original registration/G2", err)
	}
	if err := validateCodexOperatorResult(codexOperatorPending{Request: q, IntentDigest: codexOperatorDigest(q, false), NodeID: f.nodeID}, result, nil); err != nil {
		t.Fatal(err)
	}
	public := formatCodexOperatorResult(codexOperatorCommand{operation: q.Operation}, result)
	if strings.Contains(public, "joined") || !strings.Contains(public, "No Group was selected automatically") {
		t.Fatal("registration-only Join claimed Group admission")
	}
	saved, _, err := f.client.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || saved.LocallyOffline || saved.Anchor.BindingID != anchor.BindingID || saved.Anchor.BindingEpoch != anchor.BindingEpoch {
		t.Fatal("explicit Join replaced or failed to resume original anchor", err)
	}
	_, current, _, err := f.client.endpointGroupsOriginal(saved)
	if err != nil || current.SessionToken != original.SessionToken {
		t.Fatal("explicit Join manufactured a new token", err)
	}
	root := privateLocalNodeRoot(t)
	if err := startLocalNodeDiscovery(f.bridge, localNodePublishConfig{root, filepath.Join(root, "mcp", "sessions.json"), filepath.Join(root, "mcp", "outbox.sqlite3")}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_MACHINE_ID", "synthetic-forged-ambient-node")
	t.Setenv("CODEX_THREAD_ID", "synthetic-forged-ambient-thread")
	var output bytes.Buffer
	if err := nativeThreadOperatorCommand("join", []string{"--thread", q.NativeSessionID, "--name", "Synthetic terminal original Thread", "--user-root", root}, &output); err != nil {
		t.Fatal("actual thin terminal Join/private Node path", err)
	}
	if strings.Contains(output.String(), original.SessionToken) || !strings.Contains(output.String(), "registration is ready") {
		t.Fatal("terminal Join leaked a credential or claimed Group authority")
	}
	output.Reset()
	if err := nativeThreadOperatorCommand("leave", []string{"--thread", q.NativeSessionID, "--user-root", root}, &output); err != nil {
		t.Fatal("actual thin terminal Leave/private Node path", err)
	}
	if !strings.Contains(output.String(), "stopped local Cicada access") {
		t.Fatal("terminal Leave did not describe its local boundary")
	}
	stopped, _, err := f.client.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !stopped.LocallyOffline || stopped.Anchor.BindingID != anchor.BindingID || stopped.Anchor.BindingEpoch != anchor.BindingEpoch {
		t.Fatal("terminal Leave replaced original identity or did not stop local access", err)
	}
	for _, operation := range []string{"endpoint_leave", "endpoint_register"} {
		t.Run("first-send-restart-"+operation, func(t *testing.T) {
			q := endpointGroupsOperatorCommand(t, f, stopped, operation)
			if operation == "endpoint_register" {
				old := time.Now().UTC().Add(-3 * time.Minute)
				q.RequestID, err = newLocalEndpointRequestID(old)
				q.IssuedAt = old.Format(time.RFC3339Nano)
				if err != nil {
					t.Fatal(err)
				}
			}
			consumer, err := openCodexOperatorIntent(filepath.Join(privateLocalNodeRoot(t), "operator-intent.json"))
			if err != nil {
				t.Fatal(err)
			}
			original, err := consumer.prepare(q, f.nodeID)
			if err != nil {
				t.Fatal(err)
			}
			originalDigest := codexOperatorDigest(original, false)
			// The consumer saved its intent; no Node business request or durable
			// verified checkpoint has been delivered when the Node restarts.
			if err := f.bridge.Close(); err != nil {
				t.Fatal(err)
			}
			machineNodeControlClients.Delete(f.client.statePath)
			f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := consumer.call(f.bridge.path, original, f.nodeID); err == nil {
				t.Fatal("lost pre-send ticket was accepted after restart")
			}
			native := harness.SessionContext{Harness: "codex", NativeSessionID: q.NativeSessionID, MachineID: f.nodeID, Workspace: q.Workspace}
			fresh, err := endpointGroupsFreshOperatorProof(stopped.TranscriptPath, "", "", native, nil, original)
			if err != nil {
				t.Fatal("fresh current call could not authenticate retained original", err)
			}
			retry := original
			retry.InvocationProof = fresh
			if codexOperatorDigest(retry, false) != originalDigest || fresh.ContextTicketID == original.ContextTicketID {
				t.Fatal("fresh proof changed the original intent or reused the old ticket")
			}
			settled, err := consumer.call(f.bridge.path, retry, f.nodeID)
			if err != nil || settled == nil || settled.State != "COMPLETED" || settled.IntentDigest != originalDigest {
				t.Fatal("fresh exact-scope proof could not settle original pre-send intent", err)
			}
			if err := consumer.withLocked(func(disk *codexOperatorIntentDisk) error {
				if disk.Pending == nil || disk.Pending.Request != original || disk.Pending.Request.InvocationProof != nil {
					t.Error("transient call proof replaced the frozen original")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
