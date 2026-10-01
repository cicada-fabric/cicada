package main

import (
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestSealedTaskHandoffPayloadBindsCurrentHubAuthorization(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	expiresText := expires.Format(time.RFC3339Nano)
	handoffID := "op_synthetic_handoff_1234567890"
	messageID := "shared-task-handoff.v1:" + strconv.FormatInt(expires.UnixMilli(), 10) + ":" + handoffID
	refs := []store.SealedTaskHandoffArtifactRef{{ArtifactRefID: "aref_synthetic_1", Version: 3,
		Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	auth := &store.SealedTaskHandoffDeliveryAuthorization{
		HandoffID: handoffID, TaskID: "task_synthetic_12345678901234567890", GroupID: "grp_synthetic",
		FromPrincipalID: "principal_from", FromEndpointID: "ep_from", ToPrincipalID: "principal_to",
		ToEndpointID: "ep_to", TaskRevision: 9, FromOwnerEpoch: 4, MessageID: messageID,
		MessageDigest:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RequiredArtifactRefs: refs, ExpiresAt: expiresText, Status: store.SealedTaskHandoffProposed, Version: 1,
	}
	route := store.RelaySealedV1Route{MessageID: messageID, SenderEndpointID: "ep_from",
		ReceiverEndpointID: "ep_to", Kind: "send"}
	packet, err := marshalSealedTaskHandoffPayload(sealedTaskHandoffPayload{
		Type: sealedTaskHandoffPayloadType, Version: 1, HandoffID: handoffID, TaskID: auth.TaskID,
		GroupID: auth.GroupID, FromPrincipalID: auth.FromPrincipalID, FromEndpointID: auth.FromEndpointID,
		ToPrincipalID: auth.ToPrincipalID, ToEndpointID: auth.ToEndpointID, TaskRevision: auth.TaskRevision,
		FromOwnerEpoch: auth.FromOwnerEpoch, MessageID: messageID, ExpiresAt: expiresText,
		RequiredArtifactRefs: refs, Body: "synthetic handoff context",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSealedTaskHandoffPayload(auth, messageID, route, packet); err != nil {
		t.Fatalf("exact handoff packet rejected: %v", err)
	}

	for name, mutate := range map[string]func(*sealedTaskHandoffPayload){
		"wrong task":     func(p *sealedTaskHandoffPayload) { p.TaskID = "task_other_12345678901234567890" },
		"wrong endpoint": func(p *sealedTaskHandoffPayload) { p.ToEndpointID = "ep_other" },
		"wrong epoch":    func(p *sealedTaskHandoffPayload) { p.FromOwnerEpoch++ },
		"wrong revision": func(p *sealedTaskHandoffPayload) { p.TaskRevision++ },
		"wrong deadline": func(p *sealedTaskHandoffPayload) { p.ExpiresAt = expires.Add(time.Minute).Format(time.RFC3339Nano) },
		"wrong artifact": func(p *sealedTaskHandoffPayload) { p.RequiredArtifactRefs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := sealedTaskHandoffPayload{
				Type: sealedTaskHandoffPayloadType, Version: 1, HandoffID: handoffID, TaskID: auth.TaskID,
				GroupID: auth.GroupID, FromPrincipalID: auth.FromPrincipalID, FromEndpointID: auth.FromEndpointID,
				ToPrincipalID: auth.ToPrincipalID, ToEndpointID: auth.ToEndpointID, TaskRevision: auth.TaskRevision,
				FromOwnerEpoch: auth.FromOwnerEpoch, MessageID: messageID, ExpiresAt: expiresText,
				RequiredArtifactRefs: refs, Body: "synthetic handoff context",
			}
			mutate(&changed)
			badPacket, err := marshalSealedTaskHandoffPayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSealedTaskHandoffPayload(auth, messageID, route, badPacket); err == nil {
				t.Fatal("mismatched sealed handoff packet was accepted")
			}
		})
	}
	wrongRoute := route
	wrongRoute.Kind = "ask"
	if err := validateSealedTaskHandoffPayload(auth, messageID, wrongRoute, packet); err == nil {
		t.Fatal("Task handoff was accepted over a non-SEND route")
	}
	if err := validateSealedTaskHandoffPayload(nil, messageID, route, packet); err == nil {
		t.Fatal("reserved handoff message without Hub metadata was accepted")
	}
	if err := validateSealedTaskHandoffPayload(auth, "ordinary-message", route, packet); err == nil {
		t.Fatal("handoff metadata attached to an ordinary message was accepted")
	}
}

func TestSealedTaskHandoffAuthorizationBindsDigestAndCanonicalDeadline(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	handoffID := "op_synthetic_handoff_1234567890"
	messageID := "shared-task-handoff.v1:" + strconv.FormatInt(expires.UnixMilli(), 10) + ":" + handoffID
	a := &store.SealedTaskHandoffDeliveryAuthorization{
		HandoffID: handoffID, TaskID: "task_synthetic_12345678901234567890", GroupID: "grp_synthetic",
		FromPrincipalID: "principal_from", FromEndpointID: "ep_from", ToPrincipalID: "principal_to",
		ToEndpointID: "ep_to", TaskRevision: 9, FromOwnerEpoch: 4, MessageID: messageID,
		MessageDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpiresAt:     expires.Format(time.RFC3339Nano), Status: store.SealedTaskHandoffProposed, Version: 1,
	}
	delivery := fabric.NodeSealedDelivery{RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{
		MessageID: messageID, Digest: a.MessageDigest, RecipientEndpointID: "ep_to",
		Route: store.RelaySealedV1Route{MessageID: messageID,
			SenderEndpointID: "ep_from", ReceiverEndpointID: "ep_to", Kind: "send"},
	}}
	transportAuth := crossNodeGroupDeliveryAuthorization{Sender: crossNodeGroupEndpointEvidence{
		EndpointID: "ep_from", PrincipalID: "principal_from"}, Receiver: crossNodeGroupEndpointEvidence{
		EndpointID: "ep_to", PrincipalID: "principal_to", GroupID: "grp_synthetic"}, TaskHandoff: a}
	if err := validateSealedTaskHandoffAuthorization(delivery, transportAuth); err != nil {
		t.Fatalf("exact DTO/route rejected: %v", err)
	}
	delivery.Digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := validateSealedTaskHandoffAuthorization(delivery, transportAuth); err == nil {
		t.Fatal("authorization with a different ciphertext digest was accepted")
	}
	if id, _, ok := parseTaskHandoffMessageID("shared-task-handoff.v1:01:" + handoffID); ok || id != "" {
		t.Fatal("non-canonical deadline component was accepted")
	}
}
