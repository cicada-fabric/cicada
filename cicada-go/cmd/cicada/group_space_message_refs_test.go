package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSealedGroupSpaceReferencePayloadProjectsOnlyPointersAfterOpen(t *testing.T) {
	refs := []groupSpaceMessageReference{{GroupID: "group_a", RecordID: "journal_1", Sequence: 7, Kind: "JOURNAL"},
		{GroupID: "group_a", RecordID: "topic_2", Sequence: 9, Kind: "TOPIC", TopicID: "topic_2"},
		{GroupID: "group_a", RecordID: "reply_3", Sequence: 11, Kind: "REPLY", TopicID: "topic_2"},
		{GroupID: "group_a", RecordID: "status_4", Sequence: 12, Kind: "TOPIC_STATUS", TopicID: "topic_2"}}
	encoded, err := json.Marshal(groupSpaceMessagePayload{Type: groupSpaceMessagePayloadType,
		Version: groupSpaceMessagePayloadV1, Body: "please inspect these selected records", RecordRefs: refs})
	if err != nil {
		t.Fatal(err)
	}
	body, got, err := decodeGroupSpaceMessagePayload(encoded)
	if err != nil || body != "please inspect these selected records" || len(got) != 4 || got[1] != refs[1] ||
		got[2] != refs[2] || got[3] != refs[3] {
		t.Fatalf("decodeGroupSpaceMessagePayload() = %q, %#v, %v", body, got, err)
	}

	for _, test := range []struct {
		name   string
		prompt string
	}{
		{name: "cross-group Link", prompt: machineSealedRelayPrompt(
			machineRelayJournalEntry{MessageID: "msg_1", SenderEndpointID: "ep_sender", EndpointID: "ep_receiver",
				GroupID: "group_b", Kind: "send"}, encoded)},
		{name: "same Group", prompt: machineSealedRelayPrompt(machineRelayJournalEntry{MessageID: "msg_2", SenderEndpointID: "ep_sender",
			EndpointID: "ep_receiver", GroupID: "group_a", AuthorizationKind: "same-group", Kind: "send"}, encoded)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if strings.Contains(test.prompt, "record ciphertext") {
				t.Fatal("prompt included record content")
			}
			payload := test.prompt[strings.LastIndex(test.prompt, "\n")+1:]
			var message struct {
				Body           string                       `json:"body"`
				GroupSpaceRefs []groupSpaceMessageReference `json:"group_space_refs"`
			}
			if err := json.Unmarshal([]byte(payload), &message); err != nil {
				t.Fatalf("prompt does not contain a JSON relay projection: %v", err)
			}
			if message.Body != "please inspect these selected records" || len(message.GroupSpaceRefs) != 4 ||
				message.GroupSpaceRefs[0].GroupID != refs[0].GroupID || message.GroupSpaceRefs[1].RecordID != refs[1].RecordID {
				t.Fatalf("prompt projection lost body or selected locators: %#v", message)
			}
		})
	}
}

func TestGroupSpaceReferenceEnvelopeRejectsReservedMalformedMarkers(t *testing.T) {
	valid := `{"type":"cicada.group-space-message","version":1,"body":"hello","record_refs":[{"group_id":"g","record_id":"r","sequence":1,"kind":"JOURNAL"}]}`
	for _, test := range []struct {
		name string
		wire string
	}{
		{name: "unknown field", wire: strings.Replace(valid, `"body":"hello"`, `"body":"hello","hub_authority":true`, 1)},
		{name: "missing reference", wire: `{"type":"cicada.group-space-message","version":1,"body":"hello"}`},
		{name: "invalid topic coordinate", wire: `{"type":"cicada.group-space-message","version":1,"body":"hello","record_refs":[{"group_id":"g","record_id":"r","sequence":1,"kind":"TOPIC","topic_id":"other"}]}`},
		{name: "duplicate locator", wire: `{"type":"cicada.group-space-message","version":1,"body":"hello","record_refs":[{"group_id":"g","record_id":"r","sequence":1,"kind":"JOURNAL"},{"group_id":"g","record_id":"r","sequence":2,"kind":"JOURNAL"}]}`},
		{name: "reserved type after other member", wire: `{"unused":true,"type":"cicada.group-space-message","version":1}`},
		{name: "truncated reserved object", wire: `{"type":"cicada.group-space-message","version":1,"body":`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := decodeGroupSpaceMessagePayload([]byte(test.wire)); err == nil {
				t.Fatal("malformed reserved GroupSpace marker was accepted as ordinary peer prose")
			}
		})
	}
	legacy := []byte("ordinary legacy peer message")
	body, refs, err := decodeGroupSpaceMessagePayload(legacy)
	if err != nil || body != string(legacy) || len(refs) != 0 {
		t.Fatalf("legacy sealed message compatibility changed: %q %#v %v", body, refs, err)
	}
}
