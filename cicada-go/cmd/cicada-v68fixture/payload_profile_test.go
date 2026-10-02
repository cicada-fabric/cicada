package main

import (
	"strings"
	"testing"
)

func TestPayloadProfilesLegacyAndManaged(t *testing.T) {
	// Public synthetic vectors only; never use these values to initialize a deployment.
	for _, reply := range []bool{false, true} {
		legacy := "SYNTHETIC:CICADA-V68-PLAINTEXT-NEVER-IN-RELAY:fixture"
		managed := "CICADA-MANAGED-PLAINTEXT-NEVER-IN-RELAY:" + strings.Repeat("0", 16)
		if reply {
			legacy = "SYNTHETIC:CICADA-V68-REPLY-ONLY-OPAQUE:fixture"
			managed = "CICADA-MANAGED-REPLY-ONLY-OPAQUE:CICADA-ORIGINAL-B-" + strings.Repeat("0", 32)
		}
		if !v68ExpectedPayloadMatches("legacy-v68", []byte(legacy), reply) {
			t.Fatal("legacy marker compatibility lost")
		}
		payload := []byte(managed)
		if !v68ExpectedPayloadMatches("managed-native", payload, reply) {
			t.Fatal("managed synthetic profile rejected")
		}
		if v68ExpectedPayloadMatches("legacy-v68", payload, reply) {
			t.Fatal("legacy profile unexpectedly accepted managed markers")
		}
	}
}

func TestPayloadProfilesRejectInvalid(t *testing.T) {
	question := "CICADA-MANAGED-PLAINTEXT-NEVER-IN-RELAY:" + strings.Repeat("a", 16)
	answer := "CICADA-MANAGED-REPLY-ONLY-OPAQUE:CICADA-ORIGINAL-B-" + strings.Repeat("b", 32)
	cases := []struct {
		name, profile, payload string
		reply                  bool
	}{
		{"unknown-question", "unknown", question, false},
		{"unknown-answer", "unknown", answer, true},
		{"empty-question", "managed-native", "", false},
		{"empty-answer", "managed-native", "", true},
		{"wrong-question-marker", "managed-native", "SYNTHETIC-WRONG:" + strings.Repeat("a", 16), false},
		{"wrong-answer-marker", "managed-native", "SYNTHETIC-WRONG:" + strings.Repeat("b", 32), true},
		{"swapped-question", "managed-native", answer, false},
		{"swapped-answer", "managed-native", question, true},
		{"question-short", "managed-native", question[:len(question)-1], false},
		{"answer-short", "managed-native", answer[:len(answer)-1], true},
		{"question-nonhex", "managed-native", question[:len(question)-1] + "Z", false},
		{"answer-nonhex", "managed-native", answer[:len(answer)-1] + "Z", true},
		{"question-newline", "managed-native", question + "\n", false},
		{"answer-newline", "managed-native", answer + "\n", true},
		{"answer-missing-beta", "managed-native", "CICADA-MANAGED-REPLY-ONLY-OPAQUE:" + strings.Repeat("b", 32), true},
		{"legacy-empty", "legacy-v68", "", false},
		{"legacy-wrong", "legacy-v68", "SYNTHETIC-WRONG", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v68ExpectedPayloadMatches(tc.profile, []byte(tc.payload), tc.reply) {
				t.Fatal("invalid profile or payload accepted")
			}
		})
	}
}

func TestUnknownPayloadProfileDeniedBeforeFixtureAccess(t *testing.T) {
	err := check([]string{"--db", "/no-fixture/db", "--fixture", "/no-fixture", "--message-id", "synthetic-message",
		"--request-id", "synthetic-request", "--plaintext-file", "/no-fixture/question", "--reply-plaintext-file", "/no-fixture/answer",
		"--payload-profile", "unknown"})
	if err == nil || err.Error() != "unknown expected payload profile" {
		t.Fatal("unknown profile was not rejected before fixture access")
	}
}
