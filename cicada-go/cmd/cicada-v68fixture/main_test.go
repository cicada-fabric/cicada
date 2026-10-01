package main

import (
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestNativeFixtureThreadInputsFailClosed(t *testing.T) {
	a := "01999d8a-2833-7356-b50e-1023a845852e"
	b := "01999d8a-2833-7356-b50e-1023a845852f"
	for _, pair := range [][2]string{{"", ""}, {a, b}} {
		if err := validateNativeThreads(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{a, ""}, {"", b}, {a, a}, {"thread_synthetic", b},
		{strings.ToUpper(a), b}, {" " + a, b}, {"00000000-0000-0000-0000-000000000000", b}} {
		if err := validateNativeThreads(pair[0], pair[1]); err == nil {
			t.Fatal("unsafe or incomplete native fixture coordinates were accepted")
		}
	}
}

func TestV68ReplyCorrelationUsesRequestAndAskMessageSeparately(t *testing.T) {
	route := store.RelaySealedV1Route{
		Kind: "reply", RequestID: "rq_synthetic", ReplyTo: "msg_ask_synthetic",
	}
	if !v68ReplyCorrelationMatches(route, "rq_synthetic", "msg_ask_synthetic") {
		t.Fatal("exact request and ASK message correlation was rejected")
	}

	wrongReplyTo := route
	wrongReplyTo.ReplyTo = "rq_synthetic"
	if v68ReplyCorrelationMatches(wrongReplyTo, "rq_synthetic", "msg_ask_synthetic") {
		t.Fatal("request ID was incorrectly accepted as the original ASK message ID")
	}

	wrongRequest := route
	wrongRequest.RequestID = "msg_ask_synthetic"
	if v68ReplyCorrelationMatches(wrongRequest, "rq_synthetic", "msg_ask_synthetic") {
		t.Fatal("ASK message ID was incorrectly accepted as the request ID")
	}
}
