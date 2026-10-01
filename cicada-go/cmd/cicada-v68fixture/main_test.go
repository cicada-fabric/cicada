package main

import (
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

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
