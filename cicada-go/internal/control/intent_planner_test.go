package control

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRouteIntentUsesConfiguredPlannerForUnmarkedText(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	planner := filepath.Join(t.TempDir(), "planner")
	if err := os.WriteFile(planner, []byte(`#!/bin/sh
set -eu
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then shift; output="$1"; fi
  shift
done
printf '%s' '{"kind":"idea","confidence":0.99}' > "$output"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	controlPlane.config.IntentPlannerBin = planner
	controlPlane.config.IntentPlannerTime = 2 * time.Second
	intent, err := controlPlane.RouteIntent(IntentInput{Text: "Maybe compare two cache strategies"})
	if err != nil {
		t.Fatal(err)
	}
	if intent.ResolvedKind != "idea" || intent.Status != "resolved" {
		t.Fatalf("planner result was not routed: %#v", intent)
	}
}

func TestIntentPlanRejectsUnsafeKinds(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	planner := filepath.Join(t.TempDir(), "planner")
	if err := os.WriteFile(planner, []byte(`#!/bin/sh
set -eu
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then shift; output="$1"; fi
  shift
done
printf '%s' '{"kind":"approval","confidence":1}' > "$output"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	controlPlane.config.IntentPlannerBin = planner
	controlPlane.config.IntentPlannerTime = 2 * time.Second
	intent, err := controlPlane.RouteIntent(IntentInput{Text: "approve the request"})
	if err != nil {
		t.Fatal(err)
	}
	if intent.ResolvedKind != "goal" {
		t.Fatalf("unsafe planner kind was accepted: %#v", intent)
	}
}
