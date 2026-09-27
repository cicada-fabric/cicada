package harness

import "testing"

func TestDetectCurrentCodexSession(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CODEX_THREAD_ID", "thread-current")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", "gpu1")
	t.Setenv("CICADA_WORKSPACE", "/work/project")
	context, err := DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	if context.Harness != "codex" || context.NativeSessionID != "thread-current" || context.MachineID != "gpu1" || context.Workspace != "/work/project" {
		t.Fatalf("unexpected session context: %#v", context)
	}
	if context.Capabilities["wake"] != "codex_queue" {
		t.Fatalf("missing Codex wake capability: %#v", context.Capabilities)
	}
}

func TestDetectCurrentSessionDefaultsMachineToShortHostname(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "thread-current")
	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_MACHINE_ID", "")
	context, err := DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	if context.MachineID == "" {
		t.Fatal("automatic Machine discovery returned an empty ID")
	}
}
