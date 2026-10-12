package pqtls

import (
	"context"
	"os"
	"os/exec"
)

// pqtlsTestCommandContext runs target-side executables directly on native hosts
// or through an explicit user-mode emulator during cross-architecture tests.
// The runner receives the target executable as argv[1].
func pqtlsTestCommandContext(ctx context.Context, executable string, args ...string) *exec.Cmd {
	if runner := os.Getenv("PQTLS_TEST_TARGET_RUNNER"); runner != "" {
		wrapped := make([]string, 1, len(args)+1)
		wrapped[0] = executable
		wrapped = append(wrapped, args...)
		return exec.CommandContext(ctx, runner, wrapped...)
	}
	return exec.CommandContext(ctx, executable, args...)
}

func pqtlsTestCompiler() string {
	if compiler := os.Getenv("PQTLS_TEST_CC"); compiler != "" {
		return compiler
	}
	return "cc"
}
