# Completion verification

A Worker exit code or final message is a completion claim, not proof that the
Goal succeeded. Before Control creates the final artifact, the Monitor applies
a completion policy to the bounded candidate evidence.

Every harness must return a non-empty summary. Codex Workers then use the
configured official Codex CLI as an ephemeral `gpt-5.5` verifier. The verifier
receives:

- the Goal objective, success criteria, and constraints;
- the Worker's specific assignment and bounded final summary;
- existing Goal evidence and up to 20 prior Artifact summaries.

It returns a schema-constrained `accept` or `revise` verdict with confidence,
rationale, and a correction. Control honors `revise` only at confidence 0.75
or higher. A rejected local Worker resumes its existing thread with the
correction. A rejected remote Worker returns to its assigned Machine queue and
keeps its Codex thread ID. The normal recovery limit prevents an endless
verification loop; exhaustion blocks the Goal and creates the existing P0
attention notification.

The verifier runs read-only and ephemeral in a temporary directory. It does
not enter the Worker workspace, load repository instructions, or execute
project code. Candidate text is marked as untrusted data, output must match a
strict JSON schema, and rationale/correction sizes are capped.

Remote result handling first atomically changes the Worker from `running` to
`verifying`. Concurrent or repeated result requests therefore run the verifier
at most once. A user cancellation can win the final compare-and-swap without a
late verifier resurrecting the Worker.

## Availability and privacy defaults

Compose enables the verifier with:

```text
CICADA_COMPLETION_VERIFIER_BIN=codex
CICADA_COMPLETION_VERIFIER_TIMEOUT_SECONDS=20
```

Codex output has already crossed the configured model boundary, so Codex
Workers use model verification by default. Shell output and future non-model
harness output stay local unless the Goal explicitly sets:

```json
{
  "resources": {
    "completion_verifier": "model"
  }
}
```

The supported modes are `model`, `deterministic`, and `off`. The non-empty
summary check remains active in every mode. `deterministic` keeps all evidence
local; `off` skips the optional evidence judgment after that baseline check.

If the model binary, relay, or response schema is unavailable, Control accepts
the non-empty candidate so a verifier outage cannot strand long-running work.
It emits `WorkerCompletionVerificationUnavailable` with the bounded reason.
Normal decisions emit `WorkerCompletionVerified`; high-confidence rejections
emit `WorkerCompletionRejected`. These events keep the degradation visible in
the Goal timeline.
