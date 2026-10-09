# Node sealed pre-writer phase diagnostics — 2026-10-09

The scoped deterministic normal and race checks passed. This change adds
optional observation of a claimed sealed Link delivery before native queue
admission; it does not change authorization, encryption, claim recovery,
deduplication, retry, deadlines, writer leases, or queue acceptance.

`CICADA_NODE_SEALED_PHASE_DEBUG=1` enables the fixed JSON records on the existing
Node Agent stderr outlet. It is read once per attempt. The default is OFF and
returns the original context without an observer or JSON buffer. A future
disposable acceptance run must explicitly set this variable on the actual Go
Node Agent process; enabling it only on the parent driver or Codex Runtime does
not prove that the Agent emitted phases. No native run used this patch here.

Records cover `CLAIM_ROUTE`, `AUTHORITY_HTTP`, `CRYPTO_READ`, `SEALED_VALIDATE`,
its nested `LOCAL_CONTEXT`, `OPERATION_SCOPE`, and `WRITER_WAIT`, with fixed
`BEGIN`/`END`/`ERROR` states and closed error classes. Each attempt emits at most
32 records. Correlation fields are message/request/Endpoint/native-session IDs
and separate local/remote attempt IDs; an invalid or longer-than-192-byte
identifier is omitted. Records contain no prompt, payload, digest, key, token,
or arbitrary error text. Local rejection is distinguished from an observed
HTTP authorization rejection. The original lifecycle callback still runs;
logging failure cannot change the business result. Writer-wait END proves
acquisition returned, not queue acceptance or model consumption.

## Tested source and results

Run B compiled a coherent 946-file public snapshot of HEAD
`1ad5a96414c2d888f70c5b61467b3b1e4a382a91` plus dirty source, recorded in
[SOURCE-PINS](../.cicada-data/node-sealed-phase-20261009a/run-b/SOURCE-PINS.NONAUTH.json)
(SHA-256 `9242fb12c2f6a38bc1beae0a78231c27f038bcf7682cdd3bae4c323166650e2a`).
The three phase files remained unchanged through the run:

| File | SHA-256 |
| --- | --- |
| [machine_sealed_receive.go](../cicada-go/cmd/cicada/machine_sealed_receive.go) | `1eacf743aa98fd379067a82ce70bbf1740a0343c3e78f9e1013cf1ef84d0e5db` |
| [machine_sealed_phase.go](../cicada-go/cmd/cicada/machine_sealed_phase.go) | `5dcdf84a97f6dd53561dea5c489f63da3d4f32ad2870d9fd8bccb9105abe43f3` |
| [machine_sealed_phase_test.go](../cicada-go/cmd/cicada/machine_sealed_phase_test.go) | `fc9ba3dbb3d0e7acb3444c8f35d5ff6394fddb4de5eb8f56a5bb4db3f2d77241` |

The commands, from `/repo/cicada-go`, were:

```sh
go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=60s -json -run '^TestMachineSealedPhase' ./cmd/cicada
go test -buildvcs=false -mod=readonly -p 2 -race -count=1 -timeout=60s -json -run '^TestMachineSealedPhase' ./cmd/cicada
```

Each passed 6 top-level tests and 3 subtests, with 0 failures/skips. They cover
default OFF, identifier/error privacy, the 32-record cap, logging failure,
the real sealed fixture's phase order and original callback, and a real physical
writer-lock deadline. The queue executable is the existing synthetic Go test
helper, not Codex. Package elapsed times were 2.914s normal and 47.922s race;
the combined build/test/cleanup envelope took 109.783s. This is not a performance
benchmark or Native acceptance result.

[PRESTART](../.cicada-data/node-sealed-phase-20261009a/run-b/PRESTART.NONAUTH.json)
and [ENVELOPE](../.cicada-data/node-sealed-phase-20261009a/run-b/ENVELOPE.NONAUTH.json)
record pinned Go 1.27.1 image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
UID 1000, network none, read-only source/modules/OpenSSL, cap-drop ALL, NNP,
2 CPUs, 3 GiB and 256 PIDs. The 3 GiB limit is a compilation/test envelope.
No credentials, external provider, model, VM or native acceptance gate ran.
[RESULT](../.cicada-data/node-sealed-phase-20261009a/run-b/RESULT.NONAUTH.json)
(SHA-256 `fd02c49d1d1b1934c1951704a7dae3b792345a2b6950d15518ddf91ecedd0630`)
confirms exit 0, no OOM, exact owned container ID/name absent and the six
residents' ID/image/PID/start time/restart count/running fields unchanged.

The first [run's build failure](../.cicada-data/node-sealed-phase-20261009a/RESULT.NONAUTH.json)
is retained: its snapshot captured the intermediate three/four-argument
Fabric/Store resolver interface mismatch. It exited 1 in 8.772s before tests;
race was NOT_RUN. Run B followed the Core compile-ready handshake. Two unrelated
Core files subsequently changed, as recorded in its result; this validation
belongs to the captured snapshot, not a later artifact or solely its HEAD.
Native delivery, ASK/REPLY, queue consumption and the A002 failure remain
unresolved by these deterministic checks.
