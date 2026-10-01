# Native Network JOIN binding adapter

This bounded Node/MCP change makes ordinary explicit `cicada_network_join`, exact
scope recovery, duplicate JOIN and `cicada_network_renew` register the original
Thread's native identity using the existing session-authenticated
`POST /v2/fabric/networks/<network>/direct/native-binding` request with `{}`.
It closes the missing registration step required by the existing Owner
`topology.endpoint_admission_preview` / `endpoint.admit_group` path. Network
JOIN alone still creates no Group member, role, traffic grant, key candidate,
key grant, native replacement or additional native writer.

The Node verifies the native Codex record and local context policy first,
then reuses the direct-source helper to check session `whoami` and returned
Endpoint, Principal, Node, native session, binding status, nonempty binding ID
and nonzero native epoch. A Network JOIN access binding belongs to
`network_access_sessions_v2`; its ID/epoch must not be equated to the independent
`network_direct_native_bindings_v2` identity. Access renewal retains its ID while
rotating its token/epoch; native registration retains the original native
identity/epoch. The current Hub remains authoritative for revocation and fencing.

If scope acceptance succeeds but native registration fails, the private Unix
response carries the accepted access result together with
`NETWORK_NATIVE_BINDING_PENDING`. MCP saves that credential privately before
returning the error. Initial credential publication is atomic and cannot replace
an existing session; renewal uses the existing atomic replacement helper.
Duplicate JOIN retries through renewal, avoiding a second invitation/Owner proof
or a replacement Endpoint/native Thread. Response loss after binding commit is
safe because registration reuses the current identity. A local scope block
continues to withhold credentials and retain the existing durable recovery status;
exact accepted recovery records CICADA-known history coverage, not complete native
history proof.

Source is detached `1547f2eb47094d2faa7fd0194008fcb3d45f8db0` plus the uncommitted
adapter and focused-test changes. Repaired v3 build source fingerprint:
`a117b1310df5e7e3004c107648746465ab728b64b48b3468deffb7761e700130`.
It is a dirty source fingerprint, not a commit or an image digest. Client contract
remains `client-hub-v1.6`, encrypted wire `1`, catalog `55`; catalog SHA-256 is
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`.
No Client HTTP shape, public capability or server authorization policy changes.

Validation uses disposable Docker with pinned
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
UID/GID `1000:1000`, `--network none`, `GOTOOLCHAIN=local`, `GOPROXY=off`, read-only
module cache `/home/zyf/CICADA/.cicada-data/m1-gomodcache` and existing build cache
`/home/zyf/.cache/go-build`. The isolated container has real loopback TCP and an
owner-only Unix socket. `native_network_binding_test.go` uses real SQLite Store,
production Fabric HTTP, trusted Node bridge, managed native-context registry and
MCP, with synthetic signed Owner/Node/device fixtures and Codex records. No
Control instance, model, real native Runtime, resident Hub or real keys are used.
Owner Group admission is verified at the authoritative Store boundary using
accepted Client request metadata; this is not an encrypted Android/UI test.

The initial adapter candidate fingerprint `b2547717…`, patch SHA-256
`0134b5804735f326b36e63f2735d532d38fefd2a199fa797c11f02411fcd9c1b`,
passed its original bounded package/race gates, but independent review found an
availability bug not covered by those gates: directory access-epoch rotation
appended a history row on every renewal. JOIN plus 63 renewals filled the native
history cap; the next renewal fenced the old token before the Node refused to
release the new one. That candidate is superseded, not accepted as complete.
Its historical results remain attributed to that source.

The repair adds `CheckAndRecordNetworkEnrollmentContext` to the metadata sidecar.
Network access-session IDs are stable enrollment IDs, not native writer bindings.
For an exact Hub/Network/no-Group/policy/Endpoint/enrollment-ID observation, the
sidecar retains the first **actual observed** epoch and refreshes only that row's
last-seen time. It checks all known dedicated-scope history every time. It records
new enrollment or policy observations with their actual current observed epoch
and applies unchanged per-identity/global caps. It never removes or rewrites prior
binding/epoch provenance. Ordinary Group/native binding history behavior remains
unchanged; current Hub access/native identity and epochs remain independently
authenticated every renewal.

The repaired focused Docker backend gate passes JOIN plus 80 mixed explicit
renewals/duplicate JOINs with usable latest access epoch 81, stable Endpoint/access
ID/native identity and exactly one native history row. It also checks known
Dedicated-Network conflict after repeated observations. The actual Hub schema
allows Network `dedicated_thread` rather than `dedicated_network`; a current
Network-only enrollment cannot satisfy its required Group scope, and the Node
continues to fail closed on that incompatible metadata. Sidecar tests separately
preserve a first actual epoch 7 through epoch 100, preserve all existing rows at
the cap, and reject new enrollment/policy observations beyond bounds, dedicated
Hub/Network conflicts, and misuse of Network enrollment semantics for Group
writer history.

Final repaired source checks all passed in the pinned disposable Docker above:

- `go test -json ./cmd/cicada ./internal/nodeinbox -count=1`: 314 top-level tests
  and 126 subtests passed, seven top-level skips, zero failures. Skips are not
  passes. Command package: 286 + 117 passed; node-inbox: 28 + 9 passed.
- `go test -race -json ./cmd/cicada ./internal/nodeinbox -run 'TestNativeNetwork|TestLocalNetworkJoinBlocked|TestMachineNetworkDirect|TestNetworkEnrollment|TestNativeContextHistory' -count=1`:
  16 top-level tests and 22 subtests passed, no skips or failures.
- `go vet ./cmd/cicada ./internal/nodeinbox`: PASS.
- `python3 scripts/client-contract.py check` and `git diff --check`: PASS.

Both JSON logs remain in the isolated worktree under
`.cicada-data/native-network-binding-repair/`. Source fingerprints before and
following validation are identical. The two JOIN/renew HTTP client constructors
are deliberately unchanged in this patch; the separately owned per-Hub PQ client
helper must be applied in a subsequent sequential overlay and validated there.

Focused assertions cover DIRECTORY-only JOIN followed by explicit Owner Group
admission without Control; no automatic Group binding; forged caller fields;
forged native response identities/status/epoch; stale access previews and tokens;
real revoked Owner, changed Node/native identity and revoked binding; native scope
block/recovery; failure before registration commit; failure after commit with
lost response; repeated failed renewal retaining its newly accepted token; stable
Endpoint, access ID, native ID/epoch and lease on retry; denied DIRECT SEND/peer
key/key publication; and absent automatic traffic/admin/history/Group key grants.

The focused disposable Docker backend/HTTP gate is separate from the packaged
Client/Hub interop suite, which this adapter slice does not rerun. Real native
Codex MCP, Android, physical devices and public HTTPS are **NOT_RUN** for this
source. The parent task must integrate/review the patch and record any subsequent
exact-image native and broader interoperability results under their actual source.
