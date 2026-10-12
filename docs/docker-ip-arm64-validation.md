# IP, ARM64 PQ TLS and first-install validation

This record separates implementation preflight from final packaged acceptance.
Software is 0.0.3; contract client-hub-v1.6.5, wire 1, catalog 55 and schema 59
are unchanged. No production API/catalog, migration or Client source was added.
The clean product producer and unified Docker result will be recorded after the
implementation freeze. Historical d86 / Native Board results retain their source.

## Current preflight evidence

Private evidence root: `.cicada-data/v00-docker-deployment-20261012/`.

| Scope | Actual result | Limits |
| --- | --- | --- |
| Operator CLI, independent exact Owner signer, approved HubID hint, exclusive Store | CGO-off selected cmd/Store tests exit 0, 4 top-level + 16 subtests, no fail/skip | operator-default-final/tests.jsonl; not whole Go suite |
| Scoped vet | cmd/cicada, cmd/cicada-ip-network-fixture, internal/store exit 0 | operator-default-final/vet.log |
| Host driver reliability | Python stdlib unittest 4 PASS; syntax/compile checks PASS | Mock daemon outcomes test cleanup/report only |
| Actual Docker network/envelope probe | self reachable and cross-Node unreachable PASS, exact CID/network cleanup verified | driver-probe-preflight/probe-attempt3.json; earlier cleanup-parser failures retained |
| Fresh operator/runtime diagnostic A6 | exit 0, 7.398s | ad-hoc native binary, borrowed stage diagnostic library path; not a package PASS |
| Peer diagnostic A7 | exit 0, 9.577s | same A6 ad-hoc binary + separately captured current fixture |
| Peer diagnostic A8 with wrong ACK | exit 0, 9.611s | actual receiver product Agent inbox/NODE_RECEIVED; native context absent and intentionally refuses further consumption |
| ARM target/tooling preflight | B reports 26 static tests exit 0 with 2 artifact SKIP; actual ARM OpenSSL 3.5.9 under explicit QEMU PASS | Final package gate pending |
| Final clean amd64/ARM package gate | NOT_RUN | Await implementation commit and actual packaged artifacts |

The bounded static probe exposed Docker absence messages in lowercase and network
`not found` form; driver cleanup now recognizes those exact diagnostics only
with a successful inventory proving the exact name/ID absent. Two failed probe
cleanup attempts are retained with recovered exact owned cleanup; probe attempt 3
passed. No failed cleanup became a PASS.

A1/A2 failed unavailable PQ consumption, A3–A5 failed checked product startup.
These failures remain in operator-native-a1…a5, and are not relabeled PASS.
A6 identified/fixed the empty explicit HubID startup order using independently
approved local state. A7/A8 add only a test coordinator sender and existing Guard
Join/proofs; actual receiver machine Agent persists inbox and its own signed ACK.
The Hub ciphertext queue, offline/restart retry and same-ID ACK dedup are checked.
The receiver's native context absence is an expected refusal after receipt, not
Native consumption success; no model/provider call occurs. This fixture does not
prove a native user Join workflow, Android TLS signer or effective native execution.

## Reproducible final Docker gate

Default is OFF. Supply the real immutable package directories and accepted stage;
the stage is mounted only in the fixture compiler, never product Node containers:

```sh
CICADA_IP_PQTLS_RUN=1 scripts/test-local-ip-pqtls.sh AMD64_PACKAGE ACCEPTED_AMD64_STAGE NEW_PRIVATE_EVIDENCE ARM64_PACKAGE ARM64_ROOTFS QEMU_AARCH64_STATIC
```

The optional three-argument mode uses two amd64 Nodes; it is not ARM acceptance.
Package checksum manifests and BUILD-METADATA are required, checked before/after,
and saved separately from fixture-source input inventories. Explicit QEMU uses
`qemu-aarch64-static -L /arm64-rootfs /node-package/bin/cicada`; no binfmt or
privileged container is involved. Package RUNPATH must resolve its own libraries;
product Node LD_LIBRARY_PATH/LD_PRELOAD are cleared.

The driver is a fresh Hub fixture with Control `--fabric-only` for enrolled peer
transport. Nodes have separate private state and separate internal bridge
networks; only the Hub driver joins both. Each listener is positively probed before
cross-Node reachability is refused. Actual inspect mount topology must prove no
Hub database or Owner private key is mounted in either Node. CID receipts, labels,
RO rootfs, dropped capabilities, no-new-privileges, writable bounded tmpfs,
CPU/memory/PID limits, actual command exits, OOM state and exact cleanup outcomes
are recorded. A daemon error is UNKNOWN, never verified absence. Cleanup failure
changes the result/exit to failure. Six protected resident services are compared
independently by Root; no old state or accepted stage is modified.

The final fixture must show actual pending enrollment refusal, fresh pairing,
independent Owner signing, signed IP locator, Prepare/Reserve/Issue/Stage/ACK/
activation/remote Apply, checked product startup, Hub restart, actual ciphertext
queue/retry/receipt/dedup and wrong ACK refusal. IPv4/IPv6 no-DNS native socket and
identity/SAN/pin/locator/epoch refusals also have A's separate focused primitive
coverage; they must retain their precise tested source rather than being claimed
as a dual-stack physical deployment result.

## Transport and Client boundary

Initial pairing uses trusted synthetic standard HTTPS with numeric IP SAN and
NIST application encryption/signatures. Only enrolled Node traffic then uses
strict PQ TLS. No DNS resolver or hosts-file substitution creates Hub identity;
HubID, logical service SAN, SPKI pin and signed socket remain distinct.

Root statically checked the independent Client trial APK from producer
`0351ee5d01f13158533f56c4c4cf1959ab9c1ebc` (later docs-only `d266c5e` is not its
producer): 85,681,811 bytes, SHA256
`158e9fe72e660324aed2325a70b45582130244398d5ead03b7906c9cce61b90c`, sole ABI
arm64-v8a and all 17 native libraries ELF64 Machine183. Its DELIVERY.NONAUTH.json
SHA256 is `f36545472647d3f0a85f34741f1e701d3106b56a462941d5316ce40ed01686f4`.
Root's local static receipt is `client-apk-root-review.NONAUTH.json` SHA256
`f07555c6a3903da850a989c8140f636c47befe24a9a0c550d909c437b9d59918`.
This is no APK execution result. Physical phone, Android TLS approval UX, public
HTTPS, real native Runtime/model consumption and three physical-server deployment
remain NOT_RUN. Use [manual installation](node-tls-first-install-cli.md) for the
available trusted operator path; broader release acceptance remains PARTIAL.
