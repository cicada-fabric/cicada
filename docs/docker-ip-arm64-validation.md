# IP, ARM64 PQ TLS and first-install validation

This record separates implementation preflight from final packaged acceptance.
Software is 0.0.3; contract client-hub-v1.6.5, wire 1, catalog 55 and schema 59
are unchanged. No Client HTTP operation/catalog/wire change or Hub schema
migration was added; a local operator CLI was added. Client source is unchanged.
Clean product producer is `ab2362f6b9f34d823cea0834c20ec615602c8130`. Unified
Docker A2 passed the scoped first-install and actual amd64/ARM64 protocol gate.
A1 remains FAIL with an unreproduced first-startup readiness timeout. Historical
d86 / Native Board results retain their source.

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
| ARM target/tooling preflight | B reports 26 static tests exit 0 with 2 artifact SKIP; actual ARM OpenSSL 3.5.9 under explicit QEMU PASS | Historical preflight scope only; final results below |
| Clean actual amd64/ARM first-install A2 | SCOPED_PASS, exit 0, 32.56s test, 1 top-level / 0 fail / 0 skip | 25 product Node command receipts, 13 explicit ARM64 QEMU; no Native consumption |

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

## Clean package and Docker delivery

Both packages were built once from clean producer `ab2362f` after code freeze.
Their checksum manifests were verified before/after the unified gate. Runtime
package probes passed with ambient LD paths cleared: actual amd64 and explicit
ARM QEMU loaded their sibling libssl/libcrypto. Their loader RUNPATH is
`$ORIGIN/../lib`; the fixture stage does not supply Node product libraries.

| Artifact | Retained location under the private evidence root | SHA256 |
| --- | --- | --- |
| amd64 product executable | product-packages/amd64/output/cicada-linux-amd64-pqtls/bin/cicada | eb38d85f7948a3b213dca03eb09c436c2fadce68bc7ff6c36e65526cf1c9e24d |
| ARM64 product executable | product-packages/arm64/output/cicada-linux-arm64-pqtls/bin/cicada | 5016f5ca1f043ab1b4e7634a60f3eb36f5ab4420eac31e745eeb125bc35357c4 |
| amd64 BUILD-METADATA | same amd64 package | 42fed12bd871617cb1e8b046da02aa78899fad93ed6e9877b39c57bdc21900c8 |
| ARM64 BUILD-METADATA | same ARM64 package | e1a032ab80a108bdebdb323d4fe4d2291976a1714bc87738aa665ba90e7df497 |
| amd64 package build receipt | product-packages/amd64/output/PQ-BUILD-RECEIPT.json | 2d1ea762f57232088b58a6043d3086e3445fea161ae482ebcb0efe639fe8932d |
| ARM64 package build receipt | product-packages/arm64/output/PQ-BUILD-RECEIPT.json | 844d833a80b0438a91e933aa25491487250d9dbc6ca9bec166ad8dbfd0b02d8d |
| explicit QEMU tool binary | arm64-qemu-runner/bin/qemu-aarch64-static | 4f55e2e88dc05dc0f619562d5795b8eb25ed2ad2547504fb4835207a6911c350 |

The package source fingerprints are respectively
`befd356c7b9e1692bb474276a3c971d6b12889b7dee7dfb664ef83caf7f80fe2` and
`bdbde75d4d5936708b3148b7ff88acef7316fcb5e30993f197d4c38dda7b51af`.
Both packages carry the same WebCrypto manifest
`c8d6bfeda05e22ffd0c204ef4fd014be255e77dfdf0051fb5b2477d480b7d7b0`.
B's separate clean amd64 scratch-image legacy gate passed 1 top-level + 4
subtests, zero fail/skip, Hub/driver exit 0 and exact cleanup. Image IID is
`sha256:1d8cf76c59bfb6919748f8911d07ee991c46658e9a9c4be82b0dedc93796aa71`;
its BUILD-RECEIPT SHA256 is
`cfaa2b4dad919522cd72a717caa4164aad42deb386620a114c937b643ceb80dc`.
That legacy DNS fixture is separate from the fresh IP installation gate.

Actual command for both A1 and A2 (different new evidence directories only):

```sh
CICADA_IP_PQTLS_RUN=1 scripts/test-local-ip-pqtls.sh \
  /home/zyf/CICADA/.cicada-data/v00-docker-deployment-20261012/product-packages/amd64/output/cicada-linux-amd64-pqtls \
  /home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9 \
  /home/zyf/CICADA/.cicada-data/v00-docker-deployment-20261012/ip-arm64-clean-a2 \
  /home/zyf/CICADA/.cicada-data/v00-docker-deployment-20261012/product-packages/arm64/output/cicada-linux-arm64-pqtls \
  /home/zyf/CICADA/.cicada-data/v00-docker-deployment-20261012/arm64-qemu-runner/sysroot/usr/aarch64-linux-gnu \
  /home/zyf/CICADA/.cicada-data/v00-docker-deployment-20261012/arm64-qemu-runner/bin/qemu-aarch64-static
```

A1 exited 1 after the first Hub readiness check at test line 215 (3.09s), before
any Node command. Its actual driver exit 1/OOM false and exact cleanup remain
recorded. The cause is UNKNOWN: the initial reporter kept diagnostic hashes and
deleted raw output. A separate clean Hub startup and two startup-only instrumented
fixtures passed, including matching dual networks and absolute mount paths;
these did not enroll devices or issue grants. No product/fixture source changed
between A1 and A2. A2 used fresh synthetic state and read-only exact-CID log and
health observers. Temporary raw observer logs were reduced to safe events/hashes
and deleted. Hub child stderr is held only in the existing fixture's Go memory;
the host observer cannot inspect that buffer. No unseen cause is asserted.

A2 passed the actual empty-state enrollment/independent Owner ceremony and
checked startup/restart in both Node containers. Its 25 receipts are 16 exit 0
and 9 expected negative exit 1 (not 25 zero exits), including expected
pending, replayed nonce, and offline Apply refusals. The peer helper supplies the
sender through checked production Runtime/Relay APIs; actual ARM64 product Node
Agent persists inbox and NODE_RECEIVED. Fixture ciphertext survives offline Hub
and restart; retry/dedup and a wrong binding-epoch ACK refusal pass. The final
receiver exits 1 after receipt because its real Native context is absent; this
is the intentional boundary and no provider is invoked.

Actual inspect recorded each Node in one different bridge network, both local
listener positive probes and both cross-Node negative probes. Neither Node had
Hub SQLite or Owner private mounts (amd64 6 bind mounts, ARM64 8). Driver limit
was 2 CPU / 3 GiB / 256 PIDs; Nodes 2 CPU / 1 GiB / 128 PIDs, all RO rootfs,
cap-drop ALL, no-new-privileges and bounded writable tmpfs. Cleanup stopped the
Node keepalive sleep PID1 within 5 seconds, yielding actual exit 137 with OOM
false on both; product child command outcomes are the separate 25 receipts.
Driver exited 0. All three exact CIDs and both exact network IDs were verified
absent using inspect plus successful inventories; private fixture roots remaining
were zero. Root independently confirmed all five owned resources absent and all
six protected residents unchanged: ID/image/start time/PID/restart count and
canonical config/HostConfig hashes equal the baseline. The independent receipt
`root-postcheck.NONAUTH.json` SHA256 is
`578128a35a76e72c7d5055a194ca66cc6c3760be2d288c09d18308c74b0265cb`;
the initial `root-resident-baseline.NONAUTH.json` SHA256 is
`0c349074db9a65eee6e2bc253adcd7355b1ad9b73f5e10f173b9d4796708c402`.

| A2 evidence | SHA256 |
| --- | --- |
| result.json | 9d5395a8e0aabee45e76b2694049252a0953de326342345ec94a63e8099dac5c |
| cleanup.json | 8919203f865ba7dc26433d37053fb6c56e2b721459f3308fb3d32afcbf70c228 |
| fixture-input-before.json and identical after | 1af1bc9aa92e2abef1c356ef57d1464b4a6a554cecc5de84bec9d17975f3b42a |
| node-command-receipts.json | e8a8688f6b7a4ab7dcf634bdbed8450e112109cf35af21564889c53074b08ea3 |

The sealed Core local trial archive is
`cicada-core-0.0.3-ab2362f-local-trial.tar.gz`, 41,218,762 bytes, SHA256
`e3038ea8ae14dce22980136eded495b53da2fe0c8e591ddb5948dcc329978df8`.
Its MANIFEST SHA256 is
`d44b28e4cb66837083468d90d9feee1d3a13a7a2d619485b9e979f5dac845d97`.
Sealed integrity passed for 24 payload files. Included documentation/catalog
references were snapshotted from `ab2362f` with separate file hashes; newly
written README/manifest text is not described as content from that producer.
The archive contains no private keys, grants, state, test payloads or APK.
See [trial delivery](v00-user-trial.md) for the portable path and separate Client.

The fixture input inventory is separate from package metadata and both identify
the tested source scope. Workspace was clean after A2 before this documentation
closeout. Documentation commits do not become package producers.

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
