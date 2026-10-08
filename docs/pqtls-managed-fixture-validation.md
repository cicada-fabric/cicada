# Managed PQTLS fixture validation — scoped protocol QA

This 2026-10-08 checkpoint migrates test fixtures to genuine managed TLS issuance, installation and current-authority validation. It changes seven test files only; production guards, contracts, schemas, dependencies and Client code remain unchanged. v0.1 remains PARTIAL.

## Tested source

Main tested base `443e3e53d868f8c104ecaa2e15eb5e7626b12c33` plus seven dirty test paths, not a clean HEAD build. E fingerprint `1181aa1c8c1555c374db06d6d350aedfa5c711284b1dd8afa4c4d298a16b97be` covers the full tracked-source inventory plus the new helper before this documentation checkpoint; it is neither Go-only nor a fingerprint of these later documentation edits.

| Test path under `cicada-go/cmd/cicada/` | Bytes | SHA-256 |
|---|---:|---|
| [native_network_pqtls_bridge_test.go](../cicada-go/cmd/cicada/native_network_pqtls_bridge_test.go) | 11912 | `29133182ec196d15a02d66fa3a8e2aa075eec952b5f2faa58d22db82f70b0910` |
| [machine_pqtls_runtime_trust_test.go](../cicada-go/cmd/cicada/machine_pqtls_runtime_trust_test.go) | 29342 | `42823c0b74a149d25abc81a8f3711c9c83dbc859dcecdaf489ab78117e847305` |
| [node_pqtls_management_test.go](../cicada-go/cmd/cicada/node_pqtls_management_test.go) | 11284 | `c22d3bfc363a5319022393288b756f88bdc6130812531c8f74c495eb23762a35` |
| [node_pqtls_runtime_test.go](../cicada-go/cmd/cicada/node_pqtls_runtime_test.go) | 20491 | `ec6de6d562d305811ea4edcb200fbd0deff51a422f88612d6a9379ca472d02f1` |
| [node_pqtls_lifetime_test.go](../cicada-go/cmd/cicada/node_pqtls_lifetime_test.go) | 12001 | `b60c146e5e24515a8b7ed7046368a21292d8dc81b6d4606a79b7a8e121e313a8` |
| [native_network_binding_test.go](../cicada-go/cmd/cicada/native_network_binding_test.go) | 29028 | `fa61359ad23c0ca1da4a3cfaad7bc67dc2bbf238b0174d610583deb76c93df08` |
| [node_pqtls_managed_fixture_test.go](../cicada-go/cmd/cicada/node_pqtls_managed_fixture_test.go) | 16493 | `ca8bad3bd511d2bd2774d550026ed5e9d827938176755bd4cfabf78e9d65047b` |

The helper uses the same Store and Node IDs/credentials with the original Owner/device identities. Management preserves existing application keys; legacy fixtures enroll genuine NodeControl identities rather than assuming those keys already existed. Real Owner-approved grants, installation ACKs, Hub-signed activation and checked Apply produce managed active files and fresh current-authority packets. Retained signing/preparation keys come from the production read APIs; scoped synthetic DNS resolves a qualified Hub name without host configuration changes. Stage/Apply consume proofs at fresh real UTC time, retaining the original certificate expiry.

The tests retain actual PQTLS traffic, encrypted RPC, SSE, revocation, two-Hub routing and the 12-second expiry window. Expired current authority must become unavailable while both durable authority reservations and scalar Owner/credential bindings remain unchanged. A same-issuer unapproved leaf proves TLS peer rejection before HTTP authentication, not a sole pin-branch, stale-epoch or Store-authority claim. Diagnostic transport assertions check the wrapper and exact per-Hub underlying transport.

## Retained attempts

The [original baseline](../.cicada-data/native-observer-wiring-20261007/full-core-443e3e5-20261008a/output-full/result-adopted.NONAUTH.json) lacked required PQ environment setup: 2,782 pass / 59 fail / 23 skip events, retained SHA-256 `fce0759b5164777966b9ab92dac295d7b099819569ac4442fcd72ac1c91639d0`. The corrected baseline had 3,071 pass / 6 fail / 23 skip events: 29 other package terminals passed and `cmd/cicada` failed. Its source fingerprint was `a28d02bbe7c5b0900bba229c30e6fccdcf7b82ad1e0d63b1fc8f178aa6ef6c13`; this is distinct from E.

[Corrected baseline](../.cicada-data/native-observer-wiring-20261007/full-core-443e3e5-20261008a/output-corrected/result.NONAUTH.json) — SHA-256 `fee7c5ff45cab637f848a99a34af39f9770c175fd7ad787f5df99202f2e22835`.

| Attempt | Retained outcome and source-grounded correction |
|---|---|
| A | Six pass events including two subtests; four failed parents. Generic installation rejection did not identify its inner phase. Hostname/certificate mismatch was a necessary fixture correction, not a measured inner cause. |
| B | Same six pass / four failed parents; Prepare passed and reserve failed. Owner grant validation requires a qualified DNS name; `localhost` was incompatible. |
| C | Seven parents and twelve subtests passed; lifetime failed. The old equality oracle conflated expired derived current authority with durable mutation. Separate durable-row equality preserves the intended invariant. |
| D | Seven parents and two subtests passed; runtime Apply failed before its subtests. Reusing a pre-Prepare timestamp can reject a newly issued activation proof as future-issued. This is source-supported; the historical inner branch was not instrumented. |

[Attempt A](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008a/output-normal/result.NONAUTH.json) — SHA-256 `cb56abe71e555645ec0fb31911723515d97a15b47a4451e4342a2d7b0759f53f`.
[Attempt B](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008b/output-normal/result.NONAUTH.json) — SHA-256 `9b7f8d0ba380aafe39eb0596070d9d32cb05b6207a6b9eea9537feb3907bcd8b`.
[Attempt C](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008c/output-normal/result.NONAUTH.json) — SHA-256 `2b35825227cd2486c4a44dda368c5e98f1c66d68c1d03fe7bebd625f3d253201`.
[Attempt D](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008d/output-normal/result.NONAUTH.json) — SHA-256 `39c8d2dad9dd0be8f4d2005f37801d2450eb0fa9aa73acf3da29947b99fe85c4`.

## E terminal evidence

| Gate | PASS scope | Timing |
|---|---|
| Focused normal | 8 top-level / 12 subtests; zero fail or skip | Host 46.386 s; package 26.412 s |
| Focused race | 8 top-level / 12 subtests; zero fail or skip | Host 193.771 s |
| Full `cmd/cicada` | 402 top-level + 287 subtest pass events; 13 top-level skips | Host 205.696 s |
| Whole tagged vet | `go vet -tags cicada_pqtls -mod=readonly -p 2 ./...`, exit 0 | 3.773 s |

[E normal result](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-normal/result.NONAUTH.json) — SHA-256 `3dcf659dee846dc12b3a8ea788b2b6f1ef3be3c5b7bb7e8694d5cea4e6971f31`.
[E normal command](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-normal/command.NONAUTH.json) — SHA-256 `a563cca69860b785df6de30b62f1a57eb60d52113b18a6874a09d86c5346750f`.
[E race result](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-race/result.NONAUTH.json) — SHA-256 `d35e21f9fd9889a4d322f7c1508429e0c05c922c88f1339bae5a89478fad194e`.
[E race command](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-race/command.NONAUTH.json) — SHA-256 `f963a8cff66523e7da8705d21db96f98a370ec253c98eb196975159dff7208b1`.
[E package result](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-package/result.NONAUTH.json) — SHA-256 `607591f77dfc28dab0a99f3cec0f96931218474b5f7c0dbecb9bece00b7795ad`.
[E package command](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-package/command.NONAUTH.json) — SHA-256 `46a88125696b67265e57c2c84372cc1af3f25524769efd7f923d0bc69fdcaf3d`.
[E vet](../.cicada-data/native-observer-wiring-20261007/pqtls-fixture-migration-443e3e5-20261008e/output-package/vet-result.NONAUTH.json) — SHA-256 `5c0552939c55e1487093a0ef94b38ad01d7941f04eafa2bc3a2b4c982a3c0ffe`.

Main executed the following selectors inside the recorded disposable environment; these are not unverified host recipes:

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=10m -run '^(TestNativeNetworkBridgeTransportConfigurationFailsBeforeRequest|TestNodeTLSRuntimeNativeProductCheckedStartup|TestNativeNetworkBridgePQJoinRenew|TestProductNodePQManagedOriginPreservesKeysAndEncryptedRPC|TestProductNodePQRuntimeRouterRelayAndCurrentCertificateAuthority|TestProductNodePQCertificateLifetime|TestNodeTLSRuntimeClientRejectsLegacyEnvironmentFallback|TestProductNodePQRejectsClassicalTLSAndPlainHTTPBeforeAuthentication)$' ./cmd/cicada
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=10m -race -run '^(TestNativeNetworkBridgeTransportConfigurationFailsBeforeRequest|TestNodeTLSRuntimeNativeProductCheckedStartup|TestNativeNetworkBridgePQJoinRenew|TestProductNodePQManagedOriginPreservesKeysAndEncryptedRPC|TestProductNodePQRuntimeRouterRelayAndCurrentCertificateAuthority|TestProductNodePQCertificateLifetime|TestNodeTLSRuntimeClientRejectsLegacyEnvironmentFallback|TestProductNodePQRejectsClassicalTLSAndPlainHTTPBeforeAuthentication)$' ./cmd/cicada
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=10m ./cmd/cicada
go vet -tags cicada_pqtls -mod=readonly -p 2 ./...
```

The 13 opt-in skips remain NOT_RUN, not PASS:

- `TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative`
- `TestMCPSealedCrossNodeGroupAskReplyNative`
- `TestMCPSealedSameGroupBroadcastNative`
- `TestMCPSealedSameNodeGroupAskReplyNative`
- `TestMachineMultiHubDockerFixture`
- `TestMachineNativeRealQueueCrashAcceptance`
- `TestMachineRestoreRecoveryDisposableFixture`
- `TestMCPMonitorBroadcastAndroidClientNative`
- `TestMCPMonitorBroadcastClientV13Native`
- `TestMCPSealedNativeThreadJoinsTwoIndependentHubsNative`
- `TestPQDistributionActualHubNode`
- `TestTaskPeerPrivacyIsolatedHubFixture`
- `TestTaskPeerPrivacyIsolatedNodeFixture`

## Isolation and remaining scope

Main used pinned Go 1.27.1 builder `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, accepted OpenSSL 3.5.9, offline module cache, read-only source export/stage/module mounts, and an approved writable build cache. Containers were UID 1000:1000, read-only root, cap-drop ALL, no-new-privileges, network none, 2 CPUs, 3 GiB and 256 PIDs; `/tmp` was bounded writable executable tmpfs. Host/attach/cleanup bounds were 1,200/1,050/120 seconds. Named results report zero model and real Native calls, owned-container absence, source equality and six protected residents unchanged. These protocol tests do not prove global Control business-call isolation.

Contract checks and three real-TCP alternate gates passed on their separately attributed baseline source; their success does not validate the shipping image:

[Contract checks](../.cicada-data/native-observer-wiring-20261007/contract-443e3e5-20261008a/result.NONAUTH.json) — SHA-256 `0b77420972ec3d015c03dffc2602baad1c38f3b3e55d6fb2f01b2f8ae1ab1acd`.
[Client TCP](../.cicada-data/native-observer-wiring-20261007/client-core-tcp-443e3e5-20261008a/output/result.NONAUTH.json) — SHA-256 `995f94c7dad145d46e01821767d79b28069beb4f92a00c0feefc713bd1734ab8`.
[Group spaces TCP](../.cicada-data/native-observer-wiring-20261007/group-spaces-core-tcp-443e3e5-20261008a/output/result.NONAUTH.json) — SHA-256 `c518abffa44592f6b6578d4ccf2d7efc60c49d27c37094903b378acedef964a3`.
[Network TCP](../.cicada-data/native-observer-wiring-20261007/network-core-tcp-443e3e5-20261008b/output/result.NONAUTH.json) — SHA-256 `1b7d9a897ddfd20cc825c0fb31328ad6b8dbea8982cafdaf571e1786292503bf`.

The [network TCP A setup failure](../.cicada-data/native-observer-wiring-20261007/network-core-tcp-443e3e5-20261008a/output/result.NONAUTH.json) remains retained separately, SHA-256 `b53248ea7ec33957bf0415f1ebfead1428e892fce271933422ee404b51d2b7cd`. Main reported shipping-build wrapper timeout exit 124; its immutable inner receipt records FAIL in build phase, exit 143, empty image ID and protocol/recovery NOT_RUN. The level label does not prove TCP execution.

[Shipping build failure](../.cicada-data/native-observer-wiring-20261007/client-interop-443e3e5-20261008a/result.json) — SHA-256 `302a488cb5c496321d6989f85832c930f13f511e49bda252c984decc5f4bbc28`.

There is no combined full-repository PASS. Native sandbox/Worker remain BLOCKED, A6 cause UNKNOWN, G2 FAIL, G3 NOT_REACHED and V67 UNSUPPORTED. Full G4/G5/T9 acceptance remains separate; Android, physical devices, public HTTPS and actual Native context are NOT_RUN or otherwise retain their earlier scoped outcomes. This checkpoint grants no broader v0.1 acceptance. Evidence links are locally retained ignored NONAUTH artifacts, not published assets.
