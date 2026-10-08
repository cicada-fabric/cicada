# Native local-trust admission validation

## Current checkpoint — v0.1 PARTIAL

On 2026-10-08, Main validated the local admission change on base `f5755d2efe343ec4d63c8eda75487d496658a2de` plus seven dirty Go paths. Tested source fingerprint: `aa30229dcc75d231038755833381476c37a0669288482bcbf5f3e8b94af94634`; this is not a clean-HEAD-only attribution. The [source inventory](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-green/source.NONAUTH.json), SHA-256 `d788a39319298795c7b0e395f0e3629f86e5eebd28de63ae8f70124d0a3e9866`, records those exact inputs. Links below are locally retained ignored NONAUTH evidence, not published assets.

### Boundary and change

Initial authenticated delivery had already verified the envelope, grants and Node-local trust before the physical writer wait. A completed local Owner/pin revocation during that bounded wait could leave Hub authorization unchanged, allowing queued plaintext to reach native intent and submission. The regression holds the physical writer, waits for initial open, revokes only target Node local authority, confirms unchanged Hub authorization, then releases the writer.

The three held-writer callbacks retain fresh Hub Guard and exact authorization comparison, then use one shared current-state helper before `BeginInjection`. It reads at most two Owner trust records and one pin record on one helper-owned CryptoState handle opened over the existing Node database; the initial open handle has already closed. Link and same-Group require the pin snapshot returned by the initial verified open; Network-direct has no pin. Snapshot comparison includes scope, identity, public key/fingerprint, version, binding and applicable Link manifest/expiry evidence. It preserves legitimate same-Group historical pin binding on reconnect; fresh Hub Guard separately fences current binding.

Definitive missing/revoked/mismatched local authority causes durable local FAILED state and journal retirement without queue/native intent. Storage, context and close failures remain retryable. No repeated decrypt/signature verification, pin mutation, contract/schema/dependency change or resident background loop was added. Record reads use the caller context; legacy `OpenCryptoState` Background initialization and its 30-second busy timeout remain unchanged. This is not a universal atomic-revocation guarantee or a measured performance claim.

### Retained validation

| Run | Actual scope and outcome | Result SHA-256 |
| --- | --- | --- |
| [RED preparation](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-red/result.NONAUTH.json) | Formatting exit 41; tests NOT_REACHED, zero test events. | `589070ec9e49024ce04e8724939439e95b13c537b044d6d121dea2d64a9eb1b0` |
| [RED-b](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-red-b/result.NONAUTH.json) | Four failing leaf cases: Link/Network-direct × source/target Owner trust. Seven failures including parents, zero skips; exit 1. Main confirmed unwanted queue/native intent. | `1f6e14873c0fa706e191dcb6123a087d09d5245a43ee5f3555a43b7c7c3eb805` |
| [GREEN](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-green/result.NONAUTH.json) | 11 top-level / 15 subtests PASS, zero failures/skips; exit 0. Host 45.299 s, package 17.869 s. Includes legitimate receipt delivery, current Guard negatives, Owner/pin revocation, crash boundaries, transport and production-handler recording-fake roundtrip. | `5cf874c4efabcc554bbaa4f0e5e44fb74ab9ef536c09b2bff55004406f018793` |
| [Nodekeys](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-nodekeys/result.NONAUTH.json) | 15 top-level tests PASS, zero failures/skips; exit 0. Host 4.106 s, package 0.258 s. | `2217913191f08e69ceb96e863ee06df5a87feddbeddd899db7e37a33ce18634d` |
| [Race](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-race/result.NONAUTH.json) | 6 top-level / 8 subtests PASS, zero failures/skips; exit 0. Host 290.734 s, package 174.042 s. | `e8cf55c94b228662ec1bd0100031d3dd56789a730db8dd5fad0dd152464e11e4` |

RED preparation used base f575 plus one dirty pre-format N2 test, fingerprint `397775ed1c871947f1380741aaacb978098d11fff64f980d7020bd802b96c533` ([source](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-red/source.NONAUTH.json)); its [preparation failure](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-red/preparation-failure.NONAUTH.json), SHA-256 `e6fefc10b9e7be7c867588ef056eee8aac673e7641210d8b77c93d3d06cc7f69`, explicitly records tests NOT_REACHED. RED-b used the formatted N2 test on the same base, fingerprint `3d52462d3ee0de50828d3c1315446d2826b41022eec8221593c1981b8a4dff71` ([source](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-red-b/source.NONAUTH.json)). Neither failure is attributed to the final seven-path GREEN source.

The [Main independent review](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/root-review.NONAUTH.json), SHA-256 `ac2e5f4d1f4ccb9fac260e06413ce5dc2cda11c18c1b7e63f2f69b4d00b0464e`, confirms the source exports, exact owned CID/name absence and six resident metadata equality across retained runs. GREEN, race and nodekeys use the same 923-file source inventory/fingerprint. Model and real Native calls were zero. The tests use synthetic fixtures and recording/helper processes, not installed Native/model context.

### Executed selectors and isolation

These are the exact Go commands retained in the public command receipts, executed by Main once per run, not instructions to repeat validation. The declared container uses pinned Go 1.27.1 image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, UID 1000:1000, network none, read-only root, cap-drop ALL, no-new-privileges, 2 CPUs/3 GiB/256 PIDs and bounded executable `/tmp`. Tracked-only source, module cache and accepted OpenSSL 3.5.9 stage are read-only; among host mounts, only the approved build cache is writable; `/tmp` is a bounded writable executable tmpfs. Command receipts set test timeout 5 minutes, host wall 420 seconds, attach maximum 350 seconds and cleanup reserve 60 seconds.

[green command](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-green/command.NONAUTH.json):

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -run '^(TestNativeDeliveryN2LinkNetworkLocalTrustRevokedAfterWriterWait|TestMachineNativeDeliveryLocalTrustRevokedAfterWriterWait|TestMachineNativeDeliveryPeerPinRevokedAfterWriterWait|TestNativeDeliveryLinkPeerPinRevokedAfterWriterWait|TestMachineNativeDeliveryAuthorityChangesDuringWriterWait|TestNativeDeliveryN2LinkNetworkCurrentGuardAfterWriterWait|TestNativeDeliveryN2LinkNetworkReleasedWriterAllowsReceipt|TestMachineNativeDeliveryTransport|TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness|TestMachineNativeDeliveryCrashAfterSuccessfulWaitBeforeOutcome|TestMachineNativeDeliveryCrashAfterDurableOutcomeBeforeReceipt)$' ./cmd/cicada
```

[nodekeys command](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-nodekeys/command.NONAUTH.json):

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -run '^(TestNodeLocalOwnerKeyTrustRequiresExpectedKeyAndRevocationIsTerminal|TestNodeLocalOwnerKeyTrustSurvivesRestart|TestPeerPinLookupRequiresExactScopeAndPeerIdentity|TestPeerPinRejectsKeyAndOwnerSubstitutionWhileActive|TestPeerPinRevocationUsesVersionAndIsTerminal|TestPeerPinSurvivesRestart|TestPeerPinConcurrentHandlesCreateOneActivePin|TestCryptoStateV2UpgradePreservesPeerPinAndRequiresLegacyInboxReconciliation|TestOwnerGrantedGroupEndpointPeerPinVerifiesAndUsesExistingSameGroupPin|TestOwnerGrantedGroupEndpointPeerPinRequiresIndependentNodeOwnerTrust|TestOwnerGrantedGroupEndpointPeerPinRejectsTrustRevokedAfterVerification|TestOwnerGrantedCrossGroupPeerPinRequiresBilateralLocalTrust|TestOwnerGrantedCrossGroupPeerPinRejectsExpiryRevocationAndStaleVersion|TestOwnerGrantedCrossGroupInboundMessageRequiresCurrentTrustAndExactRoute|TestOwnerGrantedCrossGroupReplyUsesReverseRouteAndExplicitReplyGrant)$' ./internal/nodekeys
```

[race command](../.cicada-data/native-observer-wiring-20261007/localtrust-fence-f575-20261008a/output-race/command.NONAUTH.json):

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -race -run '^(TestNativeDeliveryN2LinkNetworkLocalTrustRevokedAfterWriterWait|TestMachineNativeDeliveryLocalTrustRevokedAfterWriterWait|TestMachineNativeDeliveryPeerPinRevokedAfterWriterWait|TestNativeDeliveryLinkPeerPinRevokedAfterWriterWait|TestMachineNativeDeliveryBusyPreservesClaimAndJournal|TestNativeDeliveryN2LinkNetworkReleasedWriterAllowsReceipt)$' ./cmd/cicada
```

### Frozen Go inputs

All seven inputs had filesystem/inventory permissions `0664` (decimal 436), raw regular-file mode `100664`; Git-recorded mode `100644` is separate.

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| [cicada-go/cmd/cicada/machine_sealed_receive.go](../cicada-go/cmd/cicada/machine_sealed_receive.go) | 39128 | `43dc12e017113d04577ba2cb32898efaf54df9aa69dc78fc510c0f10f5f17efa` |
| [cicada-go/cmd/cicada/machine_network_direct_receive.go](../cicada-go/cmd/cicada/machine_network_direct_receive.go) | 28813 | `75165a26d9a77d14ff32dcb3aca2115a8d6d63e1a910872e55cc60193f34b357` |
| [cicada-go/cmd/cicada/cross_node_group_bridge.go](../cicada-go/cmd/cicada/cross_node_group_bridge.go) | 62516 | `5e1b60cc6402dbb40ac280014e0018d3541a13eb788b5f4f2c7644f43d7c3b1c` |
| [cicada-go/cmd/cicada/machine_native_delivery_test.go](../cicada-go/cmd/cicada/machine_native_delivery_test.go) | 48650 | `190a88a47875c18466ac246bc3519e826291b593428b3b4c2f9dc9fd22863bf4` |
| [cicada-go/cmd/cicada/machine_native_delivery_n2_routes_test.go](../cicada-go/cmd/cicada/machine_native_delivery_n2_routes_test.go) | 41662 | `b16aaf58b077f6a05ce206c8c3765bcdc0a3f3ac3931cd4e6169004c1e977a72` |
| [cicada-go/internal/nodekeys/owner_key_trust.go](../cicada-go/internal/nodekeys/owner_key_trust.go) | 9770 | `39943d4376b5c427c0e646d883b4ecd85a2516c5fdc3d7436d3244bdb648c83d` |
| [cicada-go/internal/nodekeys/pins.go](../cicada-go/internal/nodekeys/pins.go) | 19582 | `f1ef1af192c8d939580c01fa67bd6f120fa31d67cb12edd407c328700a291c8e` |

### Remaining scope

v0.1 remains PARTIAL: G2 FAIL / G3 NOT_REACHED, A6 UNKNOWN, general Worker/supported sandbox BLOCKED and inspected V67 account-bound local submission UNSUPPORTED. Prior delegated external Docker/DAC and selected tool-registration passes do not establish the product Native lane. Remaining G4/full T9/G5, current Client, physical-device and public HTTPS gates are separate. The retained Native acceptance plan keeps its original strict context/reply oracles, six actual/four manual/two automatic turn targets, 180+30+30-second budgets, retries zero and admitted TCP cap 16 unchanged; TCP admission is not HTTP POST measurement. Historical receipts and earlier failure causes are not rewritten.
