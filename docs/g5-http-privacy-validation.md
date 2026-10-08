# G5 HTTP privacy validation

## Current scoped checkpoint — v0.1 PARTIAL

Main's normal gate on 2026-10-08 passed 6 top-level tests / 28 subtests, zero failures/skips, exit 0; package 3.528 s / host 12.079 s. The race gate passed the two new tests / 23 subtests, zero failures/skips, exit 0; package 29.854 s / host 41.878 s. This is scoped deterministic HTTP authorization/redaction evidence, not completion of all seven G5 predicates.

Tested source: base `8987a2a9ae06c4382fbcad89b650eb1fb88c5d95` plus sole new [fabric_g5_privacy_test.go](../cicada-go/internal/server/fabric_g5_privacy_test.go), SHA-256 `de31d3763887ecd04e6e7843f386e40a1cd1130b2b198024f47aae594b360612`, 14,254 bytes, filesystem permissions `0664` / raw `100664`. The 924-input [source inventory](../.cicada-data/native-observer-wiring-20261007/g5-privacy-8987-20261008a/output-normal/source.NONAUTH.json), SHA-256 `b1c49146fd5f6774438fbebc9a7b021d1ac3e8d35938d96a7fe5e9f5b05aa8e9`, records fingerprint `1fd1e292e6eec4f7cf3642a56479304c9d9f90637cfc3a1ab8cab084b0f06121`. Attribution is not base HEAD alone or a later documentation commit. These links are locally retained ignored NONAUTH evidence, not published assets.

### Actual fixture and assertions

`TestFabricG5DirectoryPrivacyHTTP` and `TestFabricG5ArtifactPrivacyHTTP` use a real temporary Store, Service.Join-issued Fabric credentials, explicit memberships and production `server.NewFabricHandler` behind a loopback `httptest.Server`. There is no fabricated route dispatcher. The new fixture does not construct Control; the retained `TestArtifactV2HTTPRejectsWrongGroupAndRevokedMembership` does construct synthetic Control. Consequently the six-test set does not claim nil Control or measured global business-call isolation.

Directory positives resolve an authorized peer and list/filter the expected visible endpoints. Both members/list and find/resolve/inspect reject forbidden Group headers and hide foreign peers, Native IDs and session credentials. Artifact positives read exact synthetic content and permitted metadata; negative checks cover foreign collection entries/reference reads, content-only metadata redaction, metadata-only content denial, revoked reader and one synthetic Endpoint/binding/Native ID explicitly joined to A+B but lacking B Artifact grants. Switching a header cannot borrow those grants.

A requested Endpoint/ref ID is known input: its echo in a denial is not newly disclosed information. Collection results must hide foreign IDs; denial checks instead exclude unrequested peer metadata and Artifact fields/content. Trusted legacy Hub-backed Workspace/plaintext Artifact seeds prove ACL/redaction only, not peer-application E2EE or Hub blindness. No installed Node/Native/model process or real unjoined session U is exercised.

### Seven-predicate boundary

| CICADA.md §39.6 predicate | Evidence here or retained source coverage | Still unclosed |
| --- | --- | --- |
| U invisible | Explicit Join guards and service unknown-`native-u` lookup are retained source/historical assertions. | No existing real unjoined U/session discovery assertion in this HTTP fixture. |
| Forged sender/Group/Link fails | Normal gate retains actual HTTP `TestGuestOwnerNodeJoinRejectsForeignGroupAndForgedIdentityFields` and `TestSealedNodeRoutesRequireCurrentNodeIdentityAndRejectCallerRouteClaims`. | All methods/actors are not exhaustively covered; ignored principal input is not a rejection claim. |
| Cross-Group Artifact denied | New HTTP collection/read and retained `TestArtifactV2HonorsExplicitGroupScopeForMultiGroupEndpoint` / wrong-Group regression. | Real Client/device/public HTTPS is separate. |
| Revoked queue and reads fail | New Artifact read denial; earlier local-trust/Hub Guard queue and scoped Task/Request checks retain their original evidence/source. | This gate does not rerun or expand every queue/read revocation domain. |
| Monitor review cannot replace User approval | Retained source checks reject model authority fields and require trusted Client approval; review preserves delivery/approval ledgers. | Complete Monitor-to-action/Native approval flow is not tested here. |
| Search/export hides hidden objects | Current members/list/find/resolve/inspect and Artifact collection/read HTTP assertions cover those implemented routes. | No generic public export surface was established by the audit; no invented export test or full hidden-object matrix claim. |
| Shared Thread cannot gain another Group's secrets by switching group_id | New A+B Artifact-grant denial and retained scoped mailbox/dedicated-policy checks. | Broader forbidden B data/tools/keys and actual Native context validation remain separate. This does not require erasing authorized retained model memory; shared-context risk is disclosed and sensitive dedicated-Thread policy is separate. |

### Executed command and receipts

The [normal command](../.cicada-data/native-observer-wiring-20261007/g5-privacy-8987-20261008a/output-normal/command.NONAUTH.json), SHA-256 `38beb68fa312cbee77f0450279e6ad761db9b80f1e96acba71bb3240df21aaa7`, was executed once by Main inside the recorded disposable environment, not as an unverified host recipe:

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -run '^(TestFabricG5DirectoryPrivacyHTTP|TestFabricG5ArtifactPrivacyHTTP|TestArtifactV2HonorsExplicitGroupScopeForMultiGroupEndpoint|TestArtifactV2HTTPRejectsWrongGroupAndRevokedMembership|TestGuestOwnerNodeJoinRejectsForeignGroupAndForgedIdentityFields|TestSealedNodeRoutesRequireCurrentNodeIdentityAndRejectCallerRouteClaims)$' ./internal/server
```

[Normal result](../.cicada-data/native-observer-wiring-20261007/g5-privacy-8987-20261008a/output-normal/result.NONAUTH.json), SHA-256 `a59fde0d65f41545aef3daf1b9ef96a801febc57ea6c821957b3863fe95ece77`, records model/real Native calls zero, owned container absent, resident metadata equal and source unchanged. The [race command](../.cicada-data/native-observer-wiring-20261007/g5-privacy-8987-20261008a/output-race/command.NONAUTH.json), SHA-256 `ccfa528f397ba1bb40bf45cf62884f59b0cded31efef4409add301cea4d0d4d3`, was executed once by Main:

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -race -run '^(TestFabricG5DirectoryPrivacyHTTP|TestFabricG5ArtifactPrivacyHTTP)$' ./internal/server
```

[Race result](../.cicada-data/native-observer-wiring-20261007/g5-privacy-8987-20261008a/output-race/result.NONAUTH.json), SHA-256 `be8e43224eb6eacc1603d99fd5533b429633cbb21d4f131c6803a7ab2274e291`, uses the byte-identical 924-input inventory. Main's [independent review](../.cicada-data/native-observer-wiring-20261007/g5-privacy-8987-20261008a/root-review.NONAUTH.json), SHA-256 `640d3827faa15ec7d189aba6882f0c0468d5eaad6b489c0c9925af69b0c036bc`, confirms source/export equality, recorded hardening, exact owned CID/name absence and six residents' limited metadata unchanged for both gates. Model/real Native calls remain zero.

Both recorded container commands use pinned Go 1.27.1 `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, UID 1000:1000, network none, read-only root, cap-drop ALL, no-new-privileges, 2 CPUs / 3 GiB / 256 PIDs, bounded writable executable `/tmp`, source export of tracked Go plus the approved new test, module cache and OpenSSL stage read-only and approved build cache writable. Host wall 420 s / attach maximum 350 s / cleanup reserve 60 s; Go timeout 5 minutes.

### Retained limits

Historical c56 G5 8/43 and prior 8987/local-trust evidence retain their own input fingerprints and fixture scope; this result neither retags nor aggregates them. v0.1 remains PARTIAL: G2 FAIL / G3 NOT_REACHED, A6 UNKNOWN, general Worker/sandbox BLOCKED and inspected V67 local submission UNSUPPORTED. Native, full G5/T9, Client, physical-device and public HTTPS acceptance remain separate. Delegated external Docker/DAC and selected registration fixtures are not substitutes for the product Native context/reply oracle. No contract/schema/dependency or production code changed in this checkpoint.
