# Native production-handler Control-isolation validation

## Current scoped protocol result

On 2026-10-08 Main's output-c run (session 71823) exited 0: four tests passed, with zero failures/skips, package elapsed 3.131 s and host elapsed 6.2413 s. Formatting validation passed with no listed files. Model calls and real Native Runtime calls were zero. This is production HTTP/MCP protocol evidence with a recording Codex fake, not full T9 or model-context acceptance.

The [result](../.cicada-data/native-observer-wiring-20261007/t9-production-route-4f45-20261008a/output-c/result.NONAUTH.json) SHA256 is `921c5d2a77ff564a6a5e83a18b2f6168428a36fe2bf1167ae0f3cf001dbf3501`. [Main independent review](../.cicada-data/native-observer-wiring-20261007/t9-production-route-4f45-20261008a/output-c/root-review.NONAUTH.json), SHA256 `3575acfe8634b811d79386768325ee759a35917a175d7c4553766546efbe3c1f`, confirms all three owned container IDs/names absent and six resident closed metadata unchanged. Links reference locally retained ignored NONAUTH evidence, not published assets.

## Tested source and actual route

The tracked-only export was based on `4f45b58137f8d41f5ed6901e2bc54baaba5de28e` plus exactly two dirty test files; it was not a clean-HEAD build. [Source inventory](../.cicada-data/native-observer-wiring-20261007/t9-production-route-4f45-20261008a/source.NONAUTH.json), SHA256 `032e01b82ef6eb86145f1ee9d2dde110c7f80cb07eaf77bfa4e74fa5724c7b25`, identifies 923 paths matched independently against the working source, fingerprint `c570f82c8efdf1422c448672ad94743ec8e1d4135a71132c1b7597baa7fa062a`. No ignored checkout data or .git was materialized.

- [Fullchain test](../cicada-go/cmd/cicada/machine_sealed_rpc_fullchain_test.go): SHA256 `7c0ef07ea43f05d1c308615305085bda75f406da9e25351b35dd2a40cde3f6c5`, 11,040 bytes.
- [Shared fixture](../cicada-go/cmd/cicada/machine_sealed_receive_test.go): SHA256 `1090b8e677550fde2ea07ac7467441a9bef937802fb8c869000ca929f0a19bcf`, 68,141 bytes.

The fullchain test delegates routes to actual `server.NewFabricHandler(fixture.service, managerToken)`, with Control absent. Its wrapper only observes bounded wire bodies/receipts and restores bodies before delegation. An opt-in shared-fixture branch calls `JoinForNodeCredential` before Link construction, key attestations and owner grants, so those proofs cover the issued session binding epochs. Existing fixture callers retain the original branch.

Actual HTTP whoami verifies the issued endpoint, binding ID/epoch and native-session identity. Missing/wrong synthetic Manager bearers receive 401; the authenticated Manager `/v1/status` receives 503. Production MCP and Node bridges then complete opaque ASK and correlated REPLY, exact recorded queue delivery/deduplication and layered receipts. The recording fake does not establish real Codex consumption, two physical hosts or global Control business-call counters.

## One executed selector and isolation

The executed Go selector covered:

1. `TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness`
2. `TestMachineSealedReceivePersistsInjectsExactThreadAndDedupes`
3. `TestMachineSealedRequestDecryptsAndQueuesExactNativeSession`
4. `TestMachineSealedReplyReturnsToOriginalRequesterSession`

[Exact command](../.cicada-data/native-observer-wiring-20261007/t9-production-route-4f45-20261008a/output-c/command.NONAUTH.json), SHA256 `197562383d0a194b08d245be777434f704ffc0239f4264054492cfcc84960142`, records `go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -run '^(TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness|TestMachineSealedReceivePersistsInjectsExactThreadAndDedupes|TestMachineSealedRequestDecryptsAndQueuesExactNativeSession|TestMachineSealedReplyReturnsToOriginalRequesterSession)$' ./cmd/cicada`. This records an executed run, not an instruction to repeat it.

The pinned Go 1.27.1 builder was `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`; accepted OpenSSL 3.5.9 and module cache were read-only, with an owned writable Go cache. The tracked-only export was read-only. Container limits were UID 1000:1000, network none, read-only root, all capabilities dropped, no-new-privileges, 2 CPUs, 3 GiB and 256 PIDs; bounded /tmp was executable for test subprocesses. Host wall was 420 s, attach maximum 350 s and cleanup reserve 60 s. No real credentials, private histories or resident deployment were used as fixture inputs.

## Retained failures and remaining gates

The first [output result](../.cicada-data/native-observer-wiring-20261007/t9-production-route-4f45-20261008a/output/result.NONAUTH.json), SHA256 `f3b7152619677c5164c05ea691f9e5cc38aba462b2a784002833055126fc0c7b`, failed preparation; Main’s sanitized report identifies omitted CGO include/link flags (`crypto.h` unavailable). [Output-b](../.cicada-data/native-observer-wiring-20261007/t9-production-route-4f45-20261008a/output-b/result.NONAUTH.json), SHA256 `58db932cf4e68efb6042800d86e790a771fd18c030f267038974f88ee6751da7`, failed preparation; Main’s sanitized report identifies disabled temporary execution. Both are retained FAIL records with tests NOT_REACHED, not failed protocol assertions or retrospectively passed tests. Output-c corrected only the disposable execution setup; the two tested source pins remained unchanged.

Overall v0.1 remains PARTIAL. General Worker sandbox is BLOCKED, A6 cause UNKNOWN, G2 FAIL / G3 NOT_REACHED, final context NOT_PROVEN and inspected V67 account-bound local submission UNSUPPORTED. Full T9/G5, remaining G4, current Client, physical-device and public-HTTPS gates remain separate; Control counts remain NOT_INSTRUMENTED. No product API, contract, policy or acceptance scope was changed by this test-only checkpoint.
