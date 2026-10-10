# G5 permission matrix — scoped deterministic PASS

Source baseline: detached worktree `2594343b84ed0ec17a5cf349607631d831773cc3`
with the recorded G4/G5 test-only overlay. The G5 test SHA256 is
`f76b1137346eed1dbf885b1fbf72e51f91783b6578e30cb831b4c7f0bb9369af`; the G4
process-test SHA256 in the same QA run is
`611313cbf3244ed6c63d782415ff90baf8d478d8bef08a9ac1cbf36ac38fc614`. These
results are attributed to those overlay bytes and the recorded base, not to a
clean HEAD-only build.

`TestG5PermissionMatrixHTTP` reuses production HTTP routers, Fabric/Node credential
issuance, SQLite state and current Guards. All identities, native IDs, content and
cryptographic material are isolated synthetic fixtures. There is no installed
Native Runtime or model in this selector, and it makes no process-consumption
claim. The Monitor subtest reuses
`TestMonitorEndpointCannotMutateUserApprovalHTTP`, including real authenticated
PQ Client packets, exact unchanged pending-approval state, and positive Owner approval.

| Subtest | Production boundary and substantive assertion |
| --- | --- |
| `unjoined_u_hidden` | `FabricV2` → `AuthenticateForGroup` / `List` / `Resolve`: retained pending U has no membership/binding, disappears from directory and exact-ID/name/native-ID lookup; authorized peer resolves. |
| `sender_group_link_forgery` | `relayNodeGroupSealedV2` → `SendNodeSameGroupSealedV1Message` / Store pair Guard; strict DTO rejects invented sender field, wrong sender/Group denied, arbitrary unapproved Link denied by `SendNodeSealedLinkMessage`; each rejected message has no durable row. Authorized SEND persists exact sender/recipient sealed route. |
| `cross_group_artifact` | `ArtifactV2` → `ReadArtifactRefV2` → `AuthorizeArtifactRefV2ForActor`: all four scopes deny foreign ref and disclose no content/digest/name/summary; own content is exact. Legacy Hub-backed content tests ACLs, not Hub blindness. |
| `revoked_pending_queue` | Real sealed SEND has persisted positive sequence and `RELAY_ACCEPTED`; after recipient revocation, `ClaimNodeSameGroupSealedV1Deliveries` returns no deliveries, immutable sealed route/bytes remain, no native queue/resume receipt exists. No model consumption is inferred. |
| `revoked_read_surfaces` | Actual whoami/members/filtered list/find/resolve/inspect and all four Artifact router aliases, base/read variants, all metadata/summary/digest/content scopes work before revocation and reject afterward without protected data. |
| `monitor_not_user_approval` | Existing complete Monitor HTTP test: Monitor membership confirmed, Manager bearer and forged encrypted Client approval rejected, pending state exact, legitimate Owner can decide. |
| `same_thread_group_selection_not_authority` | Real second Group Join preserves one synthetic Endpoint/SessionBinding/epoch. Group header cannot borrow A grant; after B receives its own read grant, B content works but A ref remains forbidden. A retains its authorized content. |

MCP identity parsing remains in `cmd/cicada`, outside this test's package and this
agent's file ownership. Existing deterministic selectors are included below;
this new file does not claim to instantiate an MCP server. Dedicated generic
search/export APIs are absent/unsupported; actual directory lookup/filter and
Artifact content retrieval are covered. Generic export, native retained memory,
model accounts and physical/runtime boundaries remain NOT_RUN.

## Recorded Root QA (2026-10-10)

Root ran the normal and race phases with this selector; both included
`TestG5PermissionMatrixHTTP` and `TestG4CrashWindowsAtDurableBoundaries`:

```sh
go test -json -p 2 -mod=readonly ./cmd/cicada ./internal/server \
  -run '^(TestG4CrashWindowsAtDurableBoundaries|TestG5PermissionMatrixHTTP|TestCicadaMCPRejectsForgedIdentityAndCredentialArguments|TestTaskPeerPrivacyPlaintextMCPDeniedBeforeTransport|TestCicadaMCPGroupSelection401RevalidatesCurrentNativeScope)$' \
  -count=1 -timeout=180s
go test -race -json -p 2 -mod=readonly ./cmd/cicada ./internal/server \
  -run '^(TestG4CrashWindowsAtDurableBoundaries|TestG5PermissionMatrixHTTP|TestCicadaMCPRejectsForgedIdentityAndCredentialArguments|TestTaskPeerPrivacyPlaintextMCPDeniedBeforeTransport|TestCicadaMCPGroupSelection401RevalidatesCurrentNativeScope)$' \
  -count=1 -timeout=180s
```

Both phases passed: 40 tests run and passed, 0 skipped or failed, across 2
packages in each phase. The combined Root run exited 0 in 243.629 seconds with
0 model calls, unchanged source pins and the owned container absent. The Root
run receipt is
`.cicada-data/v01-next-gates-20261010/qa-a5/ROOT-RUN.NONAUTH.json` (SHA256
`e390f3fb2baa45daa851eba15b058150eadd5bfc907c47d6696c5b47f8fec3af`); counts
are in `ROOT-COUNTS.NONAUTH.json` (SHA256
`cb64ffe3b756113fb4595a16b21bcaa17f7d2d8f39c6b3fb80d73fd21015aaa9`). Normal
and race JSONL hashes are `eac03b67e6ff58678fb4c7067735d4a941d2da9cc97566a6395aee8c61c3d250`
and `ffa694723816edc2c30426990f53acc5698c63f7dc0a2a8354fe6851d4659e58`.
This PASS covers the named synthetic permission/HTTP checks only. It does not
establish Native Runtime consumption, physical stop, device behavior or public
HTTPS. The separate CLI real-queue injection result and its limits are recorded
in [the G4 validation note](g4-crash-window-process-validation.md).
