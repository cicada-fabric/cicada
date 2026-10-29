# Two-Node native acceptance entrypoint — 2026-10-29

The actual Runtime gate is **NOT_RUN** at this checkpoint. This record qualifies
the executable entrypoint, its compilation and the evidence classifier. It does
not convert the App producer's SDK-actor results, old M7 results or synthetic
classifier controls into a two-Node native pass.

The production baseline is Root's frozen
`5f270726733c10e3335b753c304cdc0f5332acda`, including App checkpoint `8d8ccd5`
and default scoped capability availability. The QA changes are the commit
containing this record. No Hub/App/Node production implementation is modified.
The enrollment contract revision is the shared value
`node-pair-trust-node-scoped-v1`; the Group contract remains
`owner-endpoint-groups-v1`. These are separate from the Git revision, binary
hash, software version, wire version and Docker image digest.

The single existing entrypoint is:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/home/zyf/Cicada/.local/artifacts/native-ip-complete/run-owner-thread-groups-cea8036-20261029/payload/licenses \
  scripts/test-native-pair.sh --owner-endpoint-groups-cross-node
```

The script selects only `TestN3OwnerEndpointGroupsCrossNode`, uses the existing
90-minute timeout, and writes a fresh isolated run under
`~/Cicada/.local/{state,evidence,artifacts}/native-pair-acceptance/`.
Exit `0` means this separate scope's `SCOPED_PASS`, `1` means failure and `125`
means NOT_RUN. Preconditions can exit `2`. A skip, partial execution or stopped
fixture cannot fill a missing case. Root will integrate the QA checkpoint and
freeze the actual execution source before authorizing Runtime execution.

| Case | Required actual observation |
| --- | --- |
| C1 | One persistent native TLS Hub, one actual App/Owner/device; two separate CLI Node processes use their own scoped private device code, Owner review and private ACK. Independent policies select the same existing Network. Two actual Hosts retain four original native Threads each. Control inference remains off. |
| C2 | Actual App CREATE reviews create G/H; exact fresh cards and separate ADD reviews grant A0/A1/B0 in G and A0/B0 in H. All five edges complete real Node key projection. The other five originals gain no implicit edge. |
| C3 | A0→B0 and B0→A0 each complete a real native ASK/REPLY in G. Both request and reply reach the exact original native SID once. |
| C4 | Normally close the original App process; complete a native ASK/REPLY in H without reopening it. |
| C5 | Arm B0's receiver expectation while B is online, stop B, send one original durable ASK, observe zero native injection while offline, then restart B with its same root/key/binding. The Host retains the original SIDs/history. Complete that exact request/reply; retain the original immutable outbox identity without a replacement ASK. |
| C6 | Reopen the same App profile, explicitly select B using its actual saved card gesture, and REMOVE only B0-G through a fresh Owner review. Re-read all eight originals' G/H relations. Fresh B0-G selection and ASK are definitively refused; the exact refused body's native queue count remains zero. |
| C7 | A0↔A1 in G and both cross-Node directions A0↔B0 in H still work. Recheck refused-G zero injection and all eight original identities, endpoint keys, bindings and workspaces. Both Hosts close with zero real-model/literal-provider calls and exact provider accounting. |

The parent uses only frozen public Core Actions. B enrollment explicitly begins
with `ActionBeginAddNode`; reviews use `ActionReviewNodePairing` and
`ActionApproveNodePairing`; the original Node ACK is read with
`ActionRefreshNodePairing`. `ActionSelectSavedNode` copies the actual current
`Targets.GestureID`. Existing Network choice comes from `Targets.Networks`.
Every Group operation uses the exact Core Thread/candidate/relation/review card.
There is no parent positive signer, SQL grant, legacy enrollment substitution,
fake App API or additional transport. SQL observations are read-only identity
and immutable-outbox audits.

Each Node has a private home, user root, state, keystore, MCP state, SQLite
outbox, Codex home, four workspaces and process log. Long-lived children and
their cleanup belong to the parent test, so finishing a scenario does not kill
the next scenario's original processes. The closed receiver expectation does
not inject a native turn; only the actual receiving Node can deliver one.
Private logs, IPC, codes, secrets, keys and databases stay in disposable state.
Exported evidence contains public coordinates, closed facts and hashes.
App-action failures retain only `ActionFailed`, a closed `Phase` enum and
allowlisted App/Node/pairing/Group/policy error codes. Unknown text becomes
`OTHER`. A deterministic privacy control rejects arbitrary private text,
including uppercase values that resemble codes. The existing App test child
uses the parent's 90-minute process lifetime only under the new selector;
all existing selectors keep their 10-minute App child limit. This does not
extend any product account, consent, business-policy or credential deadline.

The existing driver pins:

- Go image `golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
- Codex `0.164.0`, SHA-256 `b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`, with its complete package mounted read-only.
- The populated module cache read-only; the task build cache has an exclusive `flock`. Docker has no external network; services communicate over real container-local TCP. No shared development Hub or public deployment is touched.

Compile-only evidence:
`~/Cicada/.local/evidence/n2-acceptance/cross-node-entrypoint-final-5f27072-6p6q8rpl/`.

| Check | Exit / measurement |
| --- | --- |
| Go version | 0; 0.476 s |
| Actual CLI build | 0; 2.247 s; binary SHA-256 `44edb93e1c1848f95c2d1ec24784cb4adacc4c4d0ab28ea62272423266beaaba` |
| N3 test binary build | 0; 6.237 s; binary SHA-256 `169d3e2a499df88a2f1ddb775e67272d0cbece8ff905b9db140ae8b3b26b67ea` |
| N3 vet | 0; 1.390 s |
| Closed App diagnostic privacy control | 0; 0.642 s; actual deterministic helper test, zero Hub/App/Node/Host starts |
| Source before/after | Stable; snapshot SHA-256 `60bbdeb8e8b24c0aede9261edf3628c587fba2d9945d4fee53ed2916d73d954b` |
| Compile result / manifest | SHA-256 `2f38acc0674c944d222e8b50067b029d54c29c7ef6a438dc7ed97a2f5d0b583a` / `46ea16e84b9db170db65deab9bb94ffe0b7b375ef34a0f1af69096ab5e4e27b1` |
| Cleanup | Container absent with Docker available; zero state files; owned empty state directory removed |

The compile snapshot is baseline **plus dirty QA files**, not HEAD alone.
The final compile includes the exact contract revision, closed diagnostics
and App child lifetime correction. Only documentation was completed afterward.
All compiled Go input hashes are retained for final checkpoint attribution.
The earlier successful compilation is retained separately at
`cross-node-entrypoint-compile-5f27072-uj0c9_ak/` with its original source scope.

The final synthetic oracle run is
`~/Cicada/.local/evidence/n2-acceptance/cross-node-entrypoint-final-5f27072-6p6q8rpl/oracle/`:
179 checks, exit 0, product **NOT_RUN**; result SHA-256
`5988270eff387dc49ff96ea11efd733bc263da44b47fd3becae9e03635c5b195`.
The command is
`python3 scripts/fixtures/native-pair/owner_groups_evidence_checks.py NEW_PRIVATE_DIR`.
Controls retain all old classifier assertions and reject missing/duplicate
cases, non-boolean facts, fewer than eight identities, one Node disguised as
two, changed original identities, missing/wrong/colliding native request routes,
source/binary drift, truncated JSON, failed build stages and unknown/remaining
Docker resources. An initial synthetic mutation incorrectly reused the expected
reverse-route target; that control was corrected, and its failed receipt remains
at `cross-node-entrypoint-5f27072-z3dzovto/`. It was not a product failure.

The new result requires all seven exact single terminal events, all closed
facts, one eight-original identity witness and six unique cross-Node native
request/reply witnesses with the exact directions and distinct G/H scopes.
It never closes the historical full M1–M8 gate. Existing full and M7 selectors
and their assertions are preserved.

Historical full M1–M8 explicitly uses legacy App-Node v1 and `--control-url`;
the default-enabled capability does not enter the `--hub-address` auto family
selector for those commands. A separate old NPT fixture uses address+auto and
would need explicit historical legacy selection before rerunning that separate
lane. This checkpoint does not change it or any M1–M8 production/test behavior.

Actual two-Node Runtime, complete M1–M8 on the new frozen source, Windows
DPAPI/ACL/GUI/IME, Android, a physical second Node and public HTTPS remain
**NOT_RUN**. No new production defect is established by compilation or these
synthetic classifier checks. Prior failures and their original source attribution
remain unchanged.
