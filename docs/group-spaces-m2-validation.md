# Group Spaces M2 validation

**Checkpoint:** 2026-09-30. This record separates the frozen M1 baseline, focused M2 evidence, and the full disposable Hub gate. It is not a claim that Android, a native Runtime, or physical devices were exercised.

## Scope under review

M2 delivers same-owner Group Journal and Discussion records through a current Node credential and joined Group Session. The Hub stores per-reader ciphertext and bounded routing metadata. The test fixtures use visibly synthetic identities, endpoints, keys, credentials, Group sessions, and bodies. They do not initialize or contact a resident deployment. Cross-owner boards have no M2 consent, key, or history contract and remain unsupported. No M3 subscriptions or cursor hints are implemented or validated here.

The HTTP contract and limits are in [group-spaces-m2-contract.md](group-spaces-m2-contract.md). The broader design proposal is in [group-collaboration-spaces-design.md](group-collaboration-spaces-design.md).

## Baseline and focused results

The one full Go baseline used a read-only `git archive` of commit `7c4194155d6c0c342671299e447c907f0b1d94d6` (tree `e2be53331c57fb8e91752c4acb13088bb195f2b6`, archive SHA-256 `610ee383339e0c818142c7bb06806a860ce7de4b5f8d92e9a6c3a1202c35b903`) in `golang:1.27.1-alpine`, with the offline module cache and `go test -json -count=1 -p=4 ./...`. It exited **1**: 25 packages, 1,261 test passes, 12 failures, and 10 skips. The failures were in `internal/clientcontract` (1), `internal/buildinfo` (1), and `internal/control` (10). The original detailed failure output was not retained, so this record does not infer a cause or recast that run as a pass.

A focused repeat of exactly those 12 tests against the same archived source, mounted from the repository root into `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, exited **0**: 12 passes, 0 failures, 0 skips. This is diagnostic evidence only; the initial full-baseline exit remains 1. Machine-readable details are retained under ignored `.cicada-data/m2-20260930/baseline/`.

Focused M2 evidence currently recorded:

| Check | Result | What it establishes |
|---|---|---|
| `TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS` | **PASS**, exit 0, 2.647 s | A disposable SQLite store and real local TCP requests to `NewFabricHandler`; per-reader journal envelopes, exact retry after a lost response and store reopen, current read fencing, late-join and rejoin cutoffs, exact single-record Owner history grant, forged proof denial, topic version CAS, scoped/tampered cursors, retention purge and ciphertext-only database scan. This handler test has no Control instance. |
| `bash -n scripts/test-client-hub-interop.sh` | **PASS** | Shell syntax for the opt-in disposable interop gate. |
| `git diff --check` | **PASS** | No whitespace errors in the current worktree. |

The root final Go and vet gates have since completed against a **dirty** source snapshot: source fingerprint `76becd7a479dfd801427fc470c376517227f67b293392d4cd7e314f5fa5b6e7c`, revision label `7c4194155d6c0c342671299e447c907f0b1d94d6`, image `golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`. `go test -json -count=1 -p=4 ./...` exited **0** across 25 packages: 1,292 passes, 0 failures, 11 skips. `go vet -p=4 ./...` exited **0**. The 11 skips include opt-in Docker/native-daemon tests; they are not counted as passes. Machine-readable details are under ignored `.cicada-data/m2-20260930/accepted/go-gates.json`.

The focused server test uses synthetic Node credentials and trusted Group-session fixtures. It is real TCP and exercises HTTP plus encryption, but it does not represent two physical Nodes or a real native Runtime. Its Control-free property comes only from constructing `NewFabricHandler`; the full Hub container test below does not claim that the Hub's Control subsystem is disabled.

## Required M2 gates

The opt-in disposable Hub command is:

```sh
scripts/test-client-hub-interop.sh --suite group-spaces-m2
```

It builds and starts an isolated Hub container with disposable credentials and state, then runs `TestGroupSpacesM2DockerHub` against that Hub over TCP together with the Control-free HTTP test above. The Hub test exercises two synthetic Node credentials, trusted joined Group sessions, a self-readable and peer-readable sealed journal, Node/session mismatch denial, and topic status compare-and-swap including stale-version denial. It does not call management or planner operations. It does not prove Control is disabled in the full Hub process. Results must be recorded from the actual command in ignored `.cicada-data/group-spaces-m2-interop/` evidence; absence or skip is not a pass.

The Core Store boundary test `TestGroupSpaceThirtyTwoReaderSnapshotFitsLimit` constructs 32 genuine synthetic reader proofs including the author, seals a 16 KiB body for each, and measures the full reservation, commit and 16-record page JSON. The reservation snapshot measured 1,491,644 bytes; commit JSON measured 2,116,357 bytes; a one-reader Get projection measured 158,144 bytes; and the 16-record page measured 2,530,333 bytes. Separately, `TestGroupSpaceCachePersistsLegalThirtyTwoReaderWireSize` verifies that the Node's durable cache accepts a greater-than-2-MiB, 32-envelope fixture and reopens the exact bytes. The MCP test `TestGroupSpacesMCPAcrossNodesWithLostCommitResponse` covers two synthetic Nodes, lost-commit retry, history grant checks and local decryption; it is not a 32-Node end-to-end test. These fixtures are synthetic; no native Runtime or physical device was started.

| Evidence layer | Status |
|---|---|
| Deterministic focused M2 HTTP/store test | **PASS** as recorded above |
| M2 package/unit/MCP deterministic tests and full Go/vet gates | **PASS** in the dirty source snapshot above |
| Focused Go race gate | **PASS**, exit 0 |
| Disposable real Hub TCP `group-spaces-m2` suite | **PASS**, exit 0; both required tests passed |
| Disposable Hub `client` regression suite | **PASS**, exit 0 |
| Disposable Hub `network-m1` regression suite | **PASS**, exit 0 |
| Local formatting, contract, Python, shell, and whitespace checks | **PASS** |
| Android Client interoperability | **NOT RUN** |
| Real native Runtime | **NOT RUN** |
| Physical Android/device test | **NOT RUN** |
| Public HTTPS deployment | **NOT RUN** |

The final race result is in ignored `.cicada-data/m2-20260930/accepted/race.json`; it ran `go test -race -count=1 -p=2 -run '^TestGroupSpaces?|^TestNetworkV36Upgrade'` over `internal/e2ee`, `internal/nodekeys`, `internal/store`, `internal/fabric`, `internal/server`, and `cmd/cicada`, and exited **0**. The M2 Docker result is in ignored `.cicada-data/m2-20260930/accepted/group-spaces-m2-docker/result.json` and `test.log`. It exercised a disposable Hub container over TCP and passed both `TestGroupSpacesM2DockerHub` and `TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS`. The Hub image was `sha256:10e2e4c92b2e3e5fbb67975a3caa456d421a0b3a88b856e8de770c6f87ebc288`; the test image was `sha256:cd4bb0c8c9129fbc27e9845e4c3edcba3ffea5dc396ce11a8348bddbb1e54eac`. The client and M1 regression results are in `client-docker/result.json` and `network-m1-docker/result.json`; both exited **0**. All three disposable Hub builds were dirty at revision `7c4194155d6c0c342671299e447c907f0b1d94d6` and shared source fingerprint `76becd7a479dfd801427fc470c376517227f67b293392d4cd7e314f5fa5b6e7c`. The M2 suite's `control_management_routes_not_exercised` scope entry means it did not issue management or planner calls; Control was present in the full Hub process.

The baseline remains attributed to its archived source. All dirty-worktree outputs retain their source fingerprint alongside the revision; M2 code, full Go/vet, race, and all three disposable Hub suites passed. Android, real native Runtime, physical device, and public HTTPS tests remain **NOT RUN**.

## Security checks represented

The integration coverage checks that the read projection contains only the requesting reader's envelope; the producer remains the original signer after history resharing; late joins and rejoin after a new cutoff cannot read earlier records by default; a separate Owner signature is bound to one record and recipient; forged approval and changed ciphertext are rejected; and current membership, session, key, and read fences are rechecked. Cursor values bind Group, Endpoint, kind, and topic and do not authorize reads. Topic state uses an expected-version compare-and-swap. Retention removes expired reader and history material and keeps only a bounded ID/sequence tombstone to reject retry resurrection while retained. Tombstones expire after at most 30 days and are capped at 4,096 per Group; older tombstones may be discarded under that cap, so idempotency protection is not permanent.

History grants do not enlarge the old reader's audience, create a Group-wide history key, or replace the new recipient's independent sealed envelope. Artifact access remains a separate ACL and is not implied by a readable Journal or Discussion record. Ciphertext-only database scanning is a fixture-level check; it does not assert that route metadata is hidden.
