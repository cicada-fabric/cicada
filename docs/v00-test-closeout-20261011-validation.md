# Test closeout — 2026-10-11

<a id="current-source-closeout"></a>

This is the current test-source and local-artifact record for the **0.0.2
development candidate**, targeting **0.1.0**. It does not turn skipped,
blocked, failed, or independently scoped evidence into product acceptance.
The software version remains 0.0.2, schema 59, wire 1, catalog 55, and
`client-hub-v1.6.5`.

## Clean default aggregate: 328f

[`scripts/test-architecture-v2-completion.sh`](../scripts/test-architecture-v2-completion.sh)
ran at clean HEAD `328f5b5fa69571e67e7bb3e4582d5fb3bb920fd7`. The [aggregate
result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/closeout-aggregate/20261011T100622Z-91b9614330/result.json)
has SHA-256 `015f2b0f3a7cab3fb8446fdc399d14e2b794994172a39b97d917c845bb35888a`,
records source-before/source-after equality, and remains **FAIL**. Go
build/test/vet/read-only gofmt passed: 30 packages, 3,040 test passes, 24
explicit skips, zero Go test failures. Skips are not passes.

The aggregate's client interop, Network M1, Group Spaces M2, capacity,
joined-v68, multi-Hub, Node-Control and Group/Fabric stress lanes passed with
their own cleanup checks. The initial Python lane reports two FAIL and two
ERROR cases; release packaging failed on its synthetic VERSION fixture, and
client Link recovery also failed. The Web Panel runner's sanitized PATH omitted
Node and its required prerequisites remained unresolved. The aggregate
Hub-browser lane also remained BLOCKED on unresolved image/build prerequisites;
the later separate Browser run used Node 24.16.0 and passed. The aggregate Link
postcheck included the parallel PQ driver container (`e8d4…`) in its resident
comparison; the later exact-scope Link run passed its original six-resident
comparison and separately checked its own marker case. These follow-ups do not
rewrite the aggregate FAIL. Wiring and four Native lanes were NOT_RUN. Android,
Native Runtime/model, physical device and public HTTPS gates were also NOT_RUN.

Likewise, the later artifact check validates the already-built artifacts but
does not rewrite the aggregate's packaging FAIL.

## Follow-up source and artifact checks

The [frozen candidate](../.cicada-data/v01-next-gates-20261011/native-direct-audit/CANDIDATE-FROZEN-A1.NONAUTH.json)
(SHA-256 `0ea453430da9d51df29758e02ae3fe63af2167c2741b2595d3fa76aba7803380`)
pins 1,219 source inputs and six dirty Python test/orchestration files. The
candidate is distinct from the clean 328f artifact producer; it does not change
the provenance of those artifacts. Root's [frozen-source postcheck](../.cicada-data/v01-next-gates-20261011/native-direct-audit/ROOT-CANDIDATE-FROZEN-A1-CLOSEOUT.NONAUTH.json)
(SHA-256 `533235089f673c138d1bda3bcddb8914710a9e5b67cdbc2875d7126f96c3b3fd`)
confirmed the 1,219 inputs, six full-canonical resident snapshots, and original
aggregate and packaging receipts remained unchanged.

The [19-module Python revalidation](../.cicada-data/v01-next-gates-20261011/native-direct-audit/full-python-revalidation-a1/RESULT.NONAUTH.json)
(SHA-256 `628418987a33b164cf79fcd40d212823424869f127b0443a4b7eda33cc77bc91`)
passed 244 tests, skipped one explicitly, and had zero failures/errors in
12.409s. The [22-check artifact QA](../.cicada-data/v01-next-gates-20261011/native-direct-audit/full22-artifact-qa-a1/RESULT.NONAUTH.json)
(SHA-256 `47fc5aa3206954daa5c7e48f6e33e2dc1f8ae78ace93d146f05b55a38ba33e21`)
passed 22/22 with no skips; 41 product-artifact hashes were unchanged. It used
existing clean-328f artifacts and did not rebuild them.

The later [disposable Link recovery run](../.cicada-data/v01-next-gates-20261011/native-direct-audit/link-resident-scope-proposal-a1/actual-a3-operator/RESULT.NONAUTH.json)
(SHA-256 `305219e045860084070fb2f198f2f7d9d5c2147866ac520845ad0cef90304c6c`)
passed one top-level test and eight subtests, including two Hub restarts, its
separately owned marker case, exact cleanup, and six-original-resident equality
in 149.438s. It used the frozen six-file candidate; it is not Native,
Android, or public-HTTPS evidence.

The separate [current Browser run](../.cicada-data/v01-next-gates-20261011/native-direct-audit/current-browser-a1/result.json)
(SHA-256 `5055a4aec2fea872a0558660c2de5f443ee2109ac21194b7bba04f211bbfe35d`)
passed 29 steps using Node 24.16.0, Chromium 151, and a clean-328f Hub image
`sha256:b9b864fed789a78eec5494580570f14a65bc6cb6a4273abb5355af696deae111`.
Its fixture cleanup passed. This separate run does not change the aggregate
Hub-browser lane's BLOCKED status, and its receipt does not claim an unrecorded
container PID or process group.

The [local shipped-PQTLS gate](../.cicada-data/v01-next-gates-20261011/native-direct-audit/local-pq-operator-a1/run/RESULT.NONAUTH.json)
(SHA-256 `0478821bfd2a6615b174d92d1f62dd1eb10c721af67c9449c9326f8de847def9`)
passed one top-level test and four subtests in 69.435s against the shipped Hub
and two Node Agents, including TLS 1.3 / ML-KEM-768 / ML-DSA-65 / AES-256.
This does not establish Native PQTLS, a PQ Hub image, physical deployment, or
public HTTPS. The [offline stress run](../.cicada-data/completion-stress-20261011T100622Z-91b9614330/RUN.NONAUTH.json)
(SHA-256 `6a62a3d0c5a4190d6d9a3d930b78b4089e7ed82225524f04348625eb070cb3d7`)
passed its isolated component workload (1,000 Groups, 1,000 Members, 1,001
endpoint aliases, 32 broadcast cap, four senders × 16 asks, shuffled replies
and ACKs, and serialized same-SID callbacks). The cmd-cicada workload measured
a maximum container peak of 41,086,976 bytes (~39.2 MiB); this is component
evidence, not Hub RSS, Native, or model evidence.

The G4/G5 [normal/race run](../.cicada-data/v01-next-gates-20261010/qa-a5/ROOT-RUN.NONAUTH.json)
(SHA-256 `e390f3fb2baa45daa851eba15b058150eadd5bfc907c47d6696c5b47f8fec3af`)
passed 40 tests across two packages in each phase with zero skips/failures.
The official CLI 0.162.1 [G4 queue-crash gate](../.cicada-data/v01-next-gates-20261010/native-g4-preparation/ROOT-RUNTIME-A3.NONAUTH.json)
(SHA-256 `f03796a1c53ca2ae74690ecaf189a4049bf7a35d2401e01e08bc1d0d09d37dd6`)
passed the real queue injection before ledger completion, preserving the
uncertainty oracle and refusing reinjection; model calls and new turns were
zero. This does not prove model consumption.

The G5 HTTP bilateral-revocation case passed normal and race on its explicit
test-only source closure: each phase had 14 test RUN/PASS identities plus one
package PASS, zero skips/failures. The schema-59 reopen optimization passed its
selected server/Store race family (21 top-level tests / 71 test events across
two packages): already-applied reopen performs one integrity/FK verification;
fresh and partial migrations retain their per-migration checks. See the
[G5 record](g5-permission-matrix-current-source-validation.md#current-bilateral-link-revocation-case)
and [SQLite record](sqlite-startup-verification-validation.md).

The separate [official-CLI foreground gate](native-foreground-queue-validation.md)
passed its bounded synthetic busy-queue and draft checks with zero paid calls.
The default-daemon A5 run is separate from the one-click runner: its actual
Runtime loaded a synthetic-provider thread and verified two starts, two
completions, two synthetic POSTs, four current Guard checks, and an absent
command callback. Writer outcome remains `QUEUE_ACCEPTED`, while Node inbox
consumption is `CONSUMPTION_UNCONFIRMED`; this does not close full G2/G3 or
model reasoning. See [A5](native-default-daemon-validation.md) and its
[result](../.cicada-data/v01-next-gates-20261011/native-default-daemon/runtime-a5/RESULT.NONAUTH.json).

Historical `shipping0002e` on source 308d, with its recorded remote wrapper,
did execute the G2 hidden-member/revoked-Link denial tail and G3 encrypted
own-Owner status snapshot within scope. Its overall run remains FAIL because
the owned cleanup guard failed; later cleanup/source postchecks do not rewrite
that result. These are historical scoped results, not current-source full G2/G3
acceptance. See the [Native result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002b/request-observer-native-result-cicada-two-turn-g2https0162shipping0002e/result.json)
and [cleanup/source postchecks](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-shipping0002e/native-g2-support-cicada-two-turn-g2https0162shipping0002e/).

## C14 scoped default-daemon G2/G3 follow-up

C14 passed its bounded six-turn original-context G2/G3 scenario with 79/79
independent owned-closeout checks. The result verifies the defined ASK/Reply,
revocation-denial and encrypted status-snapshot scope; it does not rewrite the
clean-328f aggregate FAIL or the separate C9–C12 paid FAILs. The [Native
record](native-default-daemon-validation.md#c14-scoped-g2g3-acceptance) carries
the execution, zero-preparation, source and result identities. Android status
reads/GroupOwnerProof, V67/account-bound submission, two physical Nodes, public
HTTPS and complete first-release acceptance remain outside this scope.

<a id="synthetic-android-ownerproof-vector"></a>

## Synthetic Android OwnerProof vector — limited instrumentation scope

The separate A3 run passed exactly
`ai.cicada.client.hub.EndpointAttestationVectorTest#separateOwnerProofMustBindExactReviewedManifest`
(`OK (1 test)`, instrumentation exit 0; outer exit 0/EOF) in 68.05077549s on
Android API 35 / Android 15 / x86_64. It used the immutable app/test APK pair
from Client producer `1151b06e04b172de9c7b5989ffec1318e58bf862` (SHA-256
`e5707b6a5a91a45eca8285970e646408cf34d05cf246e1bcd4c9f1af9c4a3745` and
`7638c1ed4f3a3d6f549b78e64a1802612de59f4b6359bd9cc1795ce61065ca29`). At the
time, Core was HEAD `f2926bd73fdf12aca9f25e7408770c2b6de3e82b` with only
documentation changes dirty; Client was clean at `740882b86d798a3d514b24b2bc2fa2802718d79d`.
This was not a new Client APK or Core product build. The scope is synthetic
OwnerProof manifest-binding instrumentation only: model count was zero, Hub
Runtime was NOT_RUN, and `real_group_grant` plus Android encrypted status-read
were NOT_RUN. The [Root result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/owner-proof-android-a3/RESULT.NONAUTH.json)
(SHA-256 `9cbb3e826bc8c4985a36e2717511a80b96bd0a82e52000fcb6916cb0efbaaf2a`)
and [final receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/owner-proof-android-a3/FINAL.NONAUTH.json)
(SHA-256 `a881121fb577c3229ac5d913f688871946b9b57fa8086afabe74ddd9debd1fe2`)
retain the run details. The independent [38/38 postcheck](../.cicada-data/v01-next-gates-20261011/native-direct-audit/owner-proof-android-a3/ROOT-INDEPENDENT-POSTCHECK.NONAUTH.json)
(SHA-256 `34a5a6a04cd2bb64f5b13a63f195a4e5dc70ad3f69cb8245618f5e3959976e22`)
confirmed the recorded APK/driver, source and resident identities unchanged
and exact owned cleanup.

The earlier A1 `MOUNTS` prestart failure and A2 `BOOT_CONTAINER_EXIT` failure
remain retained; neither ran the selector. A1's strict mount check rejected
the image's anonymous Gradle volume. A2's `avdmanager` created the AVD under
`/home/gradle/.android` while the emulator searched the temporary HOME. A3 aligned the two
Android directory environment values without relaxing mount, capability or
UID checks. See the [A1 result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/owner-proof-android-a1/RESULT.NONAUTH.json)
and [A2 result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/owner-proof-android-a2/RESULT.NONAUTH.json).

The real-approval test overlay now matches the production fail-closed result
when Native stop is unconfirmed; it does not mark the Goal completed or emit a
summary. Its initial A1 compile attempt failed before container creation due
to invalid bare `rw` bind-mount syntax (Docker exit 125); that attempt remains
FAIL. A2 fixed only those two mount fields. The [A2 compile-only result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/real-node-overlay-compile-operator/runs/real-node-overlay-compile-1791716230985495738/RESULT.NONAUTH.json)
(SHA-256 `93bd89398259c8e7823c8255e7041db8c572cc5a88b58d4f9ccb6cb99b875d47`)
records seven Python tests and `go test -c ./internal/server` passing in the
pinned Go image; the compiled binary was not executed. Its independent
[postcheck](../.cicada-data/v01-next-gates-20261011/native-direct-audit/real-node-overlay-compile-operator/runs/real-node-overlay-compile-1791716230985495738/INDEPENDENT-POSTCHECK.NONAUTH.json)
(SHA-256 `4d9d5b2dee2e133f0ece5dba229359589d08df195a05526bca1364684ddbcebe`)
confirmed the exact owned container's create/start/die/destroy lifecycle and
absence, six full-canonical residents unchanged, and frozen source hashes.
This is compile-only test-overlay evidence, not an executed approval/Native
gate.

## Reproduction entry points

The public completion runner's supported options are documented in
[`docs/test-automation.md`](test-automation.md); this help invocation prints
them without starting any lane:

```sh
scripts/test-architecture-v2-completion.sh --help
```

These two source-only Python unit modules can be run directly:

```sh
python3 -B -m unittest -q \
  scripts.test_real_node_codex_approval_overlay \
  scripts.test_client_link_recovery_gate
```

The artifact checks require existing standard artifacts, an unpacked PQ
package, and the accepted PQ stage; omitted paths cause optional cases to skip.
The recorded invocation and exact paths are in the
[22-check QA argv](../.cicada-data/v01-next-gates-20261011/native-direct-audit/full22-artifact-qa-a1/ARGV.NONAUTH.json).
The recorded Python invocation used these artifact/stage inputs, with zero
builds, Docker workloads, or model calls:

```sh
CICADA_RELEASE_ARTIFACT_DIR=/home/zyf/CICADA/.cicada-data/v01-next-gates-20261011/native-direct-audit/closeout-packaging-once/output/standard \
CICADA_PQTLS_PACKAGE_DIR=/home/zyf/CICADA/.cicada-data/v01-next-gates-20261011/native-direct-audit/closeout-packaging-once/output/pq-unpacked/cicada-linux-amd64-pqtls \
CICADA_PQTLS_STAGE=/home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9 \
timeout --signal=TERM --kill-after=5s 180s python3 -B scripts/test-release-packaging.py
```

These variables name build inputs only; they do not contain credentials or
private-key paths.

## Remaining first-release acceptance

C14 passed the bounded six-turn default-daemon G2/G3 scenario with independent
exact cleanup. A3 separately passed only the synthetic OwnerProof vector
instrumentation; it did not exercise a real Group grant. The independent
v1.6.5 Android encrypted status read across an exact owned Hub restart, a real
Group grant, V67/account-bound submission, two physical Nodes and public HTTPS
remain unresolved or NOT_RUN. V67's account-bound Native submission API is
**UNSUPPORTED**, so it is not a source-only implementation task until a
supported API exists. Broader Native acceptance beyond C14's bounded
default-daemon scope remains unverified; C14 does not establish the separate
foreground model-consumption path. G4's real queue-crash result preserves
`INJECTION_UNCERTAIN` and refuses reinjection; it does not establish cold
resume, which is not claimed as an unconditional first-release gate. A5's
separate `QUEUE_ACCEPTED` / `CONSUMPTION_UNCONFIRMED` state remains attributed
to A5. The clean-328f aggregate remains **FAIL** and the product remains
**PARTIAL**.
