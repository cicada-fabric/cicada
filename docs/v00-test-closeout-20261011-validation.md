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

## Current Group-key fixture bootstrap — scoped preparation

The fixture now accepts canonical v1.3+ patch revisions, including v1.6.5,
and confirms exact stopped-container absence before deleting mounted state.
The [Root unit result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-fixture-metadata-a1/ROOT-INDEPENDENT-UNIT.NONAUTH.json)
(SHA-256 `25a107eb7a26f6a8e4cd6020ed5be2dd670c097de75ac736fab278da329ba9d6`)
passed 45/45 tests (15 fixture + 30 runner) in 12.885s, exit 0/EOF. These are
hermetic fake-Docker tests; the new module is registered in the existing
one-click Python test list.

The separate [A2 Docker result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-current-bootstrap-a2/run-20261011-a2/RESULT.NONAUTH.json)
(SHA-256 `86e0771fb692e6c5fe93697cdae6f42db5f01e72c51af1424f21b05f3efcc408`)
passed scoped bootstrap: start/stop exit 0/EOF, Hub provenance, synthetic
Owner-key isolation and Node pending confirmation, with confirmed cleanup,
source and six-resident equality. The clean c6887 Hub image producer and
dirty-five-file host 150657 fixture source remain separate; exact pins and
commands are in the [fixture record](client-group-key-disposable-fixture.md#current-v165-bootstrap--2026-10-11).
The [independent A2 closeout](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-current-bootstrap-a2/INDEPENDENT-CLOSEOUT-A2.NONAUTH.json)
(SHA-256 `ab6bb303d34256d167df1e72620ce0302f34ef5ed83183742eb9a189d1d34039`)
confirmed the exact hashes, source, residents and resource absence.

The earlier [A1 result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-current-bootstrap-a1/run-20261011-a1/RESULT.NONAUTH.json)
(SHA-256 `8efdea6c7c6b0c006d0186ec2a83842326ff04fb798b6c20c06f6517572c5d5a`)
remains **FAIL_OR_UNKNOWN**: bootstrap succeeded, but the Hub was not yet
absent immediately after stop. A later [independent closeout](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-current-bootstrap-a1/INDEPENDENT-CLOSEOUT-A1.NONAUTH.json)
(SHA-256 `fb54e32f36cac2d8d3e03a59a8c0e660579d0d0c79130cdeec533711d053c3cf`)
confirmed eventual absence without rewriting that failure. A pre-start
self-pin refusal was separate from Hub execution. Model calls were zero;
that bootstrap did not test native Join or Android Group grant/status. The
separate Android/Native operator attempts below reached further scoped stages.
The independent eight-case v1.6.5 Link-policy encrypted status/restart cases,
physical Android and public HTTPS remain **NOT_RUN**. The A3 below is a
different synthetic OwnerProof selector.

<a id="group-key-android-native-a1-a5"></a>

## Group-key Android/Native operator A1–A11 — scoped evidence and retained failures

These one-shot operator attempts are distinct from the fixture bootstrap A1/A2
above and the synthetic OwnerProof vector below. A1–A10 retain their individual
failures; A11 is a separate zero-provider protocol and Android grant/status
pass, not a fresh CLI Runtime run.

| Attempt | Result and boundary |
| --- | --- |
| A1 | **FAIL_OR_UNKNOWN**, 66.679s, `ANDROID_PROCESS_CENSUS_EXIT`; headerless `docker top` output failed the process-census check. No provider POST or Native business turn occurred. Cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T210023Z-523c7993/RESULT.NONAUTH.json), SHA-256 `7fa9984740d9f93543c4a0b4aa2502e3aa152fbc78c03b500c7a0fd8f6b205f4`. |
| A2 | **FAIL_OR_UNKNOWN**, 85.343s, `DEVICE_PUBLIC_JSON`; Android readiness and owned listener checks passed, then the device-identity read failed. The `exec-out shell` invocation was a command-construction error. No provider POST or Native business turn occurred; cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T210440Z-c4f32c8a/RESULT.NONAUTH.json), SHA-256 `343ecd96dff9870cd783ca67c1b1674d5b72f4da1acd62ddbba044b81efd7bd8`. |
| A3 | **FAIL_OR_UNKNOWN**, 121.814s, `ANDROID_DIALOG_BUTTON`; device enrollment and fresh Group bootstrap passed, but the first Node confirmation button was not selected. No provider POST or Native business turn occurred; cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T210956Z-0c31c8a7/RESULT.NONAUTH.json), SHA-256 `d23d790e63ec1ff5dafa8f41d27698931934c61238c1a2eb4e8b37d071a5708a`. |
| A4 | **FAIL_OR_UNKNOWN**, 305.146s, `ANDROID_DIALOG_BUTTON_TIMEOUT`; the first Node confirmation was observed and tapped, but the later dialog/result was not retained. The pinned APK's older instrumentation selector sends only `user_code`, while the current Hub contract requires `candidate_digest` and positive `candidate_version`; this is a source-proven fixture mismatch, not proof of the discarded JUnit failure cause. No provider POST occurred; cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T212000Z-71ac26ea/RESULT.NONAUTH.json), SHA-256 `61c4d515b6b5aad283327e4a32cfe6cad1a7e9e70d75ac9c739967bb3afc5197`. |
| A5 | **FAIL_OR_UNKNOWN**, 282.617s, `NATIVE_EXEC_NONZERO`; the first real TLS POST returned HTTP 403 before any Native business turn. The request model was not instrumented. Bounded inspection observed HTTP 403 and an HTML-document marker; the exported error-string SHA is recorded below. Its exact cause is UNKNOWN, with no provider/quota attribution. Cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T220540Z-e517fa16/RESULT.NONAUTH.json), SHA-256 `b4c3b8d5654e6d9dd3740f15ed1a4ee2bf31e9ccf2740f74f33239fa4f8fc15c`. |
| A6 | **FAIL_OR_UNKNOWN**, terminal exit 1/EOF after 352.727s, `NATIVE_EXEC_NONZERO`; Android enrollment, production-UI Node pairing and fresh Group creation passed. The first Native CLI execution completed a turn on SID `01a12d19-e74c-7001-9aa2-ab034c8d0ba6` and yielded a fresh READY/session-metadata witness; the second CLI invocation exited 1. A code-mode call to `tools.cicada_join` returned `NOT_A_FUNCTION`, with no Join/candidate receipt. Three outbound POSTs returned HTTP 200, 200 and 500, each for the instrumented `gpt-5.6-luna` request model. The final upstream `internal_server_error`/HTTP 500 remains unexplained; no causal link to the code-mode error or quota attribution is established. Cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T222905Z-ca4b9b73/RESULT.NONAUTH.json), SHA-256 `b871f5df5ac670c1b033cf024533c34466215099aa1fe6c9b5f0ada11dad20db`. |
| A7 | **FAIL_OR_UNKNOWN**, terminal exit 1/EOF after 334.216s, `NATIVE_MCP_NOT_COMPLETED`. Two CLI executions/turns completed and five POSTs returned HTTP 200 (three `gpt-5.6-luna`, two `codex-auto-review`). The Join attempt was `HUB_COMMITTED_LOCAL_SCOPE_BLOCKED`: its scope check saw an empty Hub ID because the fixture agent environment omitted `CICADA_HUB_ID`, returning `SCOPE_CHECK_UNAVAILABLE` before registry lookup. The observed SID was `01a12d2f-181e-7530-ab93-9518679731d5`, Endpoint `ep_1a0225c0ae2152a9`, binding `bind_caaf64512930d909`, epoch 1. `whoami` errored and publish was not reached; no Join/candidate receipt or Group grant was established. Cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T225234Z-92b07140/RESULT.NONAUTH.json), SHA-256 `48248de9a67a5fa5aee0640b46fa9729f2ad380bd84e0f75169362a446219569`. |
| A8 | **FAIL_OR_UNKNOWN**, terminal exit 1/EOF after 289.388s, `NATIVE_EXEC_NONZERO`. The first fresh CLI invocation exited 1 with no completed-exec receipt; one `gpt-5.6-luna` POST returned HTTP 500 / `BODY_EOF` before resume or Join, and no MCP call occurred. This operator revision included `CICADA_HUB_ID`, but this run did not reach Join and cannot validate the Hub identity correction in a Native run. The upstream cause is UNKNOWN. Cleanup was confirmed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261011T230943Z-e766d841/RESULT.NONAUTH.json), SHA-256 `6f020b217d86a3ae868664d017a25a737d66c9cf42febb06c835c8f8ff686685`. |
| A9 | **FAIL_OR_UNKNOWN**, 479.449s, `ANDROID_POST_RESTART_STATUS`. Two Native business turns completed real `cicada_join`, `cicada_whoami` and candidate publish; the Join also exercised the approved single-Hub identity correction on its recorded Node artifact. Android Owner enrollment, Group grant and initial encrypted status `CURRENT` passed. The post-restart field guard remained UNKNOWN, so the overall attempt failed. Six provider POSTs returned HTTP 200; no quota cause is inferred. Cleanup/source/resident checks passed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261012T000017Z-80b3d06a/RESULT.NONAUTH.json), SHA-256 `34465f881765731628b399666fe8e7fea07bf4580e470117b4313707f6af237a`. |
| A10 | **FAIL_OR_UNKNOWN**, 323.829s, `NATIVE_EXEC_NONZERO`. The fresh CLI call completed and recorded a session; exact resume returned HTTP 500 before MCP. There were two actual `gpt-5.6-luna` POSTs (HTTP 200, then 500); the result's `native_business_turns: 0` is not a zero-model count. No Join, Group grant or encrypted status was reached. The HTTP 500 cause is UNKNOWN; cleanup/source/resident checks passed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261012T002029Z-e8775ab9/RESULT.NONAUTH.json), SHA-256 `73e3134cbcbbb3dd2e0e530f2a33db926e44fffafbea577ee6280480982bb209`. |
| A11 | **PASS_GROUP_GRANT_AND_RESTARTED_STATUS_SCOPED**, 408.642s, terminal exit 0/EOF. The frozen operator used the previously recorded same-UID SID/context metadata for a protocol-only MCP process that completed `cicada_join`, `cicada_whoami` and `cicada_publish_endpoint_key_candidate`; Android completed the Owner Group grant and encrypted status reads returned `CURRENT` before and after an exact owned Hub restart with the same Hub identity, config and state mount. This was not a CLI/Runtime/provider execution or proof of AI autonomy, Native account authentication or context. Provider POSTs, Runtime, credential reader and CLI business execution were not created/run. Cleanup and source/resident checks passed. [Result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/run-20261012T004331Z-e7a6691b/RESULT.NONAUTH.json), SHA-256 `a97f3099b76b66969a78264be89786d85b0598b153b8a5ab067fcebc17df53af`. |

A9 and A10 used Core `0326b1c6e6f4105347c2f0c31a0a7c9394dcd924` and clean
Client `740882b86d798a3d514b24b2bc2fa2802718d79d`, with source fingerprints
`340d9a28e5acc57dad30014c536a9817aa1e2b6dc30daf89e207032ec8345355` and
`5922414dfdaab4563e83152b6f9b375ffc346460de6171de837c989942192d22`. A11 used
the same Core/Client source identities and clean status snapshots. The Hub was
the retained c688 image
`sha256:b7bc42678adf9ab44df2a3c51732b2956d668dd7745a93ec3c2a0387d3fc07c2`;
the APK pair (`e5707b6a…a3745` / `7638c1ed…5ca29`) belongs to immutable Client
producer `1151b06e04b172de9c7b5989ffec1318e58bf862`, not Client HEAD 740882.
For A11, Node used the A3 compile-check artifact from dirty Core producer
`ff3196bfb4bb21813a683e2b72835c72b714167a` (binary SHA-256
`e8bb14cc0cb2aa6f299355a52753c7735b53e31bac66c19cea2d3dc61cfbaf9e`); the
recorded post-commit mapping covers Go source plus `go.mod`/`go.sum` bytes and
modes, not every embedded build input and not a new Hub image. The A11 frozen
operator SHA-256 is
`8371379784e404f04ae881ebb9405eb0907135229ec34ec7afb067d82dde6162` and its
[freeze receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/A11-OFFLINE-FREEZE.NONAUTH.json)
SHA-256 is `04461b1ea73c7d0361e1332a7006bc49651f886534c2b0717db821b8b20b60da`.
It was invoked as `python3 -B operator-a11.py --execute` in an authorized
interactive terminal; the operator budget was 1,200 seconds. The A11 result
records the previously observed SID and same-UID local metadata, but an exact
pre-run file-stat equality was not recorded.

The A11 [independent review](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/ROOT-A11-INDEPENDENT-CHECK.A2.NONAUTH.json)
(SHA-256 `cdc32c9dde959bfe03c666401b64aa21f180443ba1820188f100e9cd17f74f1f`)
passed 31/31 scoped protocol/owned-resource checks. It verified current Core
and Client identities, six resident canonical digests and owned cleanup. The
earlier independent-review attempt (SHA-256
`c6ee62b05b1909300dfc0c510935b19391d031a2c357509086dd15c830223c17`) failed
its own `models == 0` predicate because the field is `NOT_INSTRUMENTED`; that
review failure is not an A11 product failure. The zero-provider boundary is
supported instead by the frozen no-Runtime/no-provider protocol path and the
actual zero POST/admission counts, completed MCP process receipt and zero CLI
business executions.

A11's scoped Android `group.key_manifest/grant/status` success does not close
the independent eight-case v1.6.5 encrypted
`session.capabilities`/`link.list`/`link.review_policy_status` suite or its
restart/uncertainty cases. It also does not establish a fresh CLI Runtime turn,
foreground autonomy, Native account authentication, V67, physical Android,
two physical Nodes or public HTTPS. The clean-328f aggregate remains **FAIL**;
overall first-release acceptance remains **PARTIAL**.

A5 used clean Core host HEAD `40c0c5afc376b3325b92772d6f6619ba93b5d8e3`
with source SHA-256 `c814a7138aefe0be009645c9834d3de7f4427bccf6b1477b1c11fd9589c612f8`,
the c688 Hub image `sha256:b7bc42678adf9ab44df2a3c51732b2956d668dd7745a93ec3c2a0387d3fc07c2`,
and immutable app/test APKs from producer `1151b06e04b172de9c7b5989ffec1318e58bf862`
(`e5707b6a5a91a45eca8285970e646408cf34d05cf246e1bcd4c9f1af9c4a3745` /
`7638c1ed4f3a3d6f549b78e64a1802612de59f4b6359bd9cc1795ce61065ca29`). Client
checkout `740882b86d798a3d514b24b2bc2fa2802718d79d` was not the APK producer.
The frozen A5 operator SHA-256 was
`9900eec44187ed587d032d21d086d645d01f48f472bf15984682412df80d2a7c`.
The actual production UI Node-pairing flow confirmed the candidate and its
success/list correlation; the raw `nodes.list` response was not captured. The
Node-side approved binding matched the candidate, while owner/device fields
were not present in that Node state. Android created fresh Group
`grp_97a40b2c38454923`; this does not prove Native Join, an Owner-signed
Group-key grant, or an encrypted Android status read. A5 records one actual
outbound POST/HTTP 403 and zero Native business turns; the model field was not
instrumented. Bounded inspection observed HTTP 403 and an HTML-document marker;
the exported error-string SHA is
`d5ef25596eb2a5d3b58555d02fe80e36168050ed72a24d4c6d27bef12941739f`; it does
not identify the upstream cause. The owned Codex rollout's bounded error string
is distinct from the sanitized proxy/driver receipt. The exact Hub, Android,
Runtime and Node-agent identities and fixture path were independently found
absent; current Core/Client source hashes and six resident canonical digests
matched the recorded before/after snapshots. A6 used Core HEAD
`40c0c5afc376b3325b92772d6f6619ba93b5d8e3` with five documentation files dirty
(Core source snapshot SHA-256
`3403f1c29b58dc8cf7d6ec1e829979b282df5ecab0b07f6718497d0e26c20359`), clean
Client HEAD `740882b86d798a3d514b24b2bc2fa2802718d79d`, the same c688 Hub image,
and the same immutable APK producer `1151b06e04b172de9c7b5989ffec1318e58bf862`.
Its operator SHA-256 was
`55ffe1fddb484863a25c5ece69c6f46cc945fc05bf8be0c3fd18e3cbff206c48` using
official CLI 0.162.1; shell-sandbox execution is `NOT_RUN`. The first CLI result
included a fresh READY/session-metadata witness for SID
`01a12d19-e74c-7001-9aa2-ab034c8d0ba6` and one completed turn; a code-mode call
to `tools.cicada_join` returned `NOT_A_FUNCTION`, so there is no Join/candidate
receipt. The final upstream `internal_server_error`/HTTP 500 remains unexplained;
no causal link to that tool result is established. The
top-level `native_business_turns: 0` records that
the helper's full result was not assigned after the second CLI failed, not that
no turn completed. A6 does not establish the required Native Join/publish proof,
Owner-signed Group-key grant, or Android encrypted status. Its cleanup check
reconfirmed the exact Hub, Android and Runtime container IDs/names, fixture
path, original Node-agent process incarnation and socket were absent; provider
handlers were closed. Core/Client snapshots and all six resident canonical
digests matched before/after. Android encrypted status, Native Group-key
grant/ASK/Reply, V67, physical-device and public-HTTPS scopes remain NOT_RUN or
not reached for this Group-key operator; C14's separate scoped ASK/Reply result
is unchanged.

A7/A8 used clean Core HEAD `ff3196bfb4bb21813a683e2b72835c72b714167a`, Core
source snapshot SHA-256 `2ae25b78bbbaab58096071e8c137e92542e16be4a3dcb513604089b4ac1be734`,
and clean Client HEAD `740882b86d798a3d514b24b2bc2fa2802718d79d`, source
snapshot SHA-256 `5922414dfdaab4563e83152b6f9b375ffc346460de6171de837c989942192d22`.
Both used the pinned c688 Hub image and immutable app/test APKs from producer
`1151b06e04b172de9c7b5989ffec1318e58bf862`; the Core checkout did not produce
those APKs. Operator hashes were A7 `3a538a211f166f6f69e35dd1e4c353faa3728af61af3d37ae2a223836bc85acf` and A8 `0bbfc5e5295fc470dc13660a53d581b8a1951270305a7d815400e18570988517`.
Independent postchecks confirmed exact owned-resource absence and unchanged
source/resident snapshots for both runs. A7/A8 remain their original Native
results; neither proves that the later Go correction below completes Native
Join.

<a id="single-hub-approved-identity-pin-go-validation-scope"></a>

## Single-Hub approved identity pin — Go validation scope

A three-file Go correction now pins a Hub ID from existing Owner-approved
Node-Control state when an Agent starts without an explicit single-Hub pin.
An atomic in-memory reference makes the approved ID visible to existing Agent
context copies; no new hot-path file I/O, dependency, schema, wire, contract or
software-version change was introduced. The focused tests exercise synthetic
UDS Join/approved-Hub-pin behavior and existing Hub context, registry, worker,
credential and revocation cases; they do not exercise a real Node wake or Native
Runtime Join.

The source was dirty at Core HEAD `ff3196bfb4bb21813a683e2b72835c72b714167a`,
with a 918-row source snapshot fingerprint
`55f5b96cb3a01041656024194a35dd34c08780ad88d17107d011f148f2bf8890`.
`machine_hub_context.go` SHA-256 was
`5919900e6557c8574091225e6ffd3300ab1547bd6f00c236b4de218ce8249e4f`,
`machine_agent.go` was
`7386a65a95295543d870ac192d665cb2ca719fc338762a3ce485b37f9984f393`, and
`machine_agent_hub_pin_test.go` was
`5b6d25ff81c6427ecd2f956fbeda10f053601ab76ebd9c7deb5fa60f6bcf2eb0`.
In the pinned Go 1.27.1 offline test container, focused normal and race runs
both passed 11 top-level and 9 subtests, with zero skips/failures. The complete
`go test ./cmd/cicada` run passed 422 top-level and 318 subtests, with 13
optional top-level skips and zero failures; `go vet ./cmd/cicada` and
`go build ./cmd/cicada` also passed. Total elapsed time was 304.433s; model
calls were zero. Source and resident snapshots were unchanged during the run,
and the owned test container was removed. The [A3 result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/shipping-agent-hub-pin-a3/RESULT.NONAUTH.json)
(SHA-256 `6c5df493e1beabe05d510ca5f601f20dfd2000d38d5200085a254a9085a611d4`),
[freeze](../.cicada-data/v01-next-gates-20261011/native-direct-audit/shipping-agent-hub-pin-a3/FINAL-FREEZE.NONAUTH.json)
(SHA-256 `1d72f9c96edee36a29a8f273bc15393358c3c11ff182b073f84202e10bf5ce67`),
and [independent check](../.cicada-data/v01-next-gates-20261011/native-direct-audit/shipping-agent-hub-pin-a3/ROOT-INDEPENDENT-CHECK.NONAUTH.json)
(SHA-256 `d8661106cbc8134203e508035607048a7c94689b0cdc07c754ee81f3a249de70`)
record the scope and cleanup. The independent current-contract check also
passed all 55 catalog operations for fingerprint
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.

Two earlier invocations were setup failures, not product-test failures: A1
could not read an entry in the shared Go build cache as UID 1000; A2 compiled
but could not execute the test binary because its temporary filesystem was
mounted `noexec`. Both ran zero tests and had confirmed cleanup and unchanged
source/resident snapshots. [A1 receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/shipping-agent-hub-pin-a1/RESULT.NONAUTH.json)
(SHA-256 `842e907eadd8751e8cbaef40f35a315ec71396dcecc8d695b4f3c05cc81ec67e`);
[A2 receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/shipping-agent-hub-pin-a2/RESULT.NONAUTH.json)
(SHA-256 `1abf57ed6df6276293ef7f43ac9f3224d671d4e87870d71dac1ede5d21b0f752`).

The compiled command artifact SHA-256
`e8bb14cc0cb2aa6f299355a52753c7735b53e31bac66c19cea2d3dc61cfbaf9e` is a
compile-check artifact only, not a release binary or Runtime deployment. This
Go test build is not a new Hub image and does not retroactively alter the c688
image or APK producer used by A7/A8. A7 and A8 remain their recorded Native
attempts; neither the Go regression suite nor the catalog check is an actual
Native wake/Join, Owner-signed Group grant, or Android encrypted status result.
The independent eight-case v1.6.5 Link-policy status/restart cases remain **NOT_RUN**.

A separate host-only provider diagnostic returned HTTP 200 for one
`gpt-5.6-luna` POST through the existing CONNECT-verified TLS route; it made no
Runtime call and retained no request payload. This is a separate diagnostic,
not evidence of A6's cause or a successful A6 turn. [Diagnostic result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/group-key-native-android-driver-a1/provider-access-diagnostic-run-a1/RESULT.NONAUTH.json), SHA-256 `6432d503216f9e5cb40e754ea8b7e063d8023a4214487cc7ec78e52c508529c4`.

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
exact cleanup. A11 separately passed an Android Owner Group grant and encrypted
Group-status read before/after an owned Hub restart through a same-UID MCP
protocol scope; it did not run a CLI Runtime/provider. The independent eight-
case v1.6.5 Link-policy encrypted status read across an exact owned Hub restart,
V67/account-bound submission, two physical Nodes and public HTTPS remain
unresolved or NOT_RUN. V67's account-bound Native submission API is
**UNSUPPORTED**, so it is not a source-only implementation task until a
supported API exists. Broader Native acceptance beyond C14's bounded
default-daemon scope remains unverified; C14 does not establish the separate
foreground model-consumption path. G4's real queue-crash result preserves
`INJECTION_UNCERTAIN` and refuses reinjection; it does not establish cold
resume, which is not claimed as an unconditional first-release gate. A5's
separate `QUEUE_ACCEPTED` / `CONSUMPTION_UNCONFIRMED` state remains attributed
to A5. The clean-328f aggregate remains **FAIL** and the product remains
**PARTIAL**.
