# Clean 144e079 artifact and bounded native validation

Recorded 2026-10-02. The clean product checkpoint is
`144e079ddf62a4e08f1d1cf9476ab41d25d28f5c`; standard source fingerprint
`e64f244961d56265933dd75feec19d2b74fa934533abf9b750c061f09094a902`.
The standard producer captures 806 exact build inputs, including raw modes.
Catalog remains `client-hub-v1.6.1`, wire 1, 55 operations,
SHA `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b`.
Software version, source revision, inventory, image ID and binary hash are
separate identifiers. Native drivers are reviewed isolated overlays, not clean
product source; the exact producer/complete inputs and artifact remain pinned.

| Actual bounded gate | Result and exact attribution |
|---|---|
| STD immutable Hub/interop | Hub `sha256:04e8bcb4e22f4a00100b30a57d8cd5b3c65d5d4abe3d09844f5c121c26beb1bb`; interop `sha256:4ddf7bdc25c7da2fd59024a1a85006f7370e40e14f9546d65fcbea9f2ac957d3`. Producer receipt `ab09f15f31ecead8871a3cb6cefbe093df3a3c41d75b0e0ba98f3a93e65b6f06`. Exact delivered pair Go protocol clients passed 2 top/3 sub, terminal 0; required selectors were `TestClientDockerHubSmoke` and `TestClientDockerHubRecoveryFixture`. Receipt `5ceae9cccb2ce55ee0a106f1ade65aeaf4df1ef78879dcc94e889c5302f4ef44`. This gate was not Android/native/PQ/public HTTPS. |
| Clean PQ distribution | `PASS_BOUNDED_FINAL_CLEAN_PQ_DISTRIBUTION`, distinct PQ input closure `bb9bc8a63d380e1c8902c56c8fb502859c2efe75e0dd49f196effa93d4bd765a`; image `sha256:ad3899fe7ea280aa974ac1c586e688fea950cabca1e89d871c6be2bd42694f48`. Image producer `7d37f67ad161319ad695a681edced96a9ff58601018a2e475218bde2c7a4b37e`, package producer `2e002466663da9183aceb2e1bd51451c9f93dec801fe9515ecfd1fe58ebd6d5b`. Actual image gate 1 top/3 sub and relocated package CLI gate 1 top/3 sub, both terminal 0, zero skips, no provider/model/native calls. One Hub and two independent Agent processes shared one isolated driver network namespace in the image gate; the relocated package gate ran separately. This is process/driver isolation, not two isolated Node containers or physical Nodes. Status receipt `3d408d4a7dc6872a0e72002df34627ae31ba4d64ef6473ea139af7181aab5634`; distribution report hash `61325a2c7912479d03463a513dafee020bf1eaee2048484595fa4aaf86d551a3`. Not independent physical/PQ Hubs or native/public proof. |
| Exact STD Monitor nonpaid preflight | `PREFLIGHT_PASS_NATIVE_NOT_RUN`, 73 commands all terminal 0, models/credential mounts 0, complete input/source unchanged and cleanup true. Actual delivered Hub without rebuild/overlay; extracted Node binary `8a983dc9da33000021b5c79fac36661abfafdb180f8d08699ebec3fb3261c7e3`. Receipt `31b5f0916ca5d2e5ff8a9b7bcf9b06a6a3a374bcbac38d9174d0850d928be174`. Self key 200, peer key/Directory/traffic denied, no `directory.read` or Owner key grants; Monitor keeps its four explicit role grants. Synthetic native record only. |
| Exact STD paid Monitor | `NATIVE_NETWORK_MONITOR_PROPOSAL_PASS`, terminal 0, three actual CLI turn records, same original Thread/context witnesses, complete source unchanged and cleanup true. Receipt `0ef56fa9cbfb102bf2c3c2785d1e48d8e109e34c7f0227e114c63eb4a2dbb9fd`; tested Monitor driver `91debc3867d73b19288690008d6d370ca80d35a77d9748637adeee0485a668bb`, shared two-node driver `2979b54616ebd1aa9533a01b3b1629e3db73261a815b71b5117db4eb81896f86`. Native CLI 0.159.3 / `gpt-5.6-luna`, runtime `sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57`. Original Thread `01a0fa4a-b44c-7e10-a099-bf200869fab5`, Endpoint `ep_da77417c7c23877f`, Network binding `native_d8bed58ce857b241`, Group binding `bind_bf691d14a461eb8f`, epoch 1. |
| Exact STD two-node preparation | `PREPARATION_PASS_NATIVE_NOT_RUN`, terminal 0, 17 commands all exit 0, no model/credential mount; both Codex 0.159.3 and actual interop Go 1.27.1 checked. Same delivered pair/Node binary; synthetic V68 fixture `93fb91d41b115d020347d5e09d0be4d43cd642a66643c1e2398e30547f1604be` compiled inside actual interop source snapshot. Complete 806 inputs/source and six owned file hashes/modes stable; cleanup true and independent owned container/network lists empty. Receipt `7c0dbb2dda57601fd20740bae469436b54a294676a2277ccd55c2167f79c4c7a`. Preparation only: no full protocol/MCP/Control/native traffic proof. |
| Exact STD paid two-node | Actual `PASS`, terminal 0, 77 command steps all exit 0, exactly seven native CLI turns/attempts, no automatic retry; Codex 0.159.3 / `gpt-5.6-luna`. Same delivered STD pair/Node binary and synthetic fixture as preparation. Receipt `bbf5bd38d34179be4a847709103bf94c02617f9f892a9fb1e229799e597680b2`; tested two-node driver `843173cffeeed2f511a01c2795ca7a9beb210ffc25bd631ac297d077f0240ba1`, shared image helper `ba6050f9988cbc35c1cacb0d8b8e77d9a6c16594a9aa6c64687fc8d109377ff9`. Bindings before/after equal, original-context witnesses true, complete source unchanged and cleanup verified. Bounded G1 original-context sealed Ask/Reply PASS; durable consumption remains unconfirmed. |
| Client delivery on clean 144 | Clean Client `2ce183373429dddcb21259b54b3b261ae010bd55`, receipt `/gpu1-share/data/cicada-client/client-final-144e079-20261002/provenance/client-delivery.redacted.json` SHA `9069d2c4fa2dbd279fd1eca35eccc4b7bd0b8a9102651d6a724ca7ca4c60384f`; 40-evidence manifest SHA `5b0830b4130a9fde09873c8e6b7393d3f52aa868a67d416fa7ca6e06c8dd5b5d`. Targets source `e64f2449…`, STD image `04e8bcb4…`, v1.6.1 / wire 1 / 55 operations. Receipt records 81 Kotlin tests, 15 selectors, five UI smoke checks, app/test builds and bounded recovery checks. Actual two-Owner Link status and configured-policy/foreign-Owner checks are BLOCKED because no supported native Endpoint/Link producer is available. Android Node/Worker native, physical-device, public HTTPS and v1.6.2 repin remain unaccepted. |


## Post-144 Main candidate — integrated focused QA passed; clean release pending

Main integrates the Directory/native/relay/ML-DSA work, the final Monitor/ACK correction and the 14-file Link-proof patch. Its dirty source-input fingerprint is `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` on Git HEAD `144e079`; candidate contract `client-hub-v1.6.3`, catalog SHA `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`, wire 1, 55 operations and Hub schema v55. Integrated focused normal QA passed 49 top + 128 subtests across six packages, zero skips/failures and six binaries. Affected vet/build and contract check/export/verify passed; Python 15 tests + 17 subtests passed. Source/STD input metadata stayed stable at 835/829. The [receipt](../.cicada-data/combined-link-proof-20261002/receipt.json) SHA is `6416728daca6fdf4e95f0b0fc60f06ad6dd4ca77ed910ab7c1f2ba90fe8c12e7`. Full default/tagged/race was not rerun on this source. The dirty local bundle `8b22ceb…` is integrity-only; clean checkpoint and exact v1.6.3 standard/PQ artifacts and image gates are pending. Overall v0.1 remains PARTIAL.

The prior `cb4d122945be92d625dfab4349280279b77886f0b992b9b50b4118962c0ad660` snapshot retains its exact 831-input inventory, full Go 1,181 top + 754 subtests, 13 explicit skips and 30 binaries; focused normal 104 + 149; tagged CSR normal/race 9 + 32 and certificate normal/race 9 + 40; and standard/tagged vet/build exit 0. Its separate focused-race attempt remains **FAIL** on the 20-minute Store timeout (93 top + 134 subtests, zero skips, five packages passed, six binaries retained); final stack was `SameNodeRelayEvidence/missing_payload`. The [race result](../.cicada-data/combined-directory-relay-csr-20261002/focused-race-final/result.json) SHA is `304a3247e9c84551f09a24679b896feed78f9a5b67e291497e480292bee0926c`. These results remain attributed to `cb4d`; the earlier `19eedc…` failure/retry also remains historical.

The final seven-path Monitor/ACK component source `31e36040363e100547303becc5267f7377af4d7dcdf897b7333a6d81885be495` passed normal and race at 19 top + 38 subtests each, zero skips/failures; affected vet/build exited 0. Its [receipt](../.cicada-data/combined-directory-relay-csr-20261002/monitor-repair/final/receipt.json) SHA is `40b21ebb5631cf7d60898e612b2cad00b8325c333d420b5a9d1bd73aacc4f304`. This is component evidence and does not replace the `cb4d` broad race failure or prove integrated broad race.

The 14-file Link-proof patch passed its separate focused normal/race, encrypted loopback TCP, contract/export/verify, vector and Python gates on `144e079 + Directory15`; exact patch SHA `432c90917fe1b29a2271a65ad42256d98c47eb74e51fcca98acb180ab2ed6f11`, manifest SHA `dbb13004c412e366c03988ff93db2a0c3d9490e5ba0586f4cd577a499879a66e`, [results](/tmp/cicada-link-client-proof-20261002/results.json) SHA `51b441940f1b657fae633ff248d1d6c8221dd7fa7c36cb2212c6f663187e7bb0`. Root verified the exact bytes/raw modes in Main. These component results are separate from the integrated gate.

The fifth native zero-model fixture is `READY_HELD_LIVE_FOR_CLIENT` on immutable clean 144/v1.6.1, not on the v1.6.3 candidate. Two endpoints joined; a synthetic Owner device RPC created a `PROPOSED` Link with `NONE` review policies and no accepted sides. Its receipt records 97/97 commands exit 0, four native app-server starts and zero model/provider/turn/inject calls. The [execution receipt](/tmp/cicada-client-link-native-fixture-20261002/private-hop-freeze/approved-execution/result.json) SHA is `85ac6f8ff5f01dfac780cc9a4b53209fc9be679026cec1d9b8e0f890c697d4b1`; the three-container/three-bridge [public topology](/tmp/cicada-client-link-native-fixture-20261002/private-hop-freeze/approved-execution/new-public-topology/public-topology.json) SHA is `db4a30d22d487bc008ab9af87e518bf58a2cbfb8aabc143e3ed29fc284072dda`. It remains held for Client follow-up; cleanup has not run. Four prior fixture failures remain retained. This is not Android approval, Link activation, native Ask/Reply or message-consumption evidence.

Client carrier preflight fails because its old exact-one-Hub guard rejects the valid two-Node/three-bridge topology. A dedicated Client correction uses the exact public inventory; selectors and native runtime are **NOT_RUN**, and no v1.6.3 repin is claimed. PQ authority D1, Task handoff and restore validation in `/home/zyf/CICADA_pqtls_authority`, `/home/zyf/CICADA_task_handoff` and `/home/zyf/CICADA_restore_validation` are separate and not accepted in Main. Same-Node default Hub Relay has bounded component proof; `nativeDirect` remains unsupported. Task peer list/get/claim/renew/accept return objective or acceptance prose, while `task_submit` summary lacks explicit Manager recipient/purpose. This is a v0.1 security release gap; the next slice needs trusted purpose classification, existing sealed-object transport with small metadata DTOs, Task/ArtifactACL and current binding/ownerEpoch checks, and rejection of legacy plaintext routes. Legitimate Control-management plaintext remains. PQ authority D1 startup/reload/current-authority-floor/renewal also remains PARTIAL outside Main. The current overall status remains PARTIAL.

The Monitor's original witness appeared in the seed and final resumed turn.
Network Join and Group Join/proposal used that same original Thread and exact
current Node/Endpoint bindings. Three explicit encrypted Owner management phases
alternated with three fabric-only business phases, retaining fixture identity and
database; authenticated management probe returned HTTP 503 during business.
Proposal `rgrp_491d5e4725f53b87` remained `PROPOSED`; fake-delegation apply was
denied. The Owner is a visibly synthetic fixture, not a real user's approval.
No Group messages were sent: `CONSUMPTION_UNCONFIRMED` remains appropriate and
this is not G1 ASK/REPLY consumption or delegated execution acceptance.

The later six-file exact-pair driver/helper refactor has its own 48 deterministic
unit tests and 81 subtests, zero failures/errors/skips, and matching zero-model
preparation. It does not inherit the earlier Monitor execution by relabeling its
changed driver hashes. Its separate Supervisor-run seven-turn result records original bindings, sealed
ASK/REPLY oracle, controlled receipt/context, Control isolation, source stability
and verified cleanup. CLI attempts are not
provider HTTP request/token/billing counts. Driver failure/timeout is terminal;
there is no automatic model retry.


The actual pair retained A Thread `01a0fa5e-2775-7d40-9c55-2c7debbdf152` /
Endpoint `ep_db76392563ec7ba1` and B Thread
`01a0fa5e-5877-7573-8e9d-3bb625c17df3` / Endpoint `ep_751b990b37879dc7`,
with both exact leases/binding epochs 1 unchanged. Seven native turns covered
seed A/B, explicit original-thread Join A/B, A Find/offline sealed Ask, B
Reply with its original witness, then B Receive and A Receive with both context
witnesses. Request `rq_e63eb09bd1127428546c961c7bb9b4be` passed the sealed
Ask/Reply oracle; Hub database/WAL/log lacked private markers, and no Node keys
or provider credentials were mounted to Hub. Both outbound SSE streams were
ready HTTP 200, cross-Node and Hub-to-Node ingress was denied, and neither Node
published ports. The fabric-only Hub excluded the Control business-service
constructor, and its authenticated management probe returned 503; this is
dependency/route evidence, not an instrumented peer-business call counter. The
two durable message records remain `CONSUMPTION_UNCONFIRMED`: controlled tool
output/context is bounded G1 Ask/Reply proof, not durable ledger consumption
or unattended busy-wake proof.
The fixture's Owner/key approvals are visibly synthetic, not real user approval.
Independent review matched all six frozen file hashes/raw modes and all 77 exits;
read-only Docker filters found no remaining resources owned by the run.

Historic full Go 1155/799-input proof belongs to its pre-fix source, while the
review-policy handler/Store fix has its own b16 package/Store/race checks and e64
test-only follow-up. Those histories stay attributed to their actual inputs;
none is relabeled a new full-suite run. Historical paid Monitor directory-read
workaround and fe565/fb8 nonpaid proof also remain separate from these 144 images.
General foreground/uncertain consumption, busy wake, physical dual Nodes,
Android, automatic certificate lifecycle, full restore reconciliation and public
HTTPS remain outside the accepted bounded evidence here. A skip is not a pass.
