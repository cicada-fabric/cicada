# Cicada development environment

## Current development entry

Use `dev` for active development; `main` is currently a public placeholder and
is not a synchronized or accepted product snapshot. Read [AGENTS.md](AGENTS.md),
[current task guidance](CICADA_PROMPT.md) and [technical documentation](docs/README.md).
The current development source is **0.0.5**, with additive Hub schema **61**
for Owner account claim/login and encrypted session state. Frozen Client
contract **client-hub-v1.6.5**, encrypted wire **1**, and catalog **55** remain
unchanged. Architecture v2.3 is
the adopted specification, independent of these versions. Confirm actual
source/dirty state and build provenance before attributing a test or artifact.

The standalone Windows-first native App is at **N1 PARTIAL**. The source has a
Gio UI, Hub identity verification, account claim/login/inspect/logout, a
scope-pinned encrypted local vault and separate Owner/App-device identity
records. Native Windows execution, DPAPI/ACL acceptance, encrypted existing
PKCS#8 input, the one-code Root activation, restart without repeating installer
authority, and native App integration for authorized live canvas and Node
actions remain incomplete or NOT_RUN. Supported unencrypted existing Owner
identities can be imported into the encrypted vault; using one to prove Root
remains incomplete. Existing Hub/Node status, preview/confirm and Guard APIs
remain the authority for App integration. The App is not a released installer,
and the target Hub public-root
404 is not yet validated. The current browser account surface is legacy
implementation/compatibility, not the native App workflow. See
[native App architecture](docs/native-app-architecture.md) and
[stage plan](docs/native-app-plan.md). Earlier Windows cross-build evidence is
captured at its exact dirty source in
`.cicada-data/native-app-foundation/run-20261015T055201Z-yurHdO/validation.json`;
it does not establish native Windows acceptance. Focused `appvault` and
`appkeys` tests, race, vet and Windows package cross-compilation have also
passed on the current dirty 0.0.5 tree; do not attribute them solely to HEAD.

The current [IP/ARM64 deployment checkpoint](docs/docker-ip-arm64-validation.md)
has [manual independent-Owner server steps](docs/node-tls-first-install-cli.md).
They are a current operator procedure, not the target App onboarding. Clean
amd64/ARM64 package first installation passed its scoped Docker gate; standard
HTTPS bootstrap and enrolled strict PQ TLS are separate stages.

Start with [distribution](docs/distribution.md) for current local Hub/optional
Node commands and [test automation](docs/test-automation.md) for relevant checks.
The clean-328f default aggregate remains FAIL; later scoped results retain their
own tested-source attribution and do not change that result. C14 subsequently
passed a bounded six-turn default-daemon G2/G3 run on the original A/B contexts,
with independent exact-owned cleanup. C12 remains an earlier paid FAIL: B's
second POST returned HTTP 500, its cause was not retained, and later work was
NOT_REACHED; C14 does not rewrite it. A5 remains a separate loaded-queue result
with Node inbox consumption `CONSUMPTION_UNCONFIRMED`. Shipping `a4` ordinary
Worker and Joint11's eight Android recovery cases passed their stated scopes.
Android encrypted status-read/restart and GroupOwnerProof, physical-device and
public HTTPS acceptance remain NOT_RUN; full first-release acceptance remains
PARTIAL. See the [current evidence](docs/v01-current-closeout-20261009-validation.md#current-20261010).
Continue 0.0.x development until the user's actual acceptance; main/0.1.0
publication needs separate authorization. Documentation publication is not a release.

The dated checkpoints below preserve their original evidence. Their old schema,
Runtime images, provider/model choices and local “Main” integration labels are
historical, not current deployment pins or the public Git branch `main`.

## Historical 2026-10-02 checkpoint — scoped evidence; product acceptance remains PARTIAL

This checkpoint's baseline is `52cc2f6e0f97829332be372cb302cdb9f0ab0558`; source domains are listed separately; current `dev` is determined by `git rev-parse HEAD`. Product/version identities remain separate: `0.1.0-dev`, Architecture v2.3, Hub schema 57, Client `client-hub-v1.6.4`, encrypted wire 1, catalog 55 (`953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`). The finite 17-path QA receipt is for a frozen candidate delta over that baseline; it is not a clean whole-repository test result.

Current bounded evidence includes the 17-path focused run, M5 run-04 nonempty two-Hub/two-Node fixture, shipped clean52 PQ artifact fixture and the separate SSE matrix. The combined 17-path result has four actual skips: `TestHubBoundedCapacityDocker`, `TestClientDockerHubSmoke`, `TestGroupSpacesM2DockerHub`, and `TestNetworkM1DockerHub`; each required its own isolated disposable Hub fixture. Do not report those as passes. A derived 19-path source candidate adds public payload-profile tests, but its combined Go gate has not run and it does not inherit the 17-path receipt. SSE has 19 top/33 sub across eight successful test executions (not eight unique packages) and retains two real harness failures; its deadline/revocation cases are represented by that finite matrix. See [the current checkpoint record](docs/v01-clean52-current-checkpoint-validation.md) for exact paths, SHA-256 values and source boundaries.

Native05 did not complete A's fifth automatic turn. Native06 preserves the original fixture-sentinel FAIL separately from scoped 5/5 AskReply continuity. The older 3/17 focused tests were isolated/fixture-private rather than ordinary repository CI; a corrected single-copy helper passed, and separate public negative tests passed 3 top/17 negative cases. The original fullHubBlind helpercheck exited 1 and Hub logs were not retained, so fullHubBlind remains NOT_CONFIRMED. F4 stopped at a real UI viewport failure before any Target write/Alert, and its Source proof expired. F5 failed at Source KEY review step 11: the signer rejected a UTC RFC3339Nano timestamp with trailing fractional zeroes; the first ten Source review steps passed, but no Source signature/Grant or Target operation followed. Client commit `508ca333` completed the offline correction (40 pure Kotlin tests across five classes, 0 fail/skip; Native/Android-test compilation and both debug APK builds exited 0); the new APK pair has all runtime validation **NOT_RUN**; the F5 five-operation chain, Alert and bilateral result are not complete. Production recovery/deployment, physical dual-device and public HTTPS evidence remain separate. Overall v0.1 is **PARTIAL**; the approximate 85% project estimate is not a test or acceptance fraction. This docs-only candidate does not update product code, rerun tests, build images, start services, or change deployments.

## Historical development checkpoints and environment notes

以下正文保留旧环境、命令和测试来源。其“current”、image待验与旧catalog/schema指向当时；
通用开发步骤不构成启动本轮QA或修改部署的授权。

## Historical prior checkpoint — 2026-10-02 current checkpoint — source QA passed; image gate pending

Main integrates retained-certificate lifetime checks and the recovery metadata
query over `06d0a58` (runtime source `648162e…`). Focused receipts retain their
tested sources; the query keeps quarantine held and never re-executes work.
Current integrated Main source is `e64f2449…`. Full Go QA passed on the
pre-policy-fix source `97a008…`, with explicit skips retained; its separate
799-input proof connects only `97a008…` to the pre-policy-fix shipping baseline
`bab6569…`, and does not cover the later policy fix. Focused shipping script
checks retain their `bab6569…` attribution, with artifact skips retained. Clean package/image and
exact-image acceptance are NOT_RUN. Its real Agent observation covers startup/poll/RSS only;
ASK/heartbeat/revoke ran in the driver context. Historical `fec658…` is retained.

Client contract `client-hub-v1.6.1`, wire 1, 55 operations and Hub schema v55
are unchanged; Architecture v2.3/v0.1 remain PARTIAL. The [status table](docs/architecture-v2-status.md)
owns source inventories, focused receipts and independent device-layer limits.

The existing encrypted `topology.apply` action `membership.set_directory_permission` independently controls the current `directory.read` grant for an exact same-Owner Group Membership, with Owner-scoped snapshot review, current-request Guard, CAS and revocation. The full ordinary-user/admin permission system, delegation/governance UX and any additional `directory.read` proposal are deferred to v0.2; those additions are planning only. Group Endpoint key `manifest/grant/status`, Monitor role binding and exact regroup delegation already exist; Join does not grant a role, traffic or history permission.

### Historical 2026-10-01 framework checkpoint — bounded PASS

Final dirty bd79-based source `2858c57ec3bc33f5f4d03f4f8c75ec6c13f89fd128a3a8a493b7c7605af51e17` retains production code from 54f with corrected private-socket test fixtures and two new public proof vectors. Contract was v1.6/wire 1/55 operations. Final full Go PASS: 27 packages, 1,092 top-level + 547 subtests, 12 top-level SKIP, 0 FAIL; vet EXIT 0; repaired fixture selector and race each passed 3 top-level + 3 subtests. Independent contract check/export/verify, Python26 and shell20 PASS. No skip is a pass. Earlier 54f Browser/three Docker suites and bounded native multi-Hub Join passed; 54f full Go recorded three fixture failures, retained separately. 432f native ASK/REPLY (282.74 s), 432f plus test-overlay broadcast (298.14 s, both original Threads consumed) and Worker approval (76.83 s) passed; joined V68 passed on 840a test-helper overlay with recording fake queue. These results keep their own source identities. Android v1.6, physical dual-Node and public HTTPS are NOT_RUN; pure PQ TLS is NOT_IMPLEMENTED at that checkpoint. Final clean commit/image/bundle are queried from `.cicada-data/v01-finish-20260930T145216Z/client-v1.6-clean-handoff/metadata.json`; this is not a push or release. [Evidence and retained failures](docs/v01-completion-checkpoint-validation.md).

The historical f55 v0.1.x candidate was source snapshot
`final-code-git-snapshot-20261001T102124Z`, fingerprint
`f55b5255628030857ac88bd7edbd6da7da1b63d543014c76111f9219f46ad255` (dirty
base `bd79ff93c90ecafc28a2471dd9523444903b39e6`) and Hub image
`sha256:da88805eaa1987a1c6e06448fc5cddf7d4ce368e8b5eeb3071a1406dad2cb977`.
Full Go, vet, v1.6/55-operation contract, 19 Python tests and the three
disposable Docker suites passed on f55. Prior 432f Go/race/Browser/M5 results do not
transfer to f55. On 432f, V68 and real Worker approval failed; the first
Node-Control HTTP driver failed but a later protocol-only overlay passed. Its
Client Docker suite failed on a stale pairing fixture, then the Client-only
repair passed on separate source/image `cf168…`; that does not turn the 432f
three-suite run into PASS. Android v1.6, native peer results specifically on f55, physical
dual Nodes and public HTTPS remain NOT_RUN. See the
[checkpoint report](docs/v01-completion-checkpoint-validation.md),
[architecture status](docs/architecture-v2-status.md) and
[V01–V88/G1–G5 ledger](docs/completion-ledger.md). The f55 source/image are frozen but remain a dirty development candidate; do
not treat the candidate contract as a Client handoff or release.

The current catalog is Client `client-hub-v1.6.1` with 55 operations. The
independent Android repository remains owned by `../CICADA_CLIENT`; this
repository does not edit it. Historical Android v1.5 results stay pinned to
their bd79 Hub/source/APK/package and do not validate the current candidate.

## Local Hub and optional Node — current entry points

The root `docker-compose.yml` is now a local development profile for one
loopback-only Hub built from `docker/Dockerfile.hub`. It has a persistent named
volume and contains no Codex CLI, provider key, or legacy management bearer.
On Linux with Docker Engine and Compose v2, start it explicitly from this
checkout:

```sh
scripts/install-cicada-server.sh
```

The default endpoint is `http://127.0.0.1:8788`. The installer builds the local
source, does not fetch an unpublished release, and refuses to reuse an existing
`cicada-v2-local` project unless `CICADA_DEPLOY_UPDATE=1` is set. Stop the Hub
without deleting its data with:

```sh
docker compose -p cicada-v2-local -f docker-compose.yml stop hub
```

For a Node, use a host with the installed Codex CLI's `codex queue` command and
run the real foreground agent as the local Codex user:

```sh
CICADA_CONTROL_URL=https://hub.example.org \
CICADA_MACHINE_ID=node-lab-a \
scripts/install-cicada-worker.sh
```

The Node keeps its credential and state locally, initiates outbound Hub
connections, and prints a short-lived device code. The owner must inspect the
exact pending Node in the authenticated Android Client and separately Preview
and Confirm it. A remote Node needs an operator-configured HTTPS endpoint. The
Hub does not host an approval page. The script does not install Codex, download
a CICADA binary, configure a service, or request provider credentials. Full
operator preconditions and data boundaries are in
[`docs/distribution.md`](docs/distribution.md).

## Development checks

The lightweight Hub does not need a Codex installation or model credentials.
Run the contract checks and disposable Client/Hub interop gate from a source
checkout:

```sh
python3 scripts/client-contract.py check
python3 -m unittest discover -s scripts -p test_client_contract.py
scripts/test-client-hub-interop.sh
```

Use `scripts/run-client-hub-dev.sh` only for its separate loopback Client
development fixture on port 8787. It is not the root Compose deployment and
must not replace a resident Hub. Follow the [joint Client/Hub workflow](docs/client-hub-development.md)
for Android contract ownership and evidence attribution. Android, disposable
Docker, real native Runtime, physical-device, and public HTTPS checks are
separate result layers; a skipped test is not a pass.

The source `docker/Dockerfile` currently sets `CODEX_RELEASE=0.162.1` as its
build argument default; this is not an installed Runtime acceptance result.
The following 2026-09-30 Runtime preparation evidence is historical: from old image
`cicada-codex:monitor-native-0.157.1`
(`sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`),
a disposable no-credential/no-host-mount `codex update` exited 1; the official
installer fallback exited 0 and produced local CLI 0.159.2 image
`cicada-codex:monitor-native-update-20260930`
(`sha256:97cd6f07551fb4f794fca95d7b97e5e3e85131b3d7cdb682a43b47a904b2d5d6`).
A later disposable no-credential container ran `CODEX_NON_INTERACTIVE=1 codex
update` successfully from 0.159.2 to 0.159.3. Its local image is
`cicada-codex:native-current-20260930`,
`sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57`; the
queue help check found `--thread` and `--message`. These are local runtime
preparation results, not a CICADA release or proof that a model/native gate
passed. Keep the Dockerfile build default, prepared runtime image/version, and
CICADA source/image identities distinct.

Historical product and runtime acceptance remains linked from the
[`architecture status`](docs/architecture-v2-status.md),
[`native validation`](docs/architecture-v2-native-validation.md), and
[`migration boundaries`](docs/architecture-v2-migration.md). Do not use a
resident Hub, production key, or paid model run as a disposable test fixture.
