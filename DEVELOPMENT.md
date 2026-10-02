# Cicada development environment

## 2026-10-02 current checkpoint — source QA passed; image gate pending

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

The next proposed permission slice is an explicit Owner-controlled `directory.read` action for a same-Owner Group Membership, with preview, CAS and revocation. It is planning only. Group Endpoint key `manifest/grant/status`, Monitor role binding and exact regroup delegation already exist; Join does not grant a role, traffic or history permission.

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

## Local Hub and optional Node

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

`docker/Dockerfile` currently sets `CODEX_RELEASE=0.159.2` as its build
argument default. Runtime preparation evidence is separate: from old image
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
