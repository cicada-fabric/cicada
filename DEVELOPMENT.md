# Cicada development environment

The current work starts from the historical M2 checkpoint at `dev` HEAD
`f30892fcd79a27bfe5604575deaecebe52c5ec50`. M2's frozen evidence remains
attributed to its recorded dirty source fingerprint in
[`docs/group-spaces-m2-validation.md`](docs/group-spaces-m2-validation.md).
The current worktree contains M3 cursor/unread, M4 delegated regrouping,
v40 dual-Owner new-record Group boards, v41 atomic nested Group creation,
and an editable Hub canvas. The newer M5 durable native-outcome path and the
combined schema-v41 source passed the bounded frozen
[c33f… gate](docs/v01-group-panel-checkpoint-validation.md): 1,336 Go PASS /
11 SKIP / 0 FAIL in 25 packages, vet, 36 focused race PASS, eight Python
PASS, three disposable Docker suites, Chrome 151 loopback Browser and
controlled real Codex CLI 0.159.2 same-Group ASK/REPLY across two logical
Node state roots in one container. Earlier bounded gates
remain attributed to their own fingerprints: `5414…` passed full Go/vet/race,
three disposable Docker suites and a real Chrome 151 encrypted canvas run
on a loopback Hub; `e13b…` passed 1,308 Go tests (11 SKIP) and vet but its
real Codex 0.159.2 run failed at the route allowlist; `434c…` failed at the
first native Join after the model shortened a synthetic Group ID. The browser
run did not exercise `UNCERTAIN` fault injection or public HTTPS. Current
Android v1.5, physical Nodes, public HTTPS and complete G1–G5 demonstrations
remain unaccepted; see the
[`architecture status`](docs/architecture-v2-status.md) and
[`V01–V88/G1–G5 ledger`](docs/completion-ledger.md).

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

The Node runtime image currently defaults to the official Codex CLI standalone
release `0.159.2`. Its update preparation used one disposable container from
the old image `cicada-codex:monitor-native-0.157.1`
(`sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`),
with no credential or host-directory mount. In that container,
`codex update` exited 1. The official installer fallback
`curl -fsSL https://chatgpt.com/codex/install.sh | sh` exited 0 and reported
`codex-cli 0.159.2`; the resulting local image is tagged
`cicada-codex:monitor-native-update-20260930`, image ID
`sha256:97cd6f07551fb4f794fca95d7b97e5e3e85131b3d7cdb682a43b47a904b2d5d6`.
This records a local runtime preparation only; it is not a CICADA release or a
native acceptance result. The image source and version remain distinct from
the current unreleased CICADA source and software version.

Historical product and runtime acceptance remains linked from the
[`architecture status`](docs/architecture-v2-status.md),
[`native validation`](docs/architecture-v2-native-validation.md), and
[`migration boundaries`](docs/architecture-v2-migration.md). Do not use a
resident Hub, production key, or paid model run as a disposable test fixture.
