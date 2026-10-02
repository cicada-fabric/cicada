# Distribution and deployment

This repository provides an opt-in, checkout-based local Hub Compose entry and
an optional host-user Node agent launcher. It does not provide a signed
production release installer or a public HTTPS deployment.

Hub, Node and Client are deployment responsibilities, not separate required
machines. The Hub owns authoritative SQLite state and serves Control/Fabric;
the Node owns its credential, Endpoint keys, inbox and native Runtime access;
the Android Client owns user keys and explicit approval. Installing the Hub,
Node binary, MCP server or plugin never joins a native Thread or grants a Group.
Network and Group membership, Endpoint registration, SessionBinding, directory
visibility and message grants remain separate server-checked permissions.

## Local Hub

`docker/Dockerfile.hub` builds a non-root static Go runtime without Codex,
provider/model credentials or a legacy management bearer. The root
`docker-compose.yml` contains one Hub service, Linux host networking, a
loopback-only listener and a persistent named volume
`cicada-v2-local-hub-state`. It does not mount the legacy `cicada.env`, read a
resident state directory, publish a port to non-loopback interfaces or start
placeholder services. The Hub identity and SQLite state persist in the named
volume. Stop it without deleting data:

```sh
docker compose -p cicada-v2-local -f docker-compose.yml stop hub
```

From a Linux CICADA checkout with Docker Engine and Compose v2, explicitly
start the local Hub with:

```sh
scripts/install-cicada-server.sh
```

The installer builds the current local checkout and starts
`http://127.0.0.1:8788` by default. It does not fetch a GitHub branch, curl an
unpublished artifact, request model credentials, or clear any data. It refuses
to reuse an existing `cicada-v2-local` Compose project unless
`CICADA_DEPLOY_UPDATE=1` is explicitly set. A rebuild/recreate preserves the
named volume. `scripts/bootstrap-cicada.sh` is an alias for this explicit Hub
installer; it no longer creates a shared env file.

This loopback HTTP profile is for same-host development. A physical Android
device or remote Node requires the operator to configure an HTTPS reverse
proxy, certificate and firewall policy. Neither this Compose file nor its
health check proves public HTTPS readiness.

## Optional Node agent and owner confirmation

On a host with the user's existing Codex CLI (`codex queue` supported), use:

```sh
CICADA_CONTROL_URL=https://hub.example.org \
CICADA_MACHINE_ID=node-lab-a \
scripts/install-cicada-worker.sh
```

The installer defaults to `--mode relay`. To also let this Node process its
Node-authorized Worker queue and Monitor notices, opt in explicitly:

```sh
CICADA_CONTROL_URL=https://hub.example.org \
CICADA_MACHINE_ID=node-lab-a \
scripts/install-cicada-worker.sh --mode managed
```

`--mode relay` runs outbound Fabric delivery only; `--mode managed` enables
the existing single-Node Worker and Monitor processing paths. Both use the
Node's own bearer and local state. Managed mode does not join a Thread or Group,
approve the pending Node, or grant it broader server permissions. The Owner
still reviews the exact device code in the authenticated Client before Relay
or managed work is authorized. Choose managed mode only on a host where local
Codex and configured Worker execution are intended.

For same-host development, `CICADA_CONTROL_URL=http://127.0.0.1:8788` is
accepted. Remote Node enrollment requires HTTPS. The script builds the Go
binary from this checkout (or uses an explicit local `CICADA_BINARY_PATH`),
creates a private local state directory and runs the real host Node agent in
the foreground. It does not download a binary, run npm, configure a systemd
unit, pass a management bearer/provider credential to the Hub or expose an
inbound port. The Node generates and retains its own bearer locally, submits
only its digest to `POST /v2/nodes/device-code`, and waits for owner binding.

The agent prints a 10-minute pairing code. In the already authenticated
Android Client, the Owner must inspect the exact pending Node with
`nodes.preview` and separately call `nodes.confirm`. `/client/device` is a
Client navigation route; the Hub does not host a browser approval page. The
device code is not login, a password bypass or an authorization grant. In
relay mode the Node processes outbound Relay SSE/HTTP only. In managed mode it
also polls and executes the Worker jobs authorized for its Node credential and
processes Monitor notices. Ctrl-C stops the foreground agent but preserves the
Node identity and inbox state. A real native Thread still needs the local Codex
runtime; queue acceptance is not a general model-consumption or cold-wake
receipt.

The unreleased multi-Hub Node entry accepts `cicada machine agent --hubs-file
FILE --state-root DIR --relay-only`. The private JSON registry has `version:1`
and two to eight `{hub_id,control_url,node_id}` entries. The command keeps
credentials, cursors, inbox and journal under separate private Hub subtrees;
`cicada mcp --hub-id ID --hubs-file FILE --state-root DIR` selects one exact
Hub. This path currently runs outbound Relay only. Multi-Hub Control Worker
management fails closed, and existing single-Hub state is not moved or rekeyed
automatically. Back it up and review a stopped migration before switching.

The native writer lock serializes one OS user's harness/native Session ID only
among processes configured with the same `--state-root`. Its persisted epoch
orders writers, and the durable native-outcome CAS rejects a completion from a
stale writer epoch. A different StateRoot can bypass the local lock, so this
does not claim machine-wide writer exclusion. Multi-Hub HTTP credential
isolation has focused tests, while a disposable two-Node full native ASK/REPLY
run remains unverified.

## Version and upgrade boundaries

Keep these identities separate in every build/deployment record:

| Identity | Meaning |
|---|---|
| CICADA software version | Current unreleased line [`0.1.0-dev`](../VERSION); Architecture v2.3 is a product/architecture target. No public `0.1.x` release is available. |
| Git revision and dirty flag | Source revision and whether uncommitted changes were present. |
| Source fingerprint | Hash of the source/build inputs used by a binary release; a dirty build is not identified by HEAD alone. |
| Client contract revision and wire | Current Client contract revision [`client-hub-v1.6.4`](../cicada-go/internal/clientcontract/catalog.json), encrypted wire v1 and 55 operations; catalog SHA-256 `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`. Contract/catalog identity is separate from an independently built or accepted Android Client binary and from internal Node MCP APIs. |
| SQLite schema | Current development Hub supports schema v57 ([`CurrentV2SchemaVersion`](../cicada-go/internal/store/migrations_v2.go#L24)); this source schema level is separate from the software version, Git revision, and image digest. |
| OCI image ID/digest | Record the exact local build or registry artifact, distinct from source and software versions. Client APK, STD Hub, and PQ Hub/Node artifacts retain separate source/build records and applicable binary/image digests. |
| Codex CLI version | Node Runtime version, separate from Hub image and CICADA version. |

Complete ordinary-user/admin role-based access control (RBAC) and delegated authorization workflows remain in v0.2 scope; v0.1 continues to enforce its existing identity and owner-scope checks through the server Guard on each operation.

Before upgrading a stateful Hub, stop its writer, use the existing Hub
`migration backup`/verify tools, review inventory and migration behavior, and
retain Owner keys and Node-local state separately. Do not open a newer schema
with an older binary, delete a state directory to simulate rollback, or assume
that the Hub backup includes Node subtrees. No public `0.1.x` release is
available. `scripts/build-release.sh` stages the Go 1.27.1 WebCrypto runtime,
compressed WASM and generated manifest into a temporary Go source copy before
cross-compiling, then embeds version, revision, dirty state and source
fingerprint in each binary and writes `BUILD-METADATA.json` plus `SHA256SUMS`.
The release workflow publishes the Hub-only OCI image from
`docker/Dockerfile.hub`, which contains no Codex CLI or provider credentials.
It derives the image source fingerprint and catalog digest through
`scripts/build-hub-image.sh --source-info-only`, checks the generated WebCrypto
manifest against the binary job's manifest, and passes version, revision,
dirty flag and source fingerprints into the Hub build. Binary and Hub image
fingerprints cover different build inputs and must be read with their artifact
type; neither is a substitute for the image digest. These packaging paths are
not a signed production installer. See
[migration boundaries](architecture-v2-migration.md) and the
[current acceptance ledger](completion-ledger.md) before treating an internal
or historical checkpoint as a release qualification.
