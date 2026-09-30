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

For same-host development, `CICADA_CONTROL_URL=http://127.0.0.1:8788` is
accepted. Remote Node enrollment requires HTTPS. The script builds the Go
binary from this checkout (or uses an explicit local `CICADA_BINARY_PATH`),
creates a private local state directory and runs the real host Node agent in
the foreground. It does not download a binary, run npm, configure a systemd
unit, pass a management bearer/provider credential to the Hub or expose an
inbound port. The Node generates and retains its own bearer locally, submits
only its digest to `POST /v2/nodes/device-code`, and waits for owner binding.

The agent prints a 10-minute pairing code. In the already authenticated
Android Client, the Owner must inspect the exact pending Node with `nodes.preview`
and separately call `nodes.confirm`. `/client/device` is a Client navigation
route; the Hub does not host a browser approval page. The device code is not
login, a password bypass or an authorization grant. After confirmation the
Node opens outbound Relay SSE/HTTP only. `--relay-only` excludes legacy Control
Worker-management polling. Ctrl-C stops the foreground agent but preserves the
Node identity and inbox state. A real native Thread still needs the local
Codex runtime; queue acceptance is not a general model-consumption or cold-wake
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
records acquisition order; it does not fence completion receipts from an old
writer. A different StateRoot can bypass this lock, so this candidate does not
claim machine-wide native writer fencing. Multi-Hub HTTP credential isolation
has focused tests, while a disposable two-Node full native ASK/REPLY run remains
unverified.

## Version and upgrade boundaries

Keep these identities separate in every build/deployment record:

| Identity | Meaning |
|---|---|
| CICADA software version | Current unreleased line `0.1.0-dev`; Architecture v2.3 is a product/architecture target. |
| Git revision and dirty flag | Source revision and whether uncommitted changes were present. |
| Source fingerprint | Complete source input used by a build; a dirty build is not identified by HEAD alone. |
| Client contract revision and wire | Current Android management contract `client-hub-v1.4`, encrypted wire v1; separate from internal Node MCP APIs. |
| SQLite schema | Current accepted M2 checkpoint v37; later dirty migrations need their own frozen evidence. |
| OCI image ID/digest | Exact local build or registry artifact, distinct from source and software versions. |
| Codex CLI version | Node Runtime version, separate from Hub image and CICADA version. |

Before upgrading a stateful Hub, stop its writer, use the existing Hub
`migration backup`/verify tools, review inventory and migration behavior, and
retain Owner keys and Node-local state separately. Do not open a newer schema
with an older binary, delete a state directory to simulate rollback, or assume
that the Hub backup includes Node subtrees. No public `0.1.x` release is
available. See [migration boundaries](architecture-v2-migration.md) and the
[current acceptance ledger](completion-ledger.md) before treating an internal
or historical checkpoint as a release qualification.
