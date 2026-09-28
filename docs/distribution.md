# Distribution and deployment

This document distinguishes the current repository packaging from the adopted
Architecture v2.3 deployment target. A Go binary, a container image, an
installer, a Client, and a running CICADA service instance have different
identities and lifecycles. This repository does not currently provide a
production release installer for the M1 Network model.

## Deployment model

CICADA has three physical deployment responsibilities: Hub, Node, and Client.
They are service-instance roles, not mutually exclusive kinds of physical
host. One computer can run a Hub instance and a Node instance at the same time.
The Hub keeps the authoritative SQLite state and may host Control, Directory,
Relay, the web panel, and Network policy in one process. A Node runs the local
agent and connects out with one credential per selected Hub; its Endpoint has a
separate explicit registration/access grant in each Network. Sharing a host,
Docker bridge, address, workspace, or operator account does not grant Network
membership or bypass authentication and Guard.

A Hub identity can host multiple Networks. Each Network has one authoritative
Hub. Network isolation is an application-level identity, membership, grant,
and resource-scope check; a VLAN, Docker network, process boundary, URL alias,
or separate volume cannot replace it. Network membership does not join a
Thread to any Group. Installing the binary, plugin, MCP server, or Node service
does not automatically join a native Thread. M5's multi-Hub registrations
remain a future stage; this round does not add Hub-to-Hub forwarding.

The default transport for arbitrary authorized Thread pairs is HubRelay, which
handles peer payloads as ciphertext. A direct local exception requires both
target Threads on the same physical host and Codex account and a supported
native API that the Node can call for the exact target Thread. CICADA still
resolves the authorized Nickname/Endpoint and independently checks current
Join and Network/Group/Link scope before local delivery. Same Hub, Network,
Node label, workspace, or address alone is not enough. A model-visible TUI tool
does not give the Go Node an independently callable API; a general TUI adapter
is not implemented. The existing same-Node sealed route already keeps peer
bodies in the Node ledger and native queue while using Hub Guard for
authorization metadata; queue acceptance does not prove consumption or cold
wake. No path auto-joins or exposes all Threads in an account. See the
[bounded local transport review](native-local-direct-design.md).

| Instance | Adopted target | Current repository evidence |
| --- | --- | --- |
| Hub | Minimal OCI image, non-root service, private persistent volume, SQLite; no Codex runtime or model credential required for Fabric. Control model calls are optional management capabilities with a separately configured boundary. | `docker/Dockerfile.hub` builds the Go service, runs as UID/GID 1000, and stores Hub state under `/state`. It contains no Codex binary, model configuration, or provider credential. This is a lightweight development/test Hub image, not a signed production release. |
| Node | Host-user service is the default for a user's existing native Codex environment. A dedicated Docker Node is useful for an isolated runtime or test fixture when its runtime integration is intentionally provisioned. A bounded same-host direct-adapter check follows M1. | `scripts/install-cicada-worker.sh` installs a host binary and optional systemd service. The root `docker-compose.yml` worker profile is an inspection container running `sleep infinity`, not the production Node supervisor. |
| Plugin / MCP | Thin workflow and tool entry point. It uses a verified native Session and explicit Join; installation alone grants no endpoint or Network access. | `.agents/plugins/cicada` bundles workflow material and the local `cicada mcp` server. Runtime session identity must be verified by the adapter. |
| Android Client | Independent APK and versioned Client contract. It is not part of Hub or Node deployment. | Android is maintained in `../CICADA_CLIENT`; the current Hub contract is `client-hub-v1.4`. This repository does not modify the Client repository, and Android M1 interoperability remains separate evidence. |
| Web panel | Operator interface for the currently implemented management surface. | The embedded PWA uses the legacy bearer-token channel. It is not the formal post-quantum Android Client and does not satisfy the Android↔Control E2EE requirement. |

An Agent runtime must not receive the Docker daemon socket or an automatic
mount of the operator's entire home directory. Docker daemon access can grant
host-level filesystem control; a writable bind mount also lets a container
change the mounted host files. Give an isolated Node only the specific runtime,
state, and workspace paths it needs. Docker's security boundary depends on
the host daemon, container configuration, kernel namespaces and capabilities;
container separation alone is not the M1 Network authorization boundary. The
deployment trusts the host and its administrators; a malicious host
administrator is outside CICADA's protection boundary. CICADA still limits
service-process privileges and access to Hub data, Node state, peer keys, and
Network scopes. Host trust does not authorize plaintext Hub processing: peer
private keys stay with their endpoints, and the Hub must handle peer payloads
as ciphertext. A trusted host administrator can inspect local process and
storage state; CICADA cannot hide deployed keys or data from that administrator.
See Docker's [Engine security guidance](https://docs.docker.com/engine/security/),
[volume documentation](https://docs.docker.com/engine/storage/volumes/), and
[bind mount constraints](https://docs.docker.com/engine/storage/bind-mounts/).

## Current runnable packaging

`docker/Dockerfile.hub` builds a static Go service into a minimal Alpine runtime
with CA certificates, a non-root `cicada` user, `/state` and `/workspace` mount
points, and a health check. The deployed Hub stage contains the runtime binary,
not the Go builder, test binary, Codex, or model credentials.
`scripts/build-hub-image.sh` records build provenance. The image is used for
disposable protocol and integration tests; it is not evidence of a signed
installer or deployment readiness. Root is measuring the final image and idle
footprint separately; this document does not invent size or performance
numbers.

The existing root `docker-compose.yml` and `docker/Dockerfile` are an older
Control/Codex development stack. The image includes Codex and a model config;
Compose passes the shared `cicada.env` file to services and bind-mounts state,
workspaces, and logs. Its `control` service combines management and Fabric
HTTP in one instance; its optional `worker` service is an inspection shell.
Those choices are not the minimal Hub target described above.

`scripts/install-cicada-server.sh` currently builds and starts the Compose
`control` service. If its secret file does not already exist, it requires or
prompts for a model credential and also creates a legacy management bearer.
`scripts/install-cicada-worker.sh` writes that bearer and an optional model
credential into a systemd environment file for a host machine agent. These
scripts document and support the existing development/legacy path; they do
not implement M1 Network enrollment, per-Hub Node credentials with
per-Network Endpoint registration/access, the formal Android Client flow, or a
current production installation path.
Their default repository reference is `main`, so they are not a reproducible
release pin by themselves. No release or resident deployment is created by
this task.

The current implementation uses Hub schema v36 and Client contract v1.4; the
latest integrated gate status and exact source identities are in the
[validation matrix](network-m1-validation.md). M1 is not complete until the
final Go/race gates pass. Client v1.4 `group.create` carries an explicit
`network_id`, required on an ACTIVE Hub for a Network the authenticated owner
controls. A v1.3 Client has no selector; a v1.3 PREPARING smoke does not
establish ACTIVE compatibility. The host Codex update check through proxy port 7890 exited
`0` and reported latest `0.157.1`; `docker/Dockerfile` pins Codex `0.157.1` for
development images. The update used the shell installer, without npm or
resident deployment replacement. Codex version is distinct from CICADA's
`0.1.0-dev` software line.

The current `scripts/test-client-hub-interop.sh` is a disposable real-TCP Hub
runner. It builds local Hub and test images from the worktree, starts a uniquely
named Hub with a private temporary SQLite state directory and synthetic
credentials, runs selected Go HTTP tests, records build identity, and removes
owned containers/images. New M1 Docker checks should use that disposable
pattern and must not point at a resident development Hub. A skip or missing
Docker daemon is not a passing result.

## Distribution and upgrade rules

Pin and record each identity independently:

| Identity | What it identifies |
| --- | --- |
| CICADA software version | Current unreleased line `0.1.0-dev`; planned public product releases use `v0.1.x`. This version line is independent of Architecture v2.3, Client wire v1, contract `client-hub-v1.4`, schema version, and the retired historical prototype tag `v0.2.0`. |
| Git revision and dirty flag | Source history and whether the source tree had changes |
| Source fingerprint | The complete source input used for a build |
| Client contract revision | The published Client operation/schema contract |
| OCI image ID/digest | The exact built or deployed container image |
| SQLite schema version | The data format and migration state |

A dirty image must not be attributed only to its Git HEAD. A reusable image is
not proof that its SQLite data can be moved between versions. Before an
upgrade, stop the relevant writer, take a consistent backup with the existing
Hub migration backup command, review the migration inventory/dry run, and
preserve owner keys and Node-local state through their separate procedures.
The Hub backup excludes Node subtrees. Schema migrations may be forward-only;
restarting an old binary against a newer schema is not a rollback plan. Keep
the data and keys when stopping a deployment; do not delete a state directory
to make an upgrade appear clean. See [migration boundaries](architecture-v2-migration.md).

`scripts/build-release.sh` produces five OS/architecture-specific static
binaries plus checksums. A deployment downloads the one binary matching its
platform; the five artifacts are not one combined runtime package. The Hub OCI
runtime likewise excludes the builder and test image. No public `0.1.x`
release exists yet, and final image-size/idle measurements are recorded
separately when available.

## M1 distribution acceptance

M1 can be tested with one disposable Hub and two synthetic Network scopes; it
does not require a model, provider credential, Android APK, or real Codex
session. At minimum, a review run must prove:

- one Hub identity can host Network A and Network B with distinct, current
  memberships and Group mappings;
- a test actor joined to A cannot enumerate B, resolve B-only aliases, read
  B's history/artifacts/tasks, or cause delivery/claim/injection into B;
- the same native Thread can have separately authorized registrations without
  reassigning a live writer or weakening either scope;
- cross-Network access remains denied unless the exact future operation and
  same-Hub policy explicitly grant it;
- an ambiguous Group→Network mapping remains pending through the dry run and
  activation, with no loss or rewrite of old IDs, messages, receipts, keys,
  replay counters, or approvals;
- the test uses an isolated StateDir, synthetic credentials, and exact image
  provenance, then removes only its own temporary resources.

Report deterministic Go tests, disposable Docker HTTP results, Android,
real native Runtime, physical device, and public HTTPS as separate evidence
levels. The first three non-Docker external results are not inferred from a
protocol test. Network isolation remains **not accepted** until M1's complete
Guard and migration gates pass.
