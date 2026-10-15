# CICADA

CICADA is a Go system for authorized collaboration between native AI sessions.
It keeps session identity, scoped communication, durable delivery and user
approval separate from model-generated claims.

- **Hub** owns authoritative state, Directory, Relay and Guard; Control manages
  user goals and approvals. Ordinary peer communication does not require
  Control to interpret its messages.
- **Node** owns local session access, Endpoint keys and durable inbox/writer
  state, and connects outbound to the Hub.
- **App** is the independent user entry point. Windows is the current native
  target; ordinary use must not depend on a browser or WebView. Android is a
  planned separate distribution whose source is under `apps/android`; its
  original Git history is retained by the monorepo import.
- The human **Owner** supplies authority. **Manager** coordinates goals and
  approvals, **Advisor** makes bounded recommendations, and **Worker** executes
  authorized tasks. Hub Control is a service, not the Owner.

Installing a component does not Join a Thread or grant access. Explicit Join,
current SessionBinding and per-operation Network/Group/Link authorization are
required. A tool being available is not permission to use it.

The cryptographic design uses NIST ML-KEM, ML-DSA and authenticated encryption.
Peer plaintext belongs at authorized Endpoints; App account requests are
addressed to Hub Identity/Authorization, and Manager instructions are decrypted
by Control. The Hub peer Relay does not receive peer plaintext. These
application E2EE boundaries are distinct from HTTPS and the future Windows
PQTLS transport. Content sent to an
external model is visible to that provider; this is not provider-blind E2EE.

## Development and local deployment

The current [IP/ARM64 deployment checkpoint](docs/docker-ip-arm64-validation.md)
has [manual independent-Owner installation steps](docs/node-tls-first-install-cli.md).
Clean amd64/ARM64 package first installation passed its scoped Docker gate;
standard HTTPS bootstrap and enrolled strict PQ TLS are separate stages.

The development line is **0.0.5**, unreleased on `dev`, with Hub schema 61.
The account backend and earlier browser/WASM account flow are implemented and
validated within their recorded scopes, but the current product direction is a
native Windows App. Its source foundation is **N1 partial**: native UI and
vault-backed protocol code exist, but native Windows/DPAPI/ACL execution,
encrypted PKCS#8 input, the one-code Root activation, trusted automatic profile
restart/reconciliation, and native App integration for the authorized live
canvas and Node actions are not accepted or complete. Supported unencrypted
existing Owner identities can be imported into the encrypted vault; using one
to prove and activate Root remains incomplete. The Hub/Node APIs and Guard
already exist for App integration. The App is not a released installer, and
the Hub public-root 404 target is not yet validated. See the
[native App architecture](docs/native-app-architecture.md) and
[native App plan](docs/native-app-plan.md). The independent-Hub Docker account
gate and standard legacy Client-protocol interop passed their own bounded
scopes; neither is native Windows acceptance. The Hub bootstrap checkpoint's
segmented normal and selected race PASS results, Store fixture corrections,
original A7/R3 aggregate failures/timeouts, vet/build and Python results remain
in the [Hub bootstrap record](docs/hub-owner-bootstrap-validation.md). The
[operator guide](docs/hub-owner-bootstrap.md) documents the current Hub-volume
procedure, not the final App onboarding. Android, native Windows, physical-device
and public-HTTPS acceptance remain NOT_RUN; Windows custody, Root activation
and lost-Root recovery remain incomplete. A main merge or
0.1.0 release follows the user's actual acceptance and separate authorization.
Real G1, current CLI sandbox and Worker private-fixture checks passed their
scoped predicates. C14 also passed its bounded six-turn default-daemon G2/G3
scope with exact cleanup; this does not close every Native, device or release
gate. Shipping `a4` ordinary Worker and Joint11's eight Android recovery cases
passed their stated scopes. Android encrypted status reads and GroupOwnerProof,
physical-device and public HTTPS acceptance remain NOT_RUN. Historical G2/G3
failures and later scoped results retain their original attribution in the
[current closeout](docs/v01-current-closeout-20261009-validation.md#current-20261010).

The [test automation guide](docs/test-automation.md) covers `scripts/test-architecture-v2-completion.sh`; the default run uses no paid models and reports NOT_RUN/BLOCKED separately from passed checks.

Use the checkout-based commands in [distribution and deployment](docs/distribution.md):

- New Hub: the current 0.0.5 operator procedure is in the
  [Hub bootstrap guide](docs/hub-owner-bootstrap.md). It is a transitional
  local-operator flow; the target user flow is the native App's one-use
  activation code and is not implemented as a complete Root setup yet.
- Existing configured Compose-managed Hub: `scripts/install-cicada-server.sh`
  is a controlled update helper that requires an explicit fresh backup. Its
  `scripts/bootstrap-cicada.sh` alias is not a fresh-install path. Do not pass
  a manually created setup volume to this helper; it treats such a volume as an
  orphan and refuses it.
- Optional host Node: `scripts/install-cicada-worker.sh`; review the Hub URL,
  state and Owner confirmation requirements before running it.
- Binary packaging: `scripts/build-release.sh VERSION [OUTPUT_DIR]`
  (requires Go 1.27.2); optional PQ packaging requires an accepted OpenSSL stage.
- Local Hub image: `scripts/build-hub-image.sh --image IMAGE --metadata-file PATH`.

These commands build from a local checkout. No published image tag or signed
release installer is implied. Read [DEVELOPMENT.md](DEVELOPMENT.md) for setup,
[CICADA.md](CICADA.md) for the adopted architecture, and
[AGENTS.md](AGENTS.md) for repository engineering rules.

The canonical checkout is `~/Cicada/cicada`, on `dev`; `~/Cicada` is the parent
workspace. Go remains under `cicada-go`, Android under `apps/android`, and the
authoritative shared contracts under root `docs` and `cicada-go`. Use task
worktrees for concurrent writers. See the [workspace guide](docs/workspace-development.md)
and [history and evidence migration record](docs/repository-migration.md).

## License

First-party CICADA material is licensed under [Apache-2.0](LICENSE).
Third-party components retain their own licenses and notices; the project
license does not replace them. The packaging scripts copy the root LICENSE
into standard assets and LICENSE-NOTICES.tar.gz, and into PQ packages at
share/licenses/cicada/LICENSE. Hub Dockerfiles copy it alongside third-party
notices. Actual standard/PQ artifact checks and create-only inspections of both
Hub images verified the exact project LICENSE and retained third-party notices.
These are local development artifacts, not a published or formal release; see
the [scoped results and retained failures](docs/v01-current-closeout-20261009-validation.md).

## Documentation and community

Start with the [v0.1.x technical guide](docs/v01-technical-guide.md) and
[documentation index](docs/README.md) for current capabilities, contracts,
operations and acceptance limits. The patch position in v0.1.x can increment
for compatible fixes; larger product changes are planned for v0.2.x.
See [Contributing](CONTRIBUTING.md), [Support](SUPPORT.md) and
[Security reporting](SECURITY.md) before opening an issue.

The public `main` branch is an unreleased landing-page placeholder; active code
and technical documentation are developed on `dev`. Read
[repository maintenance](docs/repository-maintenance.md) for branch roles and
historical evidence, and the [v0.2 Agent collaboration design](docs/v02-agent-collaboration-design.md)
for planned directory/contact and organization work.
