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

The development line is **0.0.5**, unreleased on `dev`. On 2026-10-20, the user
reported successful original A/B Thread Joins, separate Owner consents,
bidirectional ASK/Reply and continued communication after closing the App
window. This is **USER_REPORTED_PASS** on the existing delivered Pair flow;
the [batch record](docs/native-app-validation.md#2026-10-20-user-operated-same-node-pair-batch)
keeps process-context checks, user feedback and unmeasured delivery/timing
separate. It is not a fresh build or complete independent native acceptance.

The [current feedback ledger](docs/native-app-plan.md#current-feedback-and-acceptance-ledger)
tracks the remaining product and safety work in one plan. Hub, Node and App are
composable components; installation, ordinary registration, account login and
business/Owner authorization are separate. The bounded Hub backend at
`d3acd4bfe6f3f10867db6a5e3ae432f8477d9748` implements
[zero-right Endpoint registration and private Owner directory reads](docs/native-endpoint-directory-contract.md).
Its [producer checks](docs/native-endpoint-directory-validation.md) and
[independent fault checks](docs/native-app-validation.md#2026-10-20-independent-endpoint-and-hook-checkpoint)
have separate source attribution. Node local-bridge source at `97d8a1d` and
actual App Owner-read source at `07bd265` are integrated; the
[App signed-read/recovery checks](docs/native-app-validation.md#2026-10-20-actual-app-owner-directory-integration)
remain separate from product Hook/MCP and native Runtime acceptance, which are
pending. Native navigation/CJK source at
`bb0644b68627579af470ead52035d42618372c75` is integrated; physical Windows review
remains NOT_RUN. App/Node/MCP storage-default source at
`73d6f9ad13c26ad7cf203e2924adcc7a46104213` is a partial installed-root change;
Hub/workspace/cache defaults and migration remain pending. The broader
installation-registration family is frozen. [C0.1](docs/hub-installation-registration-contract.md)
at `e0e05582dabea005eaa7c3c2d8da3527e263682a` freezes the
`installation-registration-v1.1` crypto/wire boundary, with default public
availability **false**. H1/H2 and actual registration consumers remain NOT_RUN.
This new capability is separate from the already delivered `native-pair-v1`
flow. See the [native architecture](docs/native-app-architecture.md).

Existing N2 finite Owner activation, N3 Node status and Pair contracts remain
separate. Account login is not Root; registration grants no Network/Group/peer
or Runtime rights. Original identities, current Guards and independent Owner
signatures remain authoritative. App pre-registration custody, UI/installer
checks and the empty App2 container adapter have bounded
[validation records](docs/native-app-validation.md); none establishes the new
cross-component registration flow. The real conversation feedback above has
its own user-reported scope.

Historical Windows observations include **USER_REPORTED_FAIL** for Chinese
text and second-instance setup; keep the [original batch](docs/native-app-validation.md#windows-11-eight-step-user-batch)
and [subsequent profile-recovery source](docs/native-app-validation.md#profile-recovery-follow-up)
attributed separately. Dedicated Windows DPAPI/ACL/GUI security tests and
independent native consumption, automatic-wake and public-operation traces
remain NOT_RUN; uninstall scripts are outside the current remediation stage.
Encrypted PKCS#8 import and recovery after losing all Owner signing-key copies
are not implemented. Source-bound Hub, Worker and Android outcomes remain in
the [dated closeout](docs/v01-current-closeout-20261009-validation.md#current-20261010)
and linked receipts; a main merge or 0.1.0 release needs later user acceptance
and separate authorization.

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
  (requires Go 1.27.3); optional PQ packaging requires an accepted OpenSSL stage.
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
