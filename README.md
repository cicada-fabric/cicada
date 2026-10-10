# CICADA

CICADA is a Go system for authorized collaboration between native AI sessions.
It keeps session identity, scoped communication, durable delivery and user
approval separate from model-generated claims.

- **Hub** owns authoritative state, Directory, Relay and Guard; Control manages
  user goals and approvals. Ordinary peer communication does not require
  Control to interpret its messages.
- **Node** owns local session access, Endpoint keys and durable inbox/writer
  state, and connects outbound to the Hub.
- **Client** is the user identity and approval surface. Android development is
  owned by the separate `CICADA_CLIENT` repository.

Installing a component does not Join a Thread or grant access. Explicit Join,
current SessionBinding and per-operation Network/Group/Link authorization are
required. A tool being available is not permission to use it.

The cryptographic design uses NIST ML-KEM, ML-DSA and authenticated encryption.
Peer plaintext belongs at authorized Endpoints; Client management plaintext
belongs at the Client and Control. These application E2EE boundaries are
distinct from HTTPS and the optional PQTLS transport. Content sent to an
external model is visible to that provider; this is not provider-blind E2EE.

## Development and local deployment

The development line is **0.0.1-dev**, unreleased on `dev`. A main merge or
0.1.0 release follows the user's actual acceptance and separate authorization.
Real G1 passed; current CLI sandbox and Worker private-fixture checks passed
their scoped predicates. G2 failed before model activity, G3 and current Android,
physical-device and public HTTPS acceptance remain open. Historical failures and
the shipping/fixture distinction remain in the
[current closeout](docs/v01-current-closeout-20261009-validation.md#current-20261010).

The [test automation guide](docs/test-automation.md) covers `scripts/test-architecture-v2-completion.sh`; the default run uses no paid models and reports NOT_RUN/BLOCKED separately from passed checks.

Use the checkout-based commands in [distribution and deployment](docs/distribution.md):

- Local Linux Hub: `scripts/install-cicada-server.sh`.
- Optional host Node: `scripts/install-cicada-worker.sh`; review the Hub URL,
  state and Owner confirmation requirements before running it.
- Binary packaging: `scripts/build-release.sh VERSION [OUTPUT_DIR]`
  (requires Go 1.27.1); optional PQ packaging requires an accepted OpenSSL stage.
- Local Hub image: `scripts/build-hub-image.sh --image IMAGE --metadata-file PATH`.

These commands build from a local checkout. No published image tag or signed
release installer is implied. Read [DEVELOPMENT.md](DEVELOPMENT.md) for setup,
[CICADA.md](CICADA.md) for the adopted architecture, and
[AGENTS.md](AGENTS.md) for repository engineering rules.

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
