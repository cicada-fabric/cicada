# CICADA technical documentation

[The clean IP/ARM64 checkpoint](docker-ip-arm64-validation.md) passed its scoped
amd64/ARM64 first-install Docker gate; [manual installation](node-tls-first-install-cli.md)
uses independent Owner signatures. Bootstrap standard HTTPS, enrolled PQ TLS,
Native consumption and physical-phone acceptance remain separate scopes.

Read the published [community technical site](https://cicada-fabric.github.io/)
or start with the authoritative [v0.1.x technical guide](v01-technical-guide.md). It describes the
current 0.0.3 source, deployment boundaries and remaining acceptance work.
Development stays in 0.0.x until user acceptance; the guide's v0.1.x names the
planned first release line and its incrementing patch number.

| Area | Authoritative entry points |
|---|---|
| Product architecture | [Adopted specification](../CICADA.md), [implementation status](architecture-v2-status.md), [completion ledger](completion-ledger.md) |
| Next Hub setup and device pairing checkpoint | [Owner account and device onboarding](owner-onboarding-design.md) — initialize server Hub/account first, then one Node/Client QR/pairing-key flow; adopted user requirement, **NOT_IMPLEMENTED** |
| Deployment and platform interface design | [Web UI, CLI and local components](deployment-interface-design.md) — official-product research and Linux/macOS/Windows delivery plan; platform build/runtime evidence kept separate |
| Install and operate | [Distribution](distribution.md), [development setup](../DEVELOPMENT.md), [Hub build provenance](hub-build-input-provenance.md) |
| Identity and permissions | [Owner bootstrap](owner-approval-bootstrap.md), [Node trust](node-owner-trust.md), [permissions](permissions.md), [Network contract](network-m1-contract.md) |
| Native sessions and MCP | [Harnesses](harnesses.md), [Fabric](fabric.md), [Join self identity](native-join-self-identity.md), [Runtime capability limits](runtime-operation-capabilities.md) |
| Encrypted collaboration | [Peer privacy](task-peer-privacy-contract.md), [Group spaces](group-spaces-m2-contract.md), [multi-owner boundaries](group-spaces-multi-owner-contract.md) |
| Client interoperability | [Development boundary](client-hub-development.md), [wire v1](client-hub-wire-v1.md), [OpenAPI](client-hub-v1.openapi.yaml), [Web panel](hub-web-panel.md) |
| Backup and restore | [Node backup](node-backup.md), [Hub quarantine](hub-restore-quarantine.md), [safe activation](hub-restore-safe-activation.md), [migration](architecture-v2-migration.md) |
| Acceptance evidence | [Current closeout](v01-current-closeout-20261009-validation.md), [verification](completion-verification.md), [test automation](test-automation.md) |
| Future design | [v0.2 Agent collaboration design](v02-agent-collaboration-design.md), [integration roadmap](v02-openai-integration-roadmap.md) — planning, not shipped functionality |
| Repository maintenance | [Branch roles, documentation history and permissions](repository-maintenance.md) |
| Community | [Contributing](../CONTRIBUTING.md), [security reporting](../SECURITY.md), [support](../SUPPORT.md), [license](../LICENSE) |

Dated validation documents retain the source, artifact and environment tested
at that checkpoint. Old “current” headings and historical inventories do not
supersede later evidence. A contract check or local browser result does not
establish Android, real native Runtime, physical-device or public HTTPS acceptance.

The organization profile and static site have been published. Public HTTPS
retrieval of the technical site succeeded; that proves documentation readability,
not Hub public HTTPS readiness or product acceptance. Core dev remains the sole
source for protocol contracts, catalog, runtime instructions and validation.
