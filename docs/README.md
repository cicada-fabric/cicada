# CICADA technical documentation

[The clean IP/ARM64 checkpoint](docker-ip-arm64-validation.md) passed its scoped
amd64/ARM64 first-install Docker gate; [manual installation](node-tls-first-install-cli.md)
uses independent Owner signatures. Bootstrap standard HTTPS, enrolled PQ TLS,
Native consumption and physical-phone acceptance remain separate scopes.

Read the published [community technical site](https://cicada-fabric.github.io/)
or start with the authoritative [v0.1.x technical guide](v01-technical-guide.md). It describes the
current 0.0.5 source, deployment boundaries and remaining acceptance work.
The native Windows-first App is at N1 PARTIAL; it is not a browser product or a
released installer. Development stays in 0.0.x until user acceptance; the
guide's v0.1.x names the planned first release line and its incrementing patch
number.

| Area | Authoritative entry points |
|---|---|
| Product architecture | [Adopted specification](../CICADA.md), [implementation status](architecture-v2-status.md), [completion ledger](completion-ledger.md) |
| Hub Owner bootstrap checkpoint | [Operator guide](hub-owner-bootstrap.md), [first-signer contract](hub-owner-bootstrap-contract.md), [validation](hub-owner-bootstrap-validation.md), and [full onboarding design](owner-onboarding-design.md) — bounded Hub/account checkpoint SCOPED PASS across Docker A2, segmented normal/race, vet/build and Python checks; aggregate A7/R3 failures/timeouts remain recorded. Browser account UI exists in that source; native App Root proof/activation and lost-Root recovery remain **NOT_IMPLEMENTED** |
| Native App | [Architecture and authority boundaries](native-app-architecture.md), [stage plan](native-app-plan.md) — standalone Windows-first Gio App, N1 PARTIAL; encrypted PKCS#8 input is unsupported (supported unencrypted existing identities can be vaulted), native Windows/DPAPI/ACL, installer and N2 Root activation are not accepted or complete; N3 native App integration with existing Hub/Node status, preview/confirm and Guard APIs is incomplete |
| Deployment and platform interfaces | [CLI, legacy Web UI and local components](deployment-interface-design.md) — official-product research and platform delivery plan; the native App is the current user-interface target, and platform build/runtime evidence stays separate |
| Install and operate | [Distribution](distribution.md), [development setup](../DEVELOPMENT.md), [Hub build provenance](hub-build-input-provenance.md) |
| Identity and permissions | [Owner bootstrap](owner-approval-bootstrap.md), [Node trust](node-owner-trust.md), [permissions](permissions.md), [Network contract](network-m1-contract.md) |
| Headless compatibility client | [Encrypted no-phone management Client](owner-headless-client.md), [scoped validation](owner-headless-client-validation.md) — existing-Owner INITIAL SDK slice complete under legacy Client protocol names; it is not the native App UI |
| Native sessions and MCP | [Harnesses](harnesses.md), [Fabric](fabric.md), [Join self identity](native-join-self-identity.md), [Runtime capability limits](runtime-operation-capabilities.md) |
| Encrypted collaboration | [Peer privacy](task-peer-privacy-contract.md), [Group spaces](group-spaces-m2-contract.md), [multi-owner boundaries](group-spaces-multi-owner-contract.md) |
| Frozen Client-wire compatibility | [Development boundary](client-hub-development.md), [wire v1](client-hub-wire-v1.md), [OpenAPI](client-hub-v1.openapi.yaml), [legacy Web panel](hub-web-panel.md) — existing wire identifiers are retained; the App target has no browser dependency and Hub-root 404 retirement is not yet validated |
| Backup and restore | [Node backup](node-backup.md), [Hub quarantine](hub-restore-quarantine.md), [safe activation](hub-restore-safe-activation.md), [migration](architecture-v2-migration.md) |
| Acceptance evidence | [Current closeout](v01-current-closeout-20261009-validation.md), [verification](completion-verification.md), [test automation](test-automation.md) |
| Future design | [v0.2 Agent collaboration design](v02-agent-collaboration-design.md), [integration roadmap](v02-openai-integration-roadmap.md) — planning, not shipped functionality |
| Repository maintenance | [Branch roles, documentation history and permissions](repository-maintenance.md), [workspace cleanup and retained source](workspace-maintenance.md) |
| Community | [Contributing](../CONTRIBUTING.md), [security reporting](../SECURITY.md), [support](../SUPPORT.md), [license](../LICENSE) |

Dated validation documents retain the source, artifact and environment tested
at that checkpoint. Old “current” headings and historical inventories do not
supersede later evidence. A contract check or local browser result does not
establish Android, real native Runtime, physical-device or public HTTPS acceptance.

The organization profile and static site have been published. Public HTTPS
retrieval of the technical site succeeded; that proves documentation readability,
not Hub public HTTPS readiness or product acceptance. Core dev remains the sole
source for protocol contracts, catalog, runtime instructions and validation.
