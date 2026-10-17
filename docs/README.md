# CICADA technical documentation

[The clean IP/ARM64 checkpoint](docker-ip-arm64-validation.md) passed its scoped
amd64/ARM64 first-install Docker gate; [manual installation](node-tls-first-install-cli.md)
uses independent Owner signatures. Bootstrap standard HTTPS, enrolled PQ TLS,
Native consumption and physical-phone acceptance remain separate scopes.

Read the published [community technical site](https://cicada-fabric.github.io/)
or start with the authoritative [v0.1.x technical guide](v01-technical-guide.md). It describes the
current 0.0.5 source, deployment boundaries and remaining acceptance work.
The native Windows-first App has N2 Hub/App core with independent Linux protocol
SCOPED_PASS (131 events, zero failures/skips); native Windows remains NOT_RUN.
The bounded N3 Node authority/status slice is implemented under
[app-node-authority-v1](hub-app-node-authority-contract.md), schema 63, using the
[identity/Node-only Hub](hub-nodes-only.md) with Control inference disabled.
Independent [actual-process acceptance](native-app-validation.md#n3-independent-process-acceptance)
passed 84/0/0 on bookworm and 84/0/0 using the same binaries in Ubuntu 24.04.4.
Live canvas, App SSE, real native Runtime and physical acceptance remain incomplete.
It is not a browser product or a
released installer. Development stays in 0.0.x until user acceptance; the
guide's v0.1.x names the planned first release line and its incrementing patch
number.

| Area | Authoritative entry points |
|---|---|
| Product architecture | [Adopted specification](../CICADA.md), [implementation status](architecture-v2-status.md), [completion ledger](completion-ledger.md) |
| Hub Owner bootstrap checkpoint | [Operator guide](hub-owner-bootstrap.md), [first-signer contract](hub-owner-bootstrap-contract.md), [validation](hub-owner-bootstrap-validation.md), and [full onboarding design](owner-onboarding-design.md) — historical bounded Hub/account SCOPED PASS; original aggregate failures/timeouts retained. N2 adds [finite activation and exact pending-Owner continuation](hub-owner-activation-contract.md). Lost/revoked Root recovery is not implemented by N2 |
| Native App | [Architecture](native-app-architecture.md), [plan and matrix](native-app-plan.md), [integration evidence and Windows procedure](native-app-validation.md#n2-hubapp-integration) — N2 independent Linux protocol SCOPED_PASS; bounded N3 Node enrollment/status/recovery SCOPED_PASS in two Linux containers. Windows DPAPI/ACL/GUI, visual review and installer remain unaccepted. Unencrypted existing Owner identities can be vaulted and proved; encrypted PKCS#8 input unsupported |
| Identity/Node-only Hub | [Operator guide](hub-nodes-only.md), [N3 contract](hub-app-node-authority-contract.md), [Hub validation](hub-app-node-authority-validation.md) — standard HTTPS plus application PQ envelopes; strict PQTLS, native Runtime and physical deployment acceptance remain separate |
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
| Repository maintenance | [Workspace and task worktrees](workspace-development.md), [monorepo history/evidence migration](repository-migration.md), [branch roles, documentation history and permissions](repository-maintenance.md), [historical workspace cleanup and retained source](workspace-maintenance.md) |
| Android App source | [Imported Android subtree](../apps/android/README.md), [migration validation](../apps/android/docs/monorepo-migration-validation.md) — source and history now live in this repository; runtime acceptance remains separately attributed |
| Community | [Contributing](../CONTRIBUTING.md), [security reporting](../SECURITY.md), [support](../SUPPORT.md), [license](../LICENSE) |

Dated validation documents retain the source, artifact and environment tested
at that checkpoint. Old “current” headings and historical inventories do not
supersede later evidence. A contract check or local browser result does not
establish Android, real native Runtime, physical-device or public HTTPS acceptance.

The organization profile and static site have been published. Public HTTPS
retrieval of the technical site succeeded; that proves documentation readability,
not Hub public HTTPS readiness or product acceptance. Core dev remains the sole
source for protocol contracts, catalog, runtime instructions and validation.

N2 independent acceptance is recorded in the existing native App
[threat model](native-app-architecture.md#n2-independent-threat-model),
[fault matrix](native-app-plan.md#n2-independent-acceptance-matrix) and
[validation](native-app-validation.md#n2-hubapp-integration).
The default account-core lane remains a scoped baseline. The explicit
`--require-n2` lane exercises real Root proof, legacy continuation and recovery;
it never accepts native Windows behavior by inference from a cross-build.
