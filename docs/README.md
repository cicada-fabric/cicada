# CICADA technical documentation

## Current development — 2026-10-26

Software **0.0.5 remains unreleased**; **v0.1.0 is the planned first release**.
The [adopted specification](../CICADA.md) defines the product, while the
[native App plan and current acceptance ledger](native-app-plan.md#current-feedback-and-acceptance-ledger)
track implementation and remaining acceptance. Current integrated source includes:

- Explicit Node background `on/off/status` for an already paired, single-Hub
  relay-only Node, retaining its state and keys. See the
  [lifecycle plan](native-app-plan.md#native-node-onoffstatus-safety-preparation-2026-10-25)
  and [distribution contract](distribution.md).
- A Node-first device request, exact Owner review/approval in the Windows App,
  and the original Node's private ACK. See the
  [device-pairing contract](node-pair-trust-contract.md).
- External-terminal registration/resume of each original Codex Thread, with only
  the Cicada MCP `PreToolUse` hook in the default plugin. See the
  [native Endpoint contract](native-endpoint-directory-contract.md).
- Hub-authoritative Owner management of exact Thread/Group relations: the App
  creates a named empty Group, then separately reviews adding or removing one
  Thread. A Thread can retain several Groups and its original identity; current
  MCP Group selection is separate from membership. See the
  [Owner-managed Group contract](native-endpoint-directory-contract.md#proposed-owner-managed-endpoint-groups-v1).

Use the [current ledger](native-app-plan.md#current-feedback-and-acceptance-ledger),
[App validation](native-app-validation.md) and
[Endpoint/Group source validation](native-endpoint-directory-validation.md) for
the actual passing scopes and retained failures, including the source-bound
four-Thread M1–M8 Runtime status. Integration, producer checks and candidate
packaging retain their separate scopes. Independent physical Windows
DPAPI/ACL/GUI and 24-hour elapsed expiry remain **NOT_RUN**.

Pre-submit contact/input UI stays in **v0.2 PLANNED/NOT_RUN**; the
[version decision](native-app-plan.md#current-feedback-and-acceptance-ledger) and
[existing roadmap](v02-openai-integration-roadmap.md) retain that boundary.

## Historical checkpoints and reference index

The additive [Node-scoped App authority](hub-app-node-scoped-authority-contract.md)
and [scoped Node pairing trust](node-pair-trust-scoped-contract.md) freeze
independent Scope2 shared codecs. Both new capabilities remain false; the
[producer validation](hub-app-node-scoped-authority-validation.md) covers codecs
and isolated discovery only. The scoped Store carrier, App/Node consumers and
actual second-Node integration remain pending.

The dated checkpoints below retain their original source, artifacts and tested
scope. Their old “current” descriptions and literal-prompt workflows describe
those checkpoints; use the entry points above for the present implementation.

The [Node pairing trust contract](node-pair-trust-contract.md) defines one local
secret device code, independent Owner-to-Node trust and a private ACK while
retaining the existing Node-Control binding. The Hub service/Store carrier adds
atomic ACK gates, original receipt recovery and bounded anonymous state. The
Node qualification checkpoint adds protected secret/TTY, retained-binding and
explicit retry consumers and enables this carrier for QA. Integrated process and
physical acceptance remain separate; earlier evidence retains its own source.

The additive [Hub native TLS contract](hub-native-tls-contract.md) defines a
stable logical origin, numeric dial locator and trusted public TLS descriptor
with an unchanged activation-v1 wrapper. Its shared codecs/client have separate
[producer validation](hub-native-tls-validation.md); the later
[Hub runtime validation](hub-native-tls-runtime-validation.md) covers saved
TLS profiles, CLI and native serving separately. The
[Node consumer validation](hub-native-tls-node-validation.md) covers protected
routing persistence, selected MCP/heartbeat/Network and uncertain outbox recovery.
Complete Node/App integration and direct public-IP installation remain separate
acceptance scopes.

[The clean IP/ARM64 checkpoint](docker-ip-arm64-validation.md) passed its scoped
amd64/ARM64 first-install Docker gate; [manual installation](node-tls-first-install-cli.md)
uses independent Owner signatures. Bootstrap standard HTTPS, enrolled PQ TLS,
Native consumption and physical-phone acceptance remain separate scopes.

Read the published [community technical site](https://cicada-fabric.github.io/)
or start with the authoritative [v0.1.x technical guide](v01-technical-guide.md). It describes the
current 0.0.5 source, deployment boundaries and remaining acceptance work.
Current work follows the [single feedback and acceptance ledger](native-app-plan.md#current-feedback-and-acceptance-ledger).
On 2026-10-20 the user reported original A/B Joins, separate consents,
bidirectional ASK/Reply and communication after closing the App window as
successful. The [batch record](native-app-validation.md#2026-10-20-user-operated-same-node-pair-batch)
labels this USER_REPORTED_PASS, separately from Root's read-only MCP-context
observations and independent execution. The existing delivered Pair flow is
available for this bounded use; new registration work is a separate scope.
The bounded Hub backend at `d3acd4bfe6f3f10867db6a5e3ae432f8477d9748`
implements the [Endpoint/directory contract](native-endpoint-directory-contract.md),
including zero rights, exact Leave CAS, private Owner proofs and foreign-card
redaction. [Producer validation](native-endpoint-directory-validation.md) and
[independent fault evidence](native-app-validation.md#2026-10-20-independent-endpoint-and-hook-checkpoint)
remain distinct. Node local-bridge source `97d8a1d` and App Owner-read source
`07bd265` are integrated. Actual App signed reads, old-Hub denial and original
read recovery have [independent scoped evidence](native-app-validation.md#2026-10-20-actual-app-owner-directory-integration);
actual installed-plugin [PTY/Host context checks](native-app-validation.md#2026-10-20-actual-installed-plugin-pty-and-host-mcp-context)
now have a bounded Linux PASS: normal trust, visible literal register/peers,
zero literal provider POSTs and Host `whoami` reaching an unjoined business
refusal. Earlier seven-event process guards keep their separate source.
The separate [actual default-five-minute cold gate](native-app-validation.md#2026-10-20-actual-default-five-minute-cold-lease-and-current-revocation)
passes named connects, authenticated App identity matching and dual consent,
Node restart/renewal before the first joined Host tool, and current revocation.
It requires the existing manual Owner public pin. Operator faults, Leave, real
model/queue consumption and physical Windows remain unaccepted.
`bb0644b68627579af470ead52035d42618372c75` integrates native navigation
and CJK font source; physical Windows review remains NOT_RUN. Broader C0 work is frozen.
Partial storage-default source `73d6f9ad13c26ad7cf203e2924adcc7a46104213`
covers App/Node/MCP/custom-root and installer file prefix; Hub/workspace/cache
defaults and migration remain pending.

[C0.1](hub-installation-registration-contract.md) at
`e0e05582dabea005eaa7c3c2d8da3527e263682a` freezes
`installation-registration-v1.1` proofs, codecs and bounds. Its default public
availability remains **false**; H1/H2 and actual registration consumers are
NOT_RUN. Original v1 checks keep their source attribution. Start with the
[native architecture](native-app-architecture.md), [plan](native-app-plan.md)
and [source-specific validation](native-app-validation.md). Installation,
registration, account login and Owner/business authorization are distinct.

Earlier N2 Owner activation and bounded N3 status/Pair results retain their own
contracts, source/artifact hashes and environments. App pre-registration local
custody, component-installer/UI checks and the empty App2 container adapter are
preparatory scopes; they do not establish actual new registration, Owner-pin
exchange or independent App2 authorized Hub-state reads. Dedicated Windows
DPAPI/ACL/GUI security tests, automatic-wake/timing traces and independent
real-consumption/public-operation evidence remain NOT_RUN. Uninstall scripts
are outside this remediation stage. The [Windows batch](native-app-validation.md#windows-11-eight-step-user-batch)
retains USER_REPORTED_FAIL for Chinese text and second-instance entry; later
[profile-recovery code](native-app-validation.md#profile-recovery-follow-up)
does not erase that historical attribution or prove a new physical retest.

The App is Windows-first and has no browser/WebView dependency. Live canvas,
App SSE and full physical/native Runtime acceptance remain incomplete. Software
stays in unreleased **0.0.5** development until user acceptance; the technical
guide's v0.1.x denotes the planned first release line.

| Area | Authoritative entry points |
|---|---|
| Product architecture | [Adopted specification](../CICADA.md), [implementation status](architecture-v2-status.md), [completion ledger](completion-ledger.md) |
| Hub Owner bootstrap checkpoint | [Operator guide](hub-owner-bootstrap.md), [first-signer contract](hub-owner-bootstrap-contract.md), [validation](hub-owner-bootstrap-validation.md), and [historical UI and retained security-design notes](owner-onboarding-design.md) — historical bounded Hub/account SCOPED PASS; original aggregate failures/timeouts retained. N2 adds [finite activation and exact pending-Owner continuation](hub-owner-activation-contract.md). Lost/revoked Root recovery is not implemented by N2 |
| Native App | [Architecture](native-app-architecture.md), [plan and matrix](native-app-plan.md), [integration evidence and Windows procedure](native-app-validation.md#n2-hubapp-integration) — earlier N2/N3 Linux scopes and later Core/UI/installer/cross-build records remain source-specific. Dedicated Windows DPAPI/ACL/GUI/uninstall and physical visual review remain unaccepted. Unencrypted existing Owner identities can be vaulted and proved; encrypted PKCS#8 input unsupported |
| Controlled installation registration | [C0.1 contract](hub-installation-registration-contract.md), [native plan](native-app-plan.md#composable-installation-and-shared-state-acceptance-target), [validation](native-app-validation.md) — v1.1 crypto/wire checkpoint committed; default public availability false and actual INST integration NOT_RUN |
| Explicit native Endpoint and private Owner directory | [Contract](native-endpoint-directory-contract.md), [producer validation](native-endpoint-directory-validation.md), [actual App read/recovery](native-app-validation.md#2026-10-20-actual-app-owner-directory-integration), [actual installed plugin](native-app-validation.md#2026-10-20-actual-installed-plugin-pty-and-host-mcp-context) — bounded actual register/peers and Host context PASS; [actual cold lease/revocation](native-app-validation.md#2026-10-20-actual-default-five-minute-cold-lease-and-current-revocation) passes with manual Owner pin; faults, Leave, extended privacy/expiry and native consumption remain separate gates |
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
