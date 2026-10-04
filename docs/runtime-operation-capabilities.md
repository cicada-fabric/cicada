# Runtime operation capability metadata

The existing Session and Machine `capabilities` maps add `adapter_capabilities`.
A Session describes its selected adapter; Machine discovery describes the five
built-in adapters, including executables absent from the current host. Legacy
`wake`, `fabric_tools`, `harnesses`, scheduling, Join and Guard paths are unchanged.
The descriptions cover the ten CICADA.md §26.1 operations with four status values,
implementation/test references and limits. They are descriptive metadata and
never authorize callers, join a Group, approve work or dispatch a Runtime.

Installation uses the same executable lookup as existing adapters (including
operator binary overrides); no CLI/version/model probe or provider configuration
read is added. `present` proves only that lookup found an executable. Actual binary
version and authentication remain `unknown`, with `version_source=not_observed`.
An isolated Codex app-server version/protocol test is not attributed to every
installation. No operation is currently described as `verified`; references
identify bounded implementation checks, not current-installed-Runtime receipts.

Codex CLI queue/resume are partial: queue acceptance does not prove wake or
consumption, and returned Thread identity/read metadata does not prove model
memory or cross-host recovery. Foreground-busy safety and consumption remain
`not_tested`. General native-turn cancellation, optional-adapter original-Thread
Join/injection/resume, and shell native-session operations are `unsupported`.
Owned CLI launch/output and authenticated Node Worker paths remain partial.
Existing current Owner/Node/device/binding authorization is still required.

The validated implementation uses `dev` base `4804411` plus this additive
change, included in the current checkpoint. It changes no Client contract,
encrypted wire version, database schema, dependency, service or native compiled
acceptance artifact. Normal/race selectors on the applied source each passed 41
tests (22 top-level and 19 subtests, zero fail/skip); affected compile/vet/build,
`machine discover` and the Client contract check also passed. The receipt is
`.cicada-data/v01-finish-20261002/capability-261-main-tests-20261004/receipt.redacted.json`
(SHA-256 `3c5552d05342a073f34ebaa1bc80df817f37c999486c7101d4b44cbe41818ee6`).
`machine discover` reports five adapters and 50 operations, all unverified;
authentication and version remain unknown. These checks do not verify a
currently installed Runtime or add fields to Client DTOs. Previously delivered
Client/Native artifacts keep their original source identity.

The separate Hub restore-quarantine checkpoint and combined regression status are recorded in the [v0.1 validation report](v01-final-release-exit-checkpoint-validation.md).

2026-10-04 evidence addendum: the actual injected-before-ledger queue gate passed once on the clean-326 compiled artifact from an exact 900-input committed inventory. It observed one submission, preserved INJECTION_UNCERTAIN, refused reinjection, started zero turns and retained the historical baseline. This narrow result does not change foreground-busy safety or consumption from not_tested, and does not establish G1, model consumption or exactly-once execution. A separate offline-only Forwarder seven-check selector passed; it does not establish actual G1 or native execution.

The Client contract review follows `docs/client-hub-development.md`. Encrypted
`session.capabilities` (the Owner/role/RPC allowlist) is a different DTO from
harness `SessionContext.Capabilities`; no encrypted Client capability is added.
`ClientNodeStatus` projects only Node ID/name/verified/connectivity, and
`ClientTopologySnapshot` explicitly excludes capabilities. The new Machine
metadata therefore is not added to these Android status/topology result fields.
`nodes.list` returns fixed `NodeDeviceBinding` records, which have no capabilities
field. It lives in existing generic Machine/Fabric metadata, not a new catalog RPC.
The authoritative catalog, OpenAPI, wire document and schema remain byte-identical;
contract revision/catalog/wire are unchanged. Existing Client/Native artifacts
retain their old source identity and acquire no behavior from this overlay.

The actual recursive sensitive-key rules are unchanged. JSON-roundtripped detected
Session metadata is accepted by both Control and Fabric Join. Nested token,
credential, private-key and password field names remain rejected even with a
value of `unknown`; Join still derives ownership and grants only member status.
