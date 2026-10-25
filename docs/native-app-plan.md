# Native App plan

This plan describes the Windows-first native App inside the CICADA monorepo.
Its Go implementation remains in `cicada-go`; Android is maintained under
`apps/android` with its original history retained. The layout does not establish
native Windows acceptance. “App” is the current product name; older Client-facing wire names,
code and evidence remain attributed to their original contract and source.

## Product boundary

CICADA is operated through three independently distributed components: Hub,
Node and App. A human Owner is an independent authority, not a service role.
Manager handles user intent, management and approval; Advisor may provide
bounded recommendations; Worker performs authorized execution. These logical
roles do not collapse into the Hub or App. The Hub remains authoritative for
identity, encrypted account sessions and server-side authorization. The App
must preserve existing Hub state and Owner keys and must not synthesize grants,
Root activation, Manager authority or Node membership.

The native App is a self-contained Windows target with a Go core and native
renderer. It has no browser/WebView UI target and no browser storage. Private
identity and exact pending protocol state are kept only in the encrypted
application vault. The current Hub account protocol uses the existing
ML-KEM-768 / ML-DSA-65 application envelopes. Transport policy is explicit;
HTTPS is required by default, and HTTP is permitted only when a user/operator
explicitly enables a loopback fixture. A native strict-PQTLS transport is not
implemented or accepted by this plan.

## Direct numeric-IP TLS acceptance driver

2026-10-23 user target: one Hub process accepts secure App/Node connections by
numeric `IP:port`, without a domain, Caddy, reverse proxy or deployment-preset
external origin. Remediation and complete new acceptance are authorized; the
shared contract `hub-native-tls-v1` and API are frozen at `12fe1be`. Hub owns
the shared transport/protocol; App owns its core/UI; QA owns independent fixtures,
this matrix and the existing validation record. No DTO, TLS mode, trust migration
or implicit Owner authority is inferred by the driver.

The selector is `TestN3DirectIPTLSAcceptance`, invoked with
`CICADA_NATIVE_PAIR_LICENSES_DIR=<reviewed-complete-notices> scripts/test-native-pair.sh --direct-ip-tls`.
It reuses the pinned disposable
Docker envelope, actual Hub executable/App-core child and Node process seams,
real TCP/cryptography, persistent stores and source/binary/cleanup receipts.
The final same-source gate on integrated product `e8d31c6` plus its recorded QA
overlay is **SCOPED_PASS / exit 0**: all twelve product cases and 21 named fixture
events pass, with zero skips, both actual Codex 0.164.0/Hook/MCP address-family
summaries, stable source/binaries and confirmed owned-container cleanup. Actual
App children use their default production transport; the existing static
provider supplies the native business turns. The opaque-TCP negative lane
qualifies original committed-response recovery separately from positive direct
TLS. See the [final receipt and retained failures](native-app-validation.md#2026-10-23-complete-direct-ip-tls-integration).
A parent PASS alone cannot qualify this gate.
The earlier explicit-skip preparation receipt retains its original 125 scope.
No paid model, existing Hub, real credential or resident deployment is required.

| Case | Independent observation required after contract/source freeze | Current status |
| --- | --- | --- |
| DIP01 — fresh single Hub | New owned state and explicit temporary component roots inside the disposable environment. The actual Hub process terminates TLS directly; observe argv/listener/process tree, no reverse proxy and no preset external origin. File installation, explicit Node start and plugin connection are distinct stages. Default installation roots remain a separate final-package/manual lane. | SCOPED_PASS; Linux temporary roots |
| DIP02 — IPv4/IPv6 without DNS | Actual App-core input, Node first pairing/bridge/relay and selected-Node MCP whoami/directory/ASK/Reply (including requestWithGroup with a selected local Node, not only a Node-private HTTP client) use only IPv4:port or bracketed IPv6:port with no DNS/hosts alias or external proxy. Exercise both families with new state. Missing IPv6 is NOT_RUN, not a full dual-stack pass. | SCOPED_PASS; both numeric families, actual 0.164.0 Host |
| DIP03 — independent first trust | Independently obtained Hub/bootstrap material binds complete Hub identity and TLS trust. Before actual confirmation, public metadata is not authority: zero secret POSTs, no secret vault mutation or Owner activation. A server-supplied pin compared with that same untrusted response cannot qualify MITM protection. | SCOPED_PASS |
| DIP04 — canonical input | Valid numeric addresses/ports work; credentials, path/query/fragment, invalid port and ambiguous/forbidden IP spellings refuse according to the frozen shared codec. Socket location, cryptographic identity and signed application scope remain distinct. | SCOPED_PASS |
| DIP05 — real X.509 trust/time | Missing/wrong CA, TLS identity/SAN/pin, complete Hub key/HubID, expired and not-yet-valid certificates reject through real verification. Any injected test clock is recorded as synthetic verification time, not natural elapsed expiry; leaf auto-renewal must extend validity without changing the independently trusted CA/SPKI/Hub epoch or application identity, and must be observed through actual verification. Selecting new Hub TLS and old enrolled Node PQ simultaneously refuses without fallback. | SCOPED_PASS; controlled near-expiry leaf, saved descriptor byte-identical |
| DIP06 — fake Hub/MITM | Real attacker TLS/socket fixtures cannot receive password, code, credential or secret-bearing packets, change pins or create authority. Keep only bounded method/path/count/digest evidence, never sensitive bodies. | SCOPED_PASS; actual App and Node live-identity refusals |
| DIP07 — redirects | Metadata and secret operations reject 301/302/303/307/308 to same/foreign origins and HTTP downgrade. Trap listeners observe no forwarded secret request or credential headers. | SCOPED_PASS; five statuses × three targets |
| DIP08 — proxy/Host spoof | Poisoned proxy variables, DNS and Host/Forwarded/X-Forwarded-* cannot select trusted identity or persist a forged origin. Positive production TLS uses no custom test HTTPDoer, test TLS front or host trust-store modification. | SCOPED_PASS |
| DIP09 — no implicit Owner | TLS/IP connection, identity discovery, registration and ordinary account login do not become Root, App-device enrollment, Node/Network rights or Manager power. Exact bootstrap possession, Owner proof and current Guard remain separate. | SCOPED_PASS; Root proof precedes login, Control off |
| DIP10 — restart/replacement | Same-state process restart retains identity and current trust. Swapped Hub, TLS credentials, key version or epoch cannot silently re-pin, downgrade or recover another profile. An existing Hub missing any required application key refuses without regenerating identity; only a genuinely empty Hub initializes new keys. | SCOPED_PASS |
| DIP11 — origin compatibility | Retain old DNS/IP origin cards, vaults, signed original packets/receipts and keys. A locator change or explicit migration follows the frozen protocol; do not rewrite old signed origin bytes or borrow credentials across Hubs. | SCOPED_PASS; fresh and legacy DNS/IP origins |
| DIP12 — uncertain original recovery | Real response loss after commit and process restart retain original ciphertext/IDs/keys and authenticate the original result, without creating another authority or duplicating an uncertain operation. | SCOPED_PASS; actual Hub/App restart, one exact cache row |

The final fresh-install lane must use the user's selected default roots within
owned fixtures and the final reviewed artifacts; it must not reuse old pins or
an old TLS reverse-proxy ceremony. Historical manual Owner public-pin results
remain attributed to their old procedure. The replacement FB-03 default uses
the actual Node's one private device code and automatic independent pin; its
Linux scoped coverage is recorded in the [NPT closure](native-app-validation.md#2026-10-24-node-pair-trust-scoped-acceptance-closure); the updated fresh guide must not substitute
manual pinning. Physical
Windows DPAPI/ACL/GUI, real public-IP routing, physical ARM and real-model
acceptance require distinct receipts. Older IP/PQ/ARM and Windows user reports
retain their exact original scope and successful existing user state is preserved.

## Installed user-file root

2026-10-20 user requirement: after installation, Cicada-owned user files
default to `~/.cicada`, with a custom root selectable during installation.
Configuration, component state, protected identities/outboxes, managed
workspaces and caches belong under the selected root, with their existing
component and security scopes preserved. `~/Cicada` is the development workspace,
not an installed-user-data default. `~` denotes the current user's home on
the target platform.

The partial implementation at `73d6f9ad13c26ad7cf203e2924adcc7a46104213`
defaults new App vaults to `<root>/app/vaults`, implicit Node state to
`<root>/state` and MCP session state to `<root>/mcp/sessions.json`.
`--user-root` takes precedence over `CICADA_USER_ROOT`; a custom App launch must
retain that flag/environment. The component installer defaults its file prefix
to the selected root, without migrating existing data or launch settings.
Authenticated discovery retains original legacy/nested vault and outbox sources,
with no copying or replacement keys. Hub `/state`, managed workspace `/workspace`
and caches are not unified by this checkpoint. Global unification/migration and
physical Windows acceptance remain pending; historical paths/results retain
their original attribution.

The 2026-10-20 user-operated two-Thread batch used new workspaces and a Cicada
MCP cache under `~/.cicada/acceptance` for its bounded manual workaround.
This does not migrate, copy or recreate
the existing Node state or Windows vault, or change the original Codex account
and `CODEX_HOME`. Current priority is the consolidated product/security
remediation below; the partial paths source has separate producer and affected
integration receipts, not full installed-root or migration acceptance.

## Three-stage installation and Node connection

2026-10-22 user direction: **IN_PROGRESS**. The ordered flow is
download/install → manually start Node daemon → install/connect the Codex plugin
to that running Node. The existing `components install` is already file-only
and the persistent Node agent already exists. Formal connection
configuration/discovery and consumers are now implemented; the
[bounded actual Linux gate](native-app-validation.md#2026-10-22-persistent-codex-daemon-three-stage-acceptance)
passes on the integrated source. Rollout and broader acceptance remain in
progress; no replacement installer or Node daemon is introduced.

2026-10-22 user clarification: the same Node and OS user form a trusted-host
boundary; individual Threads are not strong isolation principals. Business
permissions govern Node-to-Network membership and service-mediated shared or
cross-domain resources/operations. The Owner panel manages policy; Hub maintains
its authoritative grants. Explicit Thread registration remains for identity and
routing. Within an explicit Node/user/Network policy scope, local collaboration
does not require human approval for every Thread pair. The current Pair flow
remains a bounded implemented mode, not the default local product target.
The new domain-level policy has bounded actual App and
[Native SCOPED_PASS results](native-app-validation.md#2026-10-23-original-daemon-domain-native-integration).
Node approval is not authority over every Network, and old Pair rights are not
retroactively expanded. Group boundaries, cryptography and current Guards remain. Record
identity/anti-misbinding checks and business authorization require separate
review; no chmod or ACL solution is selected by this clarification.

Hub/Node owns a private locator under the selected root, live Node description,
same-UID checks and pin revalidation. App owns extending the file-only component
installer to materialize the single existing plugin asset set with an absolute
executable and explicit `--user-root`; MCP and Hook use one resolver rather
than terminal deployment variables. Scope excludes C0 registration changes,
general installer/uninstaller scripts, shared Codex-daemon environment repair
and applying the earlier temporary user launcher. Concrete discovery fields,
transport, commands and failure codes remain subject to interface review.

The table retains the required observations. One source-bound Linux case now
covers existing-root file installation, old-plugin update through a persistent
environment-free Codex daemon, Node absence/start/stop/restart and original-pin
recovery. Multi-Node ambiguity and unsafe-discovery adversaries remain **NOT_RUN**
in this independent scope; producer checks and platform results stay separate.

| Observation | Required evidence after the interfaces and code are frozen |
| --- | --- |
| Install without starting | In an isolated selected root, record installed executable/plugin assets and hashes plus the process/state inventory before and after file installation, preserving its existing 0755 mode and canary. No resident Node, service/autostart, identity registration or business grant is created by installing files. Existing state and unrelated components remain unchanged. |
| Old shared daemon and old installed plugin | Start an owned Codex app-server before setup, with none of the five terminal Cicada deployment variables. Through the supported update path, update an already installed old copy of the same plugin and observe the intended current asset hashes and normal Hook trust. MCP and Hook resolve the same explicit executable/root without changing that daemon's environment, adding user-config Hook/MCP replacements or creating a duplicate plugin. Actual managed startup is required; direct stdio initialization alone cannot pass this row. |
| Node absent | Install/connect the plugin while the selected Node is absent. Observe a clear offline/unavailable result; an MCP frontend or tool catalog is not Node liveness. No Node is spawned, no alternate hostname/Hub/root is guessed, no identity is registered and no cached authority is promoted to current. |
| Explicit Node start | Start the intended existing Node only through the user's separate action. Match the live selected Node and original Hub/Owner pins through the reviewed discovery contract. MCP and Hook bind that same instance/root; connection does not itself Join a Thread, issue grants or replace keys. |
| Stop and restart the original Node | Stop only the selected owned Node and observe loss of current availability without automatic restart. Restart it manually with the original state and verify the same identities/pins and permitted epochs; consumers reconnect to the original choice. Retain uncertain requests and their original recovery material. Missing, busy or corrupt state must not silently create a replacement identity. |
| Ambiguous or unsafe discovery | Present multiple Nodes, stale hints or a same-label alternative and require explicit exact selection; a stopped/revoked selection cannot retarget another Node. Exercise the reviewed wrong-UID, substituted-instance and changed-pin refusals without inventing acceptance from a locator/socket alone. Exact errors and fixture inputs follow the delivered contract. |

Execution will extend existing isolated process/TCP/persistent-state acceptance
after Hub/App freeze the contract and implementation. Preserve the original
Node/Hub/Owner IDs, keys, root/state, epochs and operation receipts; compare only
qualified public identity and configuration observations, keeping secrets out of
evidence. Use disposable resources and read-only dependency caches. Registration,
context proof, current authorization, native consumption and platform security
retain their own gates; connection/tool discovery grants none of them.

The existing [startup diagnosis and external launcher check](native-app-validation.md#2026-10-22-installed-plugin-mcp-startup-failure-and-isolated-launcher-check)
remain historical: user-reported zero tools, independently observed ENOENT and
one direct-stdio candidate initialization PASS. The launcher/helper has not been
applied, and actual managed reconnection/Hook lookup are NOT_RUN there. Neither
that candidate nor earlier fcea942 Pair/cold evidence validates this new flow.

## Node/user/Network policy acceptance preparation

2026-10-23 actual-model follow-up: **USER_REPORTED_FAIL**. Native A Join
succeeded, but the first `cicada_resolve` with a target workspace was refused
by `CODEX_TOOL_ARGUMENTS_INVALID`. The earlier static-provider scoped pass
remains unchanged; it did not exercise this model-selected argument shape.
The [independent actual-Host directory-filter RED/GREEN](native-app-validation.md#independent-directory-filter-redgreen)
now passes on dirty `e902a836` plus the exact QA overlay; actual-model retest
remains pending. The [complete fresh-install
manual procedure](native-app-validation.md#complete-removal-and-fresh-install-manual-acceptance)
records the requested removal and new setup, with automatic FB-03 and physical
platform scopes unaccepted. The requested next delivery
is a complete fresh-install procedure, not a repair package; destructive removal
and physical platform steps require their own evidence.

2026-10-23 bounded integration results: the
[formal contract](native-local-domain-contract.md), actual App recovery and
original-daemon Native main line now have separate
[source-specific receipts](native-app-validation.md#2026-10-23-original-daemon-domain-native-integration).
The final Native gate is **SCOPED_PASS**, exit 0, on clean `88ff963`: original
umask-0002 A/B, actual App Close and by-name Host ASK/Reply, real original login
expiry, fresh native C and current-policy revoke with healthy Hub/Node.
The earlier App recovery result retains its dirty `bd0d901` plus exact QA source.
This matrix extends the isolated driver without adding production commands,
grants or authorization bypasses. Historical Pair, N2 and three-stage results
keep their scopes; the remaining adversarial and platform rows are not implied
by the positive main line.
Root has approved the design direction: the default policy lasts until explicit
revocation, with optional Owner-selected expiry; a short activation proof is not
the delegation's lifetime. A newly named private Network or an exact existing
Network uses a dedicated non-Pair Group. The Hub capability advertises server
availability, not a completed Native adapter or caller authorization.
Unexecuted rows below remain acceptance targets.

The accepted historical native positive lane used an explicit manual Owner
public-pin prerequisite. Its receipts retain that limitation; it is not the
new onboarding selected by the user below. Never initialize trust from the
arriving policy's own public key. Receiver verification uses the existing
CryptoState OwnerKeyTrust's complete public identity, current ACTIVE state and
local trust version. Missing/wrong/revoked trust refuses; policy ACTIVE alone
does not establish communication. Automatic FB-03 trust delivery now has Linux
scoped coverage; the historical manual prerequisite remains visible in those receipts.

Root-frozen supplementary requirements and separately bounded acceptance:
the actual agent automatically publishes a Node-signed local-user report with
at most five minutes validity. Prepare may leave user scope empty so Hub derives
it from that fresh exact report; App independently verifies the report in the
challenge and never substitutes its own host UID. Report freshness limits new
configuration only. Its later expiry cannot terminate an active policy or block
status, revoke or original-request reconciliation. Node-scoped Owner status
recovers Hub policy history without a cached policy ID or an online Node;
pagination must obey both row and encoded-byte limits.

The security principal boundary is the selected Node and its OS user in an
explicitly authorized Network. Threads under that same trusted UID are not
mutually isolated principals. Native-record SID/cwd/source/inode checks still
prevent misbinding; accepting a record mode under a reviewed trusted-host policy
cannot replace actual other-UID protection of private IPC and keys. In particular,
test UID 1001 with GID 1000: membership in the writer's group must not grant Node
context or signing authority. A malicious same-UID process is inside the local
trust boundary. This policy must not claim to revoke that UID's underlying OS
filesystem/IPC capabilities.

Treat forged App/Owner authority, other Nodes/Owners/Networks, modified packets,
stale epochs and replay after revocation as untrusted. An account session, visible
directory card, matching label, Node registration or old Pair does not imply the
new domain grant. Hub's durable current authorization governs service-mediated
requests; closing App must not move that authority into an online UI dependency.

| Case | Minimum independent observation after freeze | Current status |
| --- | --- | --- |
| DOMAIN-01 — one approval, new A/B | Actual App authorizes one exact Node/user/Network through its own signing action. The original persistent Codex daemon creates fresh A and B; literal Join has zero provider POSTs, exact original SID/cwd/name, and no per-Thread/Pair Owner approval. Current by-name discovery resolves exact IDs; actual Host ASK/Reply succeeds within scope. | SCOPED_PASS on clean `88ff963`: one actual domain policy, native A/B and by-name Host ASK/Reply; fresh C also joins after original login expiry. See [final gate](native-app-validation.md#2026-10-23-original-daemon-domain-native-integration). |
| DOMAIN-02 — original `0002` writer | Observe the same daemon PID/start ticks and actual `/proc` Umask 0002 before/after installation and each fresh A/B. No per-record chmod, recursive repair or new-shell umask substitutes for the writer's policy. Record actual record/tree metadata and ordinary Hook trust. | SCOPED_PASS on clean `88ff963`: same measured original daemon, actual umask 0002 and native metadata through installation and A/B/C, without record chmod. |
| DOMAIN-03 — other UID, same group | A real UID 1001/GID 1000 process in the exact owned running container cannot read Node private keys, connect to private context/signing IPC, obtain a usable context proof or cause a signed business request. Observe actual denied operations, not only mode helpers. | OS file/IPC boundary SCOPED_PASS on dirty `18c54a6`; new domain context/signing still NOT_RUN. See [bounded run](native-app-validation.md#2026-10-22-actual-other-uid-private-file-and-node-ipc-boundary). |
| DOMAIN-04 — foreign coordinates | Same Network/different Node; same Node/different Network; different Owner; absent/wrong/forged grant; stale grant or Node epoch all deny by current Guard. Capture redacted typed errors and unchanged unauthorized state. Group boundaries retain their existing contract. | NOT_RUN |
| DOMAIN-05 — App/session lifetime | Close actual App process and cross the real authenticated Hub login deadline (currently 15 minutes), separately from short report/status TTLs. Newly created Threads and new permitted operations continue only within the independently granted domain lifetime. Domain expiry itself denies; restart Hub/Node and re-read the original persistent grant. An App logical-clock offset is not Hub expiry. | SCOPED_PASS for actual normal App Close, real authenticated original login expiry, post-expiry A/B and fresh C communication on `88ff963`. Policy expiry, report-expiry-only behavior and a post-activation Native Node/Hub restart remain separate NOT_RUN scopes. |
| DOMAIN-06 — explicit revoke | Actual App revokes the exact domain. New discovery/business operations deny immediately according to the frozen linearization rule, including an already connected MCP client and a fresh Thread. Never confuse App close/logout with domain revoke. | SCOPED_PASS on `88ff963` for authenticated current same-policy revoke with healthy Hub/Node and denial of a new ASK through the already connected Host, without a new request ID. Post-revoke fresh-Thread and discovery adversaries remain NOT_RUN. |
| DOMAIN-07 — loss and original retry | Reuse existing method-specific barrier for loss before forward, loss after commit, unsigned/corrupt responses and uncertain result. Restart App/Hub/Node as appropriate; retry the original encrypted packet and reconcile the authenticated original outcome without new authority. | Activation response loss after commit plus actual App/Hub restart and original recovery SCOPED_PASS on dirty `bd0d901`. Other faults, Node restart and Native business recovery remain NOT_RUN. |
| DOMAIN-08 — concurrency and replay | Concurrent exact retries produce one original grant/outcome; conflicting requests cannot claim a different domain. Pre-revoke accepted history may be readable only as the contract permits; retry never renews revoked authority or expands scope. | NOT_RUN |
| DOMAIN-09 — legacy Pair migration | An old exact Pair, old pending packet or read cache retains its original scope and identity. It cannot silently become a Node/Network-wide grant, repair a wrong pin or revive a revoked Endpoint. | NOT_RUN; migration rule pending |
| DOMAIN-10 — identity without inference | Account login alone cannot act as Root or issue a domain grant. With Control inference off, actual identity/Owner approval, explicit Join and deterministic Guard operations remain usable. | Actual App/Node/Join/Host main line passes with Control inference off on `88ff963`. Account-login-is-not-Root remains independently proved in the older N2 scope; new-domain account-only negative coverage is separate NOT_RUN. |
| DOMAIN-11 — platform | Actual Windows DPAPI, ACL and physical GUI; Android and public HTTPS each require their own run. | NOT_RUN |
| DOMAIN-12 — empty policy cache | Preserve the original protected Owner/device vault; reconstruct actual App Core with empty local domain cache and no retained policy ID. Read by exact Node from Hub through authenticated Owner actions, including all pages and original states, without requiring Node online. An independently enrolled App2 is a separate case and cannot be simulated by copying App1 private keys. | Scope confirmed by Root; execution NOT_RUN. Independent new-device enrollment remains separate NOT_RUN. |
| DOMAIN-13 — signed user report | Actual Node publishes its exact signed writer scope automatically. Empty-scope Prepare derives that value and App verifies it. Wrong Node/UID/epoch, missing/forged/expired report refuses new setup; after a genuine activation, report expiry alone does not affect current work, status/revoke or original recovery, even with Node offline for Owner reads. | Actual Node signed report and independently verified derived-scope preparation are observed in the App/Native positive paths. Wrong/missing/forged/expired reports and report-expiry-only independence remain NOT_RUN; the Native login wait keeps reports refreshing. |
| DOMAIN-14 — bounded policy pages | Use real PQ identities/proofs so byte size, rather than row count, can truncate a page below the row cap. Verify valid continuation, bounded complete recovery, empty/bad/repeated cursors, no omitted/duplicated policies in a stable history, and no foreign Node/Owner disclosure. | NOT_RUN; full independent byte/row and pagination fault gate remains pending. |
| DOMAIN-15 — nested original receipts | Lose the actual encrypted activation response after commit; retain and reconcile the original packet/keys across restart. Real PQ proof/receipt sizes must fit the original, embedded base64, body and encrypted outer limits; exact/over-bound inputs fail atomically without fresh authorization or duplicate policy creation. | Actual original encrypted activation-response recovery passes in the bounded App slice. Exact/over-bound nested real-PQ receipt rejection remains NOT_RUN. |

Freeze dependencies are the exact Node/user/Network identity binding and selectors,
Owner/App action and signed-packet schema, grant lifetime independent of account
TTL, current-version/epoch and revocation linearization rules, native-context
record policy, local/foreign directory behavior, Group interaction, and original
request/recovery plus legacy-Pair migration semantics. No parameter value or API
is inferred from this table.

The existing `--codex-product-three-stage` gate now accepts these isolated inputs:
`CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK=0077|0002` (default 0077),
`CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS=1|2` (default 1), and
`CICADA_NATIVE_PAIR_CODEX_PREPARATION=none` (the only currently executable policy).
An unfrozen preparation value exits 125 with NOT_RUN before starting resources;
invalid umask/count or use in another mode exits 2. Parameter values are captured
in source/result receipts. The umask applies to the official daemon-start child;
the actual daemon's status must match it, with the same PID/start ticks through
all stages. QA's own evidence files retain umask 0077. No chmod/ACL preparation
is performed on Codex records. Two-Thread mode checks distinct native IDs,
matching names/cwd and the actual App-signed zero-right directory; that is still
registration evidence, not DOMAIN-01 business authorization.

Prepared reproduction, **not yet executed** on this source:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/path/to/matching/complete/notices \
CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK=0002 \
CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS=2 \
CICADA_NATIVE_PAIR_CODEX_PREPARATION=none \
scripts/test-native-pair.sh --codex-product-three-stage
```

Use the existing pinned network-none Docker, real crypto/TCP/persistent owned
databases, read-only module cache and locked task build cache. The other-UID
probe must use the exact owned container, retaining cap-drop/no-new-privileges;
the Go fixture receives no Docker socket and needs no root/setuid capability.
Literal Join's zero-POST sentinel is separate from actual Host ASK/Reply via a
synthetic static provider. That Host lane is not a real model, native queue
consumption or automatic wake. No new business row passes until actually run.

The separate `--codex-product-domain-native` entry connects the actual App/Core,
Node and native Host main line when the backend is available. Its original
official Codex 0.163.0 daemon starts with umask 0002 before file installation;
the same PID/start ticks, executable and empty deployment environment remain
required throughout. Normal plugin update and Hook trust precede distinct fresh
A/B literal Joins, each with zero provider POSTs and checked native SID/cwd/name.
An actual App approval creates one persistent policy and dedicated Group. After
normal App Controller.Close, the original Threads use actual Host MCP for
identity, by-name peers, ASK, authenticated receive and Reply. No Pair approval,
manufactured native record or caller-supplied ticket replaces those steps.

Prepared reproduction, **runtime NOT_RUN**:

```sh
CICADA_NATIVE_PAIR_LICENSES_DIR=/path/to/matching/complete/notices \
scripts/test-native-pair.sh --codex-product-domain-native

CICADA_NATIVE_PAIR_LICENSES_DIR=/path/to/matching/complete/notices \
CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY=1 \
scripts/test-native-pair.sh --codex-product-domain-native
```

Default expiry parameter 0 covers the main line without a login-expiry claim.
Parameter 1 waits past the initial authenticated Hub session expiry in actual
wall time, repeats A/B communication, then creates fresh native C and tests its
by-name exchange. It uses no App ClockOffset or shortened server lifetime.
The runner allows 30 minutes. Finally the same original App profile reopens,
logs in again if needed and explicitly revokes its authenticated current policy.
A successful post-revoke Node heartbeat and live Hub/Node qualify the fresh Host
business denial; a service outage is not the negative oracle. The public result
requires the independent native measurement, exact expected test, stable inputs
and binaries, bounded static-provider call counts and cleaned owned containers.
Typed unsupported capability is NOT_RUN/125, any failed assertion is exit 1,
and only the complete measured scope returns 0. Invalid parameter values or use
in another lane return 2 before resources start. Other-UID domain signing,
cross-scope/epoch faults, original business-request recovery, policy pagination,
legacy Pair and physical platforms retain separate NOT_RUN rows.

## Current feedback and acceptance ledger

2026-10-20 consolidation on recording baseline
`6f7f2c9bd5e98caa1ef76465f6a2a79e8062d735`. This is the single current
feedback list, not a new task book or authorization to change a protocol.
App owns product implementation/unit checks; independent QA owns integration,
security and evidence. Hub owns shared contracts and authoritative state.
Unsettled protocol/API rows remain DESIGN_PENDING before executable drivers.
Source/portable results, user observations and independent real execution stay
separate; older matrices and failures below keep their original attribution.

The bounded backend at `d3acd4bfe6f3f10867db6a5e3ae432f8477d9748` implements
[zero-right Endpoint registration and private Owner read](native-endpoint-directory-contract.md),
including immutable original identity, Leave CAS, bounded snapshots and foreign-card
redaction. Its producer checks and independent TCP fault results remain
[source-specific](native-app-validation.md#2026-10-20-independent-endpoint-and-hook-checkpoint).
Node local-bridge source `97d8a1d` and actual App read source `07bd265` are integrated,
with [independent signed-read/recovery scopes](native-app-validation.md#2026-10-20-actual-app-owner-directory-integration).
Actual installed-plugin [PTY/Host context checks](native-app-validation.md#2026-10-20-actual-installed-plugin-pty-and-host-mcp-context)
now pass a bounded Linux scope: normal trust, visible register/peers, literal
provider POST count zero and Host `whoami` returning a verified-context unjoined
refusal. Seven earlier direct-process guard events remain separately sourced.
The separate [actual default-five-minute cold gate](native-app-validation.md#2026-10-20-actual-default-five-minute-cold-lease-and-current-revocation)
passes named Pair connects, authenticated current App SID/Endpoint/BindingEpoch
matching, dual consent, Node restart/renewal before the first joined Host tool,
and current revocation, using the existing manual Owner public pin. Operator
faults, Leave, valid-ticket replay/fork, real native model/queue consumption and
physical Windows remain pending. The broader
C0 installation-registration family stays frozen; its pure results are separate.
Native navigation/CJK source at `bb0644b68627579af470ead52035d42618372c75` is
integrated, with physical Windows review still NOT_RUN.

The [2026-10-20 native A/B user batch](native-app-validation.md#2026-10-20-user-operated-same-node-pair-batch)
reports original A/B Join, separate consents, forward/reverse ASK/Reply and
window-close continuation as **USER_REPORTED_PASS**. Root separately reported
matching actual MCP child SID/cwd/Node/API after manual exact resume. Request/
message IDs, timing, automatic wake and independent native-consumption traces
were not supplied. This does not close every older N3-TT or Windows gate. The separate
[2026-10-25 fresh-install batch](native-app-validation.md#2026-10-25-user-fresh-install-and-node-plugin-digest-blocker)
reports Hub reinstall, App first setup and Enter login as USER_REPORTED_PASS;
Node file installation stopped at the packaged plugin-set digest check. The
corrected complete ZIP now passes independent metadata-driven CLI file installation;
the subsequent user continuation and its distinct log-backed direction are
recorded in the [lifecycle preparation](native-app-validation.md#2026-10-25-node-lifecycle-preparation-and-user-native-continuation).

| ID | Feedback and required independent observation | Current boundary |
| --- | --- | --- |
| FB-01 | Optional Hub/Node/App on one host; ordinary registration allows only necessary self-auth/status, with zero business rights. Account login cannot create Root, Join, communication or execution authority. | Bounded actual installed-plugin registration/peers and Host context pass with an actual App-approved Node and signed offline card; Host whoami refuses the unjoined Thread. A separate actual cold gate matches original SID/Endpoint/binding/epoch through authenticated current App status and first joined Host identity, then verifies revocation; no direct database mapping or broader C0 acceptance is claimed. Broader C0.1/H1/H2 stay frozen/NOT_RUN. |
| FB-02 | Owner chooses explicit software/business permissions or presets; Hub durably verifies the original Owner signing-key chain, exact actor/target/current versions and expiry. Unsigned/self-issued presets or revoked/stale authority deny. | Broader policy behavior DESIGN_PENDING. Existing finite Pair/status grants retain their contracts; UI presets cannot become a new authority. |
| FB-03 | Node takes only the Hub address, requests and displays a device code; the already trusted App accepts that code, reviews the exact candidate and approves once. Hub maintains the binding and Node establishes independent Owner trust without manual Owner-key/fingerprint or descriptor transfer. Business permissions are configured afterward. | SCOPED_PASS coverage of NPT01–12 through source-bound original runs and focused continuations, including actual address-only Node/TTY/App/automatic pin and existing 0.164 daemon/plugin literal Join/MCP with zero provider POSTs. Original full-run FAIL remains unchanged; this is not a fresh all-green full gate or a Windows/package/physical pass. See [closure, defects and receipts](native-app-validation.md#2026-10-24-node-pair-trust-scoped-acceptance-closure). The initial 2026-10-25 Node attempt failed plugin digest preflight; after correction the user reports Node pairing and local collaboration authorization passed. This remains distinct from independent NPT evidence and pending lifecycle work. |
| FB-04 | Own lists lead with name + workspace + Node + status and retain original SID/Endpoint ID/workspace/name. Renaming changes neither stable identity, keys nor permissions; removing an association preserves the original Thread/workspace.  Future Host object search selects discoverable cross-Node Endpoints by Network/Node/name/workspace and inserts a reference with associated metadata, without memorizing names or copying IDs. | The d3acd4b contract preserves original metadata; repeat registration cannot rename/revive. Actual App Core 07bd265 reads original names/workspaces and distinct same-name IDs through signed snapshots. Local bridge 97d8a1d is integrated; human plugin selection, rename and physical GUI remain separate.  The Host selector/reference UX is future DESIGN_PENDING work, outside this on/off/output change. |
| FB-05 | Duplicate names return AMBIGUOUS/require explicit choice. Matching name/workspace can use human labels; selection binds exact internal ID/current version. Revocation rejects an old choice rather than retargeting another same-name Endpoint.  A reference grants no authority: selection binds exact Endpoint ID/binding/version and a fresh Guard must run before send. | `e902a836` corrects schema/validator disagreement for the five directory tools. Independent actual Host resolves the real B by name/workspace, rejects wrong filters/unknown or forged fields, preserves A identity and denies after revoke. Actual-model retest, ambiguity/stale-selection extension remain pending; no rename operation is added.  Future Host reference insertion is not an accepted capability. |
| FB-06 | Current-machine and remote lists filter by this Owner or exact authorized scope. Cross-Owner discovery hides absolute paths by default; qualified Owner inventory may show registered but unpermitted objects with that distinction visible. Hub persists inventory/permissions.  A future Host picker searches the Hub current authorized directory, including only Endpoints this caller may discover across Nodes; cross-Owner privacy remains redacted. | Backend and local bridge are integrated. Actual App Core signed own-Node zero-right cards, old-Hub refusal and original-read recovery pass source-bound independent scopes. Cross-Owner privacy, paging/cache expiry and old-N2-TTL independence retain producer evidence; broader independent cases remain NOT_RUN.  That Host directory expansion remains future scope. |
| FB-07 | Plugin/MCP binds the actual original native record, SID and canonical cwd, with original Codex account, Node/API and independent Node record validation. Reject missing/mismatched records, A/B swaps and inherited SID/workspace aliases. | Actual installed-plugin PreToolUse→real Node issuer/consumer→real MCP reaches a verified-context unjoined refusal. Five missing/forged-context cases and restart nonce refusal pass separately. Valid-ticket replay/expiry, cross-context/fork, A/B late heartbeat, clear and subagent cases remain NOT_RUN; older mock probes stay separate. |
| FB-08 | Explicit local/plugin registration or Join commands execute deterministic guarded operations without model decision-making and bind the actual original context. Zero-right registration does not require a Pair/slot; communication still needs separate authority, including exact Pair/slot for the existing reserved-Pair flow. | Actual installed literal register/peers completes through the real Node with zero provider POSTs and visible name/full cwd/offline state. The distinct Host read uses two static-provider POSTs and no real model. Named reserved-Pair connect, App dual consent, default-five-minute cold lease/Node restart and first joined Host identity now pass a separate actual gate with manual Owner pin. Leave and original-intent faults remain NOT_RUN. |
| FB-09 | New installations default Cicada-owned user files to `~/.cicada`, permit custom root and apply it consistently to configuration/state/managed workspace/cache. Development `~/Cicada` stays separate. | Partial source 73d6f9a covers new App/Node/MCP paths, custom root and installer file prefix with original-state recovery. Hub/workspace/cache defaults, migration and physical Windows remain pending; no real state or Codex account is moved. |
| FB-10 | Locate and unlock old/nested vault layouts, resume the original profile/keys/outbox and reconcile uncertain original requests. Missing/busy/corrupt storage gives safe recovery, never silent first setup or a replacement identity. | Existing profile-recovery source/portable checks and old second-instance failure retain their records. Matching physical Windows recovery retest NOT_RUN. |
| FB-11 | Login-first presentation hides Node/Owner/private workspace data before current account authentication. A persistent Node registration survives the separate 15-minute App status-access expiry, explicit end and reauthorization without reinstalling or pairing again. | Earlier login/status user batches passed their reported scopes. New cross-scope, expiry/stale and privacy assertions require separate evidence. |
| FB-12 | Native navigation has clear summaries and collapsible detail, usable errors/recovery, legible CJK at real DPI and selectable/copyable public fields. Copy/export never exposes private keys, tokens or secret tickets. | Native navigation/CJK source bb0644b is integrated. Initial dirty-source normal/race, later CJK cross-builds and Root's clean-bb0644b normal 133/0/0 plus two Windows cross-builds retain distinct receipts; none retests physical fonts/DPI/GUI. The historical Chinese USER_REPORTED_FAIL remains. |
| FB-13 | Keep original Hub/Owner pins, DPAPI/ACL and exact encrypted requests before send. Loss, unsigned/corrupt responses, duplicates and restart recover authenticated original outcomes; expiry/stale data cannot renew authority. | Original Node failure/correction receipts remain. Actual App Owner-read loss-before-forward/lost-response/unsigned403 retains pending, original keys/packet and authenticated cached snapshots across child/Hub restart. Two earlier successes and four corrected recovery events retain distinct manifests; no fresh six-event aggregate or Windows/operator-fault/Park acceptance is claimed. |
| FB-14 | Closing/logout of App1 does not implicitly revoke independently valid work. App2 registers with its own keys and reads matching fresh Hub state under separate grants, without copying App1 Owner keys/session/outbox. Expiry/revocation still deny at original limits. | Window-close communication USER_REPORTED_PASS; logout/expiry adversaries, actual independent App2 and shared-state recovery NOT_RUN. Empty App2 fixture is preparation only. |
| FB-15 | Keep Go core and existing crypto/TCP/persistence, with no new coordination service or model polling. Record idle/request/resource costs and exact source/toolchain/product versions; verify upstream stable versions when choosing updates. | Root checked upstream stable versions on 2026-10-20: Go 1.27.3, Gio 0.10.3, x/sys 0.49.0 and latest official Codex CLI changelog entry 0.163.0 (2026-10-15). Exact JSON/hash evidence is linked in validation; no dependency/global runtime/deployment update was performed. |
| FB-16 | 2026-10-23 user now selects deletion of old installation identities followed by complete fresh setup, rather than a repair package. Preserve only reviewed non-sensitive evidence outside the removed root, Git worktrees/.local evidence and Codex history. | 2026-10-25 Hub reinstall/App first setup/Enter login, corrected Node pairing/local policy and native A/B are USER_REPORTED_PASS. The initial plugin digest preflight FAIL remains; corrected ZIP file installation has independent scoped PASS. Root log review confirms A→B sealed request/reply and correlated native injection; reverse is user report only. New App-close/restart/revoke and dedicated Windows DPAPI/ACL security remain pending. See [continuation and lifecycle preparation](native-app-validation.md#2026-10-25-node-lifecycle-preparation-and-user-native-continuation). No additional resident cleanup, binary replacement or deployment is performed by QA. |

The 2026-10-25 Host object-picker research is tracked in FB-04/05/06. App
collected official documentation, exact **Codex 0.164.0** experimental schema
and one synthetic native-TUI form probe; QA read/hash-checked the original
receipts without repeating the research or probe. See the
[research checkpoint](native-app-validation.md#2026-10-25-codex-0164-host-selection-research-checkpoint)
for sources, hashes, retained warnings and the proposed route.

| Capability | Docs / rules review | Exact 0.164 schema | Actual native-UI evidence / boundary |
| --- | --- | --- | --- |
| Deterministic `/cicada` | Built-in controls do not establish a plugin-defined local handler | No such registration established | Rejected before Hook: 0 Hook / 0 provider POST; not a supported entry |
| Skills / custom prompts | Prompt/skill carriers, not per-Endpoint command registries | Skill uses name/path | Ordinary skill invocation remains separate; not a deterministic picker |
| Hook display | A blocked prompt is consumed; warning presentation belongs to Host | Output fields do not register composer UI | One reason body works, but Blocked-by-hook / Hook-stopped Host headings remain |
| Resources / templates | Resource status/read carriers exist | URI/name/title/templates, contextual read | This limited `@` query received no resource calls; remote composer picking unverified, not generic protocol absence |
| Completion / `@` picking | No guaranteed remote Endpoint registration found | No app-server completion method establishes a custom picker | No completion call in this interaction; do not generalize to all MCP completion |
| Fixed enum form | Server-requested form, accept/decline/cancel | Form modes, const/title options, threadId and action/content | Two labelled choices displayed; Arrow/Enter accepted the exact opaque choice. Synthetic form sub-facts verified |
| Dynamic search / paging | No live search/on-change/paging guarantee established | Static enum/text schema is insufficient | Only fixed choices exercised; dynamic search and paging NOT_RUN |
| Model requirement / entry | Elicitation is not intrinsically a model operation | Explicit MCP tool call exists; no standalone CLI form entry proven | 0 real model calls, **3 local static Responses POSTs vs expected 2**; warning retained, no model-free CLI-entry claim |
| Colored composer reference | Desktop composer extension is not a CLI guarantee | Generic mention name/path/type lacks endpoint/binding/version or custom renderer registration | Choice is in tool result, with no automatic colored/composer insertion observed |
| Approval / native actor | Host trust/tool approval is separate from Cicada authority | Thread/mention fields are not credentials | No broad Host-policy change, Cicada grant or actor/Guard integration; selection is not authorization |
| Existing directory reuse | Repository contract governs caller scope/privacy | Explicit joined Network discovery or current Group target filters | Code reuse identified, not a newly integrated Host picker |

A feasible **future bounded route**, not an implementation claim, is to start
within an authenticated native MCP tool call, obtain a finite current authorized
result set, display privacy-safe name/Node/workspace/snapshot labels where
permitted, and accept one opaque choice. Resolve its exact Endpoint/current
binding/version within that same actor scope and run a fresh Guard immediately
before the existing send. Decline/cancel, stale/ambiguous selection or loss of
scope must not send, reselect silently, create a grant or renew authority.
Entry/trigger, cancellation and actor binding still need a reviewed integration;
the synthetic form does not establish a no-model slash/CLI launcher.

Reuse `cmd/cicada/mcp.go`'s `cicada_network_directory` /
`cicada_network_resolve`, `mcp_network.go` dispatch and the five current-Group
tools in the [Endpoint directory contract](native-endpoint-directory-contract.md).
Each Network call needs an explicit joined `network_id` and its current native
discovery grant. Broader aggregation needs an authorized eligible-Network and
pagination surface; never borrow Owner inventory for a Native Thread or infer
a global directory from “the whole Network”. Same-Owner rich metadata remains
scoped; foreign Network cards use opt-in aliases/minimal cards and foreign Group
cards authorized opaque IDs, without SID/workspace/binding exposure. Exact
internal target/version validation cannot leak hidden fields into Host labels.

Full dynamic cross-Network search and persistent colored references need an
explicitly supported Host surface or separately reviewed UI integration.
Picker/reference integration remains **DESIGN_PENDING / NOT_RUN**; research
changes no public protocol, skill/resource registry, grant or current on/off /
output implementation scope.

The approved minimal independent driver reuses actual App Core Node approval,
real PQ/TCP, persistent owned SQLite and disposable Docker. It tests only the
reviewed Endpoint boundaries; App Owner-read positives now use the actual
Core action and never substitute a driver-held Owner signer. The delivered
Node/Hook consumer now has bounded actual registration/context evidence;
remaining Pair/fault cases extend that source-bound scope. Product units
remain with App. Real queue/model operation stays
user-controlled; old large matrices and uninstall implementation are not resumed.
The old lifecycle WIP is retained in two UNVALIDATED archive commits, excluded
from current builds; see the checkpoint record for exact refs and hashes.

### Native Node on/off/status safety preparation (2026-10-25)

Root froze lifecycle v1 for Hub implementation: Linux-native
`cicada on`, `cicada off` and `cicada status`, each with `--user-root ROOT`,
for an **already paired, single-Hub, relay-only** Node.
First on supplies `--codex-bin ABS -- <original machine agent arguments>`;
Hub alone writes `ROOT/node-service.json` at mode 0600, retaining the fixed
executable, original Node/state/MCP/Hub selection. Later on reuses that config
and rejects drift. The systemd **user transient unit** is scoped by UID/root/ID;
there is no enable, lingering, sudo, boot/login autostart or new Owner approval.
Off targets only that unit and preserves state/keys/grants. Status reports local
running/stopped/failed; Hub online status remains unknown unless independently
observed. The existing [distribution contract](distribution.md), owned by Hub,
carries the implementation contract: systemd >=254, Type=exec, Restart=no,
UMask=0077, argv environment expansion disabled, a closed original-argument set
rejecting once/retry/multi-Hub, and exact transient-unit/config-SHA verification.
App owns installer/PATH and Codex slash/Hook-output UX.

Independent scoped verification now covers formal Hub `9319e1d` plus App
`d9853afd`; the table separates contract-runner results, actual legacy native-TLS
service results and unexecuted default-NPT/physical scopes. See the
[source-bound gate receipt](native-app-validation.md#2026-10-25-independent-lifecycle-hookpath-and-file-install-gate).
Historical archive status neither establishes this OS-service implementation
nor decides reuse; Hub owns that review. Root
authorizes reusing the existing user manager only for new, unique task-owned
transient test units pointing exclusively at isolated synthetic fixture roots.
Create/start/stop/reclaim only those exact units; leave all user Node processes,
units, configurations, other PIDs and current binaries untouched. No enable,
lingering, global change, privileged Docker, new manager/infrastructure or real
model is required. This extends the existing observation matrix without a
duplicate taskbook/gate; CLI/exit details follow delivered source.

| Lifecycle case | Required observation under frozen v1 | Status |
| --- | --- | --- |
| Idempotent on | First on writes only Hub's 0600 config for the already-paired single-Hub relay-only Node, rejecting once/retry/multi-Hub and preserving literal argument bytes. Repeated/concurrent on reuses it and selects one UID/root/ID unit and one writer; changed executable/arguments/root/state/MCP/Hub selection is refused. Verify actual process/service outcome, not merely start acknowledgement. | SCOPED_PASS: contract runner; actual legacy repeat-on. Real first-config/NPT path NOT_RUN. |
| Foreground conflict | On refuses the existing foreground writer's lock conflict without duplicating, killing, adopting or reconfiguring that process. Its identity, state, keys, trust and policy remain unchanged. | SCOPED_PASS: genuine locks with stub manager; actual foreground/service collision NOT_RUN. |
| Off preserves custody | Stop only the owned transient unit; preserve Node keys, Hub/Owner trust, policy/grants, revocation tombstones and pending original requests. Compare public identity/version and private-file hashes only. | SCOPED_PASS: real legacy keys/credential retained; trust/policy/pending-NPT service custody NOT_RUN. |
| Same-identity restart | On after off reuses the config and resumes the same Node, fingerprints, trust and policy/version/epochs. No new approval, deadline extension or revocation reset. | SCOPED_PASS: actual legacy key/credential restart; full NPT ACK→service NOT_RUN. |
| Custom-root isolation | Two task-owned roots and foreign-process canaries remain distinct. Each selected UID/root/ID unit, config, executable/state/MCP scope and status agree; actions on one cannot affect or retarget the other. | SCOPED_PASS: unit derivation/config contract; simultaneous real multi-root services NOT_RUN. |
| No autostart | Installation/status are inert; on uses a user transient unit without enable/linger/sudo or boot/login activation. Off stays off until explicit on. Inspect owned unit/enabling state only. | SCOPED_PASS: command properties, actual transient run and file-only install; boot/login test NOT_RUN. |
| Service failure | Systemd <254, missing user bus/service, failed execution or uncertain start/stop has truthful local failure/uncertainty; it cannot report Hub online, silently fall back to a foreground writer, recreate identity or grant authority. | SCOPED_PASS: actual exit-7 failed service/status/cleanup; missing manager/lost response use stub runner. |
| Own-unit-only stop | Repeated off is idempotent; verify Transient and config SHA before targeting only the exact UID/root/ID user unit and owned process; unrelated Node/Hub/App/Codex/service canaries survive. No broad name/PID kill, system-wide stop or privilege escalation. | SCOPED_PASS: actual exact-unit cleanup; foreign-unit refusal is stubbed, actual foreign-unit canary NOT_RUN. |

Actual systemd user unavailability leaves actual service execution **NOT_RUN**,
explicitly reported. A stub command-runner test can qualify command composition
or rejection only; it cannot establish real transient-unit start/stop, liveness
or restart. Record source/CLI/unit inputs, exits, public observations, resource
ownership and cleanup; exclude credentials, tickets, nonces and message payloads.
App owns the slash-capability probe, without a duplicate QA probe or inferring a
slash feature from model text. New user App-close/restart/revoke and Windows
DPAPI/ACL checks remain separate pending scopes; the user's ongoing old-version
tests and processes are untouched.

## Composable installation and shared-state acceptance target

2026-10-19 product target; see the [authority and custody model](native-app-architecture.md#composable-installation-and-shared-authority-target).
These future observations are all **NOT_RUN**, not extensions of N2/N3 PASS.
This target list itself does not authorize schema or wire changes; actual
protocol changes follow the reviewed C0/C0.1 contracts. Unimplemented or
unaccepted flows remain pending.

The removal portion of INST-04 is retained as a later product target; uninstall
scripts are outside this remediation stage. Window-close continuity has the
separate user-reported result above, not complete INST-04 acceptance.

1. **INST-01** Fresh installation proves its identity/registers; necessary own-status works, but Owner management, Node execution and peer operations deny without business grants.
2. **INST-02** Installing optional Hub/Node/App roles on one host does not expand existing Hub/Owner grants; a new Hub's bootstrap conveys no authority on an old Hub.
3. **INST-03** Actual Hub restart with the same database preserves IDs/keys, shared state, grants/tasks/audit, revocations and original pending/replay receipts, without extending deadlines.
4. **INST-04** Close/logout App1, then uninstall its component; preserve identities/outbox and other components/state. Authorized Node/peer work continues at original limits; expiry or explicit revocation, including original App-device dependencies, still denies.
5. **INST-05** Independently register/authorize App2 with empty profile/own keys before App1 loss. Deny access to App1 files; read matching Hub objects and fresh changes after App1 exits.
6. **INST-06** Lose all copies of the sole Owner signing key: new App/password cannot self-approve or reopen Root. Recovery is NOT_IMPLEMENTED; negative denial is not recovery PASS.
7. **INST-07** A registered attacker self-grants, impersonates Owner, crosses Hub/Owner scope, submits an unknown role or substitutes public keys: reject with no unauthorized state change.

Future execution uses owned real-crypto/TCP/persistent-state Docker fixtures,
records source/artifact identity, before/after authority, original deadlines,
requests/receipts, exits and cleanup. App2 needs qualified signer approval or
separately implemented recovery. Distinguish transport, queue and real native
consumption; Windows uninstall/security remains NOT_RUN until actually executed.

2026-10-20 independent QA preparation: these seven observations retain their
INST-01..07 scope and **NOT_RUN** state. Extend the existing N3 process harness
and native-App/Pair drivers; no new wire paths, states or selectors are assumed.
QA owns `acceptance/n3`, those fault/evidence drivers and this plan/validation;
Hub owns the frozen protocol, App/Node owners their production adapters.
Reuse opaque pre-forward/ACK-loss/delayed/corrupt-response barriers and durable
original-packet recovery. Apply wrong/replaced Owner pin, concurrency, expiry,
cross-Hub/Owner scope and Hub/Node restart faults only through the reviewed
registration/pin contract. Assert zero business authority before each separate
status/Pair grant and no expansion into the other scope. Positive Owner proofs
must come from the actual App, without driver-held signer keys or injected grants.
App2 runs in an owned separate container sharing only fixture networking/source;
mount only its own profile/synthetic input, never App1 state or a Docker socket.
Keep original outbox/identities on component removal, and test current grant
expiry/revocation independently. Exact argv and pre/post executed-binary hashes
are required. Contract revision, canonical proof tuple, outcomes, ACK/retry and
restore semantics must be frozen/reviewed before adding the actual selectors.

The independent container adapter now has a separate harness-only command:
`bash scripts/test-native-app-n3.sh --app2-isolation-only`. It proves actual
empty App Core/container/network isolation, not enrollment, business authority,
shared Hub state or INST-04/05 completion; see the [adapter receipt](native-app-validation.md#app2-isolated-container-adapter-preparation).
Ordinary missing prerequisites skip; the explicitly required gate rejects
missing control/child evidence. C0.1 v1.1 is committed; actual positive
registration cases still depend on delivered Hub/App/Node consumers.

## Checkpoints

| Checkpoint | Scope | State |
| --- | --- | --- |
| N1 — Native foundation | Typed Hub connection and health verification; strict secret-free connection card; explicit transport policy; encrypted-vault identity and exact-packet persistence; existing encrypted claim/login/inspect/logout calls; honest account/Root pending states; native controller contract and deterministic protocol tests. | In progress in the current source checkpoint. See [validation](native-app-validation.md). |
| N2 — Owner proof and finite activation | Reuse exact existing Owner keys; one-use local activation code; server-authorized Root proof; finite App lease; controlled pending-Owner continuation; trusted profile restart and authenticated recovery. Account login alone never activates Root. | Hub/App core implemented under [owner-activation-v1](hub-owner-activation-contract.md), schema 62; independent Linux protocol SCOPED_PASS (131 events, zero failures/skips). Oct 17 Windows initial flow/positive ACL are user-reported PARTIAL; dedicated native security tests and comprehensive visual acceptance remain NOT_RUN. See [validation](native-app-validation.md#n2-hubapp-integration). |
| N3 — Authorized live canvas and Node actions | Add live objects only from an authenticated, authorized Hub/Node read path; add explicit guarded Node actions and status reconciliation. Empty/unavailable canvas stays empty; no demo objects are presented as live state. | Bounded Node enrollment/status/recovery under `app-node-authority-v1`, schema 63. Reviewed `854a594` plus dirty QA: Linux 84/0/0 and separate automatic status-entry 2/0/0; earlier Ubuntu 84/0/0 retains its source. Windows `1980dce` batch steps 1–5/8 are USER_REPORTED_PASS; second-instance entry and Chinese text are USER_REPORTED_FAIL. Independent native execution remains NOT_RUN. Those source-specific results remain historical. The 2026-10-20 actual Pair batch is USER_REPORTED_PASS for original A/B Joins, dual consent, bidirectional ASK/Reply and window-close continuation; independent native traces and broader workspace/task creation remain unaccepted. Live canvas, App SSE and native Runtime acceptance remain incomplete. |
| C0 / H1 / H2 — Controlled installation registration | Ordinary installation/subject identity with zero business rights; independent Owner pin; exact status/Pair read grants; actual Hub/App/Node shared-state recovery. | [C0](hub-installation-registration-contract.md) v1 crypto/DTO checks at `c2c3ced55effd1ef90f803fea8c5b9fb24a91f17` retain their attribution. C0.1 v1.1 is committed at `e0e05582dabea005eaa7c3c2d8da3527e263682a`, with default availability false. H1/H2 and actual App/Node integration, including INST-01..07, remain NOT_RUN. Local pre-registration storage and the empty App2 fixture do not substitute for those flows. |
| N4 — Legacy naming and surface retirement | Retire transitional browser and public Client names only after equivalent App behavior, migration and interoperability gates pass. Preserve old wire identifiers and historical evidence attribution. | Not started. |

The authorized Android history-preserving subtree import is complete as
repository maintenance; see the [migration record](repository-migration.md).
It used a nonsquashed Git import and did not rewrite old history. It does not
complete N1 or transfer earlier Android acceptance to the migrated source.

## N1 acceptance boundary

N1 may report success only for the exact tests and targets that pass. It does
not establish native Windows ACL/DPAPI acceptance, strict PQTLS, Android
interoperability, physical-device behavior, public HTTPS deployment, live
canvas authorization, or product/release completion. The validation document
records each result independently. Hub account `PENDING_PROOF` remains distinct
from active Root, and the App may show a ready account session only as account
session readiness; it cannot label that state as activated CICADA ownership.

The historical N1 restart path required the same unexpired secret-bearing
claim code for an initial claim, or the same still-valid public connection card
for an existing account. N2 adds authenticated local-profile discovery and
resume without installer material, Root completion and exact pending-Owner
continuation. Historical N1 receipts retain their original limited scope.

## N2 independent acceptance matrix

The independent driver is `scripts/test-native-app-n2.sh --require-n2`. It uses
real ML-KEM/ML-DSA/AES-GCM, loopback TCP, persistent SQLite, encrypted Linux
vaults and separate Hub/App-core processes in disposable Docker. No Control
inference service runs in the independent fixture. The table maps obligations
to actual tests; the [run receipt](native-app-validation.md#n2-hubapp-integration)
determines their result. It does not transfer Linux results to Windows.

Test names below abbreviate `TestN2Activation` as `A:`, `TestN2Account` as
`C:` and otherwise use the complete test name. Independent tests live in
`cicada-go/acceptance/n2`; `server` and `store` explicitly identify narrower
production-package guards. Full names and every required subcase are enforced
by `scripts/native_app_n2_evidence.py`.

| ID | Fault or boundary | Required observation | Tests and evidence boundary |
| --- | --- | --- | --- |
| N2-01 | Wrong full Hub public key/pin | Reject before secret POST/vault creation | `C:PinAndExpiryBeforeSecrets`; `A:PinAndConsentBeforeSecrets/wrong-full-pin` |
| N2-02 | Expired finite credential | Independent local and server expiry rejection | `A:PinAndConsentBeforeSecrets/expired`; `A:ExpiredProofAndCancelledMaterial/expired-real-credential` constructs a short valid credential through the trusted Store issuer, waits in real time, then sends the original encrypted packet |
| N2-03 | Consumed credential, exact duplicate and changed request | Exact durable receipt; changed request fails | `A:ConcurrentDistinctClaimsAndExactCompletion`; `C:ConcurrentClaimAndConflictingReplay`; `A:ReplacementAfterFencedCancellationPreservesKeys` additionally checks safe operator replacement after a signed terminal result |
| N2-04 | Concurrent distinct candidate claims | One durable candidate wins | `A:ConcurrentDistinctClaimsAndExactCompletion` and `C:ConcurrentClaimAndConflictingReplay`; the former also runs under `-race` |
| N2-05 | Wrong Owner/account/Hub scope | Hub rejects independently of local preflight | `C:ForeignScopeAndMissingDeviceProof`; `A:CryptographicNegativeGuards/wrong-owner-scope`; real lower-level encrypted packets bypass local body preflight |
| N2-06 | Missing Owner KEM/signature proof | No Root, credential, enrollment or lease effects | `A:CryptographicNegativeGuards/{missing-kem,missing-owner-signature,wrong-owner-signature}`; actual Hub rejection plus reopened database assertions |
| N2-07 | Forged/expired/wrong-purpose grant | No unauthorized enrollment | `A:CryptographicNegativeGuards/{forged-grant,wrong-grant-purpose}`; real short proof window in `A:ExpiredProofAndCancelledMaterial`; server `TestN2ExpiredGrantChallengeCannotActivateRoot` |
| N2-08 | Stale setup/account/device epochs | Historical receipt never revives authority | `A:CryptographicNegativeGuards/stale-account-epoch`; `A:ExpiredProofAndCancelledMaterial/cancelled-material-and-late-request`; `A:HistoricalReceiptNeverRevivesCurrentAuthority`; `A:AppRestoreEpochSettlesOldReceiptWithoutRevival`. Isolated SQL epoch fault is not a full backup/restore run; store `TestN2RestoreFencesLeaseAndPreservesCredentialAndRoot` calls the real restore fence |
| N2-09 | Unknown/substituted App | Password/public capability never bypass exact device | `C:UnknownDeviceCannotUsePassword`; `A:CryptographicNegativeGuards/wrong-app-key`; server `TestN2ClientDispatchAndCapabilitiesIntersectFiniteLease` tests actual dispatch allowlist/login guards |
| N2-10 | Lost response, unsigned 403, corrupt PQ response | Authenticated settlement only | `C:ProcessRecovery` covers six account operations × four faults; `A:AppProcessesAndLargeStatusRecovery` covers prepare/complete/status × three faults, including actual nested receipt larger than 96 KiB |
| N2-11 | Kill Hub/App and reopen persistent state | Original bytes, IDs and keys survive | `C:ProcessRecovery`; `A:AppProcessesAndLargeStatusRecovery`; `A:ConcurrentDistinctClaimsAndExactCompletion`. Child Hub/App are actually killed and restarted; not just controller recreation |
| N2-12 | Same operation ID/different ciphertext or nonce reuse | Reject conflict; keep original receipt | `A:ConcurrentDistinctClaimsAndExactCompletion`; `A:CryptographicNegativeGuards/reused-nonce`; `C:ConcurrentClaimAndConflictingReplay` |
| N2-13 | Account versus Root; Control inference off | Independent account flow; no general Manager authority | `C:ProcessRecovery` finishes claim/login/inspect/logout with Root pending; all independent activation fixtures omit Control; post-proof App tests require separate login and keep Manager unavailable |
| N2-14 | Exact legacy pending Owner | Keep credential, IDs, public key and old device | `A:LegacyImportedOwnerKeepsCredentialAndIDs` imports four real OpenSSL synthetic PEMs; tests unknown replacement Owner at Hub; server `TestN2LegacyContinuationRetainsPendingOwnerCredentialAndDevices` |
| N2-15 | Profile reopen without installer code | Authenticate saved profile and current Hub state | `A:AppProcessesAndLargeStatusRecovery`; helper removes installer material on every profile reopen; `A:AppRestoreEpochSettlesOldReceiptWithoutRevival` checks obsolete session recovery |
| N2-16 | Vault failure before send | Zero POSTs; no memory-only continuation | `A:VaultFailureBeforeSend` uses a deterministic path/persistence failure; existing App guard complements it |
| N2-17 | Two Hub scopes | Distinct keys/profiles; no inherited session | `A:TwoHubVaultScopesRemainIndependent` uses two real TCP Hubs and one encrypted-vault root |
| N2-18 | Windows DPAPI, ACL and GUI | Native execution receipts required individually | Oct 15 automated native execution NOT_RUN. Oct 17 user-reported initial GUI flow and positive ACL inspection PARTIAL; synthetic native DPAPI/ACL driver is separate and awaits execution. See [dated observations](native-app-validation.md#windows-native-security-driver-and-user-observations--2026-10-17) |
| N2-19 | Finite lease expiry/late old receipt | No renewal or revival | `A:AppClockExpiryDoesNotRenewLease` advances App `Config.Now`; store `TestN2LeaseGuardExpiryScopeAndExactHistoricalRecovery` uses logical time/past lease. Oct 17 natural expiry UI is user-reported; precise elapsed-time and new-operation Guard receipts remain NOT_RUN |
| N2-20 | ABSENT and late original | ABSENT cannot settle uncertainty; durable fence can | `A:AbsentStatusKeepsPendingUntilLateOriginal`; `C:ReconcileFencesLateCorrectRequestAcrossRestart` races under `-race` too; server `TestN2AccountReconcileRacesOriginalWithoutLateCommit` |
| N2-21 | Wrong password then correct password | Signed fence allows safe re-login | `A:AppWrongPasswordFenceAndRelogin`; server `TestN2AccountWrongPasswordAndExpiredSessionRecoverWithDurableFence` |
| N2-22 | Expired/revoked session and account epoch change | Re-login independent of revoked lease; no old-session revival | `A:AppWrongPasswordFenceAndRelogin` injects persisted session revocation; `A:AppRestoreEpochSettlesOldReceiptWithoutRevival` keeps the lease revoked after new login; server test above injects a past account-session expiry and sends the saved packet over real TCP |
| N2-23 | Native interaction and visual quality | Smooth, legible real desktop setup/recovery; no secret disclosure in snapshots or error UI | Oct 17 initial native GUI operation user-reported PARTIAL; comprehensive visual/interaction review remains NOT_RUN |

Each run must record source manifest before/after, dirty status, builder image
ID, test binary hash, selectors, individual exit codes and skips, resource
ownership/cleanup and artifact hashes. No selector match, missing prerequisite,
skip or unimplemented row is a pass. Default baseline success is a scoped
result only; `--require-n2` returns zero only for its complete declared Linux
scope, with every expected test present and zero failures/skips. Prerequisite
failure returns 2; gate failure returns 1. Physical NOT_RUN rows remain separate
even when that scoped gate passes. Android, native Runtime, physical device, public HTTPS and native
PQTLS are separate NOT_RUN scopes.

## N3 independent safety model and acceptance matrix

N3 was authorized on 2026-10-17 from clean `f8b5e58`. The first Node target is
Ubuntu **24.04.3 x86_64/amd64**, ordinary user **zyf / UID 1000**, Codex
**0.163.0**; Windows App remains x64. These are target requirements, not
observations that those programs have run. ARM64, installer/root relocation,
N4 and broad business/runtime acceptance are outside this checkpoint.

Hub owns the shared protocol and production Guard; App owns the production
controller/UI. Independent acceptance owns `cicada-go/acceptance/n3`, its
disposable driver/evidence and this matrix. The integration owner reviewed `app-node-authority-v1` types at
`a545988ac6c038da180413d4f29ffbf740c402d4`, then shared proof/framing helpers at
`5f509befa6065ac41abeb23451ef8d41cc2c76aa`. The Store checkpoint is
`e078c58d97413f5e0457acb3c586afbef1a9d438`, schema **63**. The production App controller was reviewed at
`8df8ae5034f819ff3d839b6574f02c3c887af253`, followed by actual Hub/HTTP/CLI runtime
`af92b16d3c0dc616280d694986692a2cbb1caa71`, phase **HUB_NODES_ONLY**.
The runtime fixes were reviewed at `ec72bf2891bcc7bf98565beedbac54e51f35b7db`;
UI-only guidance followed at `e81b9dce28133861b5a8c5f45bb065e9721309f3`.
Deadline/saved-Node UX followed at `530f5d5c24d16887bc9ef28be5a14beab03e920a`,
then bounded automatic status at `854a5943285b413ebf6d133af3685dd7f300c929`.
The evidence driver now pins 67 reviewed normative/helper/Store/App/runtime
files and records all inputs separately. Latest Linux gates passed separate
84-event and two-event inventories on the same frozen dirty QA source. The
earlier Ubuntu 84-event receipt and all original FAIL receipts retain their
sources in the [validation record](native-app-validation.md#n3-idle-decay-and-automatic-status-follow-up).
The Hub-owned
[contract](hub-app-node-authority-contract.md) defines the protocol; this matrix
defines independent invariants.
Preparation or reuse of an existing N2/Client guard cannot count as N3 PASS.

The assets are the established Owner/account/Hub/App identities, each actual
grant instance, target Node identity/credential/generation, current epochs and
CAS versions, exact pending ciphertext, terminal operation/digest fences and
authenticated current observations. Adversaries may own another App/Node key,
replay an old valid packet, replace a preview or grant, race cancellation or
expiry against confirmation, lose replies, crash processes or deliver delayed
packets. Transport or UI availability is not authority. Host administrators
remain trusted; no stronger enclave/host compromise claim is introduced.

An existing account session and Root proof do not silently widen or renew the
N2 fifteen-minute lease. New authority must be explicit, finite and bound to
the reviewed instance/target. Every accepted request keeps its original grant
instance: later authority cannot retroactively legalize that request. A cached
receipt may describe past success but must not revive current permission.

Before the first N3 POST, including bootstrap status, the App must fetch
`/v2/owner/app-node/capabilities` and recognize the reviewed profile and limits.
Unsupported/404 means zero secret POSTs and zero new N3 pending operation.
The five account operations are prepare, complete, status, cancel and reconcile;
the INITIAL Client RPC allowlist is exactly `nodes.confirm`. `session.capabilities`
is not allowed. Node status uses its separate HTTP read permission and returns
only the selected Node. READ_EXISTING has an empty RPC allowlist and zero
confirmation budget. Both profiles bind the exact account-session ID/expiry,
not merely any live login for the same App. After session termination, a new
login may request a new explicit status-only instance, but cannot revive the
old grant or its pending packets.

A status read is not a durable mutation: a cached historical receipt or a signed
`READ_EXPIRED` for the exact read digest may settle only that read. A mutation
requires its original receipt or durable operation/digest fence, with atomic
Client counter handling; a counter gap/conflict must retain uncertainty.
Diagnostic caches have rolling bounds, not a lifetime polling quota.

The Store additionally requires the retained N2 Client session epoch **1**;
a later reset/restore epoch cannot be silently adopted into the first N3 grant.
`LoginRequired` describes a valid matching bound login, not whether a grant is
live: an expired/self-cancelled grant with the same live login has false, with
no operations/Node; an old session-ended instance under a new login has true.
Fresh authenticated terminal diagnostics must release an obsolete unconfirmed
preview so the user can explicitly start a safe new INITIAL instance.

An INITIAL instance that became ACTIVE but never confirmed any Node may be
abandoned: after authenticated expiry or self-cancellation, with no pending
operation and no local/server successful confirmation provenance, explicit
consent may create a new INITIAL instance from a valid pending candidate/code
and current head. The same still-valid unconfirmed candidate may be explicitly
selected again; its code is a selector, not authority. This cannot
renew N2, erase history or bypass security revocation. Once confirmation has
succeeded, only READ_EXISTING for the same exact binding is eligible. Acceptance
must include an abandoned/expired-before-confirm to new-code success case.

Node freshness is derived from an accepted bound relay heartbeat in
`machines.last_seen`, capped at 120 seconds. Relay-only heartbeat `{}` does not
make `machines.status` Worker-available. Empty, malformed, future or preapproval
heartbeat is UNKNOWN; fresh is CONNECTED and aged is STALE. V1 has no OFFLINE
shutdown signal. Repeated newer observation times never extend an old heartbeat.

The reviewed helper applies the size erratum: only the five N3 account
operations use a 384 KiB inner limit; default Client/N2 remains 256 KiB. Outer
384 KiB, body 192 KiB, original/receipt 128 KiB remain unchanged. Its producer
and integration review retain the real encrypted PQ outer-frame boundary tests
in the [Hub helper receipt](hub-app-node-authority-validation.md). These receipts
do not establish an independent production Hub/App/Node N3 result.

| ID | Boundary/fault | Independent acceptance oracle | Executed scope, 2026-10-17 |
| --- | --- | --- | --- |
| N3-01 | Trusted Hub and stable identities | Full pin/origin/account/Owner/App scope is checked before secret POST; preserve existing identities and keys | SCOPED_PASS — declared Linux process scope |
| N3-02 | Explicit instance authority | Account/password/public capabilities and expired N2 authority cannot create N3 permission; explicit consent binds the exact reviewed grant instance and allowlist | SCOPED_PASS — declared Linux process scope |
| N3-03 | Old packet versus renewed authority | Persisted old packet retains its original grant instance/digest; granting new authority never executes the old packet under the new grant | SCOPED_PASS — declared Linux process scope |
| N3-04 | Foreign scope/key/target | Real Hub independently rejects wrong Hub, Owner/account, App/device/instance, target Node/key/generation; do not count local constructor refusal as server rejection | SCOPED_PASS — declared Linux process scope |
| N3-05 | Existing Root and new signed consent | Reuse the exact already ACTIVE Root proved during N2, without a fresh KEM ceremony. Pending/unproved/revoked Root, missing/forged domain-separated ML-DSA consent, wrong signer or unauthorized purpose/scope leave authority unchanged | SCOPED_PASS — declared Linux process scope |
| N3-06 | Epoch/restore/revocation | Stale account/device/Node/grant epochs and restored-state receipts cannot authorize new execution or revive revoked state | SCOPED_TCP_EPOCH_REVOCATION; producer Store restore fence separately; full backup/restore NOT_RUN |
| N3-07 | CAS/preview substitution | Missing/stale version or changed target/candidate/digest is refused without consuming a valid preview or creating partial bindings/credentials | SCOPED_PASS — declared Linux process scope |
| N3-08 | Concurrent claim/confirm | Distinct candidates have one durable winner; identical exact retries recover the original result; another Owner/Node key cannot overwrite the winner | SCOPED_PASS — declared Linux process scope |
| N3-09 | Grant expiry | Real short valid windows expire over TCP; logical clock tests and actual long wall-clock waits are recorded separately | SCOPED short-intent wall expiry; full N3 lease wall expiry NOT_RUN |
| N3-10 | Revoke/expiry versus confirmation race | Current authority check and mutation commit share a transaction; each observed winner is consistent with one allowed ordering, with no partial effect or execution after a terminal fence | SCOPED cancel/confirm ordering; queued-expiry producer tests separate |
| N3-11 | Before-forward and after-commit loss | Fault traces distinguish an unsent original from a mutation actually committed before its response was lost; confirm effects from persisted production state | SCOPED_PASS — declared Linux process scope |
| N3-12 | Hub/App/Node crash windows | Actual owned child-process kills, disk reopen and exact request reuse preserve IDs/keys and one mutation; controller recreation alone is not process-crash evidence | SCOPED_PASS — declared Linux process scope |
| N3-13 | Absent original, fence, late delivery | An authenticated absence observation alone cannot clear uncertainty. Durable original operation/digest terminal fence precedes replacement; delayed original cannot commit after restart | SCOPED_PASS — declared Linux process scope |
| N3-14 | Duplicate/conflicting packet | Exact ciphertext recovers the exact durable receipt; same operation ID with changed ciphertext or reused nonce cannot replace it | SCOPED_PASS — declared Linux process scope |
| N3-15 | Unsigned/corrupt response | HTTP 403, timeout and corrupt PQ response retain pending uncertainty; only authenticated target-bound settlement permits progress | SCOPED_PASS — declared Linux process scope |
| N3-16 | Local persistence failure | Fail before network send; do not keep a memory-only replacement or regenerate identities after vault/disk failure | SCOPED_PASS — declared Linux process scope |
| N3-17 | Target Node status privacy | Return only the authorized target Node projection; no owner-wide goals, tasks, workers or unrelated Nodes leak into the status payload | SCOPED_PASS — declared Linux process scope |
| N3-18 | Genuine Node-only liveness | Installation, binding, credentials or a cached snapshot never imply online; only accepted current target Node heartbeats establish bounded Node freshness | SCOPED_PASS — declared Linux process scope |
| N3-19 | Cached-online decay | Heartbeat/as-of TTL governs display on failed reads and elapsed time alone; fetching/recovering an old response does not refresh its heartbeat time | Core/TCP SCOPED_PASS; portable Gio Router RED/GREEN; old Windows USER_REPORTED_FAIL, `1980dce` stop/restart stale/online USER_REPORTED_PASS; exact timing trace NOT_RUN |
| N3-20 | Node process/generation recovery | Restart/reconnect preserves approved Node identity; old credentials/generation cannot publish freshness or overwrite new status | SCOPED restart/revocation and real Node restart/heartbeat after App SELF_CANCEL; natural full N3 lease continuity and key rotation NOT_RUN |
| N3-21 | Honest Runtime/SSE boundaries | Node freshness is not an SSE live subscription or native Runtime availability/execution. Unrun Codex/native sessions remain unknown/NOT_RUN; no demo objects are rendered as live | SCOPED Node presentation; App SSE/native Runtime NOT_RUN |
| N3-22 | Target platform/user | Validate actual OS/arch, UID/nonroot and Codex version only on the disposable target fixture or explicit physical receipt; a bookworm Go builder does not prove Ubuntu target behavior | Earlier-source Ubuntu 24.04.4 container SCOPED_PASS; e426 physical Ubuntu initial binding/heartbeat USER_REPORTED_PARTIAL; latest 854 gates bookworm only; user-service/reboot/Codex execution NOT_RUN |
| N3-23 | Private evidence and cleanup | Real crypto/TCP/persistent stores; task-owned state, ports, caches and resources; hashes/safe facts only, no secrets or full private payloads; modules read-only; exact cleanup | SCOPED_PASS — declared Linux process scope |
| N3-24 | Windows/public/native Runtime | Independently attributable native Windows interaction, public HTTPS, physical Node and real native Runtime receipts required; Linux fixture results do not transfer | e426 historical PARTIAL/idle FAIL/manual stale PASS retained; `1980dce` Windows batch 1–5/8 USER_REPORTED_PASS, second-instance/Chinese USER_REPORTED_FAIL; dedicated native security/high-DPI, service reboot/full N3 lease continuity/Runtime NOT_RUN |
| N3-25 | Abandoned INITIAL and explicit read authority after expiry | Before any successful confirmation, authenticated terminal/no-pending state permits a new explicit INITIAL code/grant/head; after confirmation and consumed code, explicit Owner consent may create a new finite status-only instance for the same exact approved Node/binding, with current head CAS and zero confirmation budget; no re-pair, key upgrade or N2 renewal | SCOPED self-cancel/session replacement; full N3 lease wall expiry NOT_RUN |
| N3-26 | Read-only renewal cannot authorize mutation | Old packets cannot borrow the new read grant; that grant cannot confirm; changed Node/binding/key/generation is rejected, and cached online state still follows the original heartbeat rather than a new poll's observation time | SCOPED_PASS — declared Linux process scope |
| N3-27 | Automatic selected-Node status | Lock-held exact scope/full binding/live permission checks precede new durable ciphertext; only status reads; wrong target/expiry skip without write; uncertain response freezes later ticks/restart; signed terminal settles; manual recovery precedes new reads | Separate actual Core/TCP 2/0/0 SCOPED_PASS; portable coordinator tests separate; Windows automatic stale/online USER_REPORTED_PASS, exact 30-second cadence and fault traces NOT_RUN |

The original cases below run in the full 84-event selector. The earlier Ubuntu
receipt and latest Linux receipts retain their independent source attribution;
the two automatic-entry cases use a separate selector and were not run by the
earlier Ubuntu gate. Exact names/subcases are in each result's `expected_tests`.
Zero matching cases, missing prerequisites, skips, unknown outcomes and
harness-only success never establish N3 acceptance. N2/Windows history and
earlier failures retain their tested source attribution.

| Matrix rows | Actual independent cases (`TestN3` prefix) |
| --- | --- |
| 01–02, 05 | `ActualAppUnsupportedCapabilitiesSendNoSecrets`, `ActualIdentityFlowAfterWallClockN2Expiry`, `ActualAppConsentBindingRelayAndWallClockDecay` |
| 03, 25–26 | `OriginalInstanceCannotBorrowNewInitialOrReadGrant`, `ActualAppSelfCancelRequiresExplicitReadOnlyConsent`, `ActualUnconfirmedSessionReplacementAllowsNewInitial` |
| 04–07, 09 | `ServerRejectsIndependentProofScopeAttacks`, `ServerRejectsForgedCompletionPreservingPreview`, `RealPersistedEpochAndRootSessionFences` |
| 08, 14 | `ConcurrentPrepareConfirmAndConflictingReplay` |
| 10 | `RealConfirmationVersusCancellationOrders` |
| 11–15 | `ActualAppExactFaultRecoveryAndLateOriginal` (five operations × six faults), `ActualConfirmationLocalCommitCrashBoundaries` (three local CAS windows) |
| 13–14 | `ReadCacheRollingBoundsAndPermanentMutationRecovery` |
| 16 | `ActualVaultFailureStopsBeforeSecretSend` |
| 17 | `StatusContainsOnlyExactSelectedNode` |
| 18–21 | `ActualImmediateRelayHeartbeatRetainsSubsecondOrder`, `ActualAppConsentBindingRelayAndWallClockDecay`, `RevokedNodeCannotPublishOrReuseReadProvenance` |
| 22–23 | Driver-recorded runner OS/arch, explicit UID 1000, image/binary/source hashes, isolation and owned-resource cleanup |
| 20, 27 | `ActualAutomaticStatusKeepsScopeAndSelfCancelledNode`, `ActualAutomaticStatusLossFreezesTicksUntilExactRecovery` — separate `--auto-status-only` selector, two events |

N3-05's inactive/unproved-human and missing-N2-history checks additionally use
the separately attributed producer Store case
`TestN3StoreMissingCompletedN2AndInactiveHumanDenyAuthorityKeepDiagnostics`.
For N3-06, independent TCP cases mutate only stopped private DB epoch or
revocation rows and restart the actual Hub. The producer's
`TestN3StoreRestoreAndSecurityRevocationPreserveIdentityCountersAndHistory`
separately checks the Store restore fence and historical receipt. A full
backup/restore campaign is **NOT_RUN**. N3-09 proves actual short intent expiry;
natural full 15-minute N3 lease expiry remains **NOT_RUN**. The old N2 lease did
expire naturally in both final runs. N3-10 checks actual cancel/confirm ordering;
the producer's transaction-time tests separately cover expiry while queued.
N3-20 covers retained INITIAL recovery and revoked credentials/bindings;
Node key rotation/UPGRADE remains outside the slice. The rolling cache's
five-minute age is an explicitly controlled persisted fixture, not a wall wait.

The 84-event Core actor queries `Controller.Snapshot()` after its real wait;
it does not prove native no-input redraw. Latest automatic-entry tests invoke
the production flagged refresh through the actual App child, not a simulated
client. Their triggers are explicit test commands, not a real Windows timer.
They separately prove UNKNOWN-to-real-heartbeat status, unchanged read grant,
counter/budget and keys, no-write wrong-target/logical-expiry rejection,
SELF_CANCEL Node continuity, manual READ_EXISTING consent, server-signed
revocation settlement, and loss/restart/multi-trigger freeze followed by exact
manual recovery and fresh reads. The later `1980dce` Windows batch reports
automatic stale/online behavior and account-session expiry hiding; full natural
N3 grant expiry/Node continuity and precise Windows clock/event-loop traces
remain NOT_RUN.

The supplied Ubuntu 24.04.3 / x86_64 / UID 1000 / `codex --version` 0.163.0
output is **USER_REPORTED_ENVIRONMENT**. That original environment output alone
did not establish an installed/approved Node or native Runtime execution. Later
`e426` user-reported initial binding/heartbeat and Root's read-only process/binding
observations are recorded separately; they do not accept the new Windows build
or full Node service/reboot/lease continuity. Repeated status polling must
not extend an old heartbeat's freshness merely by receiving a newer ObservedAt.

## Login-first presentation safety matrix

Prepared from `5fee32c` on 2026-10-17; independently reviewed implementation
`1980dced7c20da0be40ac8a03892a911d2ffab9b`. This is the presentation change for an
existing trusted configuration before account login. It does not introduce a
new account system, require password entry on every launch, or replace existing
first-connection/Owner setup. A restored session may reveal the workspace only
after this process completes trusted profile recovery and a fresh authenticated
server inspection. Cached profile metadata, Root ACTIVE and a saved Node binding
alone do not establish login.

The Core's current SESSION_ACTIVE, OWNER_READY and OWNER_PROOF_PENDING account
states may qualify with a verified Hub and an explicit future session deadline.
OWNER_PROOF_PENDING must remain usable after account authentication; login does
not activate Root or widen Node/Manager authority. SESSION_RECHECK_REQUIRED,
LOGIN_REQUIRED, missing/malformed/expired deadline and an unverified Hub stay
behind the presentation gate. Account recovery retains priority. A Node-only
uncertain read does not itself end an otherwise verified account session.

App owns the implementation and UI tests. QA independently reviewed the actual
root layout, privacy predicate, input transitions and recovery reachability.
App's final portable normal/race runs each passed 141/0/0, with Linux/Windows
vet and Windows cross-build exit 0. These are **SOURCE_REVIEW / PORTABLE_PASS**,
not native Windows execution or visual acceptance. See the
[source-bound receipts](native-app-validation.md#login-first-presentation-follow-up).
Existing 84-event and automatic-entry two-event receipts retain their tested
source. No Hub/Node deployment or key change is part of this work.

| ID | Boundary | Required oracle | State |
| --- | --- | --- | --- |
| LOGIN-01 | Existing configuration, not logged in | Root layout exposes only the login form and necessary neutral entry/recovery controls; no status card, stored account/Owner/Node values, fingerprints, grant deadlines, canvas or preview | SOURCE_REVIEW + PORTABLE_PASS; basic signed-out screen USER_REPORTED_PASS |
| LOGIN-02 | Cached or untrusted session | SESSION_RECHECK/expired/malformed/no session or unverified Hub never reveals details, even with cached Root ACTIVE, Node online, bound Node or stored receipts | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-03 | Current account authentication | Freshly verified SESSION_ACTIVE/OWNER_READY/OWNER_PROOF_PENDING may reveal the workspace; Root pending remains pending and available actions are unchanged | SOURCE_REVIEW + PORTABLE_PASS; original-account login restoring the same Node USER_REPORTED_PASS |
| LOGIN-04 | Input privacy | Stored username is not prefilled; password stays masked and is cleared on submit, login/authentication loss and full scope change. Clearing is transition-based so typing is not erased every frame | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-05 | Hidden sections and stale input | Details, fingerprint expansion, preview/canvas and old profile identity widgets cannot leak through an alternate branch or dispatch hidden management/Node actions before login | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-06 | Multiple profiles and routing | Prelogin selection uses neutral labels bound to exact trusted profile IDs; never silently pick another account/Hub from a username. Credentials are sent only through the existing verified origin/pin flow | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-07 | Recovery without identity disclosure | Account Recover/Retry and, where required, saved Node recovery remain reachable with neutral copy; retain original IDs/ciphertext/receipts and priority. An unauthenticated screen does not display Node identity to explain recovery | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-08 | Necessary first connection | No-profile/unfinished setup can still reach the existing controlled connection, exact Owner import/proof and activation flow; the login view neither fabricates a Hub nor generates new keys or authority | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-09 | Logout, expiry and scope transition | Hide old workspace information when account authentication is lost/rechecked or scope changes; clear stale input/expansion state, while preserving encrypted profiles, keys, Node bindings and pending recovery | SOURCE_REVIEW + PORTABLE_PASS; logout/account-session expiry hiding USER_REPORTED_PASS; scope-transition physical cases unverified |
| LOGIN-10 | Automation and authority | The presentation gate grants nothing and does not mutate AvailableActions. A hidden screen pauses future Node ticks and reopening starts a fresh interval without discarding an in-flight packet. Existing guards still require current exact permission; ordinary Node pending with valid account login retains its separate busy/recovery semantics | SOURCE_REVIEW + PORTABLE_PASS |

`TestAccountInformationRequiresCurrentTrustedSession` covers LOGIN-02/03;
`TestPreLoginPresentationHidesIdentityButPreservesGenericRecovery` covers the
projection, original action/profile locator preservation and recovery ordering
in LOGIN-01/05/06/07. `TestLoginRestoresOriginalBindingAndFirstSetupStillHasItsOwnFlow`
covers LOGIN-08/09, and `TestPresentationInputResetUsesFullScopeAndAuthenticationEdge`
covers LOGIN-04/06/09. `TestNativeAccountScreenPauseRestartsIntervalWithoutDroppingPending`
covers LOGIN-10's coordinator behavior. The root layout branches, widget reset,
credential dispatch and unchanged Core guards were reviewed separately; these
portable tests do not execute the Windows root renderer, vault or TCP recovery.

On 2026-10-17 the user reported that the three basic Windows 11 steps matched
expectations: signed-out pure login, original-account login restoring the same
GPU1 Node, then logout hiding the information. This is **USER_REPORTED_PASS**
for the clean `1980dce` delivery candidate, SHA-256
`27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`;
see the [dated observation](native-app-validation.md#login-first-presentation-follow-up).
It is not independent native execution or complete Windows acceptance. The
later [eight-step user batch](native-app-validation.md#windows-11-eight-step-user-batch)
also reports steps 1–5/8 passing: wrong-password/correct-login path, reopen,
automatic stale/online, self-cancellation, explicit same-Node read access and
account-session natural expiry/relogin. The optional recovery branch in step 1
was not reported separately. Step 6's second-instance first-setup/device-code
entry is USER_REPORTED_FAIL; step 7's Chinese text is USER_REPORTED_FAIL, with
other layout/input subcases not individually reported. The App owner handles
the entry defect; the user deferred font/style work. Dedicated DPAPI/ACL,
high-DPI, full uncertain-result recovery and independent native tests remain
NOT_RUN. The prior three-step record and old 84+2 receipts retain their source.

The follow-up [profile-recovery source](native-app-validation.md#profile-recovery-follow-up)
is `84d7aee`: native startup requires complete trusted discovery before first
setup; busy/failed recovery exposes only retry/trusted-resume controls and
rejects other Core actions. Snapshot reset publishes those controls atomically.
Conditional identity persistence preserves an unchanged vault during recovery;
new/missing identities and the original request still persist before POST.
Producer normal 290/0/0, scoped Core race 21/0/0, UI/native race 149/0/0, Root
native 369/0/0 and disposable interop passed. This is a scoped source/portable
fix, with matching Windows two-instance/retry execution NOT_RUN. The old
candidate's USER_REPORTED_FAIL and deferred Chinese display failure remain.

## Same-Node real Codex Thread acceptance preparation

Current 2026-10-20 follow-up: the [actual user batch](native-app-validation.md#2026-10-20-user-operated-same-node-pair-batch)
reports the instructed Join/consent/bidirectional/window-close sequence as
USER_REPORTED_PASS. The matrix and preparation narrative below retain their
2026-10-17 scope; they are not a claim that the later user run never occurred.
Independent traces, timings, automatic wake and adversarial cases remain open
in the [current ledger](#current-feedback-and-acceptance-ledger).

Preparation baseline `a14ad28`, 2026-10-17. The user's next priority is an actual
question/answer between two independent real Codex Threads on the same logical
Node ID and physical gpu1 host, through the existing production Join/Fabric/MCP
chain. New workspace/task contracts and task creation are paused. The user
will personally execute the real gpu1 two-Thread acceptance. This supersedes
the earlier Root-run Runtime proposal: Root/QA must not arm the WS adapter,
create SIDs, seed/continue model turns or operate the native queue. Existing
synthetic fixtures and archived WS work are retained separately. No real
pair, model turn or new peer authority has been created by this preparation.

This main lane targets the existing public Hub/account plus the actual gpu1
Node. A disposable real-Runtime lane, deterministic protocol tests and recording
fixtures must be labelled separately; none replaces the requested public lane.
The existing `test-two-node-codex-native.py` creates two independent Node/container
namespaces and is not a same-Node gate. Its old source, images and results stay
attributed to that distinct topology.

Current source has a trusted local Join bridge in the relay-only Node, but the
Hub Nodes wrapper only exposes its reviewed route allowlist. The underlying
Fabric service exists; the missing general Join/metadata/key-consent routes
must be reviewed by Hub, along with the typed Owner authorization path. An App
account login or existing N3 status grant does not supply those permissions.
Owner private keys remain in the existing vault; preparation does not export
them or widen the old status grant.

The [same-Node relay implementation](same-node-group-relay.md) sends new ordinary
same-Group ASK/REPLY through sealed HubRelay. Generic native direct eligibility
remains guarded by the [direct design](native-local-direct-design.md): same
Node/host labels alone do not establish the same authenticated Codex account
or a usable exact-Thread native API. A legitimate Relay fallback may satisfy
the conversation lane with its actual route recorded. It is not direct PASS.

| ID | Boundary | Required oracle | State |
| --- | --- | --- | --- |
| N3-TT-01 | Exact deployed topology | Pin public Hub origin/identity and actual Hub/Node/Codex artifacts; both native SIDs are distinct on the same real gpu1 host and one approved logical Node/binding, not two fixture Nodes | NOT_RUN; PRECONDITIONS_PENDING |
| N3-TT-02 | Explicit native Join | Use a real selected Network and two reviewed slots. Each trusted Runtime connection joins its original SID with zero peer/directory authority to its own stable Endpoint/current native SessionBinding; caller JSON cannot impersonate another SID/Node | NOT_RUN |
| N3-TT-03 | Unjoined isolation | Before Join, peer directory/resolve/receive cannot enumerate joined Threads or recover peer content. Node enrollment, account login and another Thread's membership confer no visibility | NOT_RUN |
| N3-TT-04 | Explicit authority and keys | Current Group/member/binding/lease and exact Endpoint key candidates/Owner grants authorize only the selected conversation; no implicit Join, directory/history grant or broad status-grant upgrade | NOT_RUN; PRECONDITIONS_PENDING |
| N3-TT-05 | Original context and B-only answer | Record separate private context witnesses and a fresh random B-only answer before traffic; A receives the question but never the answer in its prompt/config. Restrict/audit alternate file/shell/history/oracle access so A obtains the answer only through the correlated peer REPLY; Root/script never forwards peer bodies | NOT_RUN |
| N3-TT-06 | Actual native tool use | Each real Thread completes the production MCP calls on its original SID. Recording queues, curl/SDK calls by the driver and script-injected answers cannot stand in for model consumption | NOT_RUN |
| N3-TT-07 | ASK/REPLY correlation | A's ASK has exact target/operation/request/message identity; B receives that request and replies to its original request ID; A receives the matching answer and independently retains its original context witness | NOT_RUN |
| N3-TT-08 | Separate completion levels | Record transport acceptance, queue/injection observation, actual B consumption, correlated REPLY, actual A consumption and completed native turns separately; no earlier level implies the next | NOT_RUN |
| N3-TT-09 | Honest route | Record trusted route evidence for each message. Sealed HubRelay fallback is explicit; direct requires separate host/account/API/Guard evidence and is never inferred from equal Node IDs | NOT_RUN; DIRECT_UNACCEPTED |
| N3-TT-10 | Negative scope and revocation | Wrong Group/Endpoint/native binding, stale lease/epoch and revocation of owned acceptance membership/grants deny further traffic; another active scope cannot rescue it | NOT_RUN |
| N3-TT-11 | Loss/restart/replay | Recover original operation/ciphertext and durable request history after loss/restart; do not reseal or reinject an uncertain native write, and do not label queued data as consumed | NOT_RUN |
| N3-TT-12 | Reply/cancel ownership | Only the original receiver can reply and original sender cancel; cancel acknowledgement does not prove the Runtime stopped or that an uncertain question was never consumed | NOT_RUN |
| N3-TT-13 | Privacy and bounded execution | Use owned synthetic question/answer markers, bounded turns/time/budget and private traces; publish hashes/counters only, omit credentials/keys/full native context, and distinguish turn counts from provider-request counts | NOT_RUN |
| N3-TT-14 | Safe restoration and cleanup | Owned Group/Thread grants, helpers and artifacts have explicit cleanup; preserve the real Node/account/Owner keys/binding and unrelated Threads. Rejoining/recovery requires current authority and preserves original SID/context evidence | NOT_RUN |
| N3-TT-15 | Separate authority lifetimes | Protected new App authorizations require its current account session. Account-session expiry does not itself revoke established peer grants; N3 status-access expiry/cancellation neither grants nor revokes peer authority. Native SessionBinding/lease, Group/member/grant and Node/Owner revocation remain independently authoritative | NOT_RUN; CONTRACT_REVIEW_PENDING |
| N3-TT-16 | Crypto epochs, budget and replay | Separate App session epoch, native binding epoch, E2EE key/counter/replay state and message budgets. Approved `native-pair-v1` fixes four independent ASK roots in either direction, at most one outstanding ASK, one reply per ASK/four replies/eight messages/eight native deliveries, 8 KiB plaintext per message and 64 KiB total plaintext, 128 KiB ciphertext per message and 1 MiB total ciphertext. Exact retries cannot reset/double-charge budget or revive permission | CONTRACT_DEFINED; full real acceptance NOT_RUN |
| N3-TT-17 | Lightweight, measured operation | Reuse existing Go/crypto/transport/persistence with no new coordination service/dependency. Record actual request/response JSON bytes, peer ciphertext bytes, latency, requests/retries/native submissions, owned-SID model calls and idle pair traffic separately; no extra authorization renewal, model loop or polling is inferred from availability | NOT_RUN |

The following is the **user-operated manual acceptance skeleton** retained
for the delivered flow. Its instructed sequence has the later user-reported
batch above; independent trace requirements remain open. The historical
2026-10-17 13:57 UTC preflight found public Hub `e42640d` with native-pair HTTP
404 and the user-delivered `1980dce` App without Pair UI/Dispatch. That was the
older DELIVERY_PENDING checkpoint; it is not the current build status.

The integrated candidate is now packaged as `Cicada-N3-4ca29df.zip` from clean
`4ca29dfc76f3eec9143676d554b3a26c1a178f1b`; see the
[final delivery record](native-app-validation.md#final-clean-4ca-delivery-and-independent-artifact-review).
Its `delivery.json` and `SHA256SUMS` identify `cicada-app.exe`, Linux `cicada`,
protocol revisions and dependency notices. This is a reviewed delivery
candidate, not a release. On 2026-10-19, Root relayed the user's deployment,
login, export and Node setup feedback as **USER_REPORTED_PASS**; see the
[prerequisite feedback](native-app-validation.md#clean-4ca-user-reported-deployment-prerequisites).
The posted Linux checksum, Codex version, Owner-pin command status and active
Node service are recorded separately from the overall procedural feedback.
Independent Windows GUI/DPAPI/ACL checks, protected public pair operations and
independent original-SID consumption traces remain **NOT_RUN**. The later
2026-10-20 user-reported original-Thread batch is recorded separately above.
QA/Root did not operate real turns/queues for this record. Later documentation
commits do not change the package's clean-4ca build attribution.

The following onboarding feedback is tracked in FB-03/FB-12 above:

- Copy/selectable public fields have later source/portable checks; matching
  physical Windows interaction remains NOT_RUN on that source.
- Complete trusted Owner-pin establishment within the Node device-code/App
  approval flow. Current manual public-key/fingerprint export/import is an
  interim procedure, not the final onboarding UX. Preserve original identities,
  authenticated proofs and exact pin verification; account login alone still
  grants no Root authority. This is a UX target, not an accepted protocol or
  implementation change.

1. **Verify the delivered upgrade.** Root supplies actual reviewed Hub/Node/App
   revisions, source/image fingerprints, Windows executable SHA-256 and real
   entry names. The user checks the executable with PowerShell
   `Get-FileHash -LiteralPath '<delivered EXE path>' -Algorithm SHA256` and
   compares `delivery.json`/`SHA256SUMS` for the delivered `cicada-app.exe`.
   Preserve the original account, vault, Owner/device keys, Node ID and bindings. A cross-build alone is not Windows GUI/DPAPI/ACL acceptance.
   Before the two-Thread procedure, the user manually verifies that the actual
   Node service can resolve the reviewed Codex executable through its existing
   `CICADA_CODEX_BIN` override or its own `PATH`, and that its `CODEX_HOME`/login
   use the original Codex account. An interactive shell finding
   Codex is not evidence that the resident service can launch it. Root's
   2026-10-18 read-only preflight found `codex` absent from the actual Node
   service PATH, while the interactive shell found
   `/home/zyf/.local/bin/codex` version `0.163.0`; the Node used default
   `CODEX_HOME` and had no `CICADA_CODEX_BIN` override. This is a deployment
   prerequisite, not a product-code failure. The existing native delivery code
   already accepts an absolute executable path: the minimal user-operated unit
   setting is `CICADA_CODEX_BIN=/home/zyf/.local/bin/codex`, preserving the
   original PATH, account, `CODEX_HOME`, Node state, identity and binding without
   re-registration. Root supplies reviewed service-specific setting/restart
   steps before A/B acceptance. QA/Root do not replace the real
   unit or execute a native queue during development.
   Root's read-only installed Codex 0.163.0 `mcp list --json` currently returns
   `[]`: Cicada MCP registration/loading is another delivery prerequisite.
   Supply reviewed configuration limited to these two Thread launches, preserving
   global tools/model/config. Check Cicada MCP actually loaded in **each** Thread;
   a global listing or a present executable is not that proof. Do not run a
   persistent global `codex mcp add` as an inferred setup action.
   Root supplies the exact reviewed Cicada executable/API origin, original
   Hub/Owner pins and scoped MCP session-state location before these launches.
   Both use the original `CODEX_HOME`, Codex account, approved
   `CICADA_MACHINE_ID=gpu1-node` and original `CICADA_NODE_STATE_DIR`.
   The user personally launches/selects A and B and completes one harmless
   initial turn in each, establishing two distinct original native SIDs and
   checking its actual loaded MCP tools. Root/scripts do not start those turns.
   Use the actual SID read in each original native context and verify its local
   session/workspace record. Codex 0.163.0 MCP startup did not provide that SID
   in the observed run; the bounded manual remedy uses the same verified SID
   for exact resume and per-launch MCP environment, clearing conflicting aliases.
   Never invent a SID or substitute a different Thread. Complete these configuration
   and initial-turn prerequisites **before** starting App Pair bootstrap.
2. **Prepare two empty slots in the App.** The user logs in normally, selects
   the original gpu1 Node and uses the delivered new pair authorization entry.
   Review the existing Owner/Node pins, private Group and bounded policy before
   approving bootstrap. Login/status access alone supplies no Root/pair right.
   No native SID or peer permission is inferred from the two empty slots.
   Both already-prepared Threads must Join within the original displayed
   `JoinUntil` (the bounded ten-minute Join window); downloading/configuring the
   CLI or creating initial native context must not consume that window.
3. **Join the user's two actual Threads on the same Node.** The user returns
   to those same initialized A and B, retains their SIDs and distinct private context
   witnesses, and gives a fresh at-least-128-bit answer only to B. In each
   original Thread, use the delivered reserved-slot Join entry for its own slot.
   No default localhost API, manually supplied session token or guessed new
   flags/tool fields can fill that gap. MCP session persistence remains private
   and scoped by origin/harness/native SID/Node; registration grants no rights.
   Root supplies exact launch/tool syntax for the reviewed package and matching
   user-operated Hub/Node upgrade; generic old Join, a guessed command, a second
   Node or an operator DB grant is not a substitute.
4. **Authorize the actual pair in the App.** Review both distinct actual SIDs,
   the same Node/Network/Group, candidates and expiry. Only after **both** original
   candidates are ready, prepare their exact five-minute consent Plan and
   approve each slot's exact consent within its displayed expiry. Empty slots
   and the first consent leave peer traffic denied. Only
   the compatible second consent may activate both. The Owner key stays in the
   original App vault. The App does not carry peer questions or answers.
5. **A asks, B answers, A receives.** The user tells original A to make one
   production `cicada_ask` to B. B receives it in its original context and uses
   `cicada_reply` for that exact request ID, from the answer it already knows.
   Both B and A receive through the guarded delivery path confirmed for the
   delivered build, each in its original context; A reports the correlated
   answer plus its own witness. The user reported this exchange and its reverse
   successful; exact delivery/receipt traces remain unprovided for independent attribution.
   This Pair tool contract is limited to ASK/Reply/status/cancel;
   no receive-tool invocation is prescribed here. The ASK/Reply names are usable
   only after the new chain is delivered and authorized. If the user must
   explicitly continue B/A at a safe point, label USER_CONTROLLED_SAME_SID;
   do not claim automatic loaded/cold
   wake. Neither the user nor Root/scripts pastes the peer body/answer into the
   other Thread. The first check uses one ASK/Reply, preserving remaining budget.
6. **Record results and optional same-pair reopen.** Record exact executable,
   Hub/Node versions, original SIDs, request/message IDs, actual tools, route,
   answer/witness digests and completion levels. No keys/tokens/full private
   context go into public evidence. Equal Node labels are insufficient; record
   trusted Node/binding evidence. Sealed Relay is recorded as SEALED_RELAY.
   Retain original SIDs/context for a later manual reopen/second exchange. User
   observations are USER_REPORTED until independently backed by matching traces;
   absent traces and unexecuted Windows checks remain NOT_RUN/NOT_PROVEN.

For a future independently traced rerun, prerequisites are matching user-operated Hub/Node/App
upgrades, reviewed per-Thread Cicada MCP configuration/loading and the real
original-account/SID delivery path. The integrated candidate includes Hub/Node
reserved Join/candidate/Owner-pin guards and App original-vault Pair actions;
isolated evidence does not prove those paths on public deployment or physical
Windows. Missing routes, grants or UI stop the manual procedure; there is no
raw SQL, broad Client grant or old Hub fallback. No deployment operation is
authorized by this skeleton. Keep destructive loss/restart, budget exhaustion and revocation adversaries in the isolated
protocol fixture. A revoke receipt cannot undo already consumed native work.

Fault coverage includes pre-forward/post-commit loss, corrupt/unsigned reply,
duplicate ASK/REPLY, delayed original after cancellation, binding/lease change,
and queue/injection crash windows. Fixture-only outcomes remain separate from
actual public native consumption. Retain request/result hashes, process/turn
and tool counts, source/image/CLI hashes, route evidence, exit code, cleanup and
all incomplete levels. The 2026-10-20 user batch is USER_REPORTED_PASS for its
stated actions; no complete independent execution of this matrix is claimed.
Use existing transport/driver counters and bounded private traces for these
measurements; do not add a monitoring framework or a separate optimization
project before the usable chain closes. Distinguish application JSON size from
TLS/socket bytes and permission/message budgets from provider cost. Idle
observations cover only the owned pair/SIDs, so unrelated development activity
and the resident Node's existing heartbeat/SSE do not become claimed pair work.

The independent protocol lane is executable with
`bash scripts/test-native-pair.sh`. It builds the actual CLI and acceptance
binary in the pinned disposable offline Docker image, then uses the existing
production App N2/N3 flow to approve one synthetic Node before the new PQ
caller attempts bootstrap. Its initial five cases cover exact bootstrap replay
after Hub restart, a genuine Owner signature over the wrong Node scope, missing
Owner proof, pre-forward prepare loss and post-commit complete loss with exact
reconciliation. They do not create Codex SIDs or model turns. Node reserved-slot
Join, both zero-permission candidates, dual consent and actual native/MCP traffic
will extend this lane when their typed production surfaces are available.
The first execution reached real capabilities HTTP 404 after all five actual
N2/N3 setups and returned exit 1, **EXPECTED_RED_SERVICE_UNAVAILABLE**. No new
pair secret POST or business/fault assertion executed; see the validation record.

Root's separate standard disposable Client compatibility gate on clean
`209b208` passed, exit 0, with four actual TCP protocol/client/Owner-bootstrap/
recovery cases. QA checked its source/artifact attribution and independently
confirmed the five owned resources and scratch absent. This is clean-source
compatibility evidence alongside the App producer's earlier dirty-`17da393`
Core/UI results; it does not enable the false Pair capability, settle the new
Hub read-cache defect or execute the user-only native/Windows/public lane.
Full receipts and hashes are retained in the existing validation record.

The opt-in `bash scripts/test-native-pair.sh --a3-core` lane independently
exercises the frozen producer through a private server test overlay. Real PQ,
TCP, N2/N3 approval, reserved zero-permission Joins, candidate publication and
both original Owner consents create its ACTIVE state; SQL never creates a
positive authorization. Its SIDs, keys, account and Node are synthetic. Public
Pair availability remains false, so this lane does not establish public SDK,
App pair UI, actual caller/writer or native Runtime readiness. On 2026-10-18,
four normal and four race cases passed against the exact 2253-file A3 freeze;
see [the scoped receipt](native-app-validation.md#independent-a3-dual-consent-and-current-core-gate).

| A3 boundary | Independent oracle | State |
| --- | --- | --- |
| Partial consent and replay | First consent and its exact retry leave both memberships and legacy key grants ineffective; compatible second consent creates both original CURRENT grants in one revision without spending message budget | SCOPED_PASS on the recorded A3 freeze |
| Transaction failure | A private DB trigger fails the second legacy key-grant insert; both memberships/grants roll back, the exact original remains permanently fenced, and only a fresh explicit consent may activate after fault removal | SCOPED_PASS on the recorded A3 freeze |
| Committed activation, lost ACK | Close an actual proxy TCP connection after upstream commits; reconcile returns the identical original authenticated receipt and late replay neither activates twice nor resets budget | SCOPED_PASS on the recorded A3 freeze |
| Current is mandatory | Verify the actual carrier and independent Owner pin; missing evidence/Current and substituted SID, access, epoch, generation, attempt, membership/network revision or lease owner fail the shared verifier | SCOPED_PASS for shared verification only; actual caller/writer NOT_RUN |
| Complete encoded size | Real proof/tuple with peer-key fitting but full delivery exceeding 320 KiB cannot activate either membership/grant. Count actual HTTP bytes, including any encoder LF: exact limit usable, +1 byte rejected with no partial effect | SCOPED_PASS: independent HTTP 1+1 and separate Store/PQ transaction 1+1 on the later 2255-file freeze; actual caller/writer NOT_RUN |
| Revocation at use | Existing local reservation/history cannot authorize a new HTTP/queue write after revocation. Re-fetch final authorization at the actual caller/writer; preserve ACCEPTED/UNCERTAIN/INJECTING history without inventing NO_EFFECT | PREPARED; actual caller/writer NOT_RUN |

These additional threats refine N3-TT-04/10/11/16/17; they do not change the
user-only real two-Thread matrix above. A peer-key preflight alone does not
prove that a later complete delivery fits its bound. The necessary size increment
is reproducible with `bash scripts/test-native-pair.sh --a3-http` and separately
`bash scripts/test-native-pair.sh --a3-size-store`, against its approved freeze.
The first obtains real synthetic sealed Relay peer/final-authorization carriers,
then observes private typed rendering; the second checks genuine original
consent admission and rollback in persistent Store transactions, with an internal
zero-Join fixture rather than Node RPC. The Pair-only HTTP writer now emits
exactly the preflight's Marshal bytes without LF; ordinary Group encoding is
unchanged. The initial size fix retains separate source attribution. The earlier
four A3 cases, Store 9+9 and five known-RED public protocol cases were not rerun.

One final portable App-owner bridge is prepared at
`acceptance/n3/app_pair_runtime_test.go`:
`TestN3AppPairActionsBootstrapDualConsentAndRevoke`. It reuses the existing
separate production App actor and its vault. Every Pair/GroupKey Owner proof is
created by `Controller.Dispatch` through the real App actions; the driver reads
only the Hub's public Owner record and creates only synthetic Node/candidate
keys. Actual Node PQ zero-Joins/candidate publication connect App bootstrap,
fresh status, separate slot approvals, real CURRENT key grants and App revoke.
This fills a gap between the existing scripted App HTTP tests and the
independent Pair wire caller; neither earlier layer accepts this bridge.

The opt-in command `bash scripts/test-native-pair.sh --app-owner` selects only
this one scene using the original disposable driver. After its compile-only
check on dirty `3814439` (zero tests), Root integrated the App/Hub fixes and
explicitly authorized the real ready surface on dirty `995126d`. The original
five public protocol cases then passed **5/0/0**. The actual App scene reached
bootstrap/status, both explicit consents and verified real CURRENT grants, but
failed its final App revoke with `APP_PAIR_RESPONSE_INVALID`; that original
whole scene remains **FAIL**. App's narrow terminal-slot fix was then integrated
at `7e6e3d5`; the unchanged single scene passed **1/0/0**, including actual App
revoke application and effective grant removal. The five protocol cases were
not rerun or reattributed to that later source. Both original failure and
necessary successful rerun retain their own source/binaries. No discovery
shim, private initialization probe or driver-held Owner signer substituted for
these fresh App actions. See the [same-source runtime receipts](native-app-validation.md#ready-protocol-five-pass-and-actual-app-revoke-failure).
Production GUI/Windows DPAPI/ACL, real native MCP/queue/Runtime and user-operated
two-Thread acceptance stay separate and **NOT_RUN**.
