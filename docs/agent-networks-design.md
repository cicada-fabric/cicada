# Agent Networks: tenant boundary, social discovery and collaboration

**Date:** 2026-09-27
**Status:** adopted target design for planning; Network features are not implemented by this document.
**Current code checkpoint:** M1 implementation is authorized and underway from clean `dev` / `0cda61460757246789970782584b1e904173e653`. This design document states the target semantics; it does not claim Network or Journal/Discussion features are complete.
**Authority:** [CICADA architecture specification](../CICADA.md), with sequencing in [architecture-v2-plan.md](architecture-v2-plan.md).

## Purpose

A Network is an invited, private social space where people can expose a small, approved directory, contact another authorized Endpoint, publish an opt-in broadcast or task offer, and let an Agent volunteer for work. It makes Agent discovery useful across teams while keeping each person's device, Thread, history, keys and local approvals under that person's control.

“Social network” here does not mean open registration, a public global directory, or unrestricted cross-Hub federation. The deployment model stays one Go Hub/Control/Directory/Relay service, one or more Nodes and separate Clients. A Hub can host several isolated Networks; a Network has exactly one authoritative Hub.

## Object and authority model

| Object / relation | Rule |
|---|---|
| Hub → Network | One Hub may host many isolated Networks; each Network has one authoritative Hub. |
| Network → Group | Each Group belongs to exactly one Network. Parent/child nesting is within one Network and grants no inherited access. |
| Principal → NetworkMembership | Membership is a versioned, revocable presence in that Network; it does not join any Group or grant all Network actions. |
| Endpoint → Group Membership | Existing Endpoint identities remain. Membership and endpoint enrollment are separate from NetworkMembership. |
| Thread → Hub registrations | Address each registration as (hub_id, network_id, endpoint_id). Cross-Hub registrations use independent credentials and need not reveal one globally correlatable Thread ID or real Owner identity. |
| Thread → SessionBinding | Each Hub may keep its own scoped Endpoint SessionBinding. The Node locally maps those registrations to one native binding owner/writer and arbitrates all native injection. |

Network is a tenant and policy scope, not a deployment entity or participant. It does not replace User, Control, Worker or optional Monitor. NetworkAdmin is a revocable grant set scoped to one Network, not a new Principal kind, top-level role or global manager.

## Membership and simple permission presets

Joining requires an invitation or explicit Network policy, plus confirmation by the owner of the native Thread. A user may authorize a narrow Join policy once so idempotent retries do not ask again; joining another Network or expanding scope remains a separate decision. NetworkAdmin cannot silently enroll a Thread.

The UI should offer a few understandable presets, while the Guard still checks exact action, object, version and current membership. Presets are conveniences, not a role hierarchy, and never imply access to a private Group:

| Preset | Default scope | Explicitly excludes |
|---|---|---|
| Directory guest | Network card and only directory entries marked discoverable to this member | Messaging, private Group membership/history, broadcast receive |
| Network collaborator | Specifically granted Network directory, direct-message and Task-offer actions; joining a Group remains a separate choice | Automatic Group membership, ungranted directory entries, broadcast receive/publish, private Group history |
| Group collaborator | One or more named Group memberships and ordinary message/task permissions within those Groups | Other Groups, Network-wide directory, Network broadcast |
| Network administrator | Narrow membership/invite, directory-policy, Task-offer and broadcast-policy actions for one Network | Device/Node commands, private keys, native history/workspace, local user approvals, cross-Network administration |

Broadcast publication and receipt are separate explicit grants, with recipient opt-in and bounded fan-out; they are not implied by a preset. A preset does not allow “all members can see everything”: directory discovery, direct send/receive, broadcast publish/receive, Task offer listing/claiming and Artifact reads remain distinct Guard checks. Keep common choices simple; do not make users configure dozens of independent toggles.

Revocation is enforced by the authoritative Hub and Node at each connected authorization checkpoint. An offline Node must fail closed or honor a clearly bounded authorization lease when it cannot refresh current state. No design promises instantaneous global revocation through a partition, deletion of cached ciphertext, or erasure of content already placed in a recipient's native context.

## Discovery and contact

Network membership alone is not discovery permission. A member receives a small Network card and sees only Endpoint cards authorized by directory-discovery or a specific Link grant. A card may include a Network-scoped nickname, approved capabilities, freshness-qualified availability and a constrained contact route. It must not include workspace path, native Thread ID, private Group or Task details, owner credentials, real host/user identity or full history.

Nicknames are labels, never identities. Resolve only after authorization filtering. If the selected scope contains more than one matching nickname, return AMBIGUOUS; do not let an Agent guess. A reader may discover an Endpoint without permission to message it. A sender may not infer broadcast or Task permissions from a capability card.

Network-scoped private messages do not require the two Endpoints to share a Group when both have valid registrations and a specific Network direct-message grant. This permits authorized contact while preserving each private Group. The message is scoped to the Network and Endpoints; it does not expose either Endpoint's unshared Group membership, history or artifacts.

## Routes and Hub boundaries

| Route | Required path |
|---|---|
| Same Node | After the same-Network or specifically authorized Link rule admits the route, Sender MCP → local Guard/serialized writer → exact native Thread; zero Hub Relay. Locality never bypasses scope. |
| Cross Node, same Network | Sender Node → that Network's Hub Relay → receiver Node; one Relay. |
| Cross Network, same Hub | Explicit bilateral Link → the common authoritative Hub; one Relay. |
| Cross Network, different Hubs | Denied; no Hub X → Hub Y bridge. |

Cross-Network communication is deny-by-default. If enabled later, it needs a narrow, expiring Link with both Endpoint owners' approval, both Network policies' approval, explicit source/target Network and Group scopes, allowed actions/data and one common authoritative Hub. A NetworkAdmin cannot stand in for either Endpoint owner. When Network authorities differ, the route is unavailable; no implicit Hub mesh, forwarded bearer, shared key or multi-relay route is allowed.

A Node can keep one outbound connection per Hub it is authorized to use. Each Hub has its own Node credential, Network registration, subscriptions, replay/sequence state and authorization cache, and may maintain/renew its own scoped Endpoint SessionBinding under that Hub's current credentials. Separately, the Node owns one local runtime-writer lease and arbitration point for each native Thread: messages arriving through multiple Hubs pass one local Guard and bounded scheduler before the same serialized writer. A Hub cannot replace that local writer owner or make competing native injections.

Network ID and Hub ID are part of business authorization, signing/AAD scope, request correlation, idempotency, membership snapshots and crypto replay state. Hub-level device enrollment and connection registration are separate Hub+Owner operations and must not be assigned a fake default Network. E2EE protects content; minimum route metadata, member/Endpoint existence, packet size and timing can remain visible to the Hub and need limited retention.

## Team offers, volunteering and broadcasts

A team may publish a Network-level Task offer containing only an approved summary, required capability, bounded inputs, acceptance criteria, deadline, allowed return fields and offer revision. Only members with the offer-discovery grant can list it. An atomic versioned claim creates a scoped handoff; it is not a command and does not expose the publisher's private Group.

The volunteer's Monitor or Worker may take the accepted work to its own small Group. The source Network receives only the result fields and evidence explicitly allowed by the handoff; it cannot read that Group's conversations, native history or unrelated artifacts. A Monitor needs a separate task-claim/execution grant. The offer, its author or a Monitor summary never counts as user approval for side effects.

Network broadcasts use a fixed eligible recipient snapshot, opt-in receipt grants, bounded fan-out and a separate Delivery/outcome per Endpoint. Delivery, visibility and wake remain separate. Partial success is reported per recipient. No broadcast crosses to a nested Group or another Network unless an explicit authorized operation names that scope.

## Privacy and threat boundaries

Main risks are tenant-ID confusion, confused-deputy admin actions, cross-scope replay/idempotency collisions, stale membership, nickname enumeration, cross-Hub credential reuse, implicit forwarding, privacy loss through shared Thread memory, overbroad task results and prompt injection through peer content.

Controls include trusted scope derivation, tenant-qualified keys, current Guard checks at every read/write/delivery/execution point, explicit Endpoint consent, filtered cards, ambiguity rejection, bounded queues and immutable attribution. Prompt text is not an authorization or prompt-injection defense. Agent messages and Task offers are untrusted input; tools, file access and external actions keep existing policy and Approval requirements.

Reusing one Thread across Networks also reuses model memory. UI and Join flows must call this out; sensitive Networks may require a dedicated Thread, Endpoint, Workspace and credentials. CICADA cannot promise to erase messages already received by a Runtime or model.

## Migration

New installations may start with one private default Network and one Group. This is a convenience only: it does not import historical Threads or grant Network-wide visibility.

Before upgrading existing data, produce a dry-run map from every existing Group to exactly one Network and show affected Memberships, cross-owner Groups/Links, key grants and pending receipts. Do not split Groups mechanically by Owner, since this can break a legitimate shared Group; do not merge all Groups merely to retain connectivity, since that expands visibility. Missing, conflicting or widening mappings remain pending for user choice.

Keep existing Endpoint, Group and Link IDs, original Threads, receipts, approvals, key material and replay counters. Verify each exact existing grant against the proposed scope. If the old grant does not authorize the mapped scope, require the appropriate parties to reapprove; do not reset counters, copy Group keys or silently trust every former member. Schema migration must be replayable and backed up; rollback/forward-repair boundaries must be documented.

## Current prerequisite and checkpoint

The controlled `25013b5` candidate has passed the bounded Android/native Monitor chain: the same original Monitor Thread produced one verified read-only preview and one separate dispatch, and both original recipient Threads passed receive/context assertions. Client's final strict status, the scoped Hub ciphertext scan, Intake's independent Hub-state audit and all owned fixture cleanup also passed; no owned containers or fixture directory remain. Exact bounds and evidence are in the [candidate validation report](client-hub-v13-25013b5-validation.md), [Monitor approval review note](monitor-broadcast-approval-review.md), [native runbook](client-monitor-native-fixture.md), and [Client's validation report](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md).

This evidence covers one pinned, controlled run; it is not a general prompt-injection defense, full React Native consent UX, physical dual-Node test, or public HTTPS result. Earlier `81d8f1f` automatic-review denials remain historical and are not the result of this candidate. The `25013b5` Go/vet/race/TCP gates and `0d532f2` fixed native runner results apply to those exact source identities; the current `0cda614` base has no M1 code and does not inherit an M1 PASS. Group Journal and Discussion semantics are described in the [proposed collaboration-spaces design](group-collaboration-spaces-design.md); those APIs and persistent boards remain outside M1.

## Stages and exit criteria

| Stage | Scope | Exit evidence |
|---|---|---|
| M1 — Network identity and Guard | Two Networks on one Hub; scoped membership/admin grants; explicit Join; Group-to-Network migration; filtered directory and small permission presets | Cross-tenant reads/writes, revocation, stale scope, ambiguous nickname, admin boundaries and old API bypass fail closed; migration preserves IDs/history and waits on ambiguous mappings |
| M2 — Group Journal and Discussion | Encrypted Journal append/list/get and Discussion topic/reply/list/get; stable producer, idempotency, bounded cursors, Evidence ACL, explicit history/retention | Endpoint key grants are not Group-content keys. Prove the fixed reader snapshot, new-member `read_from_seq` cutoff, revoked-reader forward isolation, and ciphertext-only Hub storage. Bound body size, reader/fan-out count, pages, retention and hint queue in the future contract. Details remain PROPOSED in the [collaboration-spaces design](group-collaboration-spaces-design.md). |
| M3 — links, team tasks, broadcast and unread sync | Within one authoritative Hub, link selected board references in immediate messages; use authorized direct/Task/broadcast routes; multiplex cursor-only board hints over existing outbound long-lived connections; keep per-Endpoint unread and Delivery state | Same-Network or explicit Link rules apply before local routing; board hints carry no Journal/Discussion body and do not wake every model; immediate message delivery is unchanged. Reconnect resumes from cursor; periodic reconciliation is low-frequency/backoff compensation. |
| M4 — delegated topology and regrouping | Monitor proposals and narrow, versioned topology delegation with CAS and audit; user/owner review when readers or history scope widens | No self-grant, no implicit Group inheritance, no automatic key/history transfer or Thread context move; stale versions and out-of-scope requests fail closed |
| M5 — multi-Hub Node and Client interop | Independent Hub credentials, replay state and registration; one local writer per Thread; later Client selects active Hub/Network explicitly | No Hub-to-Hub forwarding or global public Thread ID; recovery, ambiguous routing and Client contract are validated by their respective owners |

The current native checkpoint's independent Hub audit and cleanup are recorded as PASS for the fixed candidate only. M1 is the active implementation checkpoint: its migration fixture, protected service entry points, Network data scope, contract operations, and disposable Docker scenario are being pinned and implemented in this work cycle. The present design does not assert that any Network, Journal or Discussion feature has passed acceptance.
