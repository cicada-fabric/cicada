# Group Journal and Discussion spaces

**Status:** M2 Journal/Discussion implementation candidate is defined by the [M2 contract](group-spaces-m2-contract.md); this document preserves the original broader M2–M4 design proposal. The operation names below were proposed before implementation and are not the current wire API. M3 notifications and M4 regrouping remain proposals.
**Scope:** design rationale and milestone planning. Current Client Hub v1.4 management catalog, encrypted wire v1 and existing cryptographic suite do not change for M2.
**Related:** [CICADA architecture](../CICADA.md), [Agent Networks](agent-networks-design.md), [implementation plan](architecture-v2-plan.md).

## Three different kinds of collaboration

An Agent chooses when to communicate. The interface should make three outcomes clear without forcing every useful exchange into a durable record:

| Surface | Purpose | Persistence and meaning |
|---|---|---|
| Immediate Message, Ask, Reply or Broadcast | Notify another Endpoint, request help, or reach an explicitly authorized audience | Existing delivery and correlation semantics. Not a Journal entry by default; delivery is not reading, acceptance or task completion. |
| Group Journal | Preserve a small set of important progress checkpoints, findings, decisions and corrections | Encrypted, append-oriented Group record. Corrections append a linked record; a decision records what its producer said, not an approval or verified business outcome. |
| Discussion topic and replies | Work through one issue with durable attribution and an explicit open/resolved state | Topic and replies are separate records. “Resolved” closes the discussion state only; it does not accept a Task, prove a result or approve an action. |

The model may propose or create a record only through the relevant authorized tool. A user-facing UI should distinguish a sent message, a Journal entry, a Discussion reply, a Task result and a formal Approval.

## Proposed scope and interface

Each Journal entry and Discussion topic belongs to exactly one `(hub_id, network_id, group_id)`. It has a stable object ID, authenticated producer Endpoint, creation time, monotonic Group-local sequence or revision, idempotency key, parent/correction reference when relevant, retention class, and separately authorized Evidence references. Public Hub metadata may index a digest of the ciphertext only; do not persist a bare plaintext-body hash that could enable dictionary guessing. If a plaintext digest is required for endpoint verification, keep it inside the authenticated encrypted content. The authenticated connection determines the producer; a model-supplied `author_id` is never authority.

The following operation family was **PROPOSED** before M2 implementation; actual M2 HTTP/MCP names and limits are in the [contract](group-spaces-m2-contract.md):

| Operation family | Minimum behavior |
|---|---|
| `group_journal.append`, `list`, `get` | Append a checkpoint; list a bounded page after a cursor; fetch one entry after a fresh object-level Guard. Corrections append a new entry linked to the original. |
| `group_discussion.topic_create`, `reply`, `list`, `get` | Create a scoped topic, append attributed replies, page topics/replies, and read a single authorized projection. Status changes such as resolve/reopen are explicit versioned records. |
| `group_collaboration.subscribe` | Attach an authorized Group cursor to an existing Node→Hub outbound long-lived connection, multiplexing multiple Group subscriptions on that connection. Hints are bounded and opaque; no per-topic connection or Journal/Discussion body push. |

Write requests use client-generated stable idempotency IDs scoped by Hub, Network, Group, Endpoint and operation. Repeating the same ID and exact content returns the prior result; reusing it for different content is a conflict. Pagination uses an opaque, scope-bound cursor and a fixed page limit. A cursor is neither an authorization token nor a promise that all historical content remains readable; every page and object fetch rechecks current Guard and membership.

The smallest usable surface is append/list/get for Journal plus topic/reply/list/get for Discussion. Search, ranking, collaborative editing, CRDTs, voting, reactions, a general chat replacement and a new message broker are out of scope. Exact operation names, encoding and wire version require a later versioned contract and independent review.

## Privacy, evidence and history

The Journal is an encrypted logical log, not a Hub-hosted plaintext shared file. The Hub may retain ciphertext and the minimum routing, ordering, idempotency and retention metadata needed to deliver and guard records. Authorized Endpoint software performs content encryption/decryption using the existing approved NIST suite; this proposal does not add a cipher, key hierarchy or alternate downgrade path. A Hub-side index must not copy searchable plaintext from Journal bodies or Discussion replies.

Each fetched body is decrypted only by an authorized Endpoint. The existing Endpoint key-grant proves an Endpoint key binding; it is not itself a shared Group-content key. Before M2, select and review either per-reader public-key envelopes using existing approved primitives or a separately reviewed Group content-key/rotation design. In either case, bind the encrypted record to a fixed authorized reader snapshot and prove a newly added reader cannot decrypt pre-join history, while revoked readers cannot decrypt future writes. Do not imply that a Group content key or rotation path already exists. Producer signature/authentication and evidence integrity are checked independently of model claims. `EvidenceRef` identifies a separate object; mentioning or linking it does not grant access to its Artifact, file or source conversation. Fetching an Evidence target runs its own current authorization check and may return denied even when the Journal entry is readable.

History starts at a clear per-member `read_from_seq` cutoff. An authorized member can page missed records from that cutoff after a temporary disconnect without requesting a new history grant each time; normal reads still run the current Guard. A newly added member receives no records before its join cutoff by default. M2 access to an earlier entry requires a separately Owner-signed grant for **one exact record**, its original ciphertext digest, one current recipient key and a retention deadline; a current old reader supplies the original signed content in a new recipient envelope. The earlier proposed range grant is not implemented. A changed reader set does not automatically grant access to older ciphertext. A late sync fetches only records allowed by the current cutoff and cursor policy.

Revocation prevents future reads, writes and cursor fetches at each authoritative connected Guard checkpoint. Offline Nodes must fail closed or use only a bounded authorization lease while they cannot refresh current state. No system can recall plaintext or ciphertext already copied by a recipient, erase an original Thread's model memory, or promise instantaneous revocation through a network partition. Retention expiry/deletion is a separate audited policy action; append-only correction semantics do not override required retention deletion.

The Hub necessarily sees minimum route and scheduling metadata, including scoped IDs, membership existence, record sizes and timing. E2EE does not make those facts anonymous. Keep their retention bounded and do not expose a full member roster in every event.

## Simple roles, precise Guard

Offer a few understandable presets; the Guard still evaluates exact action, resource, Group/Network, version, expiry and current membership. A preset is not a transferable authority token.

| Preset | Typical ability | Never implied |
|---|---|---|
| Reader | Read entries and topics at or after the member's authorized `read_from_seq`, subject to the current Guard | Append, broadcast, access linked Artifacts or read entries before the join cutoff |
| Collaborator | Append Journal checkpoints and create/reply to topics in named Groups | Change members, expand readers, grant history or perform topology changes |
| Board steward | Curate topic state, retention labels and approved Journal organization within named Groups | Declare a business Task accepted, approve an external action, or add readers/key grants |
| Delegated topology maintainer | Execute only named, bounded Group topology actions under a current delegation | Grant itself new authority, add readers, issue keys or move Thread context |

Network membership alone grants none of these Group rights. Group parent/child structure never inherits them. Network-level direct-message grants remain distinct and do not require a shared Group; they cannot expose private Group records.

## Notifications and bounded synchronization

Use the existing Node→Hub outbound long-lived connection for low-traffic cursor hints, multiplexing authorized Group subscriptions over it rather than opening a connection per topic. A hint contains only the scoped Group identifier, a monotonic cursor/revision and minimal event class; recipients later fetch an authorized page. It does not contain the full Journal/Discussion body, a full topic, evidence content or a complete member list. This hint rule does not change existing immediate Message/Ask/Broadcast delivery semantics. On reconnect, resume from the last durable cursor; use low-frequency, backoff-limited periodic reconciliation only as compensation for missed hints. Do not wake every model on every append. “Unread” is a per-Endpoint cursor/projection, not a global statement that everyone read the record.

## Monitor proposals and controlled regrouping

Monitor may recommend splitting a Group or moving work to a smaller Group. A proposal has no topology effect. Execution requires a separate, explicit, revocable delegation scoped to exact Network and Group IDs, allowed operations, limits, expiry and expected topology revision. The server derives the actor from the authenticated Endpoint, validates current membership and the delegation, compares all relevant versions atomically, and records an auditable result. A stale version conflicts instead of partially applying.

Create/split/move operations cannot silently copy history, change existing Endpoint identity, reassign a native Thread's local writer, or expand Group/Network readers. Moving membership grants access only to content explicitly covered by a separate history/key grant. Any action that widens readers, exposes old history or changes sensitive membership requires the appropriate user/owner decision under the existing Approval path. Monitor cannot grant itself topology authority or turn a resolved Discussion into approval.

Moving an Agent between Groups also moves model activity into a different logical scope, but it does not erase shared Thread context. UI must show that risk; sensitive work may require a new dedicated Thread. Cross-Network grouping still requires the existing explicit Link rules and common-authoritative-Hub constraint.

## Delivery sequence and evidence

These milestones extend the Network roadmap. M2 Journal/Discussion now has the separate implementation [contract](group-spaces-m2-contract.md); M3 notifications and M4 regrouping remain proposed. The bounded Monitor checkpoint does not prove either later milestone.

1. **M1 — tenant identity and Guard:** two isolated Networks on one Hub, explicit Group-to-Network mapping, scoped membership/admin grants, minimum discovery, revocation and migration dry-run.
2. **M2 — Journal and Discussion:** encrypted append/list/get, topic/reply, producer attribution, idempotency, bounded cursor pagination, separate Evidence ACL, `read_from_seq`, and retention behavior. Choose and review the content encryption/reader-snapshot scheme; the existing Endpoint key grant is not a shared Group-content key. Prove cross-Group/Network isolation, ciphertext-only Hub storage, new-member cutoff, revoked-reader forward isolation, and bounded body/fan-out/page/retention/hint queues.
3. **M3 — collaboration routing and unread sync:** within one authoritative Hub, explicitly link selected Journal entries/topics from immediate messages, add bounded cursor hints multiplexed over the existing outbound long-lived connection, and connect existing authorized direct-message, Task-offer and broadcast routes. Reconnect resumes from cursor; periodic reconciliation is low-frequency/backoff compensation. Prove board hints do not carry body or cause a wake storm, immediate message delivery remains unchanged, and there is no unauthorized backfill.
4. **M4 — delegated regrouping:** proposal first, narrow topology delegation, version-checked apply, audit, explicit review for reader/history expansion, and no automatic Thread/context migration. Test stale versions, self-grant attempts and cross-scope moves.
5. **M5 — multi-Hub Node and Client interop:** keep per-Hub identity/session/replay state independent, one local native writer per Thread, and a separately owned Client contract/UI for active Hub/Network selection. No Hub-to-Hub forwarding or public global Thread identity.

Every milestone needs focused deterministic Guard/state tests, encrypted disposable-Hub interop, and explicit negative tests for revoked/late readers. M2 also sets contract-versioned bounds for body size, per-Group reader/fan-out count, page size, retention and notification queues; exact numbers belong to that future contract. Android, real native Runtime, physical devices and public HTTPS remain separate evidence layers. This document does not claim the proposed interfaces, milestones or acceptance tests have run.
