# Task peer privacy contract

Peer Task responses contain responsibility metadata only. Objective, acceptance
criteria, result summary, evidence prose and claim keys are excluded from list,
get, claim, release, renew, accept and sealed-handoff accept responses. Existing
authenticated Control management views and historical management plaintext stay
separate. Client v1.6.3, its catalog and encrypted wire are unchanged.

Unclassified plaintext peer result submission is rejected before any Task,
result, candidate or event write. A caller-selected purpose never enables a
management plaintext fallback. Current actor, membership and ownership fences
still apply. Missing sealed definitions are explicitly unavailable.

An ordinary exact-endpoint Group sealed SEND is peer data and a candidate only.
Its Relay receipt does not prove Task registration, responsibility transfer,
Runtime consumption or result acceptance. Formal Task transitions require the
registered reference and current Core authorization/CAS. Node sealing, outbox,
Relay, endpoint signatures and replay protection are reused without a new wire
kind or dispatch protocol. Reserved sealed Task-handoff messages cannot register
as ordinary Task definition/result references.

## Trusted per-Task assignment

`POST /v1/groups/{group}/tasks/peer-shell` creates a metadata-only shell: optional
opaque `goal_id`, bounded numeric `priority`, exact `publisher_endpoint_id` and
exact `result_recipient_endpoint_id`. It stores no new objective or criteria.
`POST /v1/groups/{group}/tasks/{task}/peer-assignment` requires
`expected_revision`, `expected_assignment_version` and the two exact endpoints.
Assignment replacement increments assignment/content versions; older references
do not regain authority. Current endpoint, Owner, binding, key proof and Group
enrollment are pinned and rechecked.

Both routes use the existing configured management bearer and trusted Control
identity attribution. Without that bearer configured, the legacy management
Guard returns 503; missing, wrong or native Session credentials are rejected.
The stored manager identity is attribution within this trusted boundary; its
string does not grant a peer role or imply a Fabric Principal. Ordinary peer
roles, `task.verify`, body labels and caller-selected purposes cannot assign a
publisher or recipient. Existing legitimate management plaintext APIs and
history remain intact. Historical Tasks are `MANAGEMENT_ONLY` to peers until a
trusted assignment exists; this does not encrypt their old plaintext.

## Formal reference and current Guard

`POST /v2/fabric/tasks/sealed-reference` accepts only `task_id`, `purpose`
(`TASK_DEFINITION_V1` or `TASK_RESULT_V1`), `assignment_version`, `content_version`,
`expected_revision`, `owner_epoch`, `message_id`, `message_digest` and bounded
`artifact_refs`. Each Artifact reference contains only exact
`artifact_ref_id`, `version`, `digest` and requested `scopes`. No summary,
objective, sender selection, recipient selection or key headers are accepted.

In one transaction Core loads the actual persisted sealed message and checks its
signature/envelope, SEND route, exact source/reader/Group, digest, current pair,
enrollment-time fence, Owner approval, binding and endpoint-key grant. The
returned `sealed_route` is derived from this validated current pair. Definition
publication requires the trusted exact publisher delegation plus current
`task.read` and message authorization; it does not borrow a result producer's
`task.submit` authority. Results require current `task.submit`, exact current
Task ownership, active lease, revision/Owner epoch, a registered definition for
that owner, and the separately assigned result recipient. Both participants'
independent Artifact ACLs, current version, digest and latest version are checked.
An Artifact reference does not grant content/workspace access or expose Artifact
title/summary prose.

The reference fixes its Task, Group, purpose, assignment/content versions,
publication revision/Owner epoch, message ID/digest, sender, exact reader and
Artifact references. One message cannot acquire a second business tuple. A
definition is unique for that Task/reader/assignment/content version. An exact
retry rechecks current authority and returns the same reference without a second
business transition; changing the tuple fails without writes. Definition
registration does not advance Task business CAS. Result registration records a
body-free PENDING result and atomically advances Task to `RESULT_SUBMITTED`.
Receiving a message, registering a result, and accepting it remain distinct.

Peer GET/list expose registered references only to their exact current authorized
reader, with bounded queries. A basic mutation projection may report
`SEALED_BODY_UNAVAILABLE`; refresh GET to resolve references. Revoked, replaced,
malformed or missing authority never falls back to old plaintext. Acceptance
requires the exact registered result, current assigned recipient's `task.verify`,
current source `task.submit`, route/key/enrollment checks, Artifact ACLs and Task
CAS/Owner epoch. Ordinary and reserved sealed-handoff acceptance both return
the peer DTO. Old plaintext result submission remains denied even when supplied
with a forged sealed-purpose label.

## Local MCP body handling

`cicada_task_define` and `cicada_task_submit` accept private prose locally and a
stable idempotency key. They persist an immutable existing SEND operation, seal
the typed inner Task packet to the exact endpoint, then submit only the Relay
reference metadata to Hub. Results take their recipient from the current trusted
assignment. An existing operation cannot be retargeted on retry. Pending or
uncertain SEND outcomes retain their original operation; no automatic retry or
safe-to-retry conclusion is made. A lost formal registration response can be
resolved by repeating the same immutable reference, with current Guard checks.

`cicada_task_body` resolves a current authorized registered reference, reads its
existing local inbox and crypto/replay records, and purely opens the original
signed ciphertext using the existing receiver key and active verified sender
pin. The verified sequence must equal both stored inbox and replay sequences;
the ciphertext digest, validated route, decrypted bytes and typed inner fields
must match the reference and cached inbox body. An inbox payload/digest label
alone grants no authority. A final authenticated GET rechecks the unchanged
current reference before returning private content marked
`UNTRUSTED_PEER_CONTENT`. `cicada_task_accept` performs the same body verification
before Core's independent transactional acceptance Guard.

All SQLite reads for this body proof open a private temporary copy of the
existing DB and optional WAL, each bounded to 64 MiB. Originals are opened only
for reading, with exact regular-file 0600 checks, identity and DB/WAL hash/raw-mode
stability checks before/after the copy and query. No writable crypto constructor,
schema migration, counter/replay update, source chmod or full StateDir copy is
used. Concurrent observed DB/WAL changes fail closed; this is not a claim of
atomic detection of arbitrary external SHM changes. Temporary copies use 0700
directories and 0600 files, with deferred best-effort removal; filesystem cleanup
failure cannot be promised away. Cached body availability proves neither native
queue consumption nor execution/nonexecution, and creates no injection receipt.

Schema 57 adds only assignment/reference sidecars, definition uniqueness and
immutable-reference triggers. Existing schema 56, historical management rows,
Owner epochs and Task history are preserved. Migration interruption rolls back
57 objects and remains retryable under the existing migration ledger.
