# Native delivery reliability N2 checkpoint

This checkpoint extends the N1 native delivery lifecycle to sealed
CommunicationLink delivery, ordinary Network-direct delivery, and the metadata
notice sent to an original joined Monitor Thread. It also adds bounded recovery
of original Monitor notice records when the current Hub list omits them. Monitor
notice delivery and dispatch of the sealed Client broadcast payload are separate
operations; this checkpoint does not establish full broadcast fanout or recipient
consumption.

The source baseline is the complete 995-file frozen N1 tree with raw manifest
SHA256 `bf4274fc4b332c63a1df0b8fe2b495326dde85e40894d1b5dd239a28e03055ca`,
on detached Git HEAD `e8a029d79bbdddb75ea376afa76e62a5c8444f59` with the exact
Task14 and N1 changes already present. N2 changes and validation belong to their
own final dirty-source manifest. HEAD, raw source manifest, software version,
protocol/contract revisions, stamped build fingerprint, and actual image ID must
be recorded separately. Historical N1 or Task14 gates do not count as N2 gates.

## Delivery and recovery boundaries

The three entry points reuse the frozen `runMachineNativeDelivery` lifecycle.
One physical native writer is acquired before the preparation callback performs
the current Hub Guard read. Fallible scope and executable checks precede inbox
admission and the durable native intent. A busy, transient, or canceled
pre-admission attempt releases only a still-claimed local attempt and preserves
the received record. This cleanup uses a separate bounded local deadline; it
does not extend Hub authorization or queue execution past cancellation.

Current Guard reads bind the delivery to its original verified message, target,
native session, binding, digest and remote attempt. Link authority includes the
current CommunicationLink and Group binding. Network-direct authority uses its
own current Network enrollment, grants and native binding; it does not acquire
Group lease semantics by implication. Monitor preparation checks the current
Client approval snapshot and original native binding and admits only a pending
or Node-accepted notice. Historical terminal detail remains readable for
reconciliation and cannot authorize a new injection. These are checks at the
held-writer boundary, not an atomic transaction spanning Hub authority and a
native Runtime.

After a command has started, failed or canceled waits and ambiguous durable
writes remain uncertain. Recovery never blindly queues such work again. An exact
durable queue-accepted outcome can reconcile a local uncertain record. The
native writer closes before caller outcome lookup and receipt handling, so the
existing outcome reader can reacquire the same physical writer. A successful
queue acceptance remains `CONSUMPTION_UNCONFIRMED`; it does not assert native
wake, model consumption, application acknowledgement or business completion.

Network-direct current denial preserves the original recovery coordinates of
post-start unknown or accepted work without granting permission to acknowledge
or queue it. Known pre-intent denial retains its existing retirement behavior.
The change is limited to the Network-direct denial/retirement branches and does
not replace the surrounding shared Relay recovery implementation.

The Node's internal sealed SEND receipt DTO also accepts the `sequence` integer
already emitted by the Hub's existing `202` response. This compatibility fix
retains strict unknown-field decoding and the existing identity and authorization
checks. It changes neither the Hub wire response nor the Client contract revision.
This Relay sequence is separate from the Endpoint's encrypted message sequence.

Monitor recovery uses the original persisted notice payload and attempt to read
the exact native outcome before sending a terminal unknown receipt. A failed or
busy outcome read retains recovery state and sends no irreversible terminal
receipt. A durable accepted fact can be reported even when Client revocation or
approval expiry hides the fresh notice. The existing Hub receipt Guard still
requires the current owner-bound Node and original live native binding/epoch;
this checkpoint does not weaken it or allow terminal unknown to become accepted.

## Bounded original-inbox traversal

`Inbox.NextNativeRecoveryBatch(ctx, limit)` reads only `INJECTING`,
`INJECTION_UNCERTAIN` and `CONSUMPTION_UNCONFIRMED` rows. The dedicated Monitor
notice inbox is its production caller. It returns the original payload,
attempt and delivery coordinates; it changes no database state, schema or
delivery transition.

The limit must be between 1 and 16. SQL orders and limits the page by the
immutable stored `(created_at, message_id)` key. The private cursor belongs to
one Inbox handle and uses the existing mutex. It advances only after a complete
successful query, scan, iteration and rows close. Query or cancellation errors
leave it unchanged. A short tail wraps on the next call; an exact full tail can
use one empty probe and one bounded head query, returning at most the requested
number of payload rows for Go to materialize in total. Each new Inbox handle
starts at the head. The existing indexes and SQL limit do not guarantee that
SQLite examines only 16 underlying history or index entries; this is a payload
page bound, not a constant-time query claim.

The Monitor process handles a bounded batch and preserves individual failed
records while allowing later records to make progress. Accepted history is
periodically revisited for receipt reconciliation; a long history increases
recovery latency, and repeated process restarts repeat the first part of the
traversal. This is not a guarantee of immediate recovery under arbitrary churn,
nor a durable cursor or a full-history load.

A persistent malformed SQL row or scan error blocks that recovery page until
repaired, because errors must not advance the cursor. Fresh pending notices can
still proceed through the Monitor process. Individual metadata reconciliation
errors after a successfully decoded page are accumulated while later records
continue; they are distinct from an error reading the page itself.

## Deterministic checks and evidence attribution

The focused cursor tests cover more than 16 rows, accepted history ahead of an
uncertain tail, equal creation timestamps, original timestamp spellings, short
and exact-full tail wrap, independent/reopened Inbox handles, original
payload/attempt preservation, approved state filtering, invalid limits,
canceled/failed queries and a partial scan failure. A real SQLite connection
with `query_only` enabled, unchanged delivery snapshots, `total_changes()` and
schema version checks establish that the page method does not write the database.

The asserted cursor selector is:

```text
^(TestNativeRecoveryBatchPagesAndWraps|TestNativeRecoveryBatchExactTailWrapAndIndependentInbox|TestNativeRecoveryBatchPreservesCoordinatesAndStatesWithoutWrites|TestNativeRecoveryBatchFailureDoesNotAdvanceCursor)$
```

Route and Monitor tests use real synthetic Store/Fabric authority, actual TCP
requests, a cooperating writer subprocess and a synthetic queue subprocess.
The Network-direct receiver fixture must establish real traffic grants and
Owner-approved keys; the older signed-crypto/socket test's invented successful
authorization responses and the directory-only fixture do not establish this
authority. Monitor notice tests keep the sealed broadcast body out of the
metadata prompt. Subprocess barriers distinguish actual successful `Wait`
before durable outcome (C) from durable acceptance and writer close before
receipt (D). Raw witnesses, counter/argv hashes, child signal and exit status,
original records, and production reopen paths support those claims. A helper
entry that returns an empty PASS without its private arguments is machinery
and must be excluded from asserted capability counts.

Actual results, exact selectors, source before/after, commands, exits, structured
test counts and skips, raw log hashes, helper witnesses, binary/image provenance,
and cleanup evidence belong in
[the N2 validation summary](../.cicada-data/native-reliability-n2-20261002/validation-summary.json)
and its referenced gate records. This document contains no predicted PASS count.
Normal and race results must use the same asserted test set; concurrent event
arrival order is not a test-set difference. Each real failed test or evidence
tooling attempt retains its own tested-source attribution and raw record.

Acceptance is composed from the earlier N2 source's complete focused normal/race
pair, the final source's affected bridge and strict receipt parsing normal/race
pair, and its disposable real transport gate. Each pair retains its exact tested
source and selector; the summary records every intervening source delta. The
earlier complete selection is not described as rerun on the final source, and
passing results are not transferred between source fingerprints.

The final acceptance layers are relevant deterministic normal/race tests, vet,
format, stamped offline build/source information, and one disposable offline
transport gate. They remain distinct from installed native Runtime, provider or
paid-model turns, Android, physical Node/device and public HTTPS validation.
Those real-environment layers are `NOT_RUN` for this checkpoint. A skip is not a
pass. Cooperating subprocess writer contention does not prove protection of an
uncontrolled foreground Codex TUI or an independent app-server consumer.

No full Store suite, full Task E2EE, Main, Taskprivacy/D2, Client, PQ/schema,
NativeDirect, retired plaintext/local capability or global CLI/provider change
is claimed. The four historical Monitor payload-fanout failures and thirteen
opt-in skips belong to the earlier pre-Task14 raw source `4c1dd54b...`; they are
not current notice-delivery PASS results or failures repaired by this checkpoint.
