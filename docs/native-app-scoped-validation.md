# App scoped Node checkpoint — 2026-10-29

This checkpoint adds native App consumption of the frozen Scope2 authority and
scoped pairing contracts. It preserves the existing Owner/App identities,
legacy confirmation and one global Client counter pair. It adds saved Node
selection and authenticated existing-Network choices, and reuses the existing
LocalDomain and Owner Group business operations.

The source is `f269f207813088aedae0caf95540271ab9fb2d49`, based on reviewed integration
`fb2822a19c55c87e7c357dfb4e26700009d26c79`. The final dirty-build input manifest
contains all 36 changed Go files, including tests, with SHA-256
`f077327fd5b5a52c3a2bede7ac878086b3dc7233860fafad8c55f7bf3bb97ad1`.
The tested build is attributed to that base **and** manifest. Software remains
unreleased 0.0.5; wire version, Scope2, contract revisions and Git revision are
separate coordinates.

Private evidence is retained at
`~/Cicada/.local/evidence/n2-app/scoped-app-20261029-979wh9w8/`.
Reports contain assertions, lengths and hashes; fixture keys, codes and complete
payloads are not included in reports. All fixtures use newly generated keys,
synthetic labels and private disposable state.

## Verified scope

| Check | Result | Evidence |
| --- | --- | --- |
| Final related Core tests, including nine real TLS cases | PASS: 39 top-level tests, 59 passing test events, 139.460 s | `normal-final.jsonl` |
| Related race tests: full two-Node/Network/Group cold-recovery chain and lost ACK read | PASS: two cases, 301.578 s | `race-final.jsonl` |
| Disposable Docker interop: full chain and two original-response cold recoveries | PASS: three cases, 42.849 s; container removed | `docker-interop-entrypoint-fixed.jsonl`, `.json` |
| Windows amd64 GUI cross-build | PASS; physical execution NOT_RUN | `windows-crossbuild.json` |
| UI helpers and bilingual catalog, before the subsequent Core-only Group budget fix | PASS: 72 top-level tests, 225 passing events; final UI blobs unchanged | `ui-current.jsonl`, `source-pre-review-cold.json` |

The earlier full Core regression passed 167 top-level tests and 344 test events
in 285.189 s before the final Group storage-phase change. Its source manifest is
`source-pre-review-cold.json`; `core-regression-except-delegated-budget.jsonl`
retains that attribution. The final related gate reruns the affected Group,
scoped-state, target-selection and Network-choice cases. The separately reviewed
budget checkpoint `9dcb8e45d285ffb49df8bc57f427c5db5564b308` supplies the exact two
budget blobs; its producer normal/race results remain attributed to that source.

The real TLS cases use the actual Hub router, account/Owner services, SQLite,
saved native TLS profile and independently pinned transport. Two SDK Node
actors own different private keys and perform their own capsule opening and
private ACK. The App creates its own Owner/App keys, activates its account and
logs in through Core actions. No legacy Node is enrolled in the fresh A→B→A
case. Group availability is obtained from the actual Hub discovery response;
the final fixture does not override it.

Assertions cover:

- A creates and activates a Network; B selects that exact saved Network and
  retains a different default Group. B creates an Owner Group through the
  existing private Guard. After a lost apply response and App restart, Core
  recovers the original completed receipt without repeating the mutation.
- A→B→A preserves both bindings, heads, provenance and immutable initial
  confirmations. Global Client counters advance exactly twice. An automatic
  read target captured for A cannot issue a request under B's selection.
- A committed authority request followed by an unauthenticated HTTP 403 remains
  uncertain. Restart/reconciliation retains the exact original packet. Lost
  scoped ACK reads restore the exact confirmation and commit counters once.
- A saved review requires fresh discovery/session checks and new consent.
  An already approved original Node can ACK while the App is closed.
- Explicit self-cancellation and subsequent READ-only reauthorization preserve
  the initial binding/confirmation and do not spend another Client sequence.
  Prepared reviews and all retained unknown operation families lock selection.
- Normal-constructor expectations follow the published capability constants.
  An independent false-metadata case creates no ceremony and sends no secret
  App POST, including when the other capability is available.
- Namespace/full-digest bounds, raw-frame round trips, tombstone generations,
  missing scoped selection, opaque old state and pre-POST capacity refusals
  retain their deterministic checks.

## Environment and retained failures

Tests use the pinned Go 1.27.3 toolchain, offline modules and read-only module
resolution. Docker uses immutable image
`sha256:c850a8e59eb9ba792f9114d4b46b54b105129aeff251c2786f54d178dfbfb14d`,
no external network, a read-only root/source/toolchain and a private executable
temporary filesystem. First sends are paced to respect the real Hub admission
limit; the transport does not retry a business mutation.

The first Docker command omitted the image's existing smoke-test entrypoint
override. It failed during compilation with a Go toolchain mismatch before
running the requested App cases. Its failed log and removed-container receipt
remain in `docker-interop-final.jsonl` and `.json`. The corrected command changes
only the explicit entrypoint to the pinned Go executable; source hashes match.

Earlier frame/namespace failures, a fixture admission-rate failure and storage
budget refusals remain in their original logs. The old prep-only evidence,
stash/archive references and historical native Runtime failures are retained;
none is relabeled as this checkpoint's passing scope.

The Windows validation executable is 21,854,720 bytes with SHA-256
`f843962820cd4e795a5eaee4a10729c00e8554aa8e23b18653a5108bd35cbba7`.
It was built with `-trimpath -ldflags=-H=windowsgui`. This is a source validation
artifact; the existing delivery candidate was not replaced.

Actual native Node/Host processes, cross-Host Runtime communication, physical
Windows GUI/DPAPI/ACL, 24-hour elapsed expiry and public HTTPS are **NOT_RUN**
by this checkpoint. App cold recovery does not qualify Hub backup/restore.
The shared plan and acceptance ledger remain owned by the integration/QA work.

## App Group storage admission (2026-10-29)

This checkpoint fixes a pre-POST `APP_THREAD_GROUP_STORAGE_BUDGET` refusal for
Owner `ADD_ENDPOINT` in an App that retains two scoped Nodes and their Network
setup. Source is the commit containing this record, based on production freeze
`0d5bfb62f92f7eaed3cba46b9275cbce5617eb1a`, on task branch
`task/v01-app-real-group-budget`. Software remains unreleased 0.0.5; the wire,
contract revisions, Git revision and Docker image digest are distinct.

The original real-Node C2 report points to `ADD_ENDPOINT` after Group creation.
This checkpoint reproduces the App refusal using the existing native TLS SDK
fixture: two independent Node keys, their private scoped ACKs, actual Hub account,
Owner and LocalDomain services, SQLite and one SDK-joined original Endpoint with
completed default key installation. It does not substitute for the separate
two-Node, eight-Thread native Runtime acceptance run.

### Change and invariant checks

Before the fix, the real fixture refused ADD before sending it. Its query-phase
projection was 4,605,567 encoded bytes: original frame 229,718 bytes, recovery
frame plus reserve 400,322 bytes, outer response frame 918,838 bytes and prior
review 205,468 bytes. The existing 4 MiB vault bound correctly rejected that
projection. The RED source and raw lengths are retained separately from final
source in `source-red.json` and `red.log`.

Admission now follows the actual durable states. It checks the new original
together with the prior review before any write, then the future direct receipt
and recovered original receipt separately. The prior review is retired after
original persistence and before APPLY POST. If an interrupted retirement left an
actual review beside an already durable original, recovery still budgets it.

A query with a nested receipt already persists only the separately authenticated
original receipt. An authenticated empty terminal query now retires that settled
read-only query directly, retaining the unresolved business original. A crash
before retirement can repeat the same query. Previously saved outer responses
remain supported. Unsigned HTTP errors, nonterminal queries, wrong targets and
invalid nested receipts cannot retire an unknown original or replace its query.

The tests cover exact original persistence before POST, prior-review retirement
before APPLY POST, maximum SDK coordinate widths, old opaque state and PREPARE /
APPLY capacity refusals preserving all Group slots and their CAS versions. The
real TLS case covers cold CREATE recovery and policy-sized ADD recovery after
lost original and query responses, without repeating either mutation.

No public DTO, server behavior, packet cap, 1 MiB record bound, 4 MiB encoded
payload bound, 8 MiB vault file bound or namespace limit changes. No pending
ciphertext, counters or unrelated opaque state are evicted.

### Validation record

Final Go input manifest: `source-final.json`, SHA-256
`0aaaab82bab8ed9d520b1e1a5b9518f95ea67323be313ba7ce3a562e16c543c3`.
Private evidence is retained under
`~/Cicada/.local/evidence/n2-app/real-group-apply-budget-20261029-e900yr94/`.
Reports include assertions, byte lengths and hashes, with synthetic keys and
disposable state; they do not include private keys, grants or complete payloads.

| Final check | Result | Evidence |
| --- | --- | --- |
| Related deterministic tests, both scoped-App and Owner-Group integration tags | PASS: 30 top-level tests, 42 passing test events, 82.305 s; no failures or skips | `normal-final.jsonl` |
| Related race tests, including the complete TLS combination | PASS: 10 top-level tests, 16 passing events, 421.809 s; no failures or skips | `race-final.jsonl` |
| Disposable Docker interop, full composed TLS recovery plus storage boundaries | PASS: four top-level tests, eight passing events, 33.317 s; container removed | `docker-final.jsonl`, `docker-final.json` |

The first direct ADD GREEN passed in 22.583 seconds. An expanded cold-recovery
test initially asserted that a historical outcome would remain visible in the
current UI after restart. That assertion failed because current views are
intentionally hidden. The corrected test verifies the authenticated historical
receipt, exact original/query bytes and settled pending state instead. This was
a test-only correction. Its failed normal/Docker logs and interrupted race log
are retained and are not passing evidence.

Tests use pinned Go 1.27.3 and offline read-only module resolution. Disposable
Docker uses image
`sha256:c850a8e59eb9ba792f9114d4b46b54b105129aeff251c2786f54d178dfbfb14d`,
explicit `/toolchain/bin/go` entrypoint, no external network, read-only source,
root and toolchain, and a private executable temporary filesystem. No shared Hub
is used.

Actual native Node/Host Runtime, physical Windows GUI/DPAPI/ACL, Android, elapsed
24-hour expiry and public HTTPS are **NOT_RUN** by this checkpoint. There is no
new packaging, deployment or candidate replacement. The independent native
acceptance, QA adapter and shared ledger remain owned by integration/QA.

The composed cold ADD→A selection/status path also exposed
`APP_NODE_PAIRING_STORAGE_FULL`: its direct projection was 3,418,568 encoded
bytes, but recovery was 4,198,520 bytes, 4,216 above the unchanged 4 MiB limit.
This uses ordinary SDK data without maximum-value or opaque occupancy injection.
The RED diagnostics and source remain in `red-post-add-status-diagnostic.jsonl`
and `source-coupled-red.json`; the earlier normal/Docker failures and interrupted
race attempts remain in `extra-node-refresh-*`.

The ordinary scoped authority response uses `OpenAppNodeScopedResponse` and
the shared `DecodePacket` codec, whose existing 384 KiB outer limit also applies
to reconcile. The budget had charged the 512 KiB shared HTTP reader ceiling,
overstating that frame by 128 KiB before vault base64 expansion. Admission now
uses the smaller existing codec/reader limit for that family, including its
plaintext calculation, while retaining the actual saved response length if
larger. Independent PairTrust still reserves its full 512 KiB response. The
actual recovery phase still holds both outer and original receipts; it is not
removed from the budget.

The SDK boundary test authenticates a padded 393,215-byte authority reconcile
response containing a maximum accepted original receipt, rejects the next
representable size above 384 KiB and checks a 393,216-byte projection while the
HTTP reader remains 524,288 bytes. Existing PairTrust padding at its separate
512 KiB boundary remains covered. The composed regression keeps its A→B→A
selection/status steps after ADD and verifies the saved Group original, query
and receipt remain byte-for-byte intact.
