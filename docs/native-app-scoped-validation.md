# App scoped Node checkpoint — 2026-10-29

This checkpoint adds native App consumption of the frozen Scope2 authority and
scoped pairing contracts. It preserves the existing Owner/App identities,
legacy confirmation and one global Client counter pair. It adds saved Node
selection and authenticated existing-Network choices, and reuses the existing
LocalDomain and Owner Group business operations.

The source is the commit containing this record, based on reviewed integration
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
