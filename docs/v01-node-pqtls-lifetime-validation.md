# Retained Node PQ connection certificate lifetime validation

## Current combined checkpoint (2026-10-02)

Current integrated Main source is `e64f2449…`, over `06d0a58`, with the lifetime
layer and recovery metadata query present. Full Go QA passed on pre-policy-fix
source `97a008…`, with explicit skips retained. Its 799-input equality proof
connects only `97a008…` to pre-policy-fix shipping baseline `bab6569…`; it does
not cover the later policy fix. Shipping script checks retain `bab6569…`
attribution and explicit artifact skips;
clean package/image and exact-image acceptance are NOT_RUN.
See the [current status](architecture-v2-status.md). The focused Main receipt
below retains its `b5e38b…` attribution; it does not accept the later combined source.

## Main focused integration (2026-10-01)

The reviewed eleven-file lifetime patch is integrated over the committed
runtime/native-identity checkpoint `06d0a582641ece2553cc824f52ec434cc1af59c8`
(runtime source `648162e…`). Its focused Main gates tested dirty source
`b5e38bffd0a5aa0dc180722502a6eebdce0f593abf2c277209c33dd3f4477db5`;
complete standard source metadata, eleven owned-file hashes/raw modes and Git
state were identical before and after. The [Main report](../.cicada-data/lifetime-main-qa-20261001/report.json)
has SHA-256 `519b873e34a360af91da19b254e41276806160683d40e169c2a188c0c8c05b8a`.

| Main focused gate | Actual result |
| --- | --- |
| Default | exit 0; 5 top-level and 29 subtests |
| Tagged | exit 0; 6 top-level and 15 subtests |
| Tagged race | exit 0; 5 top-level and 5 subtests |
| Default/tagged vet, affected packages only | both exit 0 |

All gates had zero failures and skips. They used pinned Go 1.27.1 bookworm image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
network disabled, UID/GID 1000, source/module cache read-only, and the accepted
OpenSSL 3.5.9 stage. All six executed test binaries were hashed before execution
and retained; owned containers and generated synthetic crypto fixtures were
cleaned. Exact commands and binary hashes are in the report and per-gate receipts.

This accepts the focused integrated lifetime layer on its tested source. Later
combined QA, shipping and image acceptance are tracked in the current note above.
Same-window product SSE termination does not uniquely establish ticker causation;
trusted UTC and boundary-spanning I/O limits below remain. Native Runtime,
Android, physical-device and public HTTPS acceptance are separate. The isolated
snapshot's two failed attempts and temporary-binary `NOT_CAPTURED` remain
unchanged; the new Main capture does not rewrite those receipts.

## Isolated snapshot (2026-10-01)

This is a next-checkpoint validation of the isolated detached worktree
`/home/zyf/CICADA_pqtls_lifetime`, dated 2026-10-01. It is not an integrated Main,
released artifact, Android, real native Runtime, physical-device or public HTTPS
acceptance. No provider calls, dependency rebuild, resident deployment changes,
Client writes, commits or pushes were performed.

The prerequisite was detached `fe565b` plus a verified frozen Main code/script
overlay. Its complete Hub build-input fingerprint was
`fb8f0d8be8fbc786d8ee434dde3974d8ffe295aa0c99ac97eea9b44e4ceace62` on both sides
of the copy. Private `.cicada-data` state was excluded. Main's later formatting
of `group_broadcast_native_test.go` produced prerequisite fingerprint
`648162e9f52c2a14091f0537368097a2002dffb49b3f60a9e27fb43a07941985`; this candidate
retains the earlier verified copy. That formatting delta is outside this patch.
The candidate tested source fingerprint is
`53239f933b590c52c1d8214ab4fcdd916b28cc409532d51bed434fa40154bece`.
Dirty source is attributed to the complete inventory, not solely to HEAD.
Rebase and combined acceptance against a clean checkpoint remain future work.

## Behavior and boundaries

The private C snapshot obtains the actual `SSL_get0_verified_chain` after
`X509_V_OK`, under the existing SSL mutex. It copies the latest notBefore and
earliest notAfter of every returned verified-chain certificate, including the
returned trust anchor, into numeric UTC timestamps. Missing, malformed,
inverted or disjoint validity cannot verify. No borrowed certificate pointer
escapes C, and the existing OpenSSL thread cleanup remains on every return.
The Go snapshot is immutable; validity is start-inclusive and end-exclusive.

Both retained directions enforce that observed interval: a Node checks its Hub
peer before application Read/Write, and a Hub checks its Node peer. Handshake IO
is explicitly distinct from verified IO. Every verified SSL operation checks
current time before and after the SSL call. A monotonic certificate deadline
bounds socket polling independently of caller deadlines; clearing or extending
those deadlines cannot extend the connection's lifetime. Expiry latches failure
and closes after releasing direction/SSL locks. There is no timer goroutine per
connection, retry reset or transport downgrade.

The Hub additionally checks current certificate time before protected request
dispatch, covering bytes already buffered by HTTP. The existing independent
one-second SSE authority recheck also evaluates expiry, while wake/space writes
use a cheap validity fence without increasing database authority-check rates.
Existing Owner/Node binding and credential checks remain authoritative.
No CA/enrollment/rotation/OCSP/CRL service, TLS-epoch database, wire contract,
algorithm, profile or packaging changes are included.

These decisions assume a trusted UTC clock. A monotonic upper bound prevents
rollback from extending an already verified connection; wall-clock skew and
clock synchronization infrastructure are not solved. A forward clock change is
observed on IO/poll wake or the independent server recheck. Already accepted
operations or emitted bytes are not undone, and an SSL call spanning a boundary
cannot provide global instantaneous revocation.

## Actual focused gates

Evidence directory: `/tmp/cicada-pqtls-lifetime-plan-rl3kqren`.
The final gates use pinned Go 1.27.1 Docker image
`golang@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244`,
network disabled and UID/GID 1000. They mount the candidate read-only and reuse
the accepted OpenSSL 3.5.9 stage through its existing `cgo-runtime.env`; module
cache is read-only and provider configuration is absent. Test binaries are
Go-managed temporary binaries; their bytes were not independently captured.

| Final receipt | Actual result |
| --- | --- |
| `default-final.jsonl` | exit 0; 5 top-level and 29 subtests; zero skips |
| `enabled-final.jsonl` | exit 0; 6 top-level and 15 subtests; zero skips |
| `race-final.jsonl` | exit 0; 5 top-level and 5 subtests; zero skips |
| `default-vet-final.*` | exit 0 |
| `enabled-vet-final.*` | exit 0 |

The real OpenSSL tests use one finite 12-second certificate window per selected
package run. Raw connection tests cover short Node leaf, short Hub leaf and
verified CA expiry before the leaf, plus refusal of fresh expired and
not-yet-valid handshakes. Retained writes fail at expiry, blocked reads with a
longer caller deadline and blocked writes with no caller deadline terminate
within the test bound, and existing deadline-change/cancellation/listener-close
regressions pass, including the race gate.

The product test uses real strict PQ listeners, actual observed connection
state, a real Store and the existing product fixture. An actual Network Join
returns 201 before expiry. A retained client then refuses new authenticated HTTP
bytes after its Hub peer expires: the underlying connection reports certificate
validity failure and writes zero bytes; the Join handler count remains one.
Idle and continuously notified Node SSE streams close within the test's bounded
expiry wait; current transport binding remains unchanged. Because Hub and Node
certificates share the window, this real test does not isolate the independent
Hub ticker as the cause of closure versus Conn expiry/client teardown. The
independent ticker and buffered/event validity fences have source and deterministic
policy evidence. The separate existing
product current-authority regression also passes. Native enrollment metadata is
visibly synthetic; this is not evidence of a real model Runtime or Android flow.
Common table/server tests use explicitly synthetic state only for deterministic
policy checks, including buffered-request rejection; they are not TLS proof.

Two early tagged attempts failed and remain immutable. `enabled-focused.jsonl`
failed because TLS 1.3 client handshake completion was incorrectly treated as
proof of server admission of a future Node certificate, and because the synthetic
idle-node pairing used an expiry rejected by the existing pairing guard. The
next `enabled-focused-fixed.jsonl` failed because `http.Request.Write` flattened
the typed transport error. Corrections were confined to the new tests: observe
server admission/alert, use the fixture's permitted pairing duration, and observe
actual underlying connection Write bytes/error. Both attempt source snapshots
and terminal logs are retained; production changes did not depend on these
oracle corrections.

All owned containers terminated and were removed. Generated synthetic certificate
and private-key fixture directories were cleaned by the tests; the artifact
root is empty. Six pre-existing resident containers remain. The frozen patch,
owned hashes, complete before/after inventories, final source receipt, gate logs
and cleanup receipt are recorded by `final-manifest.json` and `report.json` in
the evidence directory. Historical native/PQ candidate receipts are unchanged.
