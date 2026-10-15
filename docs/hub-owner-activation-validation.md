# N2 Owner activation validation

## Configured Peer identity path repair — 2026-10-15

Base `570c12f`, dirty `task/n2-hub` candidate. `hub activation-issue` now checks
the actual configured Peer identity path from `CICADA_E2EE_IDENTITY_FILE`, with
the established StateDir default only when no override is configured. Previously
it checked the default path but loaded the configured one: a valid custom-only
installation was rejected, while a missing configured identity could be created
despite an existing default. This repair preserves the actual configured key
and rejects a missing one before any replacement file can be generated. It
does not alter wire identifiers, grants, epochs or existing account identities.

`go test ./cmd/cicada -run '^TestHubActivationIssuer' -count=1 -v` passed two
top-level tests and two subtests, zero skips (1.899 seconds). The synthetic
fixtures cover the retained default-path behavior, an existing custom Peer
without a default, and a missing configured Peer with an existing default.
The latter rejects and leaves the configured path absent; the existing Peer
bytes remain unchanged in both custom-path cases. `go vet ./cmd/cicada` and
`git diff --check` also passed. These are scoped CLI checks, not a new full
Docker or native-platform acceptance claim.

This repair was tested on Go 1.27.2 with the updated stable dependency closure,
using immutable builder
`sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`,
network disabled and a read-only module cache. Private structured evidence is
`/home/zyf/Cicada/.local/evidence/n2-hub/peerpath-repair.json`; it records the
source scope, actual completed command results and dirty source SHA-256
`8965e18e889f545dde88cdd2c3ebda6af25e2101db8ba2319555322a5fd9e70e`.
The earlier default-path and Go 1.27.1 results below retain their original
source attribution.

## Hub service checkpoint — 2026-10-15

Source base `c6107a8c6974fe804e39ebafdd819c1219f26bef`, dirty task branch
`task/n2-hub`. This implements schema 62, `hub activation-issue`, the four new
HTTP routes, Owner KEM/signature proof, exact legacy pending-key continuation,
atomic account/Root/grant/lease/receipt completion, 15-minute read scope and
authenticated account rejection fences. No App implementation is changed.
The [contract](hub-owner-activation-contract.md) records availability and scope.

The builder remains the immutable Go 1.27.1 image identified below, with the
existing read-only module closure and private N2 compiler cache. The coordinated
Go 1.27.2/module upgrade and final disposable Docker interop are owned by the
integration/acceptance threads and are not attributed to these commands.
The compatibility browser loader now expects the coordinated Go 1.27.2 WASM
manifest; model/static tests cover that guard. A browser/WASM artifact from this
intermediate old-toolchain branch is not a delivery artifact.

| Check | Result |
|---|---|
| `go test ./internal/clientwire ./internal/hubaccountwire ./internal/hubauth ./internal/hubowner` | PASS |
| `go test ./internal/server ./cmd/cicada -run 'TestN2\|TestHubAccount\|TestHubOwner\|TestHubActivation' -count=1` | PASS |
| `go test ./internal/store -run 'TestN2\|TestHubAccount\|TestHubOwner\|TestV2Migration' -count=1` | PASS |
| `go test ./internal/store -run 'TestHub\|TestOwner\|TestClient\|TestV2Migration\|Test.*Restore\|TestN2' -count=1` | PASS |
| `go test -race ./internal/clientwire ./internal/hubaccountwire` | PASS |
| `go test -race ./internal/server ./internal/store -run '^TestN2' -count=1` | PASS |
| `go vet ./internal/clientwire ./internal/hubaccountwire ./internal/hubauth ./internal/hubowner ./internal/store ./internal/server ./internal/control ./cmd/cicada` | PASS |
| Both N2 metadata and frozen Client contract Python checks | PASS; Client catalog unchanged |
| `node scripts/test-web-panel.mjs --model-only --ui cicada-go/internal/server/ui` | PASS; real WASM NOT_RUN in this command |
| Standard disposable Hub Docker interop, final Go 1.27.2 integrated gate | NOT_RUN by this Hub checkpoint; integration owner runs separately |
| Native Windows/DPAPI/ACL, Android, native Runtime, physical device, public HTTPS, PQTLS | NOT_RUN |

Real TCP tests run the Hub account handler without Control. They cover both
response-loss/reopen windows, byte-identical cached packets, concurrent same
prepare/complete, rejected replacement keys, exact existing credential/key/
device preservation, separate account login, wrong password then authenticated
rejection/corrected login, expired session then reconciliation/re-login, and
original-login versus terminal-fence races. Account session expiry is a clearly
disposable database fault fixture; no resident Hub is used.

Negative completion tests cover missing real Owner possession, expired grant/
challenge, reused nonce and full transaction rollback: no credential, Root
history, Client grant or lease remains after the last ledger write conflicts.
Local cancellation and Root revocation fence cached ACTIVE activation results;
fresh status reports current revocation while retaining the old historical
receipt. Status carries the full real PQ challenge, including maximum 128-byte
Hub/Owner/account scope IDs, within the unchanged 256/384 KiB packet limits.
Old Client APIs still reject bodies above 64 KiB; only the four new operations
select explicit bounded-body helpers. Invalid wire Grant/proof/candidate/epoch
substitution coverage also remains in the protocol checkpoint.

Store tests separately verify the two-operation lease intersection, required
current account login, expiry, forbidden new requests, receipt-only recovery,
immutable expiry/deletion rejection, restore epoch fencing with retained
credentials/Root keys, and a 128-entry diagnostic response budget which still
permits exact retry and primary terminal fences. Dispatch/capabilities use the
actual Control authorization path in a separate disposable fixture; this does
not make account authentication depend on Control. CLI tests check local-only
issuance, mode 0600 output, secret-free stdout, unknown legacy refusal and
byte-identical retained Hub identities.

Retained failures: initial migration regressions expected only 61 ledger rows;
the fixtures now include the additive 62 boundary and do not weaken migration
checks. The first CLI fixture lacked a mode-0700 output directory and was
corrected. The first status receipt test failed at its 96 KiB nested limit;
after increasing only that limit to 128 KiB, it exposed the underlying frozen
64 KiB Client plaintext default. Explicit new-operation body helpers fixed
that gap while default Client seals/opens and published vectors remain intact.
These failures are not counted as passes.

Private task evidence lives under `/home/zyf/Cicada/.local/evidence/n2-hub/`.
`server-source.json` records dirty content SHA-256
`6768ba1a06bbe5981f0010babe29dafdc33ff6826c0cf03bb60515baf299d1f6`
and its scope; regression logs are
`server-store-regression.log` and `server-http-cli-regression.log`. A dirty
build is not identified solely by its HEAD. No private keys, credentials,
signed grants or full sensitive payloads are included in these receipts.

## Protocol helper checkpoint — 2026-10-15

Base `c1b6a30`, branch `task/n2-hub`, dirty protocol candidate. This checkpoint
contains the additive contract, Go packet/crypto helpers, strict validation,
target comparison helpers and metadata check. **The Hub implementation and
CLI activation issuer are not yet provided by this checkpoint.**
See [the contract](hub-owner-activation-contract.md) for exact authority,
finite runtime lease and server checkpoint requirements. Frozen Client contract
`client-hub-v1.6.5`, wire 1 and catalog 55 are unchanged. Software remains
0.0.5; schema-62 work is planned for the implementation checkpoint.

Tests use generated synthetic identities and disposable in-memory state.
Host `go` is absent. The installed immutable builder was used with no network,
read-only dependency closure and private compiler cache:
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
(Go 1.27.1 linux/amd64). Coordinated Go 1.27.2 testing follows separately;
the protocol checkpoint does not claim that newer-toolchain result.

| Check | Result |
|---|---|
| `go test ./internal/hubaccountwire ./internal/ownerbootstrap ./internal/hubauth ./internal/hubowner` | PASS |
| `go test -race ./internal/hubaccountwire` | PASS |
| `go vet ./internal/hubaccountwire` | PASS |
| `python3 scripts/owner-activation-contract.py check` | PASS; metadata only |
| `python3 scripts/client-contract.py check` | PASS; 55 operations; catalog SHA-256 `a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9` |
| `git diff --check` | PASS |
| Server/CLI/Store N2 acceptance and disposable Docker Hub interop | NOT_RUN at protocol checkpoint; required at implementation checkpoint |
| Native Windows, Android, native Runtime, physical device, public HTTPS, PQTLS | NOT_RUN |

New negative coverage includes substituted account/Owner/App/epoch,
prepare/grant/request digest, client nonce, loopback policy, changed allowlist,
overlong or inconsistent lease, overlong grant enrollment window, wrong Owner
private key, tampered KEM challenge and tampered independent Grant. Exact
different encrypted bytes under the same request ID cannot settle a response.
Legacy material rejects unknown Owner keys. Account reconcile/status target
comparisons reject altered original IDs or digests; ABSENT remains uncertain.
These helper checks do not prove transactional server fencing or runtime Guard.

Private evidence is under `/home/zyf/Cicada/.local/evidence/n2-hub/`:
`protocol-source.json` records its domain-separated scope/content hash and
`protocol-go-test.jsonl` records package and case results. No credentials,
grants or private keys are included. The initial host attempt failed because
`go` was absent; an initial builder attempt mounted an obsolete module cache
and failed dependency resolution. The final builder used the correct verified
read-only closure; those setup failures are not test passes.
