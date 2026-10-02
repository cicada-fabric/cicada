# Optional OpenSSL 3.5.9 transport checkpoint

## Current source boundary (2026-10-02)

Clean Main `144e079` includes optional Hub/Node production transport wiring, current Store/Guard checks, per-Hub Node transport selection and certificate-lifetime checks for connections, requests and SSE. Its exact clean STD/PQ artifact gates and limited native evidence remain attributed in the [clean artifact/native validation](v01-clean-artifact-native-checkpoint-validation.md); native STD results do not imply native-over-PQ acceptance.

The integrated dirty Main source-input fingerprint is `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` on Git HEAD `144e079`, candidate v1.6.3/catalog `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`, wire 1, 55 operations and schema v55. Its focused normal gate passed 49 top + 128 subtests across six packages, zero skips/failures; affected vet/build and contract check/export/verify passed. This is not a full, tagged or race rerun on the integrated source. The exact clean standard/PQ artifacts and image gates are pending.

The tagged CSR/certificate normal/race receipts remain attached to source `cb4d1229…`: CSR 9 + 32 and certificate 9 + 40 top/subtests per run, zero skips/failures, with standard/tagged vet/build 0. On that same source, the broad focused Store race attempt failed on its 20-minute timeout (93 top + 134 subtests passed, zero skips; five packages passed). These results do not transfer to `72ec78…`. The integrated candidate contains C's explicit issuer import, leaf issue and leaf inspection paths. They require a supplied pathLen=0 issuer, explicit trust and matching key; they do not create a CA, Owner authority, filesystem installation, or automatic enrollment/rotation. For an empty-subject issued leaf, SAN is critical; a noncritical CSR request alone is not an issued-certificate violation.

TLS authorization, installation, enrollment, rotation/revocation and verified restore remain open. PQ execution is Linux amd64 only; stub compilation is not arm64 acceptance. Android/physical-device pure-PQ, native Runtime over PQ, Client native runtime and public deployment are NOT_RUN. PQ authority D1 work remains in its separate worktree and is not integrated or accepted in Main; product startup/reload, current-authoritative-floor and renewal remain PARTIAL. Adopted architecture remains `CICADA.md`; this document does not change the public contract.

## Historical standalone adapter checkpoint

The following adapter design and lifecycle details describe the standalone package before Hub/Node production wiring. Their original source-specific validation, sizes, counts and failed attempts remain attributed to that checkpoint; later integration above does not rewrite them.

## Decision and scope

Keep HTTP handlers, routing, Guard and application E2EE in Go. The optional
`cicada-go/internal/pqtls` package uses official OpenSSL 3.5.9 through CGo; it
adds no proxy, service, wire preface, Go module or fallback to `crypto/tls`.
The package is enabled only with `cicada_pqtls`, CGo, Linux and amd64. Other
builds return typed `ErrUnavailable`; Linux arm64 remains unavailable pending
real arm64 validation. Both endpoints require TLS 1.3, pure `MLKEM768`,
`TLS_AES_256_GCM_SHA384`, ML-DSA-65 CertificateVerify and ALPN `http/1.1`.

## Go HTTP and connection lifecycle

`Listen` exposes only fully handshaken and verified connections to
`http.Server.Serve`. One accept pump admits bounded concurrent workers. The
default limit is 16, configurable from 1 to 64; admission includes verified
connections waiting for `Accept`. Excess sockets are closed immediately, and
listener close cancels workers and closes queued connections. A stalled peer
does not serialize all other handshakes. This is not a total limit on accepted
HTTP connections or a production denial-of-service capacity result.

`NewClient`, `DialContext`, and `HTTPTransport` supply already verified connections
to `http.Transport.DialTLSContext`. The transport restricts dialing to one origin,
rejects plain HTTP, disables proxying and HTTP/2, and uses HTTP/1.1 for SSE. The
owning `http.Client` should reject redirects. Changing the returned transport
configuration is outside this tested surface.

`Request.TLS` and `Response.TLS` are nil: these are not `crypto/tls.Conn` objects.
Set `http.Server.ConnContext` to `HTTPConnContext` and use `StateFromContext` for
the immutable negotiated profile/peer identity. Missing state or a request for
synthetic Go TLS state returns `ErrHTTPState`. HTTP/2 and APIs that require Go's
TLS state need separate integration proof before use.

Each connection owns a duplicate nonblocking TCP descriptor; the original Go
descriptor closes immediately. A custom BIO uses per-call `MSG_NOSIGNAL`, without
changing process signal handling. SSL calls serialize under one lock;
read/write gates remain separate and release the SSL lock during `poll`.
`WANT_READ`/`WANT_WRITE` wait on actual socket direction and per-operation
deadlines. Two eventfds wake deadline changes and close. Cancellation, deadline
changes, concurrent read/write, and idempotent close have bounded loopback tests.
Close aborts instead of waiting for peer `close_notify`, wakes/shuts down first,
then frees SSL/BIO before closing owned descriptors. Failed or interrupted writes
abort the connection so a pending TLS record cannot be retried with other bytes.
Handshake deadlines are cleared before returning a connection; SSE verifies
operation beyond the handshake timeout, disconnect, handler cancellation, and
reconnection.

Nondefault OpenSSL library contexts also require per-OS-thread cleanup before
the context is freed. Serialized CGo calls may use different Go runtime threads;
serialization alone does not satisfy that lifetime requirement. The repaired
bridge calls `OPENSSL_thread_stop_ex` before returning from context-using C calls
and, after freeing SSL/provider objects, before `OSSL_LIB_CTX_free`. It preserves
`SSL_get_error` in the same C call immediately after I/O. A subprocess test
checks bounded connection lifecycle followed by actual process exit.

Each connection currently owns its own provider/library context/SSL context and
reloads configured material. This favors simple lifetime isolation over reuse;
there is no shared-context scalability claim. `TestTransportResourceMeasurements`
runs alone, measures eight concurrent client/server pairs (16 TLS connections),
samples RSS at 1 ms, and records concurrent dial latencies. RSS includes Go,
provider, and socket overhead; sampled peak is not an allocator attribution or
production capacity forecast. Actual numbers and commands are in the private
handoff report and JSON evidence.

## Reproducible isolated build and execution

The pinned source is OpenSSL **3.5.9**, SHA-256
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`
(53,279,637 bytes). Any patch/version change requires reviewed pin changes and
repeated profile tests. The offline build/test image is
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
with Go 1.27.1 linux/amd64 and GCC Debian 12.2.0-14+deb12u1. No new Go dependency
is introduced.

Within that pinned container, with a writable repository and a read-only source
archive, run the standalone helper against a **new** ignored output directory:

```bash
bash scripts/build-pqtls-runtime.sh /inputs/openssl-3.5.9.tar.gz /repo/.cicada-data/pqtls-openssl-accepted-build
source /repo/.cicada-data/pqtls-openssl-accepted-build/cgo-runtime.env
export GOTOOLCHAIN=local GOPROXY=off
export PQTLS_TEST_ARTIFACT_DIR=/repo/.cicada-data/pqtls-evidence
cd /repo/cicada-go
go test -tags cicada_pqtls -count=1 -json -timeout 60s ./internal/pqtls
go test -tags cicada_pqtls -race -count=1 -json -timeout 90s ./internal/pqtls
go vet -tags cicada_pqtls ./internal/pqtls
CGO_ENABLED=0 go test -tags cicada_pqtls -count=1 -json ./internal/pqtls
```

The helper verifies the archive SHA before extraction, configures
`linux-x86_64 shared no-tests no-docs no-legacy`, and installs only into its own
`DESTDIR` under the versioned `/opt/cicada-openssl/3.5.9` prefix. It emits explicit
`CGO_CFLAGS` include, `CGO_LDFLAGS` library, `LD_LIBRARY_PATH` loader, and CLI paths
in `cgo-runtime.env`, and checks the CLI's loaded version and `ldd` library paths.
Use this environment per process in the same mount layout; relocation requires
regenerating paths. No RUNPATH is embedded. Deployment packaging must supply its
own explicit, reviewed per-process loader paths; never replace distro libraries
or set a global loader redirect. Final tests also record `ldd` for the Go test
binary, confirming both libraries resolve to the private staged runtime.

The runtime archive includes CLI/shared libraries and Apache-2.0 `LICENSE.txt`
(and upstream `NOTICE.txt` if present), excluding headers, static archives, and
pkg-config metadata. Full upstream OpenSSL tests are **NOT_RUN**; this checkpoint
does not claim FIPS validation. Source/library/license/archive hashes, file sizes,
and the compiler/Go executable hashes are recorded in the private evidence.

## Validation and handoff boundary

The original isolated, network-disabled disposable Docker gate runs package tests, race,
vet, CGo-off/default-build tests, unsupported Windows/macOS/js-wasm/Linux-arm64
stub cross-compiles, and CICADA command test-binary/CGo-off build checks. Tests
cover the exact positive profile, certificate/SPKI pins, wrong CA/pin/SAN,
unapproved/missing Node certificates, X25519, X25519MLKEM768, alternate suite,
TLS 1.2, classical signature/server, HTTP/2 rejection, TLS key reuse, ambiguous
identity aliases, lifecycle, bounded admission, and HTTP/1.1 SSE. Rejected peers
never reach the test HTTP credentials/body handler. Tests generate private,
visibly synthetic certificates and delete them after execution.

The original isolated handoff in `/home/zyf/CICADA_pqtls` is
`.cicada-data/PARALLEL_REPORT.md` and `.cicada-data/PARALLEL_STATUS.json`, with
source SHA maps, exact executed counts,
skips, exits, log hashes, measured amd64 runtime/test-binary bytes, and sampled
resource results. A skip is not a pass. At that original adapter snapshot the
CICADA command did not import this package: its measured optional-tag binary
delta was metadata, not adapter shipping cost. Current product wiring does
import the package; these historical measurements do not measure that product.
The package enabled/stub test-binary delta includes different test code and is
not an isolated production overhead measure.

The module was integrated as `1547f2e`. Its clean main enabled-race first attempt
failed for a missing fixture environment; the second passed 22 top + 36 subtest
assertions but exited 1 with SIGSEGV during race finalization. Both are retained
FAIL results, separate from the independent adapter PASS and the main stub's
3 top + 13 sub PASS. The subsequent two-file dirty repair on `1547f2e` passes
standard and race gates, each 23 top + 36 sub with process exit 0, plus the
focused subprocess and vet, on pinned offline UID-1000 execution. The original
focused negative control also passed: the requirement correction is **not a
proven causal explanation** for the earlier SIGSEGV. Source/report hashes and
the separately passing stable-source main Go/PQ gate are in the
[transport/recovery checkpoint](v01-transport-recovery-checkpoint-validation.md).
Original binary sizes, resource samples and arm64 stub compilation remain tied
to the original adapter source; they are not repair or product measurements.

At the original adapter handoff, production HTTP integration,
browser/Android/Client, reverse proxies, real native Runtime, physical devices,
public HTTPS, deployments and arm64 execution were **NOT_RUN**. That isolated
checkpoint started no production listener, changed no real keys or deployment,
and stopped at the package ownership boundary. Subsequent Hub/Node production
wiring is recorded above. Separately attributed native HTTP/Client checks still
do not establish real native Runtime acceptance over this transport.
