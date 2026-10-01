# Optional OpenSSL 3.5.9 transport checkpoint

Status: isolated transport package; no Hub/Node adapter integration or production
acceptance. Adopted architecture remains `CICADA.md`. This note records the new
implementation and its validation boundary, not a change to enrollment or the
public contract.

## Decision and scope

Keep HTTP handlers, routing, Guard, and application E2EE in Go. Add the optional
`cicada-go/internal/pqtls` package, backed directly by official OpenSSL 3.5.9
through CGo. There is no TLS proxy, extra service, wire preface, new Go module, or
fallback to `crypto/tls`. The package is enabled only with `cicada_pqtls`, CGo,
Linux, and amd64. All other builds return the typed `ErrUnavailable`; Linux arm64
is deliberately unavailable pending real arm64 validation.

Both endpoints must negotiate TLS 1.3, pure `MLKEM768`,
`TLS_AES_256_GCM_SHA384`, ML-DSA-65 CertificateVerify authentication, and ALPN
`http/1.1`. The C bridge checks actual negotiated values and verification result
after handshake. Both leaf and verified chain must have ML-DSA-65 public keys and
certificate signatures. This strict chain requirement needs a dedicated PQ CA.
Session resumption, tickets, early data, and renegotiation are disabled.

`Config` specifies separate TLS certificate/key files, explicit CA anchors, the
local Hub/Node identity, and approved peer identities plus certificate-DER SHA-256
or DER SubjectPublicKeyInfo SHA-256 pins. SAN matching requires an exact DNS
service identity without subject-CN fallback or wildcards. No OS trust defaults,
TOFU, or unpinned peer is allowed. Private-key files must be regular, owned by the
effective process user, owner-readable, and inaccessible to group/others;
symlinks are rejected. Node and Hub TLS keys must differ and must never reuse
NodeControl/Endpoint E2EE material.

The OpenSSL certificate verification callback checks the chain, SAN, pin, pure
certificate algorithms, and distinct TLS keys before a Node sends its client
Certificate/CertificateVerify. Callback policy is a bounded C-owned copy; it
retains no Go pointers and does not call Go. A second check maps the verified
certificate to the configured identity and rejects conflicting identity/epoch
aliases. The receiving `s_server -msg` test includes a positive control: an
approved Hub receives one Node Certificate and CertificateVerify, while a Hub
with a valid CA/hostname but incorrect pin receives neither.

The configured Node binding epoch is only connection metadata. An established
TLS identity grants no Manager, Endpoint, Group, or peer-data permission. A later
Hub integration must recheck current owner binding/epoch and `CicadaNode` Guard
authorization for each request. A successful client-side TLS handshake does not
prove the server accepted the client pin or grant application authorization.
The common-Hub topology and narrow same-host direct exception, as well as the
Endpoint/NodeControl application E2EE boundaries, remain specification concerns
outside this package.

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

The isolated, network-disabled disposable Docker gate runs package tests, race,
vet, CGo-off/default-build tests, unsupported Windows/macOS/js-wasm/Linux-arm64
stub cross-compiles, and CICADA command test-binary/CGo-off build checks. Tests
cover the exact positive profile, certificate/SPKI pins, wrong CA/pin/SAN,
unapproved/missing Node certificates, X25519, X25519MLKEM768, alternate suite,
TLS 1.2, classical signature/server, HTTP/2 rejection, TLS key reuse, ambiguous
identity aliases, lifecycle, bounded admission, and HTTP/1.1 SSE. Rejected peers
never reach the test HTTP credentials/body handler. Tests generate private,
visibly synthetic certificates and delete them after execution.

The final handoff is `.cicada-data/PARALLEL_REPORT.md` and
`.cicada-data/PARALLEL_STATUS.json`, with source SHA maps, exact executed counts,
skips, exits, log hashes, measured amd64 runtime/test-binary bytes, and sampled
resource results. A skip is not a pass. The CICADA command does not import this
package: its optional-tag binary delta is metadata, not adapter shipping cost.
The package enabled/stub test-binary delta includes different test code and is
not an isolated production overhead measure.

Production HTTP routes, browser/Android/Client interop, reverse proxies, real
native Runtime, physical devices, public HTTPS, deployments, and arm64 execution
are **NOT_RUN**. This checkpoint starts no production listener, changes no real
keys or deployment, and stops at the isolated package ownership boundary.
