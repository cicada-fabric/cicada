# Independent TLS key and CSR primitives

This bounded checkpoint adds local ML-DSA-65 key generation and PKCS#10 CSR
inspection to `internal/pqtls`. A CSR proves possession of its signing key. Its
role and DNS name are requested certificate properties; they do not authorize
a Hub, Node, Owner, issuer, TLS epoch or business operation.

The implementation uses the existing isolated OpenSSL **3.5.9** runtime, source
SHA-256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
It adds no dependencies, CA, certificate issuance, persistent authorization,
enrollment route, CLI command, automatic rotation or Client operation. Existing
transport configuration and authorization remain separate from these primitives.

## API and material boundaries

`GenerateTLSCSR(TLSCSRParameters{Role, DNSName})` returns an opaque
`TLSPrivateKey` and public `TLSCSRProfile`. Every invocation generates a new
ML-DSA-65 key through OpenSSL; it has no existing-key import or filesystem API.
The caller chooses `node` for `clientAuth`, or `hub` for `serverAuth`, and an
exact lowercase DNS name. Wildcards, IP addresses, uppercase names, empty labels,
overlong labels and strings that could inject extension configuration are rejected.

`InspectTLSCSR(PEM, expectedParameters)` accepts exactly one header-free
`CERTIFICATE REQUEST` PEM block, with optional surrounding ASCII whitespace.
Input is bounded to 32 KiB before decoding. It rejects leading junk, multiple
blocks, extra PEM headers, trailing text and trailing DER. It requires:

- PKCS#10 version 0, empty subject and exactly one extensionRequest attribute;
- actual ML-DSA-65 public key and ML-DSA-65 signature OID with absent parameters;
- a valid request signature under that public key;
- exactly four extensions: critical `basicConstraints=CA:FALSE`, critical
  `keyUsage=digitalSignature`, the selected single EKU, and the single exact DNS SAN;
- no unknown, duplicate, differently encoded or differently critical extensions,
  no additional attributes, no CN fallback and no extra SAN or EKU.

OpenSSL parses and verifies PKCS#10, SPKI, signature and extensions. The bridge
compares extension encodings against objects built by official X.509 APIs, and
checks the complete extensionRequest value rather than ignoring hidden trailing
bytes. It never copies arbitrary requested extensions into an issued certificate.
There is no certificate issuer in this checkpoint.

The public profile contains a standard CSR PEM encoding, public SPKI DER, and
SHA-256 of exact accepted CSR DER bytes and the SPKI DER exported by OpenSSL.
Inspection does not assert canonicalization of the complete input CSR DER.
Digest identity does not depend on PEM wrapping. Neither
digest is an Owner approval or a trust anchor. Callers must separately bind these
public values to current, independently approved identity and authorization.

Private material is available only through explicit `TLSPrivateKey.ExportPEM()`.
The result is an independent unencrypted PKCS#8 PEM copy; the caller must secure
and clear that copy. Formatting the opaque handle redacts it; JSON marshaling
fails. `Destroy` clears the retained Go buffer, is idempotent, and shares state
across copied handles. Export and Destroy serialize under a mutex. No private
key enters the public profile, an error message, a log or a network request.

The C bridge owns its allocations and clears serialized secret buffers before
freeing them, including partial serialization on failure. Go copies private
output once before the C buffer is cleared. Each C call creates an isolated
library context, frees EVP/X.509 objects, calls `OPENSSL_thread_stop_ex`, and
frees that context on the same calling thread. It retains no Go pointers or
native key/context handles between calls. Buffer clearing does not promise
locked memory, removal of caller copies, or protection against a malicious host.

## Platform and errors

Native support remains Linux amd64 with CGo and the `cicada_pqtls` build tag.
The compile-time header check and existing runtime check require exactly 3.5.9.
Default, CGo-disabled and unsupported builds return typed `ErrUnavailable` before
generating or inspecting any material. No alternate crypto or transport fallback
is introduced.

Invalid expected parameters return `ErrConfig`; malformed PEM/DER or a failed
CSR signature return `ErrCSR`; an unexpected key, signature or requested profile
returns `ErrProfile`. Native setup/generation failures return `ErrUnavailable`.
Errors contain fixed classifications, without OpenSSL error-stack payloads.

## Validation scope

The targeted tests cover generation for both roles; exact public digests; official
OpenSSL CSR verification and exported-key/SPKI agreement; independent Hub/Node
keys; wrong role/DNS; classical and wrong ML-DSA keys; subject, extension and
attribute substitution; malformed or multiple inputs; tampered signatures;
opaque-handle redaction, export/destruction races and concurrent native context
cleanup. All CLI fixtures are private, synthetic and removed with their disposable
test environment. The CSR-only test mode deliberately skips the older transport
TestMain's CA/leaf fixture creation. It accepts exactly `-test.run=^TestTLSCSR`;
other selectors explicitly fail before running tests and are marked NOT_RUN.
Ordinary mode retains the original transport fixture setup.

Pinned offline targeted unit/race, default/CGo-disabled tests and unsupported
platform compile results are recorded in the private checkpoint receipt. Tests
and build outcomes belong to their exact source and binary hashes. A skip is not
a pass; cross-compilation alone does not establish execution on that platform.

CA issuance, Owner-approved TLS authority/CAS, installation/rotation, retained
connection revocation, recovery rollback, Docker distribution, Android, real
native Runtime/model consumption, arm64 hardware, physical devices and public
HTTPS are **NOT_RUN** for this CSR checkpoint. Earlier transport or shipping
receipts retain their original source attribution.

## Official API references

Key generation uses `EVP_PKEY_Q_keygen` with `ML-DSA-65`.
[OpenSSL key generation](https://docs.openssl.org/3.5/man3/EVP_PKEY_keygen/)

CSR signing uses `X509_REQ_sign_ctx`; inspection uses `X509_REQ_verify_ex`.
These use standard PKCS#10 and OpenSSL X.509 encoding rather than a new PKI format.
[OpenSSL X.509 signing](https://docs.openssl.org/3.5/man3/X509_sign/)

The ML-DSA signing context uses `EVP_DigestSignInit_ex` with a NULL digest name,
as required by the provider API. It does not introduce an application prehash or
custom signature variant.
[OpenSSL ML-DSA signatures](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
