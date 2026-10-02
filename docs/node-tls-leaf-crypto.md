# Local ML-DSA-65 TLS leaf certificate primitives

This C slice depends on the separately frozen B key/CSR primitives. It adds only
explicit local issuer import, fixed-profile leaf issuance and public inspection.
Neither a valid CSR nor a certificate signature establishes Owner approval,
current device permission, a Hub/Node binding or a TLS epoch. No Store, CLI,
enrollment route, deployment, rotation or Client contract is implemented here.

## Inputs and trust

`ImportTLSIssuer(chainPEM, keyPEM, trustPEM, role, at)` accepts one independently
specified public root and a complete issuer-first chain ending in that exact
root, with two to four certificates. The first certificate is a distinct issuing
CA with critical CA:true/pathLen:0 and keyCertSign usage. The chain must satisfy
OpenSSL strict path validation, CA constraints, selected client/server purpose,
ML-DSA-65 public keys and signatures, and the supplied verification time. Every
CA key in the chain must differ from the other CA keys. The issuer's explicitly
imported, single unencrypted PKCS#8 private key must be ML-DSA-65 and match that
first CA certificate. Direct root-as-issuer import is outside this narrow API.

The trust input is caller-supplied through an independent local trust procedure.
The function does not fetch trust, load system roots, convert a CSR/self-signed
leaf into trust or deduce Owner approval from a matching pin. It does not create
a CA. The opaque `TLSIssuer` redacts formatting, rejects JSON serialization and
has no private export. Copies share locked state. Destroy clears the retained
Go key buffer; signing and Destroy serialize. Caller-owned input copies must be
secured and cleared by their caller.

## Issuance and the CSR-to-certificate rule

`TLSIssuer.IssueTLSLeaf(CSR, TLSLeafParameters, at)` first applies B's strict CSR
inspection. Unexpected CSR extensions/attributes are rejected, not accepted
and ignored. The expected SPKI hash must match the verified CSR public key, and
that key must differ from every issuer/root CA key before signing. This cannot
detect reuse of an unrelated Endpoint, NodeControl or Owner key without their
independently supplied identities; that remains an authorization-layer check.

Parameters fix node/clientAuth or hub/serverAuth, one exact lowercase DNS name,
a nonzero positive serial in a 16-byte container, exact second-resolution UTC
notBefore/notAfter, and an expected public SPKI hash. Lifetime is at most 24 hours,
contains `at`, and fits completely inside the verified issuer chain's validity
intersection. The caller must reserve serial uniqueness and supply trusted UTC;
these stateless primitives do neither persistent CAS nor automatic renewal.

The issuer constructs a v3 leaf with empty subject and exactly six extensions:
critical CA:false, critical digitalSignature, the single role EKU, a **critical**
single DNS SAN, standard subject key identifier and authority key identifier.
It uses official OpenSSL X.509 extension/signing APIs and no copied CSR extension
objects, custom ASN.1 encoder or application prehash. SKI/AKI are standard public
key identifiers, not authenticators or Owner trust. Signature/key authentication
is ML-DSA-65; public receipt hashes use SHA-256.

B requests a noncritical DNS SAN in PKCS#10; C deliberately constructs critical
SAN for the issued empty-subject certificate. RFC 5280 requires this criticality
for such certificates. Successful CSR verification is not issued-certificate
compliance. Public inspection rejects a noncritical SAN on this empty-subject
profile. [RFC 5280 subject rule](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.6),
[SAN rule](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6).

`InspectTLSLeaf(leafPEM, chainPEM, trustPEM, expected, at)` verifies only the explicit
public trust/chain and the complete fixed leaf profile: actual ML-DSA-65 key and
inner/outer signature algorithms with absent parameters, signature/path/purpose,
empty subject, exact DNS/serial/validity/SPKI, six extensions with exact values
and criticality, no extra/duplicate extensions, and no CA key reused as the leaf.
It rejects malformed/multiple PEM, headers, skipped bad blocks and trailing DER.
Current Owner grants, revocation, TLS epochs and connection authorization are
not available to this crypto API and are not implied by success.

Public profiles contain certificate PEM, exact accepted/generated certificate
DER hashes, OpenSSL-exported SPKI DER hashes, issuer/root hashes and verified
validity intersection. Inspection does not claim complete DER canonicalization.
The CSR digest appears only in issuance results that actually checked the CSR.
No private key enters a result, error, log or public request.

## Native ownership and platform limits

The existing accepted OpenSSL 3.5.9 stage and pinned offline Go toolchain are
reused. Each C call owns its EVP/X.509/context objects, stops context-specific
thread state before context destruction and clears private DER copies and
decoded PKCS#8 secret octets on success/error paths. No native key/context or Go
pointer survives between calls. Go clears temporary decoded secret buffers.
Clearing does not promise locked memory, erasure of caller copies or protection
against a malicious host; allocator failure and leak instrumentation are separate.

Default, CGo-disabled and unsupported targets return typed ErrUnavailable.
Native support remains tagged Linux amd64/CGo. There is no alternate crypto,
trust-on-first-use or transport fallback. This slice adds no dependency or
production PKI process, and performs no filesystem writes in its API.

## Evidence and dependency attribution

Targeted synthetic tests exercise issuance/inspection for both roles; official
OpenSSL strict verify/hostname/purpose and SPKI equality; wrong issuer key,
trust, algorithm, CA/pathLen/KU/EKU/time; malicious signed leaf profiles; strict
CSR/expected-key mismatch, CA-key reuse, lifetime bounds, opaque destruction,
concurrency, stubs and test selector rejection. Private synthetic CA fixtures
exist only in the disposable test environment. Exact source/binary identities,
commands, exits, failures and counts belong to the independent C receipt.

The existing TestMain gains a separate certificate-only mode requiring exactly
`^TestTLSCertificate`; all/old/mixed selectors explicitly fail as NOT_RUN. B's
exact CSR-only guard and the default full transport fixture path are preserved.

B's immutable manifest correctly records actual raw mode 436 decimal (**0664**)
for all eleven B files. Its old report and handoff text incorrectly said 0644.
This note corrects that description without modifying B's frozen receipts.
B full source fingerprint `54021315…` belongs only to its isolated worktree;
C and the Root's combined Main candidate have independent fingerprints.

Owner authority/CAS, automatic issuance policy, install/enroll/rotation/recovery,
deployed PKI, full transport/distribution acceptance, Client/Android, native
Runtime/model, real arm64/other-platform execution, physical devices/public HTTPS
remain NOT_RUN in this leaf-crypto checkpoint.

Official API references: [X.509 signing](https://docs.openssl.org/3.5/man3/X509_sign/),
[verification context](https://docs.openssl.org/3.5/man3/X509_STORE_CTX_new/),
[extension context](https://docs.openssl.org/3.5/man3/X509V3_set_ctx/),
[ML-DSA signatures](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/).
