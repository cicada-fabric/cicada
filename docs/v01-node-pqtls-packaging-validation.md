# v0.1 optional Node PQ transport distribution

This checkpoint adds an explicit Linux amd64 distribution of the adopted pure
ML-KEM-768 / ML-DSA-65 / AES-256-GCM transport. The ordinary five-platform
CGO0 release and Alpine Hub keep their ordinary transport. Public availability
metadata does not grant device authority: current Store owner/epoch and request
Guard remain authoritative. Wire version, contract revision, software version,
Git revision, source fingerprint, archive SHA and immutable image ID are separate.

The packaging patch is based on `06d0a582641ece2553cc824f52ec434cc1af59c8`
plus the independently reviewed eleven-file certificate lifetime patch. That
patch enforces verified-chain validity on I/O, HTTP admission and active/idle
SSE, including an earlier root expiry and bounded blocked reads. This document
does not add automatic issuance, CA enrollment, key rotation or OCSP/CRL.

## Build and distribution

Use Go 1.27.1 on native Linux amd64, CGO1, and `-tags cicada_pqtls`. Unsupported
PQ targets, CGO0 and a missing or modified accepted OpenSSL stage fail before
building an artifact. Production WebCrypto is regenerated in a disposable copy;
the checkout and accepted library bytes stay unchanged.

```sh
scripts/build-release.sh 0.1.0-dev dist-pq --transport pqtls --pqtls-stage "$PREFIX"
scripts/build-hub-image.sh --image cicada-pq:local --transport pqtls --pqtls-stage "$PREFIX" --metadata-file image-build.json
```

`PREFIX` is the accepted OpenSSL 3.5.9 development stage, not a download or a
system installation. Its source SHA256 is
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
The 142-header identity is
`970a70cabcb6058c0152f957925d62bca6274d5de25a8cece9540f746b4b443c`.
The selected 145-file header/library/license closure is
`f4f0969bfff33d505e542dc234b97bb5358956474dd04ad455046e5390f8a4a3`.

| Runtime file | Bytes | SHA256 |
| --- | ---: | --- |
| libssl.so.3 | 1,262,480 | 83a963dfc76672d91efad7ddbd151b8d9dfea69c1080b4980520d56566b35696 |
| libcrypto.so.3 | 7,189,040 | f188195dd6841a349002ca8dc081ecaa1acf50503a3224ce8d2ccc5ee8a70352 |
| OpenSSL LICENSE.txt | 10,175 | 7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a |

The relocatable archive contains `bin/cicada`, sibling `lib/*.so.3`, actual
OpenSSL/Go/compiled dependency notices, metadata, README and SHA256SUMS. It
contains no headers, source trees, CLI/compiler, private keys, deployment
fixtures or provider configuration. Dependency notices come from the existing
module cache's actual LICENSE/COPYING/NOTICE files, with versions, checksums and
source locations in `share/licenses/go/MODULES.json`. The standard release adds
one shared notice archive covering its five compiled targets; the standard Hub
also retains Go and dependency notices. No project license is invented.

The binary uses literal `$ORIGIN/../lib` DT_RUNPATH; the interpreter is
`/lib64/ld-linux-x86-64.so.2`, and observed required glibc symbols reach 2.34.
The initially exercised host is Debian12/bookworm amd64. Alpine/musl and arm64
PQ remain unsupported. Preserve the package layout and remove ambient
LD_LIBRARY_PATH/LD_PRELOAD. No loader cache, global OpenSSL or host setting is
changed. The archive relies on host glibc and host trust roots.

The optional Hub image uses the pinned Go bookworm builder
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
and official Debian bookworm-slim amd64 glibc donor
`sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b`.
The scratch runtime retains the interpreter, libc, NSS libraries/config, CA
bundle and their actual copyright/license/source-package attribution. It runs
as UID/GID1000, with private writable state/workspace/home. Health probes are
external. It contains no shell, package manager, OpenSSL CLI, Codex or model
credentials. The same binary implements Hub and outbound Node roles.

## Startup and gate identity

Hub: `bin/cicada serve --node-pqtls-config /private/hub.json`.
Node: set `CICADA_BINARY_PATH` to the full package's `bin/cicada` and
`CICADA_NODE_PQTLS_CONFIG` to its approved private config before using
`scripts/install-cicada-worker.sh`. A PQ config rejects the automatic CGO0
installer path. The installer verifies checksums, rejects a symlink state
directory or symlink ancestor before install/chmod, preserves existing identity,
and adds no enrollment or native runtime. TLS credentials remain independently
approved and manually managed. Client/bootstrap stays on the application origin.

The Hub standard v4 inventory scope and domain are unchanged. The standard
binary release uses `cicada-binary-release-inputs-v2` and records its descriptor;
it includes the actual notice generator in dirty, fingerprint and before/after
checks. PQ uses a distinct
`cicada-pqtls-distribution-inputs-v1` domain covering product sources, its actual
Dockerfile/build/gate helpers and exact accepted external runtime. PQ dirty
provenance covers the whole repository, including packaging-only changes.

A gate requires independently supplied build receipt SHAs. The package producer
writes `PQ-BUILD-RECEIPT.json` beside the archive, containing its source identity,
archive SHA and every extracted file SHA including its checksum manifest. The
caller must obtain expected receipt hashes from its trusted build record:

```sh
CICADA_PQTLS_EXPECTED_RECEIPT_SHA256="$PACKAGE_RECEIPT_SHA" \
CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256="$IMAGE_RECEIPT_SHA" \
scripts/test-pqtls-packaging.sh "$RELOCATED_PACKAGE" "$PREFIX" "$NEW_EVIDENCE" \
  "$BUILD_RECEIPT" "$IMAGE_BUILD_RECEIPT"
```

Omit the last argument and image receipt variable for the direct CLI gate.
Before startup and after completion the gate recomputes current source/index,
stage, package and archive identity against those independent receipts. It
launches the verified immutable image ID and checks actual image labels; mutable
tags and self-reported source strings alone are insufficient. Source mutation
or a receipt/metadata/artifact/stage/image mismatch fails closed. Gate receipts
retain counts, skips, exit status and raw private logs. A skip is not a pass.

The gate uses one disposable Hub and two actual packaged Node Agent processes,
independent synthetic ML-DSA certificates and preapproved Store identities.
The actual Agent `--once` processes prove startup and outbound polling. Optional
long-lived Agents provide the idle RSS observation. Subsequent ask, heartbeat,
borrowed-bearer and revocation requests use the Go driver's PQ client context;
they are not attributed to RPCs performed by those Agent processes. The gate
proves current-authority PQ requests, sealed ciphertext
persistence/idempotency, borrowed bearer rejection, enrolled frontdoor rejection,
Client/WebCrypto access and current Store revocation on a retained connection.
The image shares the isolated driver network namespace; this is not two
independent PQ Hubs. Agents start before messages are enqueued, so this gate
performs no native/model/provider calls. Optional idle process RSS and Docker
stats are observations of that synthetic fixture, not production/peak memory.

## Validation attribution and limits

The historical `package-attempt1`, relocated CLI and image CLI receipts under
`.cicada-data/distribution/` preceded the lifetime patch and receipt hardening.
They passed their exercised paths (one top test plus three subtests per CLI
gate), but are retained only as dirty observational evidence. They must not be
called exact final-source acceptance. Their image inspect Size value 14,156,896
is an engine field; it is not the unpacked image footprint. Measure archive
bytes, binary bytes, individual libraries/notices, expanded runtime regular-file
bytes and engine/registry sizes separately.

Review-repair boundary tests cover packaging-only dirty input, modified accepted
headers/libraries/licenses/linker aliases, independently pinned receipt tamper,
package/metadata/archive tamper, other source, mutable image IDs, wrong actual
image labels, invalid target/CGO0 selection, automatic installer rejection, and
state/ancestor symlinks without target chmod or Agent startup. Exact commands,
counts, exits, frozen patch/file hashes, source identities and later artifact
sizes belong in the private handoff manifest and validation report. This avoids
changing source after an artifact was built merely to insert its own digest.

The final release gate must be rerun on Root's combined clean checkpoint after
integration and review. This dirty isolated checkpoint does not claim all v0.1
complete. Android, physical device, real native Runtime, public HTTPS, production
deployment, arm64 PQ, browser pure-PQ, automatic TLS enrollment/rotation and
independent namespace DNS/outbound acceptance remain separate NOT_RUN results.
