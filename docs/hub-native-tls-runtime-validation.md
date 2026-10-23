# Hub native TLS runtime checkpoint validation

2026-10-23 producer scope: persistent private CA/service profile, immutable
public Store pin, local CLI selectors and the native Hub Nodes listener under
the [hub-native-tls-v1 contract](hub-native-tls-contract.md). The shared-codec
checkpoint keeps its [original evidence](hub-native-tls-validation.md).
This checkpoint does not complete Node transport consumers, an actual App/Node
installation, delivery packaging or public-network acceptance.

## Source attribution and results

The main runtime checks tested dirty parent
`12fe1be4498780052976570f895b3d1de2a49f3c`, with Go-subtree input SHA-256
`c36ac77357e3d549b7e61b1bc66e6f5fc4c1a74137a37cb282fb06de64ed5ba8`
and full source manifest
`cd4d93499ab40fea5e1fde5d2bf773eb2919de66c21c968d7c35f0d5f6027b44`.
Before/after source inventories match. Evidence is retained outside Git under
`/home/zyf/Cicada/.local/evidence/hub-native-tls/`:

| Run | Result and source-bound scope |
| --- | --- |
| runtime-20261023T061518Z, normal | PASS, exit 0: 76 test/subtest outcomes, 32 top-level, no failures/skips. New profile/CLI/Store checks plus old setup, activation, serve, migration and selected restore regressions. |
| Same run, race | OUTPUT_COMPLETE_EXIT_NOT_CAPTURED: JSON reports all three packages passing, 26 outcomes, no failed/skipped tests or race reports. The driver session disappeared before saving the process exit code; this is not a complete PASS receipt. |
| runtime-resume-20261023T062121Z, contention | PASS, exit 0: the pristine concurrent-init race test repeated 20 times, no failures/skips. |
| Same resumed run, vet | PASS, exit 0: hubtransport, Store and cicada CLI. |
| Same resumed run, Docker | PASS, exit 0: 26 outcomes, 13 top-level, no failures/skips. The runtime scope runs inside an isolated network-none container. |

The original normal receipt SHA-256 is
`46761f0deeed60f05752da1814953b547dccc84d111bb465dc870aed6da2ba33`.
The race observation, including its missing-exit limitation and matching source
snapshot, is `81fe08a11f2daab767caa1f46b7d117f1f46197ed009ff59335bb422d505059c`.
The resumed aggregate receipt is
`843c84a2202b6966e0b5b06fc406554b1d9bfd5fd69d9c749e4b9133f0ff52cb`.
No second overlapping race process was launched. The remaining lanes resumed
only after confirming the original process had finished.

After those checks, the integration owner fast-forwarded this worktree to App
`3a0c632ca5a9af6a33dc80f5ea5ddf248ee229fb`, preserving every Hub WIP byte/mode.
A reviewed delta makes historical Owner-bootstrap/account-claim issuers use
strict existing-key reads whenever a native profile or public DB pin exists;
the original no-native compatibility path remains unchanged.

That delta tested dirty parent `3a0c632ca5a9af6a33dc80f5ea5ddf248ee229fb` in
`runtime-issuer-delta-20261023T063050Z`. Its Go input manifest is
`682827fa5588622667fbfdfc16979f4975add99de2b13b2942963cc08d18bd7c`, full source
manifest `139f2b22459719e10d77dbfee3a0c289ed0c3184f180d186d08b41a02b4b3645`.
Normal delta/old-issuer checks passed 16 outcomes, 4 top-level, no failures/skips;
CLI vet passed. Before/after source matched. Aggregate receipt SHA-256 is
`181080e9ccb887a5a708f06a51771b16e1a6fc652f992259f96978849065258a`.
The main runtime gates remain attributed to their earlier Go inputs, not silently
relabelled as a full run on this later combined candidate. Validation prose is
added afterward and does not change the tested Go inputs.

## Behavior covered

The new Store schema is **67**, independent of software version 0.0.5, Client
wire 1, client-hub-v1.6.5/catalog 55, activation v1 and native transport epoch 1.
Its new table stores only the immutable signed public descriptor. TLS install
does not change Owner/account coordinates, original epochs or Root history.

Tests cover concurrent first creation and repeated init, byte-identical
descriptor export/restart, original application-key preservation and recovery
of a committed bundle before public pin commit. Missing bundle/directory/key,
wrong key, mixed epoch, symlink and unsafe modes reject without regeneration.
DB pin update/delete is forbidden; losing the bundle does not enable implicit
legacy startup. Rejected HTTP-scope initialization creates no native marker and
does not break legacy startup. Invalid native setup rejects before creating its
StateDir. Native/PQ selection conflicts reject before listening.

The retained bundle lives at `<HubStateDir>/native-tls/profile.json` (0600), its
directory is 0700, and `.lock` is a separate mode-0600 inode-checked flock. Parent
and file directory entries are fsynced. An ECDSA P-256 private installation CA
and independent stable service key are additional transport material; existing
application identities are not replaced. The CA lasts ten years; leaf validity
is 90 days bounded by CA expiry, with a seven-day renewal window. Load/restart
and cached GetCertificate renew under the profile lock using the same private
keys, SPKI, epoch and exact originally signed descriptor text. Root CA/service
key rotation is not implemented.

The renewal tests exercise expired historical synthetic bundles through
LoadProfile and directly invoke the GetCertificate callback. They verify
original private-key and descriptor bytes plus a fresh leaf. They do not claim
natural clock passage through a 90-day deployment or renewal observed during
an actual TLS handshake. Actual Hub handshakes acquire a separate shared
StateDir restore guard so late certificate work cannot race offline backup.

The process test starts a **test executable child invoking the production
serve function** with native flags and a disposable state. The verified client
dials literal IPv4 while retaining the nonresolving logical origin; identity
metadata is available and plaintext health is not served. This is not the final
delivery cicada executable or a real App actor. The shared checkpoint separately
exercised actual IPv4/IPv6 TLS sockets; this process test does not accept a
physical/public IPv6 deployment.

Existing HTTPS origin, Owner/account and application keys survive native init;
an already issued activation-v1 file remains byte-identical. Native activation
export preserves inner v1 bytes in the secret wrapper and writes a mode-0600
file, without exposing its secret in default output. The missing-key issuer
delta covers both historical issuers under committed pin, bundle-before-pin
and lost-bundle-with-pin states, each with all three application keys removed
in turn. None creates a replacement key or authority output.

## Recovery limits and earlier failure

The schema-67 restore inventory recognizes the immutable public pin. A bounded
backup/restore check retains both exact descriptor and private bundle, and the
unproved restored target remains quarantined. Selected original restore tests
cover existing Owner history, nonce/replay and closed-schema behavior. This is
not acceptance of complete native TLS restore activation. Reconciliation of
an old pre-native backup against a later native pin, exhaustive power-loss
injection and current native-profile forward activation remain NOT_RUN. Missing
or mismatched private material must refuse startup; no legacy fallback is granted.

The first runtime smoke run failed its concurrent pristine-init schedule and a
synthetic activation output-directory mode check. Its retained dirty source
manifest is `5041b83b9a7ec63a82541e8dffa37664b7ff767c952ccc962f1f0177efca62a6`;
`runtime-initial-fail-20261023.json` SHA-256 is
`9db343b77c8b810ee0fb9512771039573f0631fcfb84d8bda42d218dafc31bbd`.
The producer fixed the directory-before-bundle concurrency window by waiting
for the original creator, never substituting keys, and moved the synthetic code
output to a protected directory. This failure is retained separately from the
later passing checks and the distinct driver-loss observation.

All keys/credentials are synthetic and disposable. Docker used immutable Go
image `sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
read-only source/root/module cache, network none, no capabilities and a separate
executable synthetic temp bind. No shared development Hub, real credential,
system CA, deployment, service replacement or public listener was used.

Node first identity/device-code transport, persistent per-Hub native trust,
Relay/MCP/Hook/bridge consumers and native/PQ diagnostic separation remain the
next implementation checkpoint. Automatic FB-03 Owner public-pin delivery is
unchanged and pending. Actual complete App/Node registration and original-packet
restart recovery, final CLI artifacts, Windows/Android, physical machines,
public HTTPS and real native Runtime remain separately NOT_RUN for this change.
