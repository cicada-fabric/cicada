# Hub native TLS shared-codec checkpoint validation

2026-10-23 producer scope: the additive
[hub-native-tls-v1 contract](hub-native-tls-contract.md), shared public descriptor
and secret wrapper codecs, existing ML-DSA signing adapter, and verified numeric
HTTP transport. This record accepts those components only. It does not accept a
Hub installation, new CLI behavior, saved CA/profile, Node registration, App UI,
Windows, a public IP or a deployed service.

## Tested source and retained evidence

Tests ran on dirty parent
`3b1186d355f7f739ec2c7f8a00c9edfaf4f159bc`, not that commit alone.
Full before/after source manifest SHA-256 was
`d62f627d4b3b38cc8ec5844eea6992e606ceee86dd0b2a7ca66a02f2b9fe1e7c`.
The complete Go-subtree input manifest, including JSON contracts and old App
sources used by the external compatibility test, was
`eb6291ee1398c36119c4e3f4ef584736248d01b397c36e841a936629225bb76c`.
Both manifests use sorted relative paths, file modes and SHA-256; the before
and after snapshots were identical. The subsequent validation prose and startup
mode clarification are documentation changes, not different tested Go inputs.

Retained evidence directory:
`/home/zyf/Cicada/.local/evidence/hub-native-tls/shared-20261023T053527Z`.
It contains per-lane exact commands, elapsed times, stdout JSON, stderr, receipts
and complete before/after source inventories. Aggregate `receipt.json` SHA-256:
`c8c2bbbbcdf19c2e1de4d183d321845ad5e575af67f5a7386a27fb6d5288e705`.
Synthetic keys and certificates were generated inside tests; none were printed,
committed as private fixtures or used to initialize a deployment.

The host used the existing extracted Go 1.27.3 toolchain and complete read-only
offline module closure. Docker used immutable image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network none, read-only source/root filesystem/module cache, no capabilities,
no-new-privileges, current UID/GID and an exclusive disposable synthetic temp
directory. No shared development Hub or system CA store was used.

## Results

| Lane | Result | Scope |
| --- | --- | --- |
| Shared package normal | PASS: 33 test/subtest outcomes, 11 top-level, 0 failures/skips | All hubtransport tests, including actual IPv4 and IPv6 TLS sockets and unchanged App-card parser compatibility |
| Existing crypto adapter | PASS: 1 top-level, 0 failures/skips | Correct signer/commitment, wrong signer/digest, wrong signature-version domain, nil signer and zero commitment |
| Race | PASS: 34 outcomes, 12 top-level, 0 failures/skips | The exact shared-package tests plus crypto-adapter test; no races reported |
| Vet | PASS, exit 0 | hubtransport and e2ee packages |
| Disposable Docker socket gate | PASS: 33 outcomes, 11 top-level, 0 failures/skips | The same shared codec and actual IPv4/IPv6 HTTPS client/server tests inside one isolated container; no reverse proxy/DNS |

The positive socket checks dial a numeric loopback locator while retaining a
nonresolving logical HTTPS URL, Host and TLS service name. Wrong root, SAN,
SPKI and expired leaf all fail before the HTTP handler sees the synthetic body.
Cross-origin URL/Host/Origin and plaintext requests fail at the local transport
boundary. Redirects are returned without following. Missing trust, DNS locators,
zero/alternate ports, unspecified IPs, IPv6 zones and mapped IPv4 reject.

Binding checks cover descriptor tampering, both complete PQ identities,
transport epoch, CA dates and signature, plus live Node-Control metadata
matching. Wrapper tests retain the exact original activation-v1 text, including
legacy expected Owner public identity and original policy flag, and reject
cross-Hub ID, fingerprint and origin. Expired activation does not become valid
through a wrapper. Formatting a Bootstrap value redacts its secret.

Canonical codec tests reject extra/duplicate fields, whitespace/trailing data,
wrong prefix, base64 padding and oversized inputs. The new
`cicada-hub-transport-v1:` descriptor and the existing
`cicada-hub-connection-v1:` account card reject each other through their real
decoders. The original draft prefix collision was corrected before these
formal checks; the old card and activation implementation were not edited.

## Earlier environment attempts

These did not produce a passing source gate: host gofmt was initially absent
from PATH; the first Docker attempt selected an incomplete read-only module
cache and failed package setup; the next used a nonexecutable tmpfs for test
binaries and failed before test execution. The existing absolute toolchain and
complete offline cache then enabled the host checks; Docker used a separate
executable synthetic temp bind. No environment failure is counted as a test
pass or hidden by a skip. A preliminary pre-contract smoke run is not the
source-bound result above.

## Remaining work

Hub persistent CA/service profile, atomic initialization/recovery, leaf renewal,
new CLI selectors, direct Hub TLS startup and downgrade refusal are NOT_RUN and
not implemented by this checkpoint. Full Node first identity/device-code and
later Relay/MCP/Hook/bridge consumers, actual App vault/UI/client lifecycle,
exact pending-request recovery across production restart, address change and
native/PQ selection conflicts require subsequent implementation and tests.
The existing manual FB-03 independent Owner peer pin remains unchanged.

The Docker lane is a shared in-process HTTPS client/server gate. It is not the
future single Hub executable plus actual App/Node deployment interop gate.
Physical Windows, native Runtime, Android, physical/public IPv4/IPv6 and public
HTTPS remain NOT_RUN for this new transport contract. Existing historical
acceptance remains attributed to its original source and scope.
