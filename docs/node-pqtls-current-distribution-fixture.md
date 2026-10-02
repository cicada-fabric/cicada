# Current-authority PQ distribution fixture

This is a test-source correction for the shipped `TestPQDistributionActualHubNode`
gate. It changes no product code, protocol, Guard, application contract, Android
Client, package, container image or deployment. The old test source remains in
the clean 52cc2f6 history and supervisor baseline. Its former constants 17/29 and
certificate/configuration peers did not supply current TLS authority; it also
omitted the existing HubControl identity now required by FabricOnly startup.
This correction must not be attributed to the old source or relabelled as its
successful validation.

## Real synthetic authorization

The existing sealed-message fixture supplies independently registered synthetic
Owner keys, signed OwnerDevice grants, Owner-confirmed legacy Node bearers,
endpoint attestations, current SessionBindings, OwnerLink consent and ciphertext.
The new distribution helper preserves those authorities and upgrades each Node
through the actual application-key Store APIs. Each upgrade carries a fresh
NIST signed/encrypted pairing transcript, verified with the independently held
HubControl key. The current approving OwnerDevice remains the actual registered
device; no TLS certificate, CSR or fixture configuration is treated as Owner
approval. This is trusted local synthetic setup, not an enrollment-endpoint
or Android pairing acceptance claim.

The two Nodes use independent NodeControl and TLS keys. The helper performs
Prepare, CSR reservation, the actual OwnerTLS signature, official native issuer
Issue, Stage/install ACK, the committed Store ACK, signed HubControl activation,
the activation CAS and checked Apply. Apply reads independently committed
current ACTIVE through the real Store callback. Hub peers use those actual
TLS epochs, exact SPKI pins and full current Owner/binding/credential versions;
no epoch or activation state is fabricated. The retained local Owner/Endpoint
trust and complete fixture-owned application public-key inventory stay separate
from the received grant. Existing Node application state, accepted preparation,
private Agent lock metadata and the independent local epoch floor are persisted
by the actual D1 path before startup.

The shared per-Hub StateRoot is also WriterRoot. Both actual shipped Node Agent
processes use the existing checked startup and lifetime locks with their own
Node IDs. The optional idle observation keeps both processes alive for a bounded
warmup/sampling interval, then stops and joins them before any message is queued.
Otherwise each real `--once --relay-only` Agent must exit zero. Parent checked
clients acquire the same real runtime/Agent locks only after these processes
have exited, avoiding a counterfeit concurrent singleton or a public skip-lock
option. No model, provider or native Session Runtime consumption is requested.

The actual artifact Hub runs `serve --fabric-only` with both existing identity
files and the real current Store. Ordinary identity and `node-control-identity.json`
are visibly synthetic and private, never generated in a resident deployment.
The test retains its original top name and three subcases: borrowed bearer,
strict plaintext front door, and Client/WebCrypto assets. It sends the same
opaque ask twice, checks one exact durable claim, rejects a different Node bearer,
and checks actual current Store revocation on the reused transport. Plaintext
database absence remains checked. No Guard condition is relaxed.

## Logical origin and physical transport

The leaf profile prohibits IP SANs. The Owner-signed Hub PQ origin therefore uses
the fixed `hub.synthetic.invalid` DNS name and an isolated native listener port.
The signed application origin is the separate explicit loopback HTTP front-door
origin. Node transports map only that logical origin to the approved native TLS
origin; protected plaintext front-door requests remain denied. The driver
generates a private fixed hosts file containing only loopback localhost and
`hub.synthetic.invalid`, mounted read-only at `/etc/hosts` in the disposable test
driver and artifact Hub container. It uses no environment-supplied DNS names,
real DNS query, host hosts-file edit, origin rebinding or TLS pin replacement.

## Producer source and fixture source

The driver now distinguishes two roots:

```text
CICADA_PQTLS_PRODUCER_ROOT=/home/zyf/CICADA
# Run the corrected driver from the independently frozen fixture-source clone.
```

The producer root is read only and supplies `verify-distribution` for the
independently expected package and image build receipts. It must continue to
match their original clean 52cc2f6 input closure, source fingerprint, package
checksums, immutable image ID and image labels before and after the gate. The
script never assigns the changed test-source fingerprint to an old artifact,
changes its metadata, overlays an executable or rebuilds a product.

The fixture root compiles only the corrected Go test binary. Its PQ source/runtime
input inventory and a separately named whole-root source fingerprint are
captured before and after, alongside the independent producer whole-root
fingerprint. Whole-root inventory uses cached and nonignored source paths,
raw permission modes and content (or symlink target) SHA256, excluding Git and
ignored state. The result records both roots, roles, HEADs, file counts and
fingerprint domains. Both source roots, package, accepted stage and module cache
are mounted read only. Writable paths are limited to the new evidence and
disposable build cache/state.

The relocated package binary drives the two Agents; the optional immutable
runtime image drives the Hub. Their executable hashes are recorded separately:
identical product source closure does not imply identical ELF bytes when CGO
build paths differ. The image executable is copied only to private evidence for
hashing, then that temporary copy is removed. No executable is installed,
replaced or injected into the image.

## Bounds, privacy and evidence

The exact selector remains `^TestPQDistributionActualHubNode$`. The test body
has a 180-second context, each one-shot Agent a 45-second deadline, and the
driver's single compile/run a five-minute Go timeout. These are finite budgets
for the current signature/installation/startup chain, not permission or hang
exceptions. Startup, child exits and message/revocation phases remain public;
permission/Guard errors still fail immediately. Hub shutdown must join and
exit zero before its private fixture directory is removed. The image driver
waits for the test completion marker, stops its own Hub, inspects its actual
exit code and acknowledges shutdown to the test.

Private CA/application/TLS keys, bearer credentials, databases and full packets
exist only in disposable fixture directories. Go cleanup removes the host-visible
TLS/Hub fixture after shutdown and the container removes temporary Node state.
The driver finally removes only its own containers and its narrowly named
private fixture directories, recording that none remain. Before results are written,
`container-cleanup.json` requires both exact own container names to be absent
in a successful name-only Docker listing and each narrow inspect to return the
not-found exit code. It also retains the actual driver process exit and the
Hub process exit captured before removal; cleanup cannot turn either failure
into a pass. No full container inspect, environment or private diagnostic log
is retained. It retains only
sanitized lifecycle/phase output, typed terminal events, public source codepoints,
hashes/lengths and public metadata. Temporary full diagnostic streams are deleted
and never indexed as public evidence. A skip is not a pass; the result requires
the original one top-level test and all three original subcases to pass.

Writer compilation, tests and artifact gate are **NOT_RUN**. The supervisor runs
the corrected selector once against the separately frozen producer/artifact and
fixture identities. Previous standard image passes and clean PQ build receipts
remain attributed to their original sources; they do not prove this corrected
gate. This fixture does not claim physical-device/Android acceptance, public
HTTPS, independent PQ Hubs, a model/native Runtime run, production memory limits,
renewal, live reload, recovery reconciliation or deployment readiness.
