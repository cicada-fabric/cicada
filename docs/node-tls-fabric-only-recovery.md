# FabricOnly TLS recovery read, v0.1

`serve --fabric-only --node-pqtls-config FILE` now installs two pure readers:
`ReadNodeTLSCurrentPacket` and `ReadNodeTLSRecoveryPacket`. Both use the actual
Hub Store and the existing private `e2ee/node-control-identity.json`. This serve
branch constructs no Control instance, planner, scheduler, reporter or model.
Ordinary Node-Control RPC remains unavailable with Control absent. The old
full-Control recovery dispatch remains supported.

The listener still uses the existing PQ TLS transport Guard. A configured peer
only narrows the actual current Store authority: current Owner key, approved
Owner device, Node credential/version, Node-Control binding/key/epoch and the
committed ACTIVE TLS certificate/proofs must match. Having a certificate, a
CSR, a configuration entry or a signed activation prepared before commit does
not supply current approval. Missing or invalid existing Hub identity fails
closed; this branch does not create, replace or repair that key.

The pure recovery reader opens the existing `node.recovery.status` NIST
encrypted request domain, verifies the bound application origin and performs
fresh current-authority reads around the read-only Store transaction. Its
response remains bound to the query nonce, exact request-packet digest, origin,
credential digest, restore digest, plan digest and full approved binding. A
recovered normal RPC result, an old response or the fresh TLS-current domain is
not a recovery response. The dedicated dispatch requires the strict transport
check closure as well as native TLS state; the legacy permissive fallback is
not used for this pure reader.

## Node maintenance boundary

The existing command is unchanged:

```text
cicada machine recovery query --backup PRIVATE_ARCHIVE --state-dir ABSOLUTE_ROOT \
  --writer-root RETAINED_WRITER_ROOT --plan-sha256 PLAN_DIGEST \
  --node-pqtls-config PRIVATE_ACTIVE_CONFIG
```

The command verifies the archive and restore lineage, acquires the existing
WriterRoot then Node exclusive locks through the opaque maintenance capability,
rechecks the restored state, and reads independent local Owner trust, accepted
binding, retained key inventory, TLS materials and the retained epoch floor.
Its private staged transport permits fresh authenticated current queries and
the fixed read-only recovery POST. It never publishes a general HTTP transport,
Relay or job access. Wrong roots/scopes, a closed capability, missing/unsafe lock
metadata, changed held inodes, conflicting materials/floors or unavailable
current authority fail closed. Native TLS failure does not trigger plaintext
fallback.

The TLS recovery POST has one attempt. If a response is lost, the operator may
invoke the read-only command again: that separate invocation makes new current
and recovery nonces. This change adds no automatic retry or redispatch of an
old operation. `COMPLETE`, `UNCERTAIN` and `NOT_RECORDED` are metadata; none
authorizes execution. A successful result still reports `agent_may_start=false`.
It does not clear Node, StateRoot or WriterRoot quarantine, advance counters,
reconcile uncertain Runtime work, change credentials, apply a TLS grant or
restart an Agent.

## Absolute paths and retained floors

The current installation manifest/configuration contains absolute TLS material
paths. This lane verifies same-absolute-StateRoot recovery. An unchanged archive
restored to another StateRoot does not become a valid installation there, even
when its structural archive and local recovery inspection are valid. No path
rebasing, aliasing to old secrets or TLS grant expansion is implemented.

Archived TLS floors are witnesses. Restore requires independent retained
WriterRoot floor state; it cannot install the archive floor as a replacement.
The full-flow fixture retains that file's original inode and exact bytes. The
shared WriterRoot restore gate also rejects existing shared ledgers without the
matching recovery record; it does not overwrite them because archive bytes
look equal. The positive crash fixture therefore loses the selected Node
subtree and its two archived shared ledgers under genuine exclusive locks,
while retaining the absolute WriterRoot, lock metadata, TLS material and floor.
Restore reconstructs the lost shared ledgers from the verified archive and
creates the required durable holds.

## Disposable acceptance source

The new selector is `^TestMachineTLSRestoreFabricOnly`. Its native top-level
gate runs an isolated test-binary scenario with a 300-second deadline; nested
actual CLI commands have 45-second deadlines. A deadline kills the isolated
process group to avoid orphaning children with private fixture files. Every
successful Hub child receives SIGTERM, finishes the production shutdown/join
path, and must exit zero. Public logs contain phase names and elapsed times;
CLI JSON, credentials, packets and private keys remain in private buffers and
temporary directories. A nonempty native OpenSSL fixture request with an
unavailable native profile fails. Default/CGO-off typed unavailability is
reported as native gate not executed, without a skip or native-PASS claim.

The fixture reuses the existing synthetic native D1 builder: actual OwnerDevice
and OwnerTLS signatures, independent Node TLS CSR/key, Stage/install ACK,
committed Hub activation, Apply, synthetic native CA and exact peer pins. This
is not an enrollment-endpoint acceptance test: the reused builder registers its
synthetic application binding through the existing local Store fixture. It
does not use Control to initialize a fixture or send a business request.

The source exercises:

- Actual `main` dispatch for TLS Backup, Verify, same-root Restore, inspect and
  recovery query; actual `serve --fabric-only` dispatch with an existing Hub
  database/identity/configuration, rather than an equivalent test Handler.
- A COMPLETE pending operation through the CLI, plus real held-capability
  metadata queries for COMPLETE, UNCERTAIN and NOT_RECORDED with an existing
  higher accepted sequence. Fixture receipts use the production Store admission
  and completion APIs; no model or Runtime work is executed.
- Byte/mode inventories of the restored Node/WriterRoot, original floor inode
  and bytes, crypto sequence/replay witnesses, recovery holds and logical Hub
  admission/response tables before and after reads. A normal encrypted stored
  RPC receives 503 with Control absent; the recovery read does not replay it.
- Rejection for plaintext front-door traffic, omitted Node TLS configuration,
  held WriterRoot/Node exclusive locks, wrong maintenance scopes, closed
  capability, corrupt floor/material, configuration epoch mismatch, actual TLS
  revocation, Owner key/device revocation, actual Node-Control epoch upgrade,
  credential rotation, missing/unsafe/
  foreign existing Hub identity, and another absolute StateRoot while the Hub
  remains available. Normal runtime publication remains denied by quarantine.
- An independent directly connected Hub positive before any fault proxy. The
  lost-response case then uses a test-only native TLS proxy: the Owner-signed
  public Hub origin is unchanged, while the production Hub listens at a
  separate private physical address. Both TLS legs use actual native TLS and
  the same exact synthetic certificate/pin materials. The proxy forwards
  opaque NIST packets to the actual FabricOnly Hub; it loses one successful
  sealed recovery reply. A separate actual CLI invocation succeeds with new
  current/recovery nonce routes. No plaintext leg, key rebinding, production
  fault endpoint or runtime retry hook is added.

Implementation-time tests/QA were **NOT_RUN** by the writer. Validation belongs
to the separately frozen source and supervisor receipts. This document does not
claim production deployment, public HTTPS, Android/physical-device acceptance,
actual native model/Session Runtime recovery, arbitrary-root TLS relocation,
automatic quarantine release, renewal or live transport reload.
