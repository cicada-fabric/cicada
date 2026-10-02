# Client Link public proof evidence — client-hub-v1.6.3

The encrypted `link.key_grants` response now includes enough public evidence for
an authorized Owner Client to independently verify both participating Owners'
current consent for an exact visible Link. `link.key_grant` and its exact retry
return the same evidence shape. Existing RPC names, two-element status array,
wire v1, 55 operations, schema v55 and persisted cryptographic bytes are retained.
No migration, key rotation, route activation or Node credential is involved.

The baseline is detached `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c` plus the
reviewed Directory15 overlay (`patch.diff` SHA-256
`ff44a0a985fb4ef552d98e0f37cb25df81482de210431e375f898f8f5888bc95`,
manifest SHA-256 `f1f73591c20826e498c95a79d508bea968bca04ceed37b6d98dda92f145705fc`).
Directory15's v1.6.2 evidence remains attributable to its own frozen source.
This change is a v1.6.3 response extension and needs separate Client acceptance.

Each optional `evidence` has `link_version`, `contract_digest`, `manifest_digest`,
`owner_key_id`, `owner_public_identity`, `owner_key_state`, `owner_key_version`,
`signed_proof` and `verified_at`. The enclosing status binds Link, side and Owner.
Only verified `ACCEPTED` statuses expose evidence; historical `accepted=true`
does not imply current validity. Noncurrent statuses omit proof and public key.
The Store verifies both sides with one time and transaction, including current
scope/bindings, Endpoint self-attestations, exact manifest, Owner key state,
proof signature, side, version, nonce and expiry. Responses copy proof bytes and
never rewrite retained historical proofs.

The Owner public identity returned by Hub is discovery evidence, **not independent
trust**. Client must compare it with an independently trusted Owner key or pin,
never automatically pin or trust this response. Fetch and independently verify
`link.key_manifest`, then compare its Link/version/contract/digest with both
statuses and signed claims. Verify both complete ML-DSA-65 grants with the
independently trusted Owner keys and enforce their validity periods. Separate
manifest/status reads can race; any mismatch fails closed and requires a refresh.
`verified_at` documents the Hub snapshot, not future/offline authorization.

This exact-Link query has no global Owner-key or contact lookup. The caller Owner
comes from its authenticated encrypted device session. A third Owner is denied;
missing Join, old binding, revocation, expiry and corrupt evidence cannot produce
current proof material. Accepted consent is separate from routing authorization,
Relay persistence, native injection, model consumption and task success. Android
must never use `/v2/relay/nodes/.../authorization` or a Node bearer fallback.

The exported `cicada-go/internal/e2ee/testdata/link-client-proof-v2.json` is a
visibly synthetic, public-only bilateral fixture. It contains the complete Link
manifest, contract and manifest canonical inputs, Endpoint attestation signed
bytes, exact Owner grant signed bytes/signatures and public identities. Its fixed
verification time is for reproducible tests, not deployment initialization.
No private key or deployment credential is included.

Focused Store tests cover exact response bytes, retry, snapshot races and
invalidation. The encrypted real-loopback HTTP test enrolls two participating
Owners and a third Owner, verifies both sides with trusted test keys, checks
third-Owner rejection, and verifies revoked peer proof omission. The vector test
uses the existing CIRCL verifiers and checks byte/domain/digest consistency plus
wrong-side/version, tamper and expiry rejection. Validation command logs, exits,
binaries and frozen source are retained separately with the delivered delta.
Android, real native Runtime, physical device and public HTTPS are NOT_RUN for
this slice; historical results do not certify this candidate.


## Review-policy extension — client-hub-v1.6.4

The v1.6.3 key-grant evidence and validation above remain historical evidence of
that slice. v1.6.4 adds the two missing review-policy inputs together: exact
Guard-checked reviewer qualification snapshots in preview, and selected original
Owner approval proofs in grant/status. The authoritative field names, bounds,
states and partial-candidate/active-head semantics are in the OpenAPI and wire
contract. Version0 NONE has no Owner approvals; configured signed NONE retains
the bilateral approval shape. No proof claims, wire version or operation count
change. This extension needs its own fixed-delivery Client acceptance.

Compare the ordered qualification rows with every requested reviewer and the
outer Link/side/Owner/version/contract/policy tuple. A fresh decrypted response
from a pinned Hub is authoritative for its checked DB snapshot, not an externally
signed reviewer credential. Preview and grant repeat the real Guard; lease time
does not promise future permission. Verify SOURCE and TARGET policy proofs using
independently provisioned Owner pins, with the exact canonical policy and fresh
Link manifest tuple. Returned Owner keys only support discovery and authenticated
server lifecycle state. Policy proofs do not sign reviewer qualifications,
manifest digest or Client contract revision, and are a different signing domain
from key grants.

Persist the original request packet for lost-response recovery. A cached response
preserves original proof bytes and idempotency but is historical: refresh with a
new encrypted preview/status and manifest before later signing. Evidence is
omitted for nonverified proofs or stale Link scope. Corrupt policy rejects;
noncurrent status is not a fabricated unconfigured NONE.

The public-only synthetic bilateral
`cicada-go/internal/e2ee/testdata/link-review-policy-client-evidence-v1.json`
contains normalized policy, both complete identities/original proofs, their exact
11 ordered claims/domain/signed-byte hashes, and fixed-time preview/status
examples. It must never initialize a deployment. Android, real native Runtime,
physical device and public HTTPS acceptance remain separately recorded.


For stale heads the outer Link version/contract describe the current Link, while
policy version/digest/canonical policy retain the selected head tuple; SCOPE_STALE
omits evidence. Expired or revoked heads are repaired only by existing fresh
next-version preview, no-inflight checks and two fresh proofs, never reset to
unconfigured NONE. Active-head-only status cannot resolve an uncertain first-side
partial grant: retain a durable Client uncertainty fence until exact original
packet recovery is COMPLETED, or a fresh activated pair contains the exact
original proof and tuple. Fresh preview and manifest precede signing; changed
qualifications require explicit reconfirmation. Neither verified_at nor cached
recovery alone establishes freshness.

The public response projection preflight includes the exact RPC wrapper and
worst-case HTML escaping of bounded 256-byte request/operation identifiers in
the existing 64KiB encrypted plaintext limit. Oversized preview/grant/status
responses are generically denied before commit; grant rolls back rather than
truncating evidence. Canonical proof parsing rejects padded/reordered outer JSON
and preserves accepted original bytes. No signature or runtime limit changes.
