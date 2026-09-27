# Legacy Contact peer-link encryption

This page describes historical Contact crypto state and the remaining Contact
identity-management API. The `/v1/peer-messages` and `/v1/federation/messages`
HTTP message ingress has been removed. When it existed, Control accepted sender
plaintext, encrypted in the Control process, and decrypted there for the
recipient API. Its SQLite peer envelope can be opaque while Control still
has access to plaintext. The v2 Fabric `fabric_messages.body` is also currently
plaintext. Do not claim current Cicada provides Endpoint-held E2EE or a
post-quantum Node-to-Hub channel. The target and migration boundaries are in
[CICADA.md](../CICADA.md) and
[architecture-v2-pq-transport.md](architecture-v2-pq-transport.md).

`internal/e2ee/endpoint.go` offers an isolated Endpoint envelope primitive.
It reuses the pinned-key ML-KEM/ML-DSA/AES-GCM implementation, signs the route
and ciphertext, and binds both
Endpoint/Principal/owner/Group identities, Membership revisions, SessionBinding
epochs, message/request correlation and optional CommunicationLink revision to
authenticated associated data. It is **not yet wired to MCP send/ask/reply, Fabric message
persistence or native delivery**. The caller must supply expected context from
trusted records, durably reserve the outbound sequence and exact ciphertext
before retry, and atomically check replay at the receiving Node.

The current v14 increment adds an ML-DSA-65 self-signed public-key attestation
bound to an Endpoint, Principal, Node, and current SessionBinding ID and epoch.
The Hub can store that public material as a `CANDIDATE` and expose it only to a
caller that can resolve the Endpoint in the selected Group, through
`POST /v2/fabric/endpoint-keys` and `GET /v2/fabric/endpoint-keys/{endpointID}`.
This proves possession of the signing key and consistency with the current
binding claims checked by the server. It does not prove owner approval, create
a trusted pin, or make the key safe to use for encryption. There is no pin or
activation API, and candidates do not enable routing.

After an explicit `cicada_join`, the MCP tool
`cicada_publish_endpoint_key_candidate` can publish the current Endpoint's
public candidate. It takes no identity arguments, checks the detected native
session against the cached Session and server `/whoami`, and requires an
explicit `CICADA_NODE_STATE_DIR` or `CICADA_STATE_DIR`. Its Node-local private
key never appears in the MCP result or Hub request. Repeated publication
accepts an earlier valid attestation of the same key; a conflicting Hub key
fails closed. Publication still does not approve a peer or activate E2EE.

The attestation and a `CicadaSession` credential do not solve trust bootstrap:
Join authority still comes from the management bearer when configured. If
`CICADA_API_TOKEN` is unset or its bearer scope is broad, these values do not
independently prove that the Endpoint's owner approved a peer relationship.
Candidate data must therefore be treated as untrusted public-key material.

The v15/v16 owner-approval increment adds a separate user-held identity and
signed CommunicationLink grants. `cicada owner-key generate` writes a private
identity only on the user's trusted local machine; `owner-key register` reads
its **public** JSON and requires an independently checked key ID before a Hub
operator records it in the local Hub database. The manager bearer, Node token,
Fabric Session and Endpoint self-attestation cannot register or impersonate
this user key through HTTP. Each side signs the exact current Link ID, contract
digest, version, expiry and a unique nonce using ML-DSA-65. The Store checks
both sides separately and persists proofs with replay protection. This is an
offline bootstrap and grant record, **not** an Android login, remote device
binding, activated cross-user route, or encrypted Client↔Hub session. Grants
do not turn `PROPOSED` links into `ACTIVE` links; existing Fabric messages still
reach the Hub as plaintext.

`internal/nodekeys` can create and recover a distinct private identity per
stable Endpoint ID in a Node-local 0700 directory with 0600, atomically
installed records. It rejects corrupt records rather than silently replacing
keys. The package now also has a Node-local durable `CryptoState` API for
sequence allocation, exact opaque-envelope outbox records, and inbound
replay/digest records. Node crypto-state v3 also commits an exact opaque inbound
envelope in the same transaction as its replay identity; a pre-v3 replay-only
row reports `ErrInboundRecoveryRequired` instead of claiming that the missing
ciphertext was safely received. They are not yet connected to Fabric transport
or native injection. `CryptoState.PinVerifiedPeerKey` provides a
Node-local, exact Endpoint/Group/optional-link pin only when the caller supplies
an independently authenticated peer identity, key ID, and full SHA-256
fingerprint. It verifies the candidate attestation, rejects substitution, and
retains a version-fenced terminal revocation. This library API is neither user
approval nor route authorization. No trusted approval source, pin rotation or
reapproval flow, or Fabric integration exists yet. An authenticated inbound
digest/sequence record and stored ciphertext are receive metadata; they do not prove that the model consumed a message
or make post-crash redelivery safe. Node inbox injection and
`INJECTION_UNCERTAIN` reconciliation remain separate integration work.

`CryptoState.SealOutboundEndpointMessage` and
`OpenInboundEndpointMessage` now connect the isolated Endpoint envelope to
Node-local persistence and an exact verified peer pin. Sending reserves a
sequence, seals the message, and commits the exact signed ciphertext before
returning transport bytes; a retry after restart recovers those same bytes.
The caller supplies an operation ID derived from the trusted route and
plaintext, so reusing it with a changed route or body fails closed. This ID
must remain local: its deterministic digest could reveal a guessable message
if published. Receiving checks the pinned peer and expected route, decrypts,
then atomically commits the ciphertext and replay identity before returning
plaintext. `Duplicate` means only that ciphertext was persisted, not that a
model consumed it. The caller must obtain the expected route from a real
authorization Guard; these methods do not themselves grant route permission,
verify user approval, or perform transport/native delivery.

The Node private identity and `node-crypto-state.sqlite` are outside the Hub
SQLite backup. There is no full Node crypto-state backup/restore or rollback
reconciliation yet. Fabric continues to store ordinary peer message bodies in
plaintext at the Hub.

Cicada's peer link uses a standard post-quantum authenticated envelope from
Cloudflare CIRCL:

- ML-KEM-768 (FIPS 203) establishes a per-message shared secret;
- ML-DSA-65 (FIPS 204) authenticates the sender identity;
- HKDF-SHA256 derives an AES-256-GCM key from the shared secret, sequence, and
  associated data;
- AES-256-GCM authenticates the header and ciphertext.

Cicada does not invent a cryptographic primitive or trust a public key carried
only by the envelope. A contact is pinned to its public identity (`id`, KEM
public key, and signing public key); `Open` rejects a different sender key.
Outbound sequence numbers and received sequence numbers are persisted in the
Control SQLite state, so replay protection survives a Control restart. The
Contact message storage keeps the opaque envelope; the Control API still sees
plaintext during sealing/opening. This is a legacy trust endpoint, not a blind
Relay guarantee.

The local private identity is generated once at
`$CICADA_STATE_DIR/e2ee/identity.json` (or `CICADA_E2EE_IDENTITY_FILE`) and is
written with mode `0600` in a mode `0700` directory. Deployments that need
stronger at-rest protection should put the state directory on an encrypted
volume or replace the identity file with an OS secret provider before sharing
the machine. The private key is never placed in events, artifacts, or a peer
message envelope.

The current 0.4.0 development line exposes signed discovery and a controlled
contact and envelope path:

```bash
# Create a portable public announcement signed by the local ML-DSA key.
curl -X POST http://127.0.0.1:8787/v1/identity/announcement \
  -H 'content-type: application/json' -d '{"label":"Alice"}' \
  > alice-announcement.json

# A remote Control receives the exact announcement as a JSON value. It
# validates the identity ID and ML-DSA signature, then records it as pending.
jq -n --slurpfile announcement alice-announcement.json \
  '{announcement:$announcement[0]}' |
  curl -X POST http://REMOTE_CONTROL/v1/discovery/requests \
    -H 'content-type: application/json' --data-binary @-

# Review and accept or reject the discovery request. Acceptance creates a
# pending Contact; a separate PATCH to trusted is still required.
curl 'http://REMOTE_CONTROL/v1/discovery/requests?status=pending'
curl -X POST http://REMOTE_CONTROL/v1/discovery/requests/REQUEST_ID/accept
curl -X PATCH http://REMOTE_CONTROL/v1/contacts/CONTACT_ID \
  -H 'content-type: application/json' -d '{"status":"trusted"}'

# Direct/manual pinning remains available for already verified identities.
curl -X POST http://127.0.0.1:8787/v1/contacts \
  -H 'content-type: application/json' \
  -d '{"label":"Alice","identity":{"id":"pq1-...","kem_public":"...","signing_public":"..."}}'

# Revoke a pinned identity immediately if the relationship changes.
curl -X PATCH http://127.0.0.1:8787/v1/contacts/CONTACT_ID \
  -H 'content-type: application/json' \
  -d '{"status":"revoked"}'

# The old Contact peer-message and federation ingress commands were removed.
# Retain historical Contact keys, ratchet counters and replay rows for migration.
```

The discovery endpoint authenticates a portable announcement and preserves the
operator trust decision. The signed directory/rendezvous endpoints described in
[`directory.md`](directory.md) provide public routing hints but do not create a
trusted Contact. The retired federation ingress mapped the authenticated sender identity
to a local trusted Contact, checked the encrypted envelope's recipient and
sequence, and stored replay state with the opaque message. Those historical
records remain for migration and audit. Directory transport still
requires the operator to turn a discovered identity into a trusted Contact.

Historical Control-managed peer messages bootstrapped a signed ML-KEM session
offer on the first message, derived directional HMAC chain keys, and advanced
a monotonic counter for each AES-GCM message. The old Contact session query and
rotation HTTP routes are retired together with the peer ingress. Root and chain
keys, epochs and replay counters remain in protected SQLite state for migration
and audit; no active public API accepts the old per-message envelopes.
