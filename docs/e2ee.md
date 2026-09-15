# Peer-link E2EE

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
relay/control store keeps only the opaque envelope; it never stores plaintext.

The local private identity is generated once at
`$CICADA_STATE_DIR/e2ee/identity.json` (or `CICADA_E2EE_IDENTITY_FILE`) and is
written with mode `0600` in a mode `0700` directory. Deployments that need
stronger at-rest protection should put the state directory on an encrypted
volume or replace the identity file with an OS secret provider before sharing
the machine. The private key is never placed in events, artifacts, or a peer
message envelope.

The current 0.2.0 release exposes a manually controlled contact and envelope path:

```bash
# Publish only the local public identity.
curl http://127.0.0.1:8787/v1/identity

# Pin a peer's published identity.
curl -X POST http://127.0.0.1:8787/v1/contacts \
  -H 'content-type: application/json' \
  -d '{"label":"Alice","identity":{"id":"pq1-...","kem_public":"...","signing_public":"..."}}'

# Revoke a pinned identity immediately if the relationship changes.
curl -X PATCH http://127.0.0.1:8787/v1/contacts/CONTACT_ID \
  -H 'content-type: application/json' \
  -d '{"status":"revoked"}'

# Seal an outbound message. The response contains an opaque envelope.
curl -X POST http://127.0.0.1:8787/v1/peer-messages \
  -H 'content-type: application/json' \
  -d '{"contact_id":"CONTACT_ID","message":"evidence is ready","aad":"goal=GOAL_ID"}'

# A transport delivers that envelope to the other Control.
curl -X POST http://127.0.0.1:8787/v1/peer-messages \
  -H 'content-type: application/json' \
  -d '{"direction":"inbound","contact_id":"CONTACT_ID","envelope":{...},"aad":"goal=GOAL_ID"}'
```

This is the authenticated envelope and pinned-contact layer. Federation,
automatic contact discovery, ratcheting/session key rotation, and external
transport adapters remain later work; the API keeps the transport boundary
explicit so those pieces can be added without weakening the cryptographic
framing.
