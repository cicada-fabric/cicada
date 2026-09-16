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

The current 0.3.0 development line exposes signed discovery and a controlled
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

# Seal an outbound message. The response contains an opaque envelope.
curl -X POST http://127.0.0.1:8787/v1/peer-messages \
  -H 'content-type: application/json' \
  -d '{"contact_id":"CONTACT_ID","message":"evidence is ready","aad":"goal=GOAL_ID"}'

# A transport delivers that envelope to the other Control.
curl -X POST http://127.0.0.1:8787/v1/peer-messages \
  -H 'content-type: application/json' \
  -d '{"direction":"inbound","contact_id":"CONTACT_ID","envelope":{...},"aad":"goal=GOAL_ID"}'

# Direct Control-to-Control delivery uses the receiver's federation ingress.
# Routing uses public identity IDs, so local Contact IDs need not match.
export CICADA_PEER_RELAY_URL=https://bob-control.example/v1/federation/messages
export CICADA_PEER_RELAY_TOKEN=relay-auth-token
curl -X POST http://127.0.0.1:8787/v1/peer-messages/PEER_MESSAGE_ID/deliver

# Multiple opaque relays are tried in order; a failed relay does not consume
# the message and the next URL receives the same idempotent transport ID.
export CICADA_PEER_RELAY_URLS=https://relay-a.example/v1/federation/messages,https://relay-b.example/v1/federation/messages
```

The discovery endpoint authenticates a portable announcement and preserves the
operator trust decision. The signed directory/rendezvous endpoints described in
[`directory.md`](directory.md) provide public routing hints but do not create a
trusted Contact. The federation ingress maps the authenticated sender identity
to a local trusted Contact, checks the encrypted envelope's recipient and
sequence, and atomically stores replay state with the opaque message. A lost
HTTP response can be retried with the same transport ID without creating
another message. Its receipt contains no plaintext. Directory transport still
requires the operator to turn a discovered identity into a trusted Contact.

Control-managed peer messages now bootstrap a signed ML-KEM session offer on
the first message, derive directional HMAC chain keys, and advance a monotonic
counter for each AES-GCM message. Rotate a session without exposing its
secrets:

```bash
curl -X POST http://127.0.0.1:8787/v1/contacts/CONTACT_ID/session/rotate
curl http://127.0.0.1:8787/v1/contacts/CONTACT_ID/session
```

Root and chain keys remain in protected SQLite state and the status API returns
only epoch/counter metadata. Old per-message ML-KEM envelopes remain accepted
for compatibility; ratchet counters reject large skips and replay.
