# Node-local Owner key trust

Before a Node can decrypt a cross-Group or cross-user Endpoint message, it
must independently trust the public approval keys of **both** Link owners.
The Hub's Link authorization response is verification evidence, not the source
of that trust. The private Owner signing keys remain with their owners.

On each receiving Node, obtain each owner's public JSON and verify its Owner
ID, key ID and SHA-256 fingerprint through an independent channel. Then run:

```bash
cicada machine trust-owner-key \
  --id NODE_ID --state-dir /path/to/node-state \
  --owner-id OWNER_ID --public /path/to/owner-public.json \
  --expect-key-id pq1-VERIFIED_KEY_ID \
  --expect-fingerprint sha256:VERIFIED_64_LOWERCASE_HEX_CHARACTERS
```

Run the command once for each Owner. It writes only the Node's private
`node-crypto-state.sqlite`; identical retries are idempotent. A mismatched
public key, ID or fingerprint is rejected. To revoke a local trust record:

```bash
cicada machine revoke-owner-key \
  --id NODE_ID --state-dir /path/to/node-state \
  --owner-id OWNER_ID --key-id pq1-VERIFIED_KEY_ID \
  --expected-version 1
```

Revocation is durable and blocks reinstallation of that same key identity.
Neither command grants a message route. The Node must still fetch current
authorization for the **exact Relay claim**, verify both signed grants and
the endpoint envelope, and check the native binding before injection. The
Node Agent connects these checks for explicit single-recipient `SEALED_V1`
SEND. These commands alone do not enable a route: the current Link, both
Owner grants, Endpoint keys, membership, binding and exact Relay attempt must
also pass. Only two-logical-Node/fake-Codex acceptance has run so far.
