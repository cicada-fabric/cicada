# Offline owner key bootstrap for development

This is a temporary local trust ceremony for Architecture v2.1 owner keys.
It registers the public trust root used by encrypted Client device enrollment
and key-bound Link grants. It does not by itself enroll an Android device,
create an authenticated Client session, activate a CommunicationLink, or make
Fabric messages end-to-end encrypted.
The Hub's normal management bearer and Node/Fabric credentials cannot replace
the owner's private signing key.

Generate a distinct ML-KEM-768/ML-DSA-65 identity on a machine controlled by
the user. Keep the private file there; only copy the public JSON to the Hub.
The private directory must already have mode `0700`, and the CLI creates the
private file with mode `0600` without overwriting any existing file:

```bash
mkdir -m 700 "$HOME/cicada-owner"
cicada owner-key generate \
  --private "$HOME/cicada-owner/owner-private.json" \
  --public "$HOME/cicada-owner/owner-public.json"
```

The command prints the public key ID. Verify that ID through an independent
user-controlled channel before the Hub operator registers the public key. Run
the registration command **locally on the Hub host** against its existing
SQLite database; the private file must never be copied there:

```bash
cicada owner-key register \
  --db /path/to/hub-state/cicada.sqlite3 \
  --owner-id OWNER_ID \
  --public /path/to/owner-public.json \
  --expect-key-id pq1-VERIFIED_KEY_ID
```

`OWNER_ID` must be the authoritative owner ID for the intended Link side.
The operator must also verify the association between this user and that ID;
the key ID check alone does not establish it. Registration is idempotent for
the same public key. A revoked key cannot be silently reactivated. A local
operator can revoke it with its current version:

```bash
cicada owner-key revoke \
  --db /path/to/hub-state/cicada.sqlite3 \
  --owner-id OWNER_ID \
  --key-id pq1-VERIFIED_KEY_ID \
  --expected-version 1
```

After device enrollment, the Hub already offers encrypted `link.key_manifest`,
`link.key_grants` and `link.key_grant` Client RPCs. A Client can review the
current Link contract, both Endpoint key candidates and native bindings,
then submit a separately signed SOURCE or TARGET key-bound grant. The Hub
rechecks the manifest, owner key, memberships, bindings and expiry when it
records or reads consent. A bound Node can fetch current public bilateral
evidence at `/v2/relay/nodes/{node_id}/links/{link_id}/authorization` and must
verify it against independently trusted owner keys before a non-routing pin.
The current Hub also supports one-time invitations between two separately
registered owners. Acceptance creates a `PROPOSED` Link; each owner must still
sign the current key-bound manifest separately. The Node-only sealed SEND
transport persists and claims authorized ciphertext; the target Node Agent
checks exact-attempt authorization and local Owner trust, saves a durable
crypto inbox, decrypts, and queues the bound native Codex Thread. This path
has passed two-logical-Node/fake-Codex tests, not real cross-user native
continuity or two-physical-machine acceptance. Grant
records never make the old plaintext cross-Group route usable. Do not expose
private Owner key files to a Node Agent, model, or Hub just to exercise the API.
Each Node's independent public-key trust procedure is documented in
[Node-local Owner key trust](node-owner-trust.md).
