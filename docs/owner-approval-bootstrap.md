# Offline owner key bootstrap for development

This is a temporary local trust ceremony for Architecture v2.1 Link grants.
It does not enroll an Android device, create an authenticated Client session,
activate a CommunicationLink, or make Fabric messages end-to-end encrypted.
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

The Store accepts one separately signed SOURCE and TARGET grant against the
exact current Link contract digest/version. A grant is valid only while the
owner key, both Endpoint memberships and native bindings, and the Link remain
current. Grant records never make the old plaintext cross-Group route usable.
There is not yet a safe remote Client review/sign/submit flow: callers must
not expose private key files to a Node Agent or model just to exercise this
API. The Android Client will need its own PQ-protected device session and
contract review before grants become a routine product operation.
