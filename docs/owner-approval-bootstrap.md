# Offline owner key bootstrap for development

This is the existing offline development trust ceremony for Owner keys under
the adopted Architecture v2.3; it is not a production provisioning service.
It registers the public trust root used by encrypted Client device enrollment
and key-bound Link grants. It does not by itself enroll an Android device,
create an authenticated Client session, activate a CommunicationLink, or make
Fabric messages end-to-end encrypted.
A legacy management bearer or Node/Fabric credential cannot replace
the owner's private signing key.

The user owns generation and custody of the Owner approval signing private key
and may use external standard tools. CICADA supplies algorithm/parameter,
format, verification/authorization and local import/adaptation guidance;
`owner-key generate` is an optional offline development bootstrap, not a required
product dependency. This boundary does not remove automatic Node/Endpoint/Client
device identity creation or the separate internal Node PQ certificate lifecycle.

Current signing commands read CICADA's `identityDisk` JSON: `version` plus
base64-encoded raw ML-KEM-768 `kem_private` and ML-DSA-65 `signing_private` bytes
([serialization and reader](../cicada-go/internal/e2ee/pq.go)). This is **not a
standard PEM/PKCS#8 import**. The OpenSSL 3.5 official
[ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/) and
[ML-KEM documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)
describe those algorithm variants and standard key encodings; their availability
does not mean the current CICADA CLI can directly read externally generated PEM.

External Owner key import/conversion and native Windows signing/secure-storage
adaptation are **NOT_IMPLEMENTED** follow-up work. Reuse mature libraries and
verify exact formats/public identity/signatures without protocol changes or
rotating existing keys. Native Windows Owner use has not been accepted; current
`0700`/`0600` checks follow Unix permissions and do not prove Windows ACL/secure
storage support. WSL is not a product requirement. Keep private keys on the
user-controlled signing machine; never upload them to Hub or an online converter.

For the existing optional Unix development path, generate a distinct
ML-KEM-768/ML-DSA-65 identity on a user-controlled machine. Only copy its public
JSON to Hub. The private directory must already have mode `0700`; the CLI creates
the private file with mode `0600` without overwriting any existing file:

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
