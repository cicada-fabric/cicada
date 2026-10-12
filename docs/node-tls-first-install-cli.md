# Manual first Node PQ TLS installation

Software 0.0.3 adds a local trusted-operator ceremony around the existing TLS
primitives. It works across separate machines by transferring bounded files;
Node runtime uses outbound HTTPS and needs no SSH path or Hub database. This is
an operator CLI, not an Android TLS approval screen or a CA service.

## Preconditions and trust

Use an actual PQ package on Hub and each Node. Establish the Hub's stable HubID
and application public pin independently. Initial device enrollment and Node
pairing use the existing Client path: a trusted HTTPS certificate chain with an
IP SAN for an IP application URL, the signed Owner device grant, and explicit
encrypted approval of each exact pending Node candidate. Standard HTTPS protects
this initial transport; NIST application signatures/encryption supply the
application proofs. This initial HTTPS transport is not claimed to be pure PQ.

Keep the Owner private identity only on its independently trusted signing
machine. Register its public key on Hub and pin that public key on Node with
`machine trust-owner-key`, checking the key ID and fingerprint independently.
A CSR, bearer, device code or model instruction is insufficient approval.
Keep the issuer private key local to the trusted issuer/Hub operator. Independently
review the issuer chain/root, Hub TLS root, Hub leaf SPKI, logical service SAN,
and all Node IDs/origins. The commands import existing issuer material; they do
not initialize production CA keys. Synthetic test certificates and keys must
never initialize a deployment.

Stop the Hub writer before every `hub-*` command. Each command retains an
exclusive existing state-directory lease while SQLite is open; a running Hub
causes refusal. Stop the Node writer for preparation/staging/apply. Use private
0700 transfer directories and 0600 files. Every `--output` must name a new file;
existing output is never overwritten. JSON files reject unknown fields.

In examples, `cicada` means the local packaged executable. Replace symbolic
paths/IDs with the reviewed values. The same Node `--state-dir`, optional
`--writer-root`, `--node-id`, `--hub-id`, and application `--origin` must be used
throughout and on later Agent startup. Run the sequence independently per Node.

## Binding, preparation and reservation

On Node:

```sh
cicada tls-provision node-binding-request --state-dir NODE_STATE --node-id NODE_ID --hub-id HUB_ID --origin APPLICATION_HTTPS_URL --output challenge.json
```

Copy `challenge.json` to the stopped Hub operator. It contains public coordinates
and a credential digest, not a bearer. Hub authenticates the exact current
approved NodeControl tuple and encrypts a purpose-bound response for that Node:

```sh
cicada tls-provision hub-binding-export --db HUB_DB --input challenge.json --hub-key HUB_STATE/e2ee/node-control-identity.json --output binding.envelope
cicada tls-provision hub-issuer-profile --db HUB_DB --issuer-chain issuer-chain.pem --issuer-key issuer.key --root node-root.pem --output issuer-profile.json
```

Return `binding.envelope` to Node within five minutes. Retain the original
challenge privately. The envelope does not create approval; it must match the
existing approved local Hub/Node keys, versions, binding, credential digest and
independent Owner trust. Its nonce is consumed durably once. A failed/crashed
Prepare can burn the nonce; create a new challenge rather than replaying it.

Create `prepare.json` with these exact keys (all values are strings):
`RequestID`, `DNSName`, `HubDNSName`, `HubPQOrigin`, `HubDialAddress`,
`ApplicationOrigin`, `HubSPKIHash`, `HubTrustAnchorDERHash`, `IssuerGeneration`,
`IssuerSPKIHash`, `IssuerDERHash`, `RootDERHash`.
The hashes are lowercase SHA256 hex of DER, not PEM files. Convert the
issuer-profile's 32-byte arrays to hex; its `SPKIDERHash`, `CertificateDERHash`
and `TrustAnchorDERHash` provide the corresponding issuer/root values.
`HubPQOrigin` is the logical HTTPS service origin containing the approved SAN;
`HubDialAddress` is a canonical numeric `IPv4:port` or `[IPv6]:port`, independent
of the logical port. `ApplicationOrigin` must equal the already approved pairing
origin. Domain locators, scopes/zones, mapped IPv4 and unspecified/multicast
addresses are refused in the signed IP locator.

```sh
cicada tls-provision node-prepare --state-dir NODE_STATE --node-id NODE_ID --hub-id HUB_ID --origin APPLICATION_HTTPS_URL --input binding.envelope --challenge challenge.json --preparation prepare.json --output prepared.json
```

Return `prepared.json` to the stopped Hub operator. Assemble `candidate.json`
using the exact `NodeTLSCandidateInput` keys in
[the implementation](../cicada-go/internal/store/node_tls_authority_v1.go):
`RequestID`, `NodeID`, `CredentialDigest` from challenge; `CSRPEM` and
`ExpectedTLSEpochFloor` from prepared `CSRPEM` and
`LocalAcceptedTLSEpochFloor`; `IssuerChainPEM` and `TrustAnchorPEM` as base64 PEM
bytes; `Parameters` as `{"Role":"node","DNSName":"APPROVED_NODE_SAN"}`;
`Issuer` as the complete issuer-profile JSON; reviewed `IssuerGeneration`,
`HubSPKIHash`, `HubTrustAnchorDERHash`, `HubPQOrigin`, `HubDialAddress`,
`ApplicationOrigin`; `NotBefore`, `NotAfter`, `GrantIssuedAt`, `GrantExpiresAt`
as UTC RFC3339 instants; and a fresh random 32-byte lowercase hex `GrantNonce`.
Use a short current grant window and a leaf lifetime within 24 hours and the
issuer validity. Do not copy a credential bearer into this file.

```sh
cicada tls-provision hub-reserve --db HUB_DB --input candidate.json --output reserved.json
```

## Independent Owner signature, issue and install ACK

Extract only the complete `claims` object of reserved.json into claims.json;
review its Owner/device/key versions, Hub/Node binding, CSR/SPKI hashes, issuer,
serial, epoch, logical origins, IP socket, and validity. Compute and independently
confirm SHA256 of the exact claims.json bytes on the signing machine. Then:

```sh
cicada owner tls-leaf-grant-sign --private OWNER_PRIVATE --claims claims.json --expect-claims-sha256 REVIEWED_FILE_SHA256 --expect-owner-id OWNER_ID --expect-owner-key-id OWNER_KEY_ID --expect-hub-id HUB_ID --expect-node-id NODE_ID --output owner-grant.bin
```

Return only owner-grant.bin. Hub needs no Owner private key. Create action.json
with `RequestID`, `NodeID`, `CredentialDigest` from the reservation candidate,
and `ExpectedVersion` from the latest snapshot's `row_version` (an integer).

```sh
cicada tls-provision hub-issue --db HUB_DB --input action.json --grant owner-grant.bin --issuer-chain issuer-chain.pem --issuer-key issuer.key --root node-root.pem --output signed.json
cicada tls-provision node-stage --state-dir NODE_STATE --node-id NODE_ID --hub-id HUB_ID --origin APPLICATION_HTTPS_URL --request-id REQUEST_ID --input signed.json --hub-trust independently-pinned-hub-root.pem --output install-ack.bin
```

Stage checks the independent original local Prepare record and trust, exact
Owner grant, leaf chain and application binding. Return install-ack.bin to Hub.
Set action.json `ExpectedVersion` to signed.json's row_version, then:

```sh
cicada tls-provision hub-ack --db HUB_DB --input action.json --ack install-ack.bin --output installed.json
```

Set `ExpectedVersion` to installed.json's row_version:

```sh
cicada tls-provision hub-activate --db HUB_DB --input action.json --hub-key HUB_STATE/e2ee/node-control-identity.json --output active-snapshot.json
```

## Remote Apply and startup

Restart Hub using its independently approved strict PQ listener config. Keep the
standard HTTPS bootstrap front available for enrolled/pairing operations as
needed. Return active-snapshot.json to Node, then:

```sh
cicada tls-provision node-apply --state-dir NODE_STATE --node-id NODE_ID --hub-id HUB_ID --origin APPLICATION_HTTPS_URL --request-id REQUEST_ID --input active-snapshot.json --output applied-config-copy.json
```

Apply queries the real signed/encrypted current-authority RPC over the exact
staged PQ transport and rechecks during local installation. Hub offline,
wrong current binding or an ACTIVE label alone cannot complete Apply.
`applied-config-copy.json` is a review export: startup must use the installer's
canonical `NODE_STATE/.node-tls/SHA256(HUB_ID + NUL + NODE_ID)/active.json`, not
this copied path. Set the Agent's `--pqtls-config` to that canonical active.json.
Keep the original Node ID and application origin. An omitted CICADA_HUB_ID is
recovered only from strictly checked approved local state; an explicitly wrong
HubID remains refused.

After an interrupted Hub phase, use `hub-inspect --db HUB_DB --request-id REQUEST_ID
--output new-snapshot.json` under the stopped-Hub lease. Inspect state/row_version
before another action; do not regenerate keys or invent success after uncertain
issuance. Recovery/replacement remains governed by the existing installer and
Store semantics described in [authority installation](node-tls-authority-install.md)
and [runtime startup](node-tls-runtime-startup.md).

Pairing and TLS installation do not Join a Thread or authorize its native Runtime.
Android's TLS Owner signing UI and automatic renewal remain follow-up work.
