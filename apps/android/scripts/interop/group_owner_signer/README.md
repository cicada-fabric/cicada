# External Owner signer

This development utility stays outside the APK. It signs the fixed Client
OwnerDeviceGrant and Group Endpoint key grant formats with CICADA's own
`internal/e2ee` implementation. It performs no Hub or database requests.

The private identity must be the fixture's `owner-key generate --private`
file, which is the `e2ee.Identity.MarshalBinary()` format. Keep that file on
the trusted Owner machine with mode `0600`. The existing Java
`scripts/interop/OwnerGrantSigner.java` uses a different private file format
and does not implement Group grants.

## Build boundary

`internal/e2ee` can only be imported from a package under CICADA's module
`github.com/cicada-ai/cicada`. Build from a temporary `git archive` of the
fixed Core commit `25bc586232db43362c6e03eccef1fa3a0dbec8ee`, placing
`main.go` and `link_grants.go` at `cicada-go/cmd/groupownersigner/`. Use the
Core-pinned Go toolchain and keep the archive, module cache, and Go build cache
outside both source repositories. Do not build from the current CICADA
worktree. The optional `main_test.go` belongs beside those files only when
running the signer's host unit tests; it is not needed in the executable build.

For a controlled host build, use a fresh temporary directory and the fixed
commit explicitly:

```sh
tmp_dir=$(mktemp -d /tmp/cicada-owner-signer.XXXXXX)
git -C /home/zyf/CICADA archive 25bc586232db43362c6e03eccef1fa3a0dbec8ee cicada-go | tar -x -C "$tmp_dir"
mkdir -p "$tmp_dir/cicada-go/cmd/groupownersigner"
cp scripts/interop/group_owner_signer/main.go scripts/interop/group_owner_signer/link_grants.go "$tmp_dir/cicada-go/cmd/groupownersigner/"
(cd "$tmp_dir/cicada-go" && go build -mod=readonly -o "$tmp_dir/group_owner_signer" ./cmd/groupownersigner)
```

The parent-controlled offline build runner may set the pinned compiler and
temporary Go caches around this same archive-and-copy procedure.

## Commands

Device enrollment signing:

```text
group_owner_signer device-grant \
  --private OWNER_PRIVATE_JSON \
  --device-public ANDROID_DEVICE_PUBLIC_JSON \
  --owner OWNER_ID --device DEVICE_ID --hub PINNED_HUB_ID \
  --expect-device-key ANDROID_DEVICE_KEY_ID \
  --out OWNER_DEVICE_GRANT_JSON
```

Group Endpoint grant signing:

```text
group_owner_signer group-grant \
  --private OWNER_PRIVATE_JSON \
  --manifest VERIFIED_GROUP_MANIFEST_RESULT_JSON \
  --expect-owner OWNER_ID --expect-hub PINNED_HUB_ID \
  --expect-group GROUP_ID --expect-endpoint ENDPOINT_ID \
  --expect-node NODE_ID --expect-principal PRINCIPAL_ID \
  --expect-digest MANIFEST_DIGEST \
  --out OWNER_GROUP_KEY_PROOF_JSON
```

The Group command takes the exact `result` object returned by the Android
`group.key_manifest` preview. Do not pass the surrounding RPC response or a
`group.key_status` record. Compare the expected scope and manifest digest to
the Android screen. The signer checks the complete Endpoint attestation and
its digest, public key ID and fingerprint, all positive revisions and current
binding fields, and both domain-separated digests. It then displays those
values and requires the user to type the exact digest challenge before
signing. It rejects a manifest that expires while waiting for confirmation.

Both commands write a new `0600` proof file, refuse to overwrite an existing
file, and never print a private key or proof. The Group signature uses
`SignOwnerLinkKeyGrant` with operation `group-endpoint-key-grant:v1`, manifest
digest, candidate binding digest/version, `SOURCE`, and the manifest validity
interval. A proof is consent for that precise candidate only; the Hub still
rechecks current owner, membership, Node binding, revisions and expiry.

## Cross-owner Link consent signing

These commands consume the flat `prepare.signingRequestJson` envelope from the
Client's current Link consent review. The request must be a regular file no
larger than 24 KiB, use schema
`cicada.client.link-consent-signing-request.v1`, contain no duplicate or
unknown fields, and use the exact kind-specific field set. The signer also
requires each authority value to be entered again with its corresponding
`--expect-*` option. Its typed challenge binds Owner ID/key/fingerprint, Link
ID/version, side, contract digest, manifest or policy digest, policy head and
candidate version when applicable, and both the selected expiry and preview's
maximum expiry. No generic confirmation is accepted.

The common request keys are `schema,kind,owner_id,owner_key_id,
owner_key_fingerprint,link_id,link_version,contract_digest,side,max_expiry,
expires_at`. A `KEY` request adds only `manifest_digest`. A `REVIEW_POLICY`
request adds only `policy_digest,expected_policy_version,policy_version`;
`expected_policy_version` is present even when the initial head is `0`.

The Owner fingerprint is lowercase SHA-256 hex without a prefix, using the
existing Core `OwnerDevicePublicKeyFingerprint` function and the same public
identity encoding as the Client. For key grants, `manifest_digest` is the
manifest `digest`; Core signs it as the proof's `key_binding_digest`. For
review-policy proofs, `policy_version` must equal
`expected_policy_version + 1`; the first policy head may be zero. The selected
canonical UTC RFC3339Nano `expires_at` must be in the future and no later than
the independently repeated `max_expiry` from preview. Core's existing
`SignOwnerLinkKeyGrant` and `SignOwnerLinkReviewPolicy` functions create the
nonce and signature; the tool then verifies its output with the matching Core
verifier before writing it.

Key grant:

```text
group_owner_signer link-key-grant \
  --private OWNER_PRIVATE_FILE \
  --request ANDROID_PREPARE_SIGNING_REQUEST_JSON \
  --expect-owner OWNER_ID --expect-owner-key OWNER_KEY_ID \
  --expect-owner-fingerprint OWNER_PUBLIC_FINGERPRINT \
  --expect-link LINK_ID --expect-version LINK_VERSION \
  --expect-contract-digest CONTRACT_SHA256 \
  --expect-manifest-digest KEY_MANIFEST_SHA256 \
  --expect-side SOURCE|TARGET \
  --expect-max-expiry MAXIMUM_PROOF_EXPIRY \
  --expect-expires-at SELECTED_PROOF_EXPIRY \
  --out OWNER_LINK_KEY_GRANT_JSON
```

Metadata review-policy proof:

```text
group_owner_signer link-review-policy \
  --private OWNER_PRIVATE_FILE \
  --request ANDROID_PREPARE_SIGNING_REQUEST_JSON \
  --expect-owner OWNER_ID --expect-owner-key OWNER_KEY_ID \
  --expect-owner-fingerprint OWNER_PUBLIC_FINGERPRINT \
  --expect-link LINK_ID --expect-version LINK_VERSION \
  --expect-contract-digest CONTRACT_SHA256 \
  --expect-policy-digest NORMALIZED_POLICY_SHA256 \
  --expect-policy-head CURRENT_POLICY_HEAD \
  --expect-policy-version NEXT_POLICY_VERSION \
  --expect-side SOURCE|TARGET \
  --expect-max-expiry MAXIMUM_PROOF_EXPIRY \
  --expect-expires-at SELECTED_PROOF_EXPIRY \
  --out OWNER_LINK_REVIEW_POLICY_PROOF_JSON
```

The Android review screen remains the place to inspect the complete normalized
policy and reviewer qualification results; this signer signs only the
explicitly re-entered policy digest and version tuple. A signature does not
establish peer Owner trust or reviewer permission by itself, and does not
activate the policy. The Hub still rechecks its current state and requires
each Link side's independent proof.

Both Link commands read the Owner private identity only from a host file with
no group/other permissions, require exact equality with the independently
entered Owner key ID and fingerprint, and require the user to type the complete
challenge exactly. They refuse expired requests, noncanonical timestamps,
out-of-range signed-64-bit versions, a candidate policy version other than
head-plus-one, a proof expiry past the preview maximum, and an existing output
path. The proof file is created with mode `0600`; successful stdout contains
only the proof SHA-256, status, mode, and output path. No command contacts the
Hub, reads a database, handles Node bearer credentials, or runs in the APK.
