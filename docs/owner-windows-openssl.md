# Windows: bind an existing encrypted Owner key to a 0.0.5 Hub

Use the existing ML-KEM-768 and ML-DSA-65 encrypted PEM keys and their public
SPKI files. This flow keeps the same Hub account, StateDir, Hub keys and deployed
software 0.0.5 image. A separately built local Windows helper opens the private
keys through OpenSSL and completes the finite first-Owner proof; it does not
upload private keys or replace the Hub. Implementation and acceptance status
are separate: see [the current validation record](windows-owner-openssl-validation.md).
Native Windows execution and ACL enforcement, the user's public HTTPS Hub,
Android and physical-device acceptance remain **NOT_RUN** by us.

## 1. Prepare the existing candidate on Windows

Obtain the exact `hub-owner-connection.json` produced by the operator's existing
`hub setup`. Independently verify its account/Owner IDs, HTTPS origin and full
Hub Client-Control pin. The [Hub setup guide](hub-owner-bootstrap.md) covers
setup if it has not happened yet; retain an already configured Hub and its
original connection file. A response fetched from the target Hub alone is not
independent trust.

Set the following absolute paths to your existing files and the separately
verified helper artifact. Choose a new profile path under your local account;
the helper creates it with a protected current-user/System ACL. Do not create
the profile directory beforehand. Retain the original key files outside it.
Run each command in a real terminal and stop on any nonzero exit code.

```powershell
$Helper = 'C:\CicadaTools\cicada.exe'
$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
$Keys = 'C:\ExistingOwnerKeys'
$Connection = 'C:\TrustedTransfer\hub-owner-connection.json'
$Profile = Join-Path $env:LOCALAPPDATA 'CicadaOwnerSigner'

& $Helper owner-signer prepare-openssl `
  --profile $Profile --connection-file $Connection --openssl $OpenSSL `
  --kem-private (Join-Path $Keys 'owner-kem-private.pem') `
  --signing-private (Join-Path $Keys 'owner-signing-private.pem') `
  --kem-public (Join-Path $Keys 'owner-kem-public.pem') `
  --signing-public (Join-Path $Keys 'owner-signing-public.pem')
if ($LASTEXITCODE -ne 0) { throw 'Owner candidate preparation failed' }
```

Review the displayed account, Owner, Hub, origin and complete fingerprint, then
type the exact requested approval. The command outputs `NEEDS_BOOTSTRAP` and
writes `$Profile\owner-public.json`. Transfer only that public manifest to the
Hub operator. It binds the candidate's full public keys to the saved account,
Owner, origin and Hub pin; it is not a Root grant.

If an existing public SPKI file is missing, export only that public key with
OpenSSL `pkey -in EXISTING_ENCRYPTED_PRIVATE.pem -pubout -out NEW_PUBLIC.pem`.
OpenSSL prompts locally for the passphrase. Keep the existing private key;
there is no regeneration, private PEM conversion or plaintext private-identity
import in this procedure. Passphrases stay out of arguments, environment,
Hub uploads and evidence.

## 2. Stop, issue locally, then restart the same Hub

The Hub operator checks the candidate fingerprint against the Owner's
independent record. Use the existing container's image and its exact retained
state volume. Stop the Hub cleanly, issue a challenge from that same image and
state, then start the original container. This is the same local issuer used
by the Unix guide; it does not use `owner-key register`.

```bash
HUB_CONTAINER='your-existing-hub-container'
STATE_VOLUME='your-existing-hub-state-volume'
TRANSFER_DIR='/secure/owner-bootstrap-transfer'
HUB_IMAGE=$(docker inspect --format '{{ .Image }}' "$HUB_CONTAINER")
FINGERPRINT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' \
  "$TRANSFER_DIR/owner-public.json")

docker stop "$HUB_CONTAINER"
docker run -it --rm --network none \
  --mount "type=volume,source=$STATE_VOLUME,target=/state,volume-nocopy" \
  --mount "type=bind,source=$TRANSFER_DIR,target=/transfer" \
  "$HUB_IMAGE" hub owner-bootstrap-issue \
  --candidate-manifest /transfer/owner-public.json \
  --candidate-fingerprint "$FINGERPRINT" \
  --pair-file /transfer/owner-bootstrap-pair.json \
  --state-dir /state --workspace-root /workspace
docker start "$HUB_CONTAINER"
```

The transfer directory must be writable by the image's runtime UID, normally
1000, and its public candidate file readable by that UID. Supply the actual
workspace path if your retained deployment uses a different one. Run commands
individually, stop on errors, and restart the original stopped container even
if issuance refuses. Do not delete or substitute the state volume.

Issuance requires a configured active Owner and no permanent Root history. It
checks the exact candidate and requires typed approval in the local terminal.
The new pairing file is protected local material with an expiry of at most ten
minutes. Transfer it securely to the Windows Owner promptly after restarting.
There is no HTTP issuer, public first-key upload, Node authority or bearer
substitute. A revoked or lost established Root does not reopen first setup.

## 3. Prove both existing private keys

```powershell
& $Helper owner-signer bootstrap --profile $Profile `
  --pair-file 'C:\TrustedTransfer\owner-bootstrap-pair.json'
if ($LASTEXITCODE -ne 0) { throw 'Bootstrap did not return an authenticated receipt; retain the profile' }
```

OpenSSL opens the encrypted KEM key to authenticate the exact Hub challenge.
Review the displayed finite scope and type the requested fingerprint approval;
OpenSSL then signs using the encrypted signing key. It also opens the encrypted
receipt locally. The helper does not write either decrypted private key, the
challenge nonce or the KEM shared secret to disk. Its profile records public
pins, key paths and exact encrypted protocol packets. Success prints `ACTIVE`
with the matching account, Owner, key, authority and version.

If the accepted response was lost, retain the same profile and keys:

```powershell
& $Helper owner-signer recover --profile $Profile
```

Recovery resends the exact saved proof and authenticates the cached receipt;
it does not sign a replacement or choose a different candidate. If the original
proof was never accepted and expires, the operator can perform the same
STOP–ISSUE–START procedure for a new finite authority, retaining the same keys
and profile. Import that new pairing with `bootstrap` and review it anew.
The old uncertain operation and a new operation are distinct; see the
[recovery rules](hub-owner-bootstrap-contract.md#proof-and-accept-operation).

For the deployed 0.0.5 browser-device form, the public fields come from
`$Profile\owner-public.json`: `owner_id` is the stable human Owner ID;
`owner_public_identity.id` is the approval key ID; the Owner public-key field
receives the complete `owner_public_identity` object. Do not paste the whole
manifest into that key field. Complete the finite Root bootstrap above before
expecting a Client grant to enroll the browser device. The browser's own Client
identity remains separate from this Owner approval identity.

## 4. Approve one management Client

First obtain the exact Client enrollment manifest using the existing
[Client preparation flow](hub-owner-bootstrap.md#enroll-a-management-client-and-continue-node-initial).
For the current APK's manually copied public identity, the existing local
`owner device-enrollment-prepare` helper can construct that manifest using the
already trusted Owner/Hub tuple. Public-file adaptation does not approve the
Client. Keep the Client's generated identity and its chosen Device ID.

```powershell
$GrantFile = Join-Path $Profile 'client-owner-grant.json'
$SummaryFile = Join-Path $Profile 'client-owner-grant-summary.json'
$Expires = (Get-Date).ToUniversalTime().AddHours(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
& $Helper owner-signer grant --profile $Profile `
  --manifest-file 'C:\TrustedTransfer\device-manifest.json' `
  --expires-at $Expires --output $GrantFile --summary-output $SummaryFile
if ($LASTEXITCODE -ne 0) { throw 'Client grant signing failed' }
[Convert]::ToBase64String([IO.File]::ReadAllBytes($GrantFile))
```

Review the exact Hub, Owner, Owner key, Client device ID, device public-key ID,
full fingerprint, purpose `CLIENT_CONTROL` and expiry before signing.
The command writes the existing canonical signed grant without overwrite and
prints a local `cicada.owner-device-grant-summary.v1` summary and writes the
requested separate summary file, including the Owner public identity and exact
tuple. Use `--summary-output` to export it while keeping interactive review on
the terminal. That summary helps populate/review local enrollment fields; it
is not the signed grant, a bearer or independent trust.
Use the final command's **standard padded Base64 of the exact grant file** in
an enrollment UI that requires Base64. Do not substitute summary JSON, raw
Grant JSON or URL-safe Base64. The Hub's active-key, enrollment, encrypted
session and Guard checks still decide authorization.

This Client approval does not approve a Node. Continue the existing Node
INITIAL review/confirmation path only after the management Client is enrolled.

## Historical 2026-10-13 helper

The former guide covered the separate software 0.0.3 public-key adaptation and
Client-grant signing helper. Its legacy local registration procedure is not
this 0.0.5 first-Owner ceremony. Its evidence remains attributed to dirty
`2a5791e`, build-input fingerprint
`ecc00877af17b5fa2f5db0935496128772897e6b23681b0a9499b0937c919dcd`;
[the original QA receipt](../.cicada-data/external-owner-openssl-20261013/qa-20261013-a1/QA-RECEIPT.md)
and [input inventory](../.cicada-data/external-owner-openssl-20261013/windows-build/input-inventory.json)
retain their actual focused checks, Linux OpenSSL 3.5.9 grant-signing and
exact-image TCP results against the original `ab2362f` image
`sha256:1d8cf76c59bfb6919748f8911d07ee991c46658e9a9c4be82b0dedc93796aa71`.
The historical Windows cross-build was compilation only; actual Windows,
physical Android and public HTTPS were NOT_RUN. Those results are not reused
as acceptance of the new external-PEM finite bootstrap.
