# Set up a Hub and bootstrap its first Owner signer

This guide covers Hub-local setup and the bounded Owner signer flow in software 0.0.5. It creates the
Hub's stable account-to-human Owner mapping locally, then installs one external
Owner approval signer through a finite proof-of-possession ceremony. The guide
uses manual local setup and direct Docker serving; it does not provide an
automated installer or the full account/QR-pairing product. See the separate
[protocol contract](hub-owner-bootstrap-contract.md)
and [validation record](hub-owner-bootstrap-validation.md); the latter remains
the authority for which checks have actually passed.

The Hub stores the Owner's public identity only. The Owner's Unix profile holds
the private key as a regular local file protected by directory mode 0700 and
file mode 0600. It is not encrypted at rest or protected by an HSM or OS vault.
Keep it on the Owner's controlled machine and maintain a private backup.
For an existing Windows OpenSSL encrypted PEM identity, use the separate
[Windows existing-key guide](owner-windows-openssl.md). That local helper uses
the same finite bootstrap protocol and retains the existing Hub state and keys;
it does not require a Hub image replacement. See its
[separate validation record](windows-owner-openssl-validation.md).

## New Hub state

Choose the exact HTTPS origin that users will reach after your own deployment
configures DNS, TLS termination, and the Hub listener. `hub setup` records this
origin but cannot verify that the eventual service actually answers there. Use
the same persistent StateDir for setup and later service, and use the exact
Hub image/build you intend to run.

HTTPS is the production transport. Development HTTP is restricted to a literal
loopback address, must be explicitly selected during Hub setup, and the Client
must also receive `--allow-loopback-http` during `client prepare`. Owner profile
preparation inherits the explicit policy from the independently transferred
connection file.

For a Docker Hub, the one-shot setup command can initialize a named volume. Set
`STATE_VOLUME` to a new name only for a genuinely new installation. For an
existing installation, set it to that installation's exact volume; do not
create or substitute a fresh volume. The transfer directory must be writable by
the runtime container's `cicada` UID (1000).

```bash
STATE_VOLUME=cicada-hub-state-new
HUB_IMAGE='your-local-hub-image@sha256:...'
HUB_ORIGIN='https://hub.example.org'
TRANSFER_DIR='/secure/owner-bootstrap-transfer'

# Run this only when STATE_VOLUME is intentionally new.
docker volume create "$STATE_VOLUME"

docker run --rm --network none \
  --mount "type=volume,source=$STATE_VOLUME,target=/state" \
  --mount "type=bind,source=$TRANSFER_DIR,target=/transfer" \
  "$HUB_IMAGE" hub setup \
  --owner-label 'Hub Owner' \
  --origin "$HUB_ORIGIN" \
  --public-config /transfer/hub-owner-connection.json \
  --state-dir /state --workspace-root /workspace
```

This command exits after local setup; it does not run `serve`, publish a port,
install a reverse proxy, or deploy an image. Store
`hub-owner-connection.json` as public deployment metadata. Transfer that exact
file to the Owner through a channel that lets the Owner independently trust
its origin and full Hub Client-Control public key. A public file downloaded
from the target Hub alone is not independent verification.

On the Owner machine, prepare a new private profile from that connection file.
The command creates the profile directory and writes its public manifest to
`owner-public.json` inside the profile:

```bash
cicada owner-signer prepare \
  --profile /private/owner-signer \
  --connection-file /trusted/hub-owner-connection.json
```

Transfer `/private/owner-signer/owner-public.json` back to the Hub operator as
`$TRANSFER_DIR/owner-public.json`.
It contains public keys and the complete candidate fingerprint; it contains
no private identity. IDs and the Hub pin are carried by the files, so the
normal new-Hub flow does not require manually copying an Owner or account ID.

Before serving, the Hub operator issues the finite pairing challenge locally.
The command requires a real terminal and exact typed approval of the complete
fingerprint. It checks setup and first-Root eligibility under the StateDir
startup lock before loading the durable Hub identities. The local setup/issuer
uses `hubidentity` and `hubowner` directly: it does not construct Control,
create a Workspace or Machine, or reconcile Client business. Keep the Hub
stopped and quiescent while issuing; interrupted Client operations still use
their existing recovery procedure. The pairing file is created as a new
mode-0600 file. This extraction is a development candidate, not a replacement
of the existing deployed 0.0.5 Hub.

```bash
FINGERPRINT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' \
  "$TRANSFER_DIR/owner-public.json")

cicada hub owner-bootstrap-issue \
  --candidate-manifest "$TRANSFER_DIR/owner-public.json" \
  --candidate-fingerprint "$FINGERPRINT" \
  --pair-file "$TRANSFER_DIR/owner-bootstrap-pair.json" \
  --state-dir /path/to/hub-state --workspace-root /path/to/hub-workspace
```

For a Docker-only host, run the same issuance command from the exact Hub image
with an interactive terminal (`docker run -it --rm --network none`), mounting
the same StateDir and transfer directory at `/state` and `/transfer`. After
issuance, start the new Hub directly with Docker on a loopback-only host port:

```bash
HUB_CONTAINER='cicada-hub-manual'
HOST_PORT=8787

docker run -d --name "$HUB_CONTAINER" --restart unless-stopped \
  --publish "127.0.0.1:$HOST_PORT:8787" \
  --mount "type=volume,source=$STATE_VOLUME,target=/state,volume-nocopy" \
  "$HUB_IMAGE" serve --host 0.0.0.0 --port 8787
```

This publishes only on host loopback. If the saved origin is HTTPS on a remote
name, configure and verify the operator's reverse proxy and TLS certificate to
forward that origin to `127.0.0.1:$HOST_PORT`; this guide does not configure
DNS, TLS, or the proxy. Keep the exact saved origin and Hub pin. Stop the direct
container without deleting its state with `docker stop "$HUB_CONTAINER"`.
Do not hand this manually created volume to `scripts/install-cicada-server.sh`
or its `scripts/bootstrap-cicada.sh` alias: that helper is for an existing
configured Compose deployment and deliberately rejects orphan volumes.

Transfer `owner-bootstrap-pair.json` to the Owner machine using a protected
channel. The Owner imports it into the same profile and interactively reviews
the full pairing scope and fingerprint:

```bash
cicada owner-signer bootstrap \
  --profile /private/owner-signer \
  --pair-file /private/owner-bootstrap-pair.json
```

If the Hub accepted the proof but its response was lost, keep the same profile
and recover the saved operation after the Hub is reachable:

```bash
cicada owner-signer recover --profile /private/owner-signer
```

Recovery resends the exact saved proof and authenticates the cached receipt; it
never changes the operation, proof, challenge, or nonce. If the Hub accepted
the proof but the response was lost, this exact retry can recover the cached
receipt after challenge expiry while the Root remains active. If the proof was
not accepted and the challenge expires, keep the same profile and Owner key;
after the Hub is stopped again, its operator may issue a new finite challenge.
Pass that new pairing to `owner-signer bootstrap` for a separate reviewed
operation. The signer permits replacement of an unaccepted expired operation
only when the new Hub-authenticated pairing is distinct and its conservative
signed issuance lower bound (expiry minus the maximum ten-minute lifetime) is
at or after the old expiry. The exact old `recover` operation remains unchanged.
A revoked or lost Root never makes the Hub eligible for first-Root bootstrap.

## Enroll a management Client and continue Node INITIAL

After bootstrap, a Client uses the existing Owner-signed
`OwnerDeviceGrant` format and existing encrypted enrollment endpoint. Extract
the already trusted Hub identity and Owner public identity from the public
files; this avoids transcribing their IDs or keys by hand:

```bash
ARTIFACTS='/private/client-enrollment-inputs'
mkdir -m 700 -p "$ARTIFACTS"
python3 - \
  /trusted/hub-owner-connection.json \
  /trusted/owner-public.json \
  "$ARTIFACTS" <<'PY'
import json, os, sys

connection = json.load(open(sys.argv[1], encoding="utf-8"))
owner = json.load(open(sys.argv[2], encoding="utf-8"))
root = sys.argv[3]
with open(os.path.join(root, "hub-identity.json"), "x", encoding="utf-8") as f:
    json.dump(connection["hub"], f)
    f.write("\n")
with open(os.path.join(root, "owner-public-identity.json"), "x", encoding="utf-8") as f:
    json.dump(owner["owner_public_identity"], f)
    f.write("\n")
PY

HUB_ORIGIN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["origin"])' \
  /trusted/hub-owner-connection.json)
OWNER_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["owner_id"])' \
  /trusted/owner-public.json)

cicada client prepare \
  --profile /private/operator-client \
  --origin "$HUB_ORIGIN" \
  --hub-identity "$ARTIFACTS/hub-identity.json" \
  --owner-id "$OWNER_ID" \
  --owner-public "$ARTIFACTS/owner-public-identity.json"
```

Transfer the resulting `enrollment-public.json` from the Client profile to the
Owner machine. Choose a short, canonical UTC expiry, then have the Owner review
the exact Client identity in a real terminal and write a new private grant:

```bash
EXPIRES_AT=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=23)).isoformat(timespec="seconds").replace("+00:00","Z"))')
cicada owner-signer grant \
  --profile /private/owner-signer \
  --manifest-file /private/transfers/enrollment-public.json \
  --expires-at "$EXPIRES_AT" \
  --output /private/transfers/client-owner-grant.json
```

Transfer the mode-0600 grant to the Client machine, then use the current
enrollment command:

```bash
cicada client enroll \
  --profile /private/operator-client \
  --grant-file /private/client-owner-grant.json
cicada client capabilities --profile /private/operator-client
```

The Hub still checks the active Owner key, device grant, encrypted session
capabilities, and server Guard. A public capability or the Owner key ID alone
does not grant manager operations. Continue Node INITIAL enrollment with the
existing `client nodes preview`, `client nodes confirm`, and `client nodes list`
flow described in the [headless Client guide](owner-headless-client.md).

## Existing Hub volumes

Do not initialize an existing volume as new. Take a consistent protected
backup, stop all Hub writers, and perform the normal controlled upgrade with
the new schema-60 binary. The migration preserves existing IDs and seeds
permanent Root history from every old Owner approval-key row, including
revoked rows. Start the upgraded Hub normally once, then stop it cleanly before
local adoption. Do not run `control.New` concurrently with the service.

An existing-volume adoption is allowed only for the exact established active
self-owned human whose ID is already supported by trusted enrollment or
operator records. After the stopped Hub has completed the normal upgrade,
inspect the persisted mapping read-only; do not search by display name or
choose the first human Principal. For example, using Python's read-only SQLite
mode:

```bash
python3 - /path/to/hub-state/cicada.sqlite3 <<'PY'
import sqlite3, sys
from pathlib import Path

db = sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + "?mode=ro", uri=True)
row = db.execute(
    """SELECT s.owner_id, s.state, s.provenance,
              EXISTS(SELECT 1 FROM owner_root_history_v1 h WHERE h.owner_id=s.owner_id),
              EXISTS(SELECT 1 FROM owner_approval_keys_v2 k
                     WHERE k.owner_id=s.owner_id AND k.state='ACTIVE')
       FROM hub_owner_setup_v1 s WHERE s.id=1"""
).fetchone()
if row is None or row[1] != "LEGACY_COMPAT" or row[2] != "EXISTING_LEGACY":
    raise SystemExit("No exact established legacy Owner mapping; stop for review")
print("Exact existing Owner ID:", row[0])
print("Root history ever established:", bool(row[3]))
print("Active Owner signer exists:", bool(row[4]))
PY
```

Verify that public ID against the independent existing Owner record. Only then
may the operator supply that exact ID once to explicit adoption while the Hub
is stopped:

```bash
cicada hub setup \
  --owner-label 'Existing Hub Owner' \
  --origin 'https://hub.example.org' \
  --public-config /secure-transfer/hub-owner-connection.json \
  --adopt-legacy --expect-owner-id "$KNOWN_OWNER_ID" \
  --state-dir /path/to/hub-state --workspace-root /path/to/hub-workspace
```

For Docker, run this setup command with the same exact Hub image, stopped
StateDir volume, and protected transfer-directory mount. Setup adds account and
origin metadata to that exact Owner without rewriting Owner IDs, grants, or
enrollments. Do not print or use a legacy bearer token for this procedure.
If the exact mapping is absent, generated compatibility, ambiguous, inactive,
or does not match independent records, stop; this guide provides no recovery by
guessing or selecting another human.

Before attempting first-signer bootstrap, check permanent Root history and
active signer state through the controlled local record. If any Root was ever
established, including one now revoked, do not bootstrap another first Root.
Use the existing active Owner signer and grant process if available. If no
active signer remains, preserve the volume and backup and stop; this checkpoint
does not define trust-epoch reset or Root recovery.

The existing Hub image remains under the operator's deployment controls. These
steps do not replace it, publish it, start it, or modify a resident service.
Android bootstrap, native Windows execution/ACL enforcement, model/Native
Runtime use, physical devices, and public HTTPS acceptance remain separate
work and validation. The Windows encrypted-PEM local provider is documented
separately; its cross-build or Linux PTY results do not establish native Windows
acceptance.
