# Disposable Client Group-key fixture

Status: **preparation only**. Bare `start` remains pinned to the historical
v1.2.1 Hub for reproducing the earlier run below. For the current v1.3 Hub,
pass its fixed build metadata explicitly:

```bash
./scripts/client-group-key-fixture.sh start \
  --build-metadata .cicada-data/client-v13-be0269e/interop/result.json
```

The explicit path accepts either a `cicada.hub-build.v1` record or a completed
`cicada.client-hub-interop.v1` result whose `build` uses that schema. It
requires `source.dirty=false`, full SHA formats, the current authoritative
v1.3 catalog digest, and a full `image.id`; Docker must have that exact image
ID locally, and the image's revision, dirty flag, catalog, source fingerprint
and `hub` role labels must match. Runtime `/healthz`, Client capabilities and
public identity are checked against that same metadata. The image is run by
its ID, never by a mutable tag; no image is built or pulled. The companion
`.cicada-data/client-v13-be0269e/build.json` names a different image ID, so use
the interop result above when reproducing the retained `sha256:6cc7c2c6…` image.

Both paths register a synthetic owner key and create a synthetic Node with a
pending pairing code. Neither creates a leased native Endpoint or claims a
positive Android `group.key_manifest/grant/status` result. The Endpoint must
be joined from a live native Codex Thread through the owner-bound Node's local
Join bridge; a made-up Thread ID or direct Hub request is not an acceptable
replacement. Teardown reads the fixture marker's original image and build
identity, so `stop` continues to match a v1.2.1 fixture even when the current
explicit metadata points at a v1.3 image.

The current explicit v1.3 build metadata records source revision
`be0269e80c41e94881d131bd4f4b233e80b6ffe6`, `dirty=false`, source fingerprint
`f21f206525c9deb6f959988d675606257ee796ae39f46b973f9bdd714cda7e4e`, catalog
SHA-256 `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`,
and exact image ID
`sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783`.
The contract revision is taken from the checked v1.3 catalog.

The historical v1.2.1 Android handoff and validation reports used by bare
`start` identify their target as Hub source
`967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`, protocol
`client-hub-v1.2.1`, catalog SHA-256
`25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`, and
local image ID
`sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7`.
The script requires that image to be present locally and checks its ID,
revision, clean-source label and catalog label. It does not build or pull an
image. If the fixed image is missing or any label differs, it exits
`BLOCKED` before creating fixture state.

## Prepare the Hub, Owner and pending Node

From the CICADA checkout on a Linux Docker host, run:

```bash
./scripts/client-group-key-fixture.sh start
```

The script uses a new real `/tmp/cgk.*` directory with mode `0700` and a short
synthetic Node ID. This keeps the Node's native Join Unix socket below the
system path limit without symlinking its state directory. It extracts the
`cicada` binary from the fixed image, creates a
random local management token, and starts the Hub bound to `127.0.0.1` on a
Docker-assigned port. It checks `/healthz`, Client capabilities and identity,
then stops the Hub before running the documented local
`cicada owner-key register` operation against that disposable database. This
avoids a cross-process SQLite write while the Hub is open. It restarts the Hub
and verifies that its identity did not change.

The Owner private identity is generated in a separate host directory with
mode `0700`; its file is mode `0600`. Only the public identity directory is
mounted read-only into the Hub. The private identity is not in the Hub
container, Hub state, Node state, Android APK, Git, or the fixture result
record. The output prints its file path so the Client's external enrollment
signer can use it. The fixture itself does not sign an Android
`OwnerDeviceGrant`; if the Client validation harness has no external signer
for that enrollment proof, stop here and leave Android enrollment **NOT_RUN**.
Do not place the private identity in the APK to work around a missing signer.

This fixture registers an ordinary synthetic Owner, not a Control manager;
its encrypted `session.capabilities` therefore reports role `external`.
For this acceptance run, check the encrypted allowlist for `nodes.preview`,
`nodes.confirm`, `topology.snapshot`, `topology.apply`, `group.key_manifest`,
`group.key_grant` and `group.key_status`. A public capability entry alone
does not grant any of these actions; the bound Owner and current Guard decide.

The fixed-image Node CLI creates its own Node bearer under `node-state/`, then
requests a one-use device code. The code is stored only in
`node-device-code.txt` with mode `0600`. The script never prints the code or
stores it in `commands.tsv`, `fixture-result.json`, or Git; it prints only the
file path and a conservative use-before time. Read that file locally and
enter the code into the Android Client. Do not copy `node-state/` to Android:
the Node bearer must remain with the Node.

The script output includes the Hub URL, synthetic Owner/Node IDs, Owner key
ID, Hub ID and Control public key ID. `hub-identity.json` contains the public
Hub identity captured from this exact image for an independent local pin. Give
the Client the Hub URL and pin through the validation setup; the Client must
still verify the pinned identity and complete encrypted enrollment/session
flow.

For the Android emulator container used by the v1.2.1 validation record, first
reverse the selected host port to the emulator's loopback. That container uses
Docker host networking; this mapping keeps the Hub bound to host loopback:

```bash
HUB_PORT=REPLACE_WITH_PRINTED_PORT
docker exec cicada-client-interop-emulator \
  /opt/android-sdk/platform-tools/adb -s emulator-5554 \
  reverse "tcp:${HUB_PORT}" "tcp:${HUB_PORT}"
```

Configure the Client's existing instrumentation/session setup with
`http://127.0.0.1:${HUB_PORT}` and pin the exact public identity in
`hub-identity.json` through its local trusted setup. Do not switch to a
different Hub port or trust a key fetched only from the URL. Remove the
mapping after the run with:

```bash
docker exec cicada-client-interop-emulator \
  /opt/android-sdk/platform-tools/adb -s emulator-5554 \
  reverse --remove "tcp:${HUB_PORT}"
```

The route is documented from the existing emulator's host-network mode and
the Client report's ADB runner. The Android transport and UI path were not run
by this core-side preparation.

Read-only environment check
`docker inspect cicada-client-interop-emulator --format '{{json .HostConfig.NetworkMode}} {{json .NetworkSettings.Networks}}'`
exited **0** and returned Docker network mode `host`. This supports the
loopback reverse-mapping instructions above; it is not an Android request or
an ADB reverse test.

`fixture-result.json` records the fixed image and preparation state. Its
expected status is `PREPARED_AWAITING_CLIENT_AND_NATIVE_JOIN`; fields for
Android enrollment, Node confirmation, native Join, leased Endpoint and the
Group key flow remain **NOT_RUN** until the following steps complete.

## Complete the Android and native Node steps

1. Enroll a fresh Android device under the synthetic Owner using the Client's
   existing owner-approved enrollment flow. Keep `owner-private.json` outside
   the APK. The `owner_id` and `owner_key_id` are printed by `start`; the
   Client's external signer must use that Owner identity and the fresh Android
   device public identity to create the exact `OwnerDeviceGrant`. Verify
   encrypted `session.capabilities` includes the Group key operations and
   Node/topology operations required by this run.

2. In Android, preview and explicitly confirm the pending Node using the
   one-time code from `node-device-code.txt`: call encrypted `nodes.preview`,
   review the returned synthetic Node ID/name, then call encrypted
   `nodes.confirm`. Create a fresh Group for this Owner through the encrypted
   topology UI/`topology.apply`, and record its returned Group ID. The fixture
   does not create Groups by writing Hub SQLite or by using a manager bearer.

3. Run the extracted fixed-image CLI on the same host and OS account as the
   authenticated Codex installation and its native session records. This
   starts the owner-bound Node Agent and its local Join bridge. Keep its
   output private because the CLI can print a new pairing code if owner
   confirmation did not take effect:

   ```bash
   FIXTURE_DIR=/tmp/cgk.REPLACE_WITH_PRINTED_SUFFIX
   HUB_URL=http://127.0.0.1:REPLACE_WITH_PRINTED_PORT
   NODE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node"]["node_id"])' "$FIXTURE_DIR/fixture-result.json")"
   umask 077
   ("$FIXTURE_DIR/bin/cicada" machine agent \
     --id "$NODE_ID" --name 'Disposable Client Group-key Node' \
     --control-url "$HUB_URL" --state-dir "$FIXTURE_DIR/node-state" \
     --relay-only) >"$FIXTURE_DIR/node-agent.log" 2>&1
   ```

   The shell's `umask 077` and the fixture directory mode keep this log
   private. The Node bearer remains in the Node state directory and is not
   passed to the Android process or MCP server.

4. Configure the Cicada MCP server in a disposable native Codex workspace with
   the extracted binary and these environment values:

   ```text
   CICADA_API_URL=<the fixture Hub URL>
   CICADA_NODE_STATE_DIR=<the fixture>/node-state
   CICADA_SESSION_STATE_DIR=<the fixture>/node-state/mcp-session-state
   CICADA_MACHINE_ID=<the fixture Node ID>
   ```

   Run the live Codex Thread from `<the fixture>/workspace` and explicitly
   call `cicada_join` for the Group ID created in step 2. The Node Agent checks
   that Codex's reported current Thread has a matching local session record
   and workspace, then calls supported `POST /v2/fabric/node/join` using its
   locally-held Node bearer. `cicada_join` creates the session and caches its
   binding; it does not publish an Endpoint key candidate. In that same native
   MCP context, call `cicada_whoami` and then separately call
   `cicada_publish_endpoint_key_candidate` with no arguments. The publish
   operation rechecks the cached Endpoint/Group/Node/binding against the
   current session, creates or loads the Node-local Endpoint key, signs the
   attestation and registers the candidate. Require its returned
   `endpoint_id` to match `cicada_whoami`, `candidate_status` to be `CANDIDATE`,
   and `candidate_version` to be positive; retain the returned key ID and
   fingerprint as public evidence. Only then should Android request
   `group.key_manifest`. Do not record the Session bearer or Node bearer.

5. In Android, call encrypted `group.key_manifest` for that Group and
   Endpoint. Independently verify the full candidate attestation and manifest
   as specified in [the Android Hub contract](android-client-hub-contract.md).
   Review the exact proof externally with the synthetic Owner key, import the
   resulting `signed_proof`, and explicitly confirm the grant. Then call
   encrypted `group.key_grant` and `group.key_status`; the unchanged candidate
   should return `CURRENT`. Record stale-binding/membership and expired-proof
   checks separately if run. Android must not read the Hub database or hold
   the Node bearer.

The smallest native-runtime requirement is one authorized Codex login, one
fresh disposable Thread in the fixture workspace, and the local Node Agent
running under the same OS account. If that runtime or the Client's external
Owner signer is unavailable, do not synthesize an Endpoint: retain
`native_codex_join_and_leased_endpoint` and
`group_key_manifest_grant_status` as **NOT_RUN**.

## Teardown and recorded execution

Stop the foreground Node Agent with Ctrl-C first, then remove the fixture:

```bash
./scripts/client-group-key-fixture.sh stop /tmp/cgk.REPLACE_WITH_PRINTED_SUFFIX
```

`stop` validates the fixture marker, derived container name, fixed image ID and
fixture-specific Docker labels, stops the disposable Hub container, then
removes the fixture directory, including the synthetic Owner private key,
Node bearer, one-time device code, Hub token and SQLite state. The Hub uses
`--rm`; no resident Hub container is replaced. A failed `start` runs the same
scoped cleanup automatically.

On 2026-09-25, the actual preparation command
`./scripts/client-group-key-fixture.sh start` exited **0** against the target
image above. Its recorded stages all exited **0** for binary extraction and
version, synthetic Owner key generation, initial Hub readiness and public
identity checks, Hub stop, offline owner registration, Hub restart and
identity-stability check. The expected fresh-Node command
`cicada machine agent --id <synthetic-node> --name 'Disposable Client Group-key Node' --control-url <local-hub> --state-dir <tmp-node-state> --once`
exited **1**, after producing the protected device-code file while waiting
for Owner confirmation. The script treated that exact code-producing pending
state as expected. Static `bash -n scripts/client-group-key-fixture.sh`
exited **0**. The matching `stop <fixture-dir>` command exited **0**; a
follow-up check found no fixture Hub container and no fixture `/tmp` directory.
A second `start`/`stop` run after adding container ownership-label checks also
exited **0**; the matching Hub was stopped and its temporary state removed.
A full Client/Codex Join and encrypted Group grant was not executed in this
preparation run.

For this run, Android owner enrollment, Android Node confirmation and Group
creation, native Codex Join, leased native Endpoint, positive
`group.key_manifest/grant/status`, physical Android and public HTTPS remain
**NOT_RUN**. The prepared Hub was stopped and its `/tmp` state removed after
verification; no Client repository files or Client database were accessed.

## Current v1.3 bootstrap smoke

On 2026-09-27, the explicit metadata command shown above exited **0** using
image ID `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783`.
Hub extraction/version, synthetic Owner key generation and offline
registration, Hub health/capability/identity provenance, identity stability,
and pending Node bootstrap all completed as expected. The Node's one-shot
bootstrap exited **1** after creating the protected pending-device-code file;
owner confirmation was intentionally not performed. The only result is
**bootstrap PASS**. Android enrollment, Node confirmation, Group creation,
native Codex Join, leased Endpoint, `group.key_manifest/grant/status`, physical
Android and public HTTPS remain **NOT_RUN**. The marker-based `stop` exited
**0**; a follow-up check found neither the fixture Hub container nor its
`/tmp` directory.
