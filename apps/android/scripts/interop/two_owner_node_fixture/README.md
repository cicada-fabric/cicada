# Two-Owner synthetic Node Endpoint fixture

This helper creates a **synthetic Endpoint for authorization testing only**.
It does not create or verify a native Codex/Thread session. Use it only with a
new disposable Hub built from CICADA commit
`967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a` (`client-hub-v1.2.1`) or
`be0269e80c41e94881d131bd4f4b233e80b6ffe6` (`client-hub-v1.3`). The helper uses only supported Node Join,
`whoami`, and Endpoint key candidate APIs; it has no database access or
production fault path.

The fixed Join contract accepts `harness: "codex"`, so the helper uses that
value only as simulated adapter metadata. It does not start or contact any
Codex process; the synthetic `native_session_id` and result marker make the
fixture status explicit.

For each Owner, first create a separate synthetic Node through the existing
`cicada machine agent --once --state-dir ...` flow, approve that Node in
Android, and create that Owner's Group in Android. Then invoke this helper once
for Owner A and once for Owner B with distinct Node token files, Group IDs,
synthetic session labels, private Endpoint identity files, and result files.
The CLI reads the existing raw `relay.token` created by the fixed CICADA
machine agent; it does not copy or print the token. The generated Session
bearer stays in memory only.

## Build from the fixed clean source

Run from any directory with Docker available. `build.sh` archives the pinned
core commit with `git archive`, inserts this helper only into that temporary
archive, and builds inside Docker. A dirty CICADA working tree is not used.
Build cache and output default to
`/gpu1-share/data/cicada-client/two-owner-node-fixture-build`; override with
`FIXTURE_BUILD_ROOT` if needed, keeping that directory name and placing it
outside both Git repositories. `CORE_REPO` may point at the local CICADA Git
repository and `GO_BUILDER_IMAGE` selects the Go 1.27.1 build image.

```sh
scripts/interop/two_owner_node_fixture/build.sh
```

The default remains the historical v1.2.1 source. For the frozen Monitor protocol
fixture, set `FIXTURE_CORE_COMMIT=be0269e80c41e94881d131bd4f4b233e80b6ffe6`
and use a separate `FIXTURE_BUILD_ROOT` ending in `two-owner-node-fixture-build`.
The script accepts only these complete source commits and embeds the selected
source in the helper's public result. Synthetic Monitor and recipient Endpoints
are protocol fixtures; they never establish native Monitor execution.

The binary is written to
`/gpu1-share/data/cicada-client/two-owner-node-fixture-build/bin/two-owner-node-fixture`.
The build script prints its SHA-256. It uses `--rm` for its temporary
container and removes its extracted source archive when it exits.

## Input schema and invocation

Give each Owner a separate mode `0600` JSON spec in an already private
directory (mode `0700`). Do not put Node tokens or private Endpoint identities
in the repository, APK, or process arguments. For this disposable-only helper,
`hub_base_url` must use the literal loopback IP `127.0.0.1` or `[::1]` and an
explicit port; hostnames and remote HTTPS origins are rejected before the Node
bearer is read.

```json
{
  "schema_version": 1,
  "hub_base_url": "http://127.0.0.1:8794",
  "group_id": "grp_owner_a_fixture",
  "node_credential_file": "/gpu1-share/data/cicada-client/two-owner-private/node-a/relay.token",
  "native_session_id": "synthetic-owner-a-session",
  "workspace": "/two-owner-fixture/owner-a",
  "endpoint_private_key_file": "/gpu1-share/data/cicada-client/two-owner-private/endpoint-a.identity",
  "public_result_file": "/gpu1-share/data/cicada-client/two-owner-private/endpoint-a.public.json",
  "lease_seconds": 3600
}
```

The fields are:

| Field | Meaning |
|---|---|
| `schema_version` | Must be `1`. |
| `hub_base_url` | Disposable Hub origin. |
| `group_id` | Existing Group owned by the Node's separately confirmed Owner. |
| `node_credential_file` | Existing machine-agent `relay.token`, raw token plus newline, mode `0600`; its parent must be private. |
| `native_session_id` | Stable synthetic label for this Endpoint. It is not proof of a native session. |
| `workspace` | Absolute synthetic workspace label. |
| `endpoint_private_key_file` | External ML-KEM-768/ML-DSA-65 identity file. Created on first run with mode `0600` and reused for refresh. |
| `public_result_file` | External mode `0600` output for Android/Owner signer; contains public identity, signed proof, and Endpoint/lease coordinates only. |
| `refresh` | Optional `true` only when refreshing the existing result for the same Hub, Group, and synthetic session. The helper verifies Endpoint/Principal/Node/binding continuity and an increased epoch. |
| `lease_seconds` | Optional `1`–`3600`; omitted or `0` uses the one-hour maximum. |

Run it by passing only the spec path:

```sh
/gpu1-share/data/cicada-client/two-owner-node-fixture-build/bin/two-owner-node-fixture \
  -spec /gpu1-share/data/cicada-client/two-owner-private/owner-a.json
```

The helper performs these supported operations:

1. `POST /v2/fabric/node/join` with `Authorization: CicadaNode <relay.token>`;
   it requires HTTP 201.
   The request supplies only `group_id`, `harness`, `native_session_id`,
   `workspace`, and `lease_seconds`; the Hub derives Owner and Node identity
   from its active Node binding.
2. `GET /v2/fabric/whoami` with the returned in-memory Session token and
   `Cicada-Group-Scope`; it requires HTTP 200 and response coordinates must
   agree with Join.
3. `POST /v2/fabric/endpoint-keys` using the same Session and Group scope; it
   requires HTTP 200. The response Owner, Endpoint, Principal, Node, binding,
   epoch, full public identity, key ID, submitted proof bytes, and SHA-256
   proof digest are checked against authenticated Join/whoami values.
   The proof is produced by the pinned implementation's
   `Identity.SignEndpointKeyAttestation`, which signs the ordered v1 JSON
   shape with ML-DSA-65 and the domain
   `cicada/fabric/endpoint-key-attestation/v1\0`.

The result explicitly labels the fixture
`SYNTHETIC_ENDPOINT_AUTHORIZATION_ONLY_NOT_NATIVE_EVIDENCE`. Candidate state
`CANDIDATE` is self-attested public material; it does not imply trust or
routability. Do not use this as evidence of native Join, Codex, or peer
messaging.

After the one-hour binding lease expires, re-run with the same endpoint
private-key file, `native_session_id`, Node credential file, Group, and Hub;
set `"refresh": true`. The supported Node Join rotates the Session credential
and binding epoch while preserving the stable Endpoint ID for the same owner,
Node, and native-session label. The helper verifies continuity, re-signs the
current binding coordinates, and refreshes the public candidate. A revoked
Node credential fails at Join. A changed Node, Group, Owner, or private key is
not silently adopted.

## Fixed-source route evidence

- `cicada-go/internal/server/fabric_v2.go` — `/v2/fabric/node/join` request
  schema and authenticated Node dispatch.
- `cicada-go/internal/server/endpoint_keys_v2.go` — `/v2/fabric/endpoint-keys`
  publication route and `attestation` wrapper.
- `cicada-go/internal/e2ee/endpoint_attestation.go` — exact version 1
  ML-DSA-65 signed bytes and `SignEndpointKeyAttestation`.
- `cicada-go/internal/fabric/service.go` — Node-derived owner scope and
  same-session Endpoint continuity on Join.
- `cicada-go/internal/store/endpoint_keys_v2.go` — current binding checks and
  same-public-key candidate refresh.

These references are read from the fixed commit above; dirty core worktree
changes are not part of this helper's contract.
