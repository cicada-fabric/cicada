# Link status validation — Core 144e079 native fixture

Run date: 2026-10-02. This is a bounded Android-emulator check of current Link
status metadata using the already-built `client-hub-v1.6.1` APK pair and the
pinned Core fixture at `144e079`. It does not test Link policy approval,
consent writes, Link activation, or message delivery. A `NONE` policy response
is current metadata and is not evidence that either Owner approved a Link.

## Fixed artifacts

| Item | Pinned value |
|---|---|
| Client APK source checkpoint | `2ce183373429dddcb21259b54b3b261ae010bd55` |
| App APK SHA-256 | `74c680c2dcf1162b4ff5203fc65a54483032555318c553f4fa6bbef8027776d7` |
| Instrumentation APK SHA-256 | `17fd9e576c821eee3c5d7f434e40a29fc320d884d241c8a7c084960dea4f2621` |
| Android-runner observed checkout | `4c4784e9bb7eb6b64b7b31ff34d8b5862eb6c23b`, source fingerprint `3f3dca5e569cc0c0122528b4dde1d834580f4d30a54f3f659861b0af87452ce9` (128 files at emulator start) |
| Wire contract | `client-hub-v1.6.1` |
| Core commit | `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c` |
| Core source fingerprint | `e64f244961d56265933dd75feec19d2b74fa934533abf9b750c061f09094a902` |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Hub image | `sha256:04e8bcb4e22f4a00100b30a57d8cd5b3c65d5d4abe3d09844f5c121c26beb1bb` |
| Interop image | `sha256:4ddf7bdc25c7da2fd59024a1a85006f7370e40e14f9546d65fcbea9f2ac957d3` |

The APKs were not rebuilt for this run. The encrypted runtime capability result
below applies only to these v1.6.1 binaries. No v1.6.3 APK or runtime test was
performed.

## Fixture validation and retained failures

The authorized fixture contained one Hub, two Node runtime containers, and
three networks: a Hub-only Client network and one internal Hub/Node network per
Node. The two Node fixture records included native Thread headers and explicit
Endpoint joins. Those fixture records and their empty resume checks do not
establish Android approval, a Worker Goal, or model execution. Link invitation
and acceptance came from the synthetic Core Owner producer; they are not
bilateral Android consent.

The native preflight independently pinned these public inputs:

| Input | SHA-256 |
|---|---|
| Public topology | `db4a30d22d487bc008ab9af87e518bf58a2cbfb8aabc143e3ed29fc284072dda` |
| Original fixture marker | `90e407b4f54551616137f2ad7c563eee9fe65764ee2efd4aedf5391b4f88064d` |
| Client public fixture | `86d4dc18ec2d4a8e3951ab1eda407a7e6e9a08aebf57e7b1c5e58e15545d860c` |
| Exact mount allowlist | `70c9d2f28037ac66fb05d5d039ad067f4dd018b94dd21d0606fd467a4c22dece` |

The original single-Hub verifier rejected this three-container fixture with
exit 1 (`Core fixture must own exactly one container`). It dispatched no Hub
RPC. That retained receipt is
`initial-fixture-preflight.redacted.json`, SHA-256
`bf617aeb05512498d95c0aafc6ff626ecf91fc557f035e03dc52463c7d5352b5`.

Five strict native-branch preflight attempts also failed before any Hub RPC;
each failure and the subsequent correction was preserved:

| Receipt | Failure | Receipt SHA-256 |
|---|---|---|
| `native-preflight-first-attempt.redacted.json` | Docker Go template lookup failed because Node `HostConfig.Sysctls` was absent. | `f0c8e6eac10282d85d3dcf4fd3c8590f9d86e3ff7d920adfab3a1c93a635e59e` |
| `native-preflight-second-attempt.redacted.json` | Strict inspection record omitted the exact published-source-list match field. | `3f9f7947666a3973141f0fa8bc2439fe69e5827ad9b4189864b23009342c5b2b` |
| `native-preflight-third-attempt.redacted.json` | Container fixture labels did not match exactly; the comparison was corrected to include immutable image labels plus pinned fixture labels. | `e0bfbc2fdf6db82cb00ef1a9ba5da40c6be9d4d5689124685419b89b19268e7` |
| `native-preflight-fourth-attempt.redacted.json` | Published port bindings did not match the exact loopback allowlist. The final check distinguishes the Hub's configured dynamic host port from its actual loopback publication and requires no Node port bindings. | `3eb96b5164bdd22d5c711e26369885e5c383ac4ef8dd8c12de73d62338b083f5` |
| `native-preflight-fifth-attempt.redacted.json` | Hub primary Client bridge lacked the carrier-required Hub alias. | `7bd930839afa42d27b6b2dca2f3893dd95f73b4a5b8504e982230f76c5d74182` |

Final `verify_hub` passed with exit 0. It verified three containers, three
networks, the six pinned input arguments, immutable images, resource ownership,
labels, security settings, network edges, loopback publication, and the exact
mount policy. It did not read `Config.Env`, a Hub database, or mounted file
contents, and did not dispatch Hub RPC. Receipt:
`corrected-fixture-preflight.redacted.json`, SHA-256
`baa20c083871e656571616a35ce98116ae7c87980fdedba5223d188cc2d94d55`.

An independent Docker metadata inspection compared all eleven mount tuples
(Hub 1, Node A 5, Node B 5) across `Type`, `Source`, `Destination`, `RW`,
`Mode`, and `Propagation`. It read no mounted file contents and no container
environment. Command family: `docker container inspect --format '{{json
.Mounts}}' <pinned-container-id>`; all three exits were 0. Receipt:
`mount-verification.redacted.json`, SHA-256
`610b720c57e76b1deb9430a04a9301d1e62642b1798c3ac3e07784a7d84af030`.

The Python adapter test command was run in a Docker container with networking
disabled and the repository mounted read-only:

```text
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -B scripts/interop/test_v16_native_link_fixture.py
```

The first attempt exited 5 and ran zero tests because the four pinned metadata
files were not mounted into the offline container. The second exited 1 with
two assertion errors in synthetic fixture ownership and mount tests. Both are
retained setup/test failures, not Hub or Android failures. The final run exited
0 (`Ran 13 tests ... OK`); it uses self-contained synthetic public topology,
marker, public fixture, mounts, and temporary fixture paths. It had no live
Docker inventory or RPC access and did not change the production adapter
source. Receipts: initial `native-adapter-tests.receipt.json`, SHA-256
`510cd28c516ef28025102091c035e2e171715b29ec42e98821f174a36997d602`; corrected
`native-adapter-tests-corrected.receipt.json`, SHA-256
`a7781e30a0a0ff23fdc7197821654c34bb533ca9d6f2e4ea8984df7bb966fafd`; final
`native-adapter-tests-final.receipt.json`, SHA-256
`5f17034810865f23d6b03c3ee8dd41545dd687c56041123e0114e9e0140f0492`.

## Android emulator results

The fixed APK pair was installed in the Docker-hosted Android emulator. The
emulator start command was `python3 scripts/interop/v16-android-deterministic.py
<android-evidence-dir> start --app-apk <pinned-app.apk> --test-apk
<pinned-test.apk> --app-sha256 <app-sha256> --test-sha256 <test-sha256>`;
exit 0. Start receipt SHA-256:
`46b6dcdc2b3d8ae58eb7107b23c86da9aab65a22c06a2fd9eb07ca2b0062dab0`.

Two independent Owner profiles were staged and enrolled. Their public Owner
keys and profile identities were checked independently; this report retains
only identifiers already hashed in redacted receipts. The Android
instrumentation command for each profile was:

```text
docker exec cicada-v16-deterministic-v161-144e079-link-20261002 \
  /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 shell am instrument -w \
  -e run_id v16-deterministic-v161-144e079-link-20261002 \
  -e class ai.cicada.client.hub.ClientHubV16InteropTest#enrollAndVerifyDirectory \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

Both Owner runs returned exit 0 and `OK (1 test)`. For this pinned v1.6.1 run,
OwnerDeviceGrant verification and encrypted `session.capabilities` runtime
authorization passed for both profiles. The enrollment summaries are
`enroll-primary.redacted.json`, SHA-256
`6ee6edae6bac8b916faf78d6212ff8edcb631a239570dfb386ed9b9181a7c499`, and
`enroll-foreign.redacted.json`, SHA-256
`13372012d24584b7e9676ef4725cccb73c4000b346c47d70b2aca324c55be7b0`. The
instrumentation summaries are `link-enroll-primary.json` and
`link-enroll-foreign.json`, each SHA-256
`302b1636af24a1c6015a0777582a2cc699a3133c60b709eccd92d16f0dc6ec98`.

Two early public-device UI attempts failed before any Hub request: the primary
profile's initial run and retry 1 exited 1. The later delayed-character UI
flow passed for both profile selections, each exit 0. This validates the
public-device flow only; it does not approve a Link. Receipts:

| UI attempt | Exit | Receipt SHA-256 |
|---|---:|---|
| Primary initial | 1 | `34cc49dec061e78bb422ef19cd2b928523d7e42b1abd825b0a89745ab7fe6ff9` |
| Primary retry 1 | 1 | `b7630d1025ee6393234778d8d66ae7638deaf36e4e93a023fa8ae57f5762425b` |
| Primary delayed-character retry 2 | 0 | `b9fe0e25f8df26c1a5bca74074af703e8a69ccf0880289721fa3ffd92dcd7d63` |
| Foreign delayed-character retry 2 | 0 | `edbd93ea2c40ec595a4af2d1f546b6be9d01b98fbfaa7728d5226d38f3f6a528` |

### Per-Owner Link status

The exact command was `python3 scripts/interop/v16-link-review-policy-status.py
run-owner` with the fixed APK, Core, catalog, Hub image, topology, marker,
public fixture, and mount pins; the `--owner` argument selected `primary` or
`foreign`. Each command exited 0. The complete argument vectors are retained
in `link-status-primary.receipt.json` and `link-status-foreign.receipt.json`,
whose SHA-256 values are respectively
`8c6176f161a9423fa515f6a6d63eda6f46f1918dba124e6757ee994835c90df9` and
`c4dfcf2230f946f32d61ef045c7c14d5abe103b29313ebeadb99a948f2d036be`.

Each profile ran these five Android instrumentation selectors. All ten
selector executions returned exit 0 and `OK (1 test)`:

1. `readsCurrentNonePolicyForSelectedOwnerLink`
2. `refusesUnknownAndOptionalForeignLinkBeforeStatusRpc`
3. `rejectsStaleExpectedLinkVersionBeforeStatusRpc`
4. `rejectsGenericStatusRpcBypassWithoutSequenceUse`
5. `capturesAndRecoversExactStatusPacket`

The primary Owner read side `SOURCE`; the second Owner read side `TARGET`. Both
lists confirmed the same Link ID hash
`af20c2d1f77936260047bedbabb7bc46c8ca3148e1e88bbba7647aadf881e614`, Link
version `1`, policy mode `NONE`, policy version `0`, and the SHA-256 of the
empty policy (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
Their Owner ID hashes are
`59aa9f60e1a2918ad278b22494064b2579ac8178326cb4824ca0150d3a328696` and
`60b1e58519a6923cf7d99fa81746afc239265855b22eb1d7895447a0d815d29e`.

For each Owner, the normal carrier completed 12 transactions and the response
loss carrier completed 5; both stopped with exit 0 and report
`payload_persisted=false`. The response loss was injected for
`link.review_policy_status`: the recovered HTTP 200 matched the original
encrypted response envelope and exact request packet. Per-Owner status
summaries are `link-status-owner-59aa9f60e1a2918a.redacted.json`, SHA-256
`d62857accb4fc2a02e2ba172f6a8b330aa7599cb40c79897f6202dcd7aa39a57`, and
`link-status-owner-60b1e58519a6923c.redacted.json`, SHA-256
`78bf0acead5bc174bcaf92b7f13575506af03521cc4f89a4015f1a9bd6bc0166`.

The aggregate command was
`python3 scripts/interop/v16-link-review-policy-status.py aggregate-two-owners
--owner-a <source-owner-redacted-summary> --owner-b
<target-owner-redacted-summary> --output <two-owner-redacted-summary>`; exit
0. The result independently records that both Owner lists found the same Link
and opposite sides. `bilateral_approval_inferred=false`, configured policy
`NOT_RUN`, and third-Owner refusal `NOT_RUN`. Aggregate summary SHA-256 is
`ba6f808dbe5368d25d1c819399fb23b72632abf87b76c61289d110a9f7baf4c9`; command
receipt SHA-256 is
`17e30119580415b3eba9247b7871cf92590073616ca005271cb4c5b565ec24be`.

## Acceptance matrix and limits

| Check | Result |
|---|---|
| Pinned native fixture topology and exact mount inventory | PASS; final preflight exit 0, three containers/networks, eleven exact mount tuples |
| Synthetic offline native-adapter suite | PASS; 13 tests, exit 0; two earlier setup/assertion failures retained above |
| Primary and second Owner enrollment with v1.6.1 encrypted runtime capabilities | PASS; two instrumentation runs, each exit 0 / `OK (1 test)` |
| Primary and second Owner current Link status | PASS; five selectors per Owner, all ten exit 0 |
| Same Link/version/digest from opposite Owner sides | PASS; aggregate exit 0 |
| Exact status packet recovery after dropped response | PASS; each Owner recovered the same encrypted response envelope |
| Configured review policy, third-Owner refusal, revocation, process-death recovery, missing capabilities | NOT_RUN |
| Link review preview/grant, key grant, bilateral consent write, Link activation or message delivery | NOT_RUN; these operations remain closed |
| v1.6.3 encrypted runtime capability validation or new APK | NOT_RUN |
| Physical Android device or public HTTPS | NOT_RUN |
| Worker Goal or model execution | NOT_RUN |

Client emulator/carrier stop returned exit 0; receipt SHA-256
`d29911e7405f181571ddbea64f818abe9986ae84aca202db375d81e96298ae66`. Android
teardown and emulator-absence checks report PASS; their redacted receipt hashes
are `f1f3c682641d2f37af68ec06003bc7c975d8cf2c4161a5279a0ec5be4ed48716` and
`dd2b1b07ad2de6ab414f365710af6c843700403cacd1231c574e0c60fde61ae7`.
Core separately recorded `CLEANED_OWNED_ONLY`, exit 0, removing six owned
fixture resources while retaining private fixture files for its supervisor;
result SHA-256 `52f5c124a8c06e96d7ca4eb6a49932a685c75ca1267d8f46239580e9a21a7544`.
An independent read-only layer then ran ten filtered Docker list queries: all
exited 0 and returned no matching container or network IDs, including stopped
containers and exact pinned IDs. Its receipt is
`core-cleanup-absence.redacted.json`, SHA-256
`15f38f6af0168658dd84352ec4ca26c62d277e2e045ba848f422f8cab2e7b132`. Private
fixture files were retained for the supervisor; the validation did not delete
the fixture directory or read Hub database state.

All runtime evidence is for the historical 144e079 / v1.6.1 fixture and the
fixed APK hashes above. It does not validate v1.6.3 runtime integration or
turn the two Owners' current `NONE` status into consent. The accepted local
operation policy at this checkpoint remains 39 implemented / 16 closed.
