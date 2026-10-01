# Native Network enrollment and Monitor proposal validation

Reviewed 2026-10-01. The historical paid disposable run reports
`NATIVE_NETWORK_MONITOR_PROPOSAL_PASS`, terminal exit **0**, and owned-resource
cleanup **true**. This verifies one original Codex Thread explicitly joining a
Network, joining an Owner-admitted Group, and producing a durable Monitor
proposal. **That tested end-user enrollment flow is partial:** Group Join required an
additional explicit synthetic operator `directory.read` grant outside the
encrypted Client catalog. This record does not close V01–V88, G1–G5, or M4
delegated execution as a whole.

## Current nonpaid preflight: own Join without a directory grant

After integration of the native self-identity Guard repair, the updated default
preflight reports **PREFLIGHT_PASS_NATIVE_NOT_RUN**, terminal **0**, owned-resource
cleanup **true**, **zero model calls**, and unchanged source throughout the gate.
The saved result is
`/home/zyf/CICADA/.cicada-data/native-network-monitor-self-only-preflight-20261001-pass/result.json`,
SHA-256 `397ff47b65364cd00e7e320e010b6f5af83e6357635c7687646b0feea943a1d9`.

| Current nonpaid attribute | Actual value |
|---|---|
| Git base / state | `fe565b41bb1aa86d400a0ec98c528c856d0b9579` / dirty integrated source |
| Build input fingerprint | `fb8f0d8be8fbc786d8ee434dde3974d8ffe295aa0c99ac97eea9b44e4ceace62` |
| Executed driver SHA-256 | `7b321234f573297cd45ce519eeaeb09c1312a557149ac654bf9cbc8934a9d333` |
| Cicada binary SHA-256 | `ac0f280ea6c0eeadade0ebd29bdfb62e77f52cbe4926416870e51cd12c3e028e` |
| Fixture operator binary SHA-256 | `62bc443b68e419784eeaf063547bb80558c6006df630db6529cd143959ae0028` |
| Hub image ID | `sha256:c1d7be59b8d1370b63cb0bc5ed4c47996ff0962b1d82c680349cf80ee4aabedd` |
| Pinned Go build image ID | `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195` |
| Runtime container image ID | `sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57` |

This run built the current Go binary with `CGO_ENABLED=0` and offline caches,
using Go 1.27.1. It exercised a real disposable default-HTTP Hub, outbound Node
Agent, owner-only Unix bridge, MCP server, Store and encrypted Owner RPC. No
provider credential was mounted, no model was called, and the Codex native
session record was visibly synthetic (`11111111-2222-4333-8444-555555555555`).
This is **not** a native Runtime or PQ TLS acceptance run.

Encrypted Owner admission admitted the existing Endpoint to source and target
as `member` with zero grants, history access or key consent. Only the encrypted
`membership.bind_role` CAS selected source `monitor`; its four production grants
remained `federation.represent`, `task.read`, `task.verify`, and `artifact.share`.
No Group `directory.read` was added, and the source membership stayed at version
and revision **2**. The current driver and fixture helper contain no
`grant-group-directory` action or stopped-Hub Store-grant workaround. The
synthetic bootstrap and signed Network invitation remain test setup; the Owner
signer is never mounted to the Node.

Actual `cicada_join`, own WhoAmI, and own public key candidate publication
succeeded. The Endpoint was `ep_bde3d62e1b75e23e`, the Group binding was
`bind_e1c7a0f4eabc88e3` epoch **1**, and the candidate remained **CANDIDATE**, version
**1**, on repeated publication. Network native binding
`native_f1c0712fa2a0ca9b` epoch **1** retained the same Node and synthetic Thread.
Own key HTTP read returned **200**; peer key read, `cicada_members` and
`cicada_find` returned **403**. SEND returned a durable operation result
`FAILED`, `retryable:false`, `attempts:1`, with an actual HTTP **403** permission
denial. A completed MCP RPC is not delivery success or necessarily `isError`.
Membership identity/role/grants/version/revision and candidate identity remained
unchanged; Owner key grants and relay payload commits were **0**.

Monitor proposal `rgrp_b234fd230a5306ee` remained **PROPOSED** with unchanged
source/target topology, no issued delegation and no successful apply. Forged
`user_approved:true` and fake-delegation apply were rejected. Fabric-only Node
business phases retained authenticated management HTTP **503** and ready SSE
HTTP **200**; encrypted Owner setup and readback used explicit management phases.

The focused follow-up checks passed: **16 Python tests** and **3 fixture Go
tests**, including rejection of the removed operator action. Fixture tests used
pinned Go 1.27.1, network disabled, read-only source/module cache, and no CGO.
These checks were executed after the historical paid run and are not attributed
to its binary. Whole-repository and combined strict-PQ gates remain separate.

Three unexpected driver failures were retained before this corrected run; all
have models **0**, exit **1**, cleanup **true**, and unchanged source. They are
not product acceptance passes:

| Current receipt suffix | Preserved failure | Receipt SHA-256 |
|---|---|---|
| `20261001` | `own_join_membership_candidate_missing`: driver queried a membership field absent from WhoAmI; replaced with encrypted Owner membership ID constrained by current Principal/Group | `8ae7ef516428261c20355403c277ae7920457562c897afb401dbb57264aacf28` |
| `20261001-fixed` | `actual_mcp_tool_unexpected_result_cicada_send`: driver expected an MCP error instead of the terminal durable permission failure | `170f6b7e73333f5bf8051dd77c2c40464cbe0e3c0b96d12b5ef413f71123b297` |
| `20261001-final` | `self_key_peer_directory_traffic_guard_status_mismatch`: driver added a GET probe to the retired plaintext RECEIVE route; redundant probe removed, SEND permission denial retained | `f0a6036cba9f053dcba6672791a8f71eec137e66887b305a11a1e18fce7ba807` |

These directories are under main `.cicada-data/` with prefix
`native-network-monitor-self-only-preflight-`. Saved executed drivers and each
receipt preserve their own attribution. Original worktree preflight-1 through
preflight-11 and paid real-1 logs/receipts/source/patch remain untouched. Current
own-identity success removes this particular Join dependency on `directory.read`;
it does not supply a general encrypted Group-grant API, Android UI evidence, or
current-source native Runtime acceptance.

## Historical paid source and artifacts

Evidence is retained under
`.cicada-data/native-network-monitor-real-1/` in the isolated
`/home/zyf/CICADA_native_network_e2e` worktree. Its `result.json` is SHA-256
`982e792696e2a04d002d0d92db6e385a77ee549452cba2c631ad79bb28edc9e1`.
Historical receipts and private logs have not been rewritten. Private logs may
contain full tool payloads; review their metadata locally without publishing
their contents or credentials.

| Attribute | Actual run value |
|---|---|
| Git base | `fe565b41bb1aa86d400a0ec98c528c856d0b9579` |
| Source state | **dirty**, including the reviewed Network/native adapter patch |
| Build input fingerprint | `28b53d57895422476debf7e831975c5b6f6b8dd1254e12f81381b907b9e8078e` |
| Client catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Cicada binary SHA-256 | `0d6408f625ad8c8a3219142e587b0dbee91bef24f1dfbfb8043b81896f99a2e7` |
| Fixture operator binary SHA-256 | `a439eedb53fa34280fd0ad65084ffde08286f8730ea39dc9b60e5af3ee26293c` |
| Hub image ID | `sha256:b6f2d7d2a328f19eb37545177ca32bc9f715cddf1121d106566a1ec2dad53573` |
| Runtime image ID | `sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57` |
| Runtime / model | `codex-cli 0.159.3` / `gpt-5.6-luna` |
| Executed driver SHA-256 | `7f23e09df96a3b2bdb9d8db838b77d9741e05a860c81a3396cda69b7035b0360` |
| Executed shared driver SHA-256 | `2979b54616ebd1aa9533a01b3b1629e3db73261a815b71b5117db4eb81896f86` |
| Matching preflight receipt SHA-256 | `27d6cd6876ad3217f7c861a851d74b98fba26b3a1bab775b2894f564ce08c1b9` |

The software build string is `0.1.0-dev`; Client encrypted wire is v1. Neither
is the Architecture v2.3 document version, Git base, catalog hash, or image ID.
The source fingerprint covers the build script's defined input set, not every
repository file. A read-only review recomputed the same fingerprint and compared
both historical worktree drivers with their saved executed copies: all matched. The eight
adapter code/test/document files are a separate checkpoint and are excluded
from this driver's frozen delivery patch. The accepted native evidence remains
attributed to the dirty snapshot above after integration on `dev`.

## Original native Thread and actual tools

All three actual CLI turns emitted exactly one `thread.started` event for
`01a0f95d-f15c-7bb3-84a4-f8662f1a1471`; each exited 0, completed its turn, and
had no error/failed-turn events. At execution time the driver also verified one
exact local session record for this ID and `/workspace`. The final model reply
recalled the unpredictable witness introduced only in the first turn.

| Turn | Completed MCP calls | Private JSONL SHA-256 |
|---|---|---|
| `native_original_seed` | None; established context witness | `a5ce3af205f66b9aeb823a83264e90c446f4d34c2cf65c0d243519349ba59cf4` |
| `native_explicit_network_join` | `cicada_network_join` exactly once | `b2131e4e959736d369cd518b44c87a7bdf54e372e8b602a3ddda5e0452ed3ba9` |
| `native_original_group_join_proposal_context` | `cicada_join`, then `cicada_regroup_propose`, each once | `4670d39e0e7b15c5f1e5c22a15559d2793023a40f2e5a1caba447e2d239918b8` |

The JSONL filenames are `native-<turn>-a.jsonl.private` under the real-run
directory. Review re-parsed each log with `strict_tools`: only the expected
completed MCP calls, with present result objects and neither `isError` nor
`is_error`, were accepted. No shell, file-change, search, or collaboration tool
actions occurred. There were three attempted model turns and no retry. These
are controlled native CLI resumes, not proof of asynchronous wake or safe
injection into a busy foreground turn.

## Separate authorization and binding objects

The synthetic Owner/device operator used the existing authenticated encrypted
Client RPC, without Android UI. Fixture bootstrap created a synthetic Owner,
Network, current Node binding, invitation and public trust material; it created
no Endpoint. Private Owner/device signers stayed in `operator-private`; the
Node received only a scoped signed join proof/invitation and public Owner key.
The Hub received no provider credential or Node peer private key mount.

The native Network Join created Endpoint `ep_9b25a29f58f3d0af` and Network
membership with only `directory.discover` and `directory.publish`. A direct
send probe was denied with HTTP 403; relay payload commits stayed zero.
Network Join did not imply Group admission or a Monitor role.

The encrypted Owner admission previews separately carried Network access
binding `netaccess_691963bee6f1ff64`, epoch 1, and native binding
`native_3939f4b8307465a5`, epoch 1. These happen to have equal epoch values in
this run but remain different objects and counters. Both previews checked
current Network/member/Endpoint revisions; the deterministic Python check
uses access epoch 9 versus native epoch 1 to prevent accidental conflation.

Encrypted `endpoint.admit_group` admitted the Endpoint to source and target
Groups as `member`, with no grants, history access, or key grant. An independent
encrypted `membership.bind_role` CAS changed the source membership from v1 to
v2 and explicitly selected `monitor`. Its production role grants are
`federation.represent`, `task.read`, `task.verify`, and `artifact.share`.

Those grants do **not** include Group `directory.read`. The matching nonpaid
preflight actually exercised Join without it: the Join committed, then local
Endpoint key publication failed because its guarded WhoAmI could not verify the
current session. See `local_join_bridge.go:724`,
`local_sealed_send_bridge.go:349`, and `internal/control/groups.go:49`.

To proceed, the driver stopped its own labelled Hub and invoked the explicit
test-only `grant-group-directory` helper. It validated the current synthetic
Owner signer/trust root, owned Network/Group, Endpoint Node and Principal Owner,
exact active membership ID/version, and exact production Monitor grants/role.
Store CAS added only `directory.read`, changing membership v2 to v3; it added
no message, history, delegation, or approval authority. The helper and its
signer were never mounted into the Node. This is an explicit fixture setup
operation, **not a production Client permission-grant flow**.

The ensuing Group Join reused the same Endpoint/native Thread and created
Group binding `bind_068af29e4f244ead`, epoch 1, status `leased`, on
`node_native_monitor_a9b6e9bbc5ba25dd`. The separate Network native binding stayed
`active` on that same Node and UUID. The proposal's Principal, Endpoint, Group,
binding ID/epoch and Hub were checked against those current authoritative rows.

## Proposal authority and Fabric isolation

The model proposed `SET_PARENT` from `grp_bc67c0abaf05d365` to
`grp_b620d24fd4d2bb50` within `net_61b0b89b22b962e2`, with fresh source/target
versions both 1. Proposal `rgrp_8f9dac5592e2cac2` remained `PROPOSED`. Encrypted
Owner readback exactly matched the native tool result, and a second topology
snapshot left both Group records unchanged. The delegation table was empty.
No successful delegation issuance or regroup application occurred.

A subsequent non-model MCP `cicada_regroup_apply` call against that current
Monitor used the deliberately fake delegation ID
`synthetic-forged-user-approval` and was rejected. Thus
`delegation_issue_or_apply_called=false` in the summary means no authorized
successful apply/issuance; the negative apply attempt **was called**. The
matching preflight also rejected a `user_approved:true` spoof in proposal
arguments. Neither test supplies a real Approval.

During native tools and negative Guard probes the Hub used production
`serve --fabric-only` and the Node used `machine agent --relay-only`.
Authenticated `/v1/machines` returned 503, while the Node's outbound SSE
returned 200 and `event: ready`. Management mode was used separately for
encrypted Owner setup/readback; each restart preserved the same fixture state,
identity and Hub image. `serve_fabric.go` constructs this restricted service
without Control business startup. This supports the tested proposal path's
business independence; this gate sent no successful peer messages and makes
no new Ask/Reply, relay-blindness or zero-relay business claim.

## Checks and retained failures

The earlier actual M4 attach-3 Group Join remains **FAIL** in
[the transport/recovery checkpoint record](v01-transport-recovery-checkpoint-validation.md).
Its same-UUID seed/resume observation did not yield an Endpoint/proposal or
complete post-Join context evidence. Its separate Android emulator pairing
result and historical paid failures retain their original source and results.
The bounded Network-first run here does not retroactively convert those failed
attempts or their APKs to passes.

The historical-source review ran these deterministic checks, with no provider access:

- `python3 -m unittest discover -s scripts -p test_native_network_monitor_driver.py -v`:
  exit 0, nine tests passed (exact tool/error oracles and independent epochs).
- Pinned `golang:1.27.1-bookworm` container, `--network none`, read-only source
  and module-cache mounts, `GOPROXY=off`, `CGO_ENABLED=0`:
  `go test ./cmd/cicada-native-network-fixture -count=1 -v`, exit 0, three tests
  passed (bootstrap nonreplacement/no Endpoint, private input boundaries,
  wrong Endpoint/member and stale/repeated CAS rejection with minimal grant).
- `scripts/build-hub-image.sh --source-info-only`: exit 0 and the exact tested
  source fingerprint above. Review also re-parsed the saved native logs and
  compared executed driver hashes without invoking Codex.

All local Monitor receipts remain retained. Early receipts lacking an explicit
terminal/model counter retain those fields as absent; no values were invented.

| Directory suffix | Result | Recorded failure phase/class |
|---|---|---|
| `preflight-1` | FAIL | `offline_frozen_source_build` / `command_exit_1` |
| `preflight-2`, `preflight-3` | FAIL | `isolated_nodes` / `command_exit_1` |
| `preflight-4` | FAIL | `owned_fabric_only_hub` / `command_exit_1` |
| `preflight-5` | FAIL | `owned_hub_mode_management` / `command_exit_1` |
| `preflight-6`, `preflight-7` | FAIL | `synthetic_native_record_full_preflight` / `actual_mcp_tool_unexpected_result_cicada_network_join` |
| `preflight-8` | FAIL | `synthetic_native_record_full_preflight` / `actual_mcp_tool_unexpected_result_cicada_send` |
| `preflight-9` | FAIL | `owned_hub_mode_fabric` / `actual_mcp_tool_unexpected_result_cicada_join` |
| `preflight-10`, `preflight-11` | PREFLIGHT_PASS_NATIVE_NOT_RUN | Model calls 0; terminal 0; cleanup true |
| `real-1` | NATIVE_NETWORK_MONITOR_PROPOSAL_PASS | Model calls 3; terminal 0; cleanup true |

These names have prefix `native-network-monitor-`. Each receipt preserves its
own script/source attribution; only `preflight-11` is the exact matching
preflight cited by `real-1`. Older failures are not passes and are not evidence
against unrelated later snapshots. The frozen delivery manifest hashes their
existing files without copying private contents into the patch.

## Reproduction and next exit condition

For a future explicitly authorized disposable preflight, the entry point is:

```sh
python3 scripts/test-native-network-monitor.py --result-dir /absolute/new/private/result-dir
```

It requires the existing shared `test-two-node-codex-native.py` driver, pinned
locally available Go/Hub/runtime images and offline Go caches. The default
preflight has no provider mount/model call and uses a visibly synthetic native
session record. Paid execution additionally requires `--run-native` and
`--preflight-result` from an exact matching successful snapshot; it is limited
to three attempted CLI turns and terminates after a failed attempt. No paid
rerun was performed during this review.

The next checkpoint must reconcile combined deterministic and disposable interop
gates against the exact final integrated source. Own Join does not require a
general Group directory grant after the self-identity repair. The missing
general encrypted Group-grant operation remains a separate Client-contract
capability gap for explicitly requested broader permissions; do not widen
Monitor or member role grants to substitute for it. Any future current-source
native Runtime run requires separate authorization and fresh matching nonpaid
preflight attribution. Proposal-only evidence does not establish delegated
execution or topology application.

Android UI, real Android device, a second physical Node, public HTTPS, busy
foreground wake, peer Ask/Reply, delegated topology execution, and fault-window
recovery are **NOT_RUN in this gate**. Runtime queue consumption is
`CONSUMPTION_UNCONFIRMED`; no Group messages were sent. All successful native
observations are limited to this one Docker Node on one trusted physical host.
