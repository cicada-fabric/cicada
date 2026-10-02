# Exact delivered-image native Monitor acceptance

The explicit `--exact-clean-image-metadata` mode uses a delivered standard Hub
image by immutable ID. Supply its producer receipt and independently recorded
full receipt SHA-256. The driver rejects dirty/nonstandard metadata, shortened
revision/image IDs, mismatched complete input inventory/catalog, image labels,
and actual Hub health provenance. It permits a separately recorded driver-only
worktree overlay when the complete production build inputs and HEAD match the
clean producer; it does not label that worktree itself clean.

The Hub image is neither rebuilt nor overlaid. A stopped, owned extraction
container supplies `/usr/local/bin/cicada` for the Node; the regular executable's
SHA-256 is recorded. Only the synthetic fixture operator is compiled from the
matching sources, with its own Go image and binary hash. Cleanup may remove
verified owned containers and fixture resources, never the delivered image.
The default mode remains `derived-source-fixture`; its rebuilt, dirty fixture
binary is not acceptance of an unchanged delivered image.

After freezing producer, code inputs, driver, helper, runtime and image, run a
fresh nonpaid preflight with new private evidence paths. The historical
`397ff47b…` preflight belongs to `fb8f0d8b…` and cannot qualify a new checkpoint.
Use the existing UID and keep private Codex directories/config at 0700/0600.
No credential is mounted in the preflight. `<STD_METADATA_SHA256>` is the hash
of the complete producer JSON, not its source fingerprint or image ID.

```sh
python3 scripts/test-native-network-monitor.py \
  --exact-clean-image-metadata <STD_PRODUCER_JSON> \
  --exact-clean-image-metadata-sha256 <STD_METADATA_SHA256> \
  --result-dir <NEW_PREFLIGHT_DIR>
```

Only a successful, cleaned-up, unchanged-source zero-model preflight can qualify
the opt-in native invocation. It binds the exact mode, complete source inputs,
both drivers, extracted binary, operator binary, Go/runtime image IDs, delivered
Hub image ID and producer receipt hash. Once the Supervisor authorizes the paid
run, use a distinct new result directory:

```sh
python3 scripts/test-native-network-monitor.py \
  --exact-clean-image-metadata <SAME_STD_PRODUCER_JSON> \
  --exact-clean-image-metadata-sha256 <SAME_STD_METADATA_SHA256> \
  --preflight-result <NEW_PREFLIGHT_DIR>/result.json \
  --credential-file /gpu1-share/data/cicada/secrets/cicada.env \
  --run-native --result-dir <NEW_NATIVE_DIR>
```

The pinned runtime image is
`sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57`;
it must report Codex CLI 0.159.3. The model is `gpt-5.6-luna`. There are at most
three CLI turn attempts, with no driver retry after a failure or timeout: original
context witness, same-Thread explicit Network Join, then same-Thread Group Join
and durable Monitor proposal with the remembered witness. Three attempts is not
a token, monetary or provider HTTP request cap. Credential content is used only
inside the disposable Node, from its read-only regular 0600 file; it is not
mounted to the Hub or included in evidence.

The synthetic Owner fixture performs explicit encrypted admission and Monitor
role CAS; this is not a real user's approval. Network grants remain
`directory.discover`/`directory.publish`. Group admission starts with zero grants;
the Monitor has its four role grants and no `directory.read`, peer traffic,
history or Owner Endpoint key consent. Business phases use `--fabric-only` and
assert authenticated management HTTP 503; Owner setup/readback uses separate
management phases preserving fixture identity/state. The proposal stays
`PROPOSED`, with no successful apply/delegation. Detailed peer/self denial probes
belong to the matching nonpaid preflight, not additional model turns.

No peer Group messages are sent: `CONSUMPTION_UNCONFIRMED` remains accurate.
This proposal gate does not prove peer ASK/REPLY consumption, busy wake, physical
Nodes, Android, PQ transport or public HTTPS. Every actual result must retain its
producer/source/image/binary/driver attribution; a skip or attempted turn is not
a pass or a counted provider billing event.

## Bounded exact-image Monitor execution on 2026-10-02

The Supervisor executed one paid run after matching nonpaid receipt `31b5f091…`.
Actual result `0ef56fa9cbfb102bf2c3c2785d1e48d8e109e34c7f0227e114c63eb4a2dbb9fd`
reports `NATIVE_NETWORK_MONITOR_PROPOSAL_PASS`, terminal 0, three CLI turn
attempts, unchanged source and owned-resource cleanup true. The receipt is at
`/home/zyf/CICADA_native_acceptance_144e079/.cicada-data/native-exact-144e079-native-20261002/result.json`.

This execution belongs to clean producer `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c`,
source `e64f244961d56265933dd75feec19d2b74fa934533abf9b750c061f09094a902`,
Hub image `sha256:04e8bcb4e22f4a00100b30a57d8cd5b3c65d5d4abe3d09844f5c121c26beb1bb`
and extracted binary `8a983dc9da33000021b5c79fac36661abfafdb180f8d08699ebec3fb3261c7e3`.
Executed Monitor driver SHA was
`91debc3867d73b19288690008d6d370ca80d35a77d9748637adeee0485a668bb`;
shared two-node driver SHA was
`2979b54616ebd1aa9533a01b3b1629e3db73261a815b71b5117db4eb81896f86`.
Later driver changes remain separate evidence and require their own preparation.

All three turn records identify original Thread
`01a0fa4a-b44c-7e10-a099-bf200869fab5`; original context witnesses passed in the
seed and final resumed turn. The same Endpoint `ep_da77417c7c23877f` retained
Network binding `native_d8bed58ce857b241` and Group binding
`bind_bf691d14a461eb8f`, epoch 1, on Node
`node_native_monitor_ac75b0ef4025438d`. Proposal `rgrp_491d5e4725f53b87` stayed
`PROPOSED`, exact producer-bound; fake-delegation apply was denied.

Three explicit Owner management phases alternated with three fabric-only
business phases, preserving fixture Hub identity/database. Business management
probe returned authenticated HTTP 503. This proves bounded original-Thread
Join/proposal/context continuity with a synthetic explicit Owner, not peer
ASK/REPLY consumption or real-user approval. No Group messages were sent;
`CONSUMPTION_UNCONFIRMED`, busy wake, physical Nodes, Android, PQ transport and
public HTTPS remain outside this execution.

## Exact delivered Hub and interop pair for two original Threads

`test-two-node-codex-native.py` accepts the same pinned producer metadata through
`--exact-clean-image-metadata` and `--exact-clean-image-metadata-sha256`.
The producer must name distinct immutable standard Hub and interop IDs. Both
images must match the clean full revision, source fingerprint and catalog labels;
actual interop Go must report 1.27.1. Shared `native_image_evidence.py` performs
these checks and owns only a stopped binary-extraction container. The Node binary
comes from the delivered Hub image. Only the existing visibly synthetic V68
Owner fixture is compiled inside the delivered interop source snapshot; neither
Hub nor Node application binary is rebuilt. Shared delivered images are never
cleanup-owned. Fixture bootstrap and Endpoint key consent are synthetic test
Owner authority, not a real user's approval or a Client acceptance result.

```sh
python3 scripts/test-two-node-codex-native.py \
  --exact-clean-image-metadata <STD_PRODUCER_JSON> \
  --exact-clean-image-metadata-sha256 <STD_METADATA_SHA256> \
  --result-dir <NEW_TWO_NODE_PREPARATION_DIR>
```

`PREPARATION_PASS_NATIVE_NOT_RUN` means zero-model image/input/binary/runtime
preparation only. It does not execute Group Join, peer traffic, sealed protocol
or original-Thread context assertions and must not be called a full protocol
preflight. Paid mode requires `--preparation-result` with its matching successful,
cleaned-up, unchanged-source receipt. It binds both images, current code inputs,
driver/shared verification helper, extracted binary, fixture binary and runtime.
All these inputs must remain frozen throughout the Supervisor's paid invocation:

```sh
python3 scripts/test-two-node-codex-native.py \
  --exact-clean-image-metadata <SAME_STD_PRODUCER_JSON> \
  --exact-clean-image-metadata-sha256 <SAME_STD_METADATA_SHA256> \
  --preparation-result <NEW_TWO_NODE_PREPARATION_DIR>/result.json \
  --credential-file /gpu1-share/data/cicada/secrets/cicada.env \
  --run-native --result-dir <NEW_TWO_NODE_NATIVE_DIR>
```

The bounded flow has seven CLI attempts: two original context seeds, two
original-Thread Group Joins, an offline sealed ASK, original recipient
receive/reply/context, and original sender receive/context. No automatic driver
retry follows a failed or timed-out turn. Seven CLI attempts does not cap
underlying provider requests, tokens or billing. Existing `--fabric-only`
management HTTP 503 and zero peer Control business calls remain asserted;
peer business uses Node/Fabric authority. A successful execution proves only
its exact original bindings, sealed ASK/REPLY oracle and controlled safe-point
receipt/context witnesses. Busy/asynchronous wake, general foreground/uncertain
consumption, physical dual Nodes, Android, PQ transport and public HTTPS remain
separate. The default rebuilding mode is explicitly `rebuilt-two-node-fixture`.
