# Independent two-Hub Docker transport validation

This finite gate complements `scripts/test-multi-hub-services.sh`, whose production handlers run in one Go process. It changes no production API, protocol, cryptography, dependency or Node runtime. The independent checkout starts detached at clean `25bc586232db43362c6e03eccef1fa3a0dbec8ee`; its fixture source is dirty and has its own full byte/raw-mode inventory, including checkout modes that can differ from Main.

Run the existing production image and a separately attributed test helper:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-multi-hub-docker.py \
  --evidence .cicada-data/multihub-docker-25bc586-20261002/run-01 \
  --hub-image sha256:41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4 \
  --go-image sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 \
  --module-cache /home/zyf/CICADA/.cicada-data/m1-gomodcache
```

The driver compiles only a synthetic `cmd/cicada` test helper using pinned Go 1.27.1, an offline read-only module cache, a private cache and read-only fixture source. It extracts `/usr/local/bin/cicada` from the exact clean Hub image and hashes both binaries separately. The production Agent executes the extracted shipped binary, not the test helper binary. Hub standard source fingerprint `4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032`, the fixture full-source fingerprint, Git revision and binary SHA-256 are distinct. Software `0.1.0-dev`, contract `client-hub-v1.6.4`, wire 1 and the 55-operation catalog are separate version domains.

Two independent production Hub containers have separate SQLite stores, Hub identities, Owners, device grants and approved Node credentials. One physical Node container runs a fixture observer and a separate production `machine agent --hubs-file /node/hubs.json --state-root /node/state --relay-only --interval 1s` process. Its two workers share the WriterRoot and initialized admission/native-context ledgers, while their Node identities, Owner trust, inboxes and replay-bearing state remain in independent per-Hub directories. Explicit synthetic bootstrap is test preparation; it is not evidence of Android Owner confirmation or Endpoint Join.

Two observing loopback reverse proxies each forward only to their own Hub over an internal Docker network. The Agent remains pinned to two separate origins. Observers retain only successful heartbeat/claim counts, SSE status/content type and a boolean/count for the exact bounded `ready` frame; they do not retain request headers, tokens, message bodies or model output. Guarded claims are **empty reconciliation requests**, not message delivery, injection, model consumption or business acceptance receipts. No Hub forwards to another Hub.

Finite acceptance checks are actual SSE ready frames and owner-bound heartbeat/empty-claim traffic to both Hubs; eight HTTP denials for foreign-Hub credentials, a different Owner's valid Node credential at the selected Node path, the wrong Node path and management bearer use at Node routes; continued Hub B heartbeat/claim traffic while only Hub A is stopped; Hub A reconnection after restart; and a new production Node process with unchanged per-Hub identity/token bytes/raw modes and Owner-trust/replay/outbox/sequence counts. This checks transport isolation and restart continuity with no messages injected. It does not prove serialized native Thread writes.

Every command has an actual argv, exit, bounded timeout and retained output hashes/logs after checking them against synthetic fixture credentials. The driver labels all created Docker resources, checks ownership before removal, discovers resources even after a client timeout, and reports cleanup failure. Private fixture trees are removed in `finally`; filesystem failure is reported rather than hidden. Fixtures and outputs are under the supplied new ignored checkout-local evidence directory. Source inventories and Main read-only inventory/index/HEAD/status are compared before and after; no Main, Client, global configuration, resident deployment or real credential is modified. The static helper regression checks unowned roots, colliding coordinates and nonprivate credentials. Its passing result does not substitute for the real Docker gate.

Actual results, exact source/binary/image identities and limits are authoritative in the fresh run's `receipt.json`, `commands.json`, source inventories and bounded logs. A failed attempt remains attributed to its original source and is not overwritten; skips are not passes. The document is frozen before execution, so runtime evidence does not acquire a later documentation fingerprint.

Endpoint Join, ACTIVE Network scope, sealed SEND/ASK/REPLY payload delivery, lost replies, injection uncertainty, native Runtime/Codex queue consumption, model/provider calls, Android, physical devices and public HTTPS are **NOT_RUN** in this finite gate. They retain their existing independent evidence or remaining gaps. Transport acceptance alone does not authorize closed Client operations or claim overall product completion.
