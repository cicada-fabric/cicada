# Clean Core 0213538 delivery provenance

## Scope

On 2026-10-03 the Client independently reviewed the newly delivered clean Core
package, immutable Git build inputs and Docker image metadata. This is a
**read-only provenance check**. No new Hub or emulator was started, no Owner
signature was created and no Android business RPC was sent. The prior dd81575
and F9 evidence is retained unchanged.

| Input | Independently checked value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / operations | `client-hub-v1.6.4` / `1` / `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Source dirty | `false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interop image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Build metadata SHA-256 | `b3b46fc7fc0a2f2be515f27bf819602924794b22c08f663817fb1f3030a3e51f` |

The source artifact directory is
`/home/zyf/CICADA/.cicada-data/v01-finish-20261002/clean-0213538-delivery-20261003`.
The archive is its `client-contract-bundle/client-hub-03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709.tar.gz`.
Only full immutable image IDs were inspected.

## Actual command and results

Let `E=/gpu1-share/data/cicada-client/v164-bounded-launcher-offline-20261003`.

```bash
python3 "$E/verify-clean-delivery.private.py"
```

Actual exit: **0**. Script SHA-256:
`be25d46989eeb5d6e05aecf31ba7a9f1f382581742c460dabe823ee686156cdc`.
The original output is `E/clean-0213538-review.redacted.json`; the command and
exit receipt is `E/clean-0213538-command.redacted.json`. Final Client commit and
receipt hashes are bound in `E/launcher-delivery.redacted.json` after commit.

| Gate | Result and boundary |
|---|---|
| Archive SHA, manifest commit, clean flag, contract and catalog | **PASS** |
| Exact tar member set and all 24 payload sizes/SHA-256 values | **PASS**; no extraction or executable bundle code |
| Immutable Git build inputs | **PASS**, 896 blobs read from the fixed commit; content hashes and original-byte paths match inventory |
| Source fingerprint v4 reproduction | **PASS**, computed independently from Git blob bytes and the declared raw modes |
| Actual image IDs and revision/clean/fingerprint/catalog OCI labels | **PASS**, read-only image inspection |
| Docker data root | **PASS**, `/gpu1-share/data/docker-root` |
| Image execution, baked source inspection, encrypted Android capabilities | **NOT_RUN** by this Client review |
| Fresh Android consent/Link flow, native Worker/model | **NOT_RUN** |
| Physical Android, public HTTPS | **NOT_RUN** |

Core's separate producer smoke/recovery result does not count as Client Android
acceptance. The [bounded launcher](client-bounded-acceptance-launcher.md) binds
these six Core values in an independently approved bootstrap target and requires
the fresh Scope to match them. Client source/APK/emulator provenance is separate.
A new runtime needs fresh adapters, actual Android READY, fresh Core references
and a separate Root BOOT/business authorization. No old F9 nonce may be reused.
