# v0.1 recovery / Hub panel checkpoint validation

Status: **PASS — bounded backend recovery/panel checkpoint** (2026-10-01). C4 full Go, vet, contract/Python, three disposable Docker suites and complete Browser gate passed within the scope below. This is a dirty-source validation; clean checkpoint/delivery metadata is a separate later artifact. This record preserves bounded diagnostics; it does not declare v0.1 or architecture v2 complete.

The checkpoint covers Node provider generation/intent and recovery fences, least-privilege Network native-binding registration, truthful topology context-policy projection, and implemented Hub canvas pointer/keyboard interactions with encrypted Client request recovery. Provider retry classifications do not imply that native structured throttle/backoff has been enabled. Canvas changes correct the visible box-selection rectangle under pan/zoom and add Enter/Space selection and Escape cancellation. Browser fixtures exercise Group admission, inactive Link proposal, Monitor role and its separately authorized broadcast permission. They must use the encrypted Owner device session and existing Guard; layout gestures never confer authority. No SQL identity/approval/role seeding, extra implicit Network grants, Client edits, model calls, resident deployments, key rotation, push or release are part of this work. Contract remains v1.6 / wire 1 / catalog 55; there is no version upgrade.

## Diagnostic candidate C provenance

The retained initial candidate is the dirty f4-based snapshot at `.cicada-data/next-checkpoint/closure-20261001T143705Z/source`; its `hub-build.json` records:

| Item | Exact identity |
|---|---|
| HEAD (dirty build, not sole source identity) | `f4e4725c5d81c54b166f4291b9d450c70954e6df` |
| Source fingerprint | `d205771bee22a79ec2c55e47f733d2b46e533c582e3c108e35b4c60c3c0cf0bb` |
| Hub reference | `cicada:closure-20261001T143705Z` |
| Local Hub image ID | `sha256:cf83c079556badafb499055bb3ea2162701ba17873402b8a4b804bcdfeb13643` |
| Build metadata SHA-256 | `a8ffab55a76ba98770506dc4938507e4f8f5c9ecc22de161dc0e40242d8f9dd4` |
| Chromium manifest pin | `chromedp/headless-shell@sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04` |
| Driver runtime | Node `24.16.0` |

The original snapshot driver SHA-256 is `691221f3ec42ccbbc3c611ae5a7c87429446c213c87754947ee326e3bc9743d5`. Subsequent driver-only diagnostics use the same exact Hub image, but their own hashes recorded in each result; they are not the original snapshot-driver result.

All attempts are under `.cicada-data/next-checkpoint/closure-20261001T143705Z/browser-attempt-N/result.json` with private 0600 logs/results. Attempts 1–9 remain distinct, including failures and the interrupted run. Their overall status is FAIL; none is replaced by a later PASS.

- Attempt 1: the earlier encrypted browser steps passed, then synthetic Node setup failed on host fetch. A separate disposable zero-model diagnostic proved Docker's dynamically published Hub port changed after stop/start; the driver now refreshes it.
- Attempts 2–5: retained pointer diagnostics exposed clipped references and incorrect CDP drag-button semantics. Attempt 6 proved the full box geometry and Enter selection, then timed out in the next interaction. These are driver diagnostics, not complete interaction acceptance.
- Attempt 7: directory-only signed Network Join reached Group admission, whose real encrypted preview returned `network permission denied`. Existing admission required a native binding, while the registration path required a Network transport-purpose grant. This denial remains evidence; Guard was not relaxed by the browser driver.
- Attempt 8: an explicitly signed disposable extra-scope branch reached native-binding protocol registration, then was terminated when Root paused the scope change for review. All cleanup passed. This is not admission or native-authority acceptance, and the current fixture has returned to directory-only grants.
- Attempt 9: both independent recovery steps passed as described below. The later canvas box-selection phase failed because the added Groups placed its targets outside the default small browser viewport. Overall gate remains FAIL.

The Node adapter labels are visibly synthetic. Actual Node PQ Owner pairing, signed consent and Hub protocol checks do not prove a real Codex Join, native Session identity or native candidate authority. Native verification is separately NOT_RUN. Every diagnostic attempt recorded Node/Hub/Chromium/network/private-state cleanup PASS and model calls 0.

## Attempt 9: bounded recovery PASS

Exact driver SHA-256: `3e44e9c19067460f9c4121b212dfbe38bde560733cdb9510d87e1568c6d8941f`; Hub source/image remain candidate C above.

`response_loss_exact_recovery=PASS`: CDP dropped a real successful Hub response to an encrypted Group write. IndexedDB retained the exact original ciphertext/operation/sequences. A single `/v2/client/rpc/recover` call recovered the completed response; exactly one Group remained and no replacement management write was issued.

`uncertain_write_fence=PASS`: after a second real response loss, the driver stopped only its owned Hub and changed only that run's exact completed request row to a durable interrupted state. Original ciphertext digest, request sequence, response reservation, identities, grants and counters were preserved. Hub restart and authentic recovery produced uncertainty; pending transport resolved while its semantic write fence persisted across reload/unlock and a second tab. Both tabs refused replacement writes. Two fresh encrypted snapshots preserved the fence until an explicit confirmation bound to the original operation authorized later work; confirmation did not replay the write, and the original Group remained unique.

**This is controlled durable-state injection, not proof of a real kill-window crash.** The fence tested here is the topology semantic-review fence. It is not permission to release the dedicated Network grant uncertainty fence using snapshots or an unrelated acknowledgement. No status or receipt was forged to make the result pass.

## Production corrections and C3 retained failure

Directory-only current Network membership can now register its own existing native binding without a transport-purpose grant. The shared Store guard still checks current membership/session/Endpoint/Node/Owner identity; actual traffic/key actions retain their exact grant checks. Group admission still requires Owner/group.manage and creates only member authority, no keys, history or broadcast grant. PG's five-file proof is `.cicada-data/next-checkpoint/network-member-binding-20261001/result.json`, file-set fingerprint `65ab2a5b67a6556efb1228b3ca7516e1be68d63b8348d08c2b21ca8bbbd2a43a`: focused Store cases and race passed; the actual nil-Control HTTP production route `TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials` and its race passed. The original broader 5-minute Store race timeout remains a non-PASS history entry. This focused file-set identity is not a whole-source fingerprint.

C2 `.cicada-data/next-checkpoint/closure-20261001T161032Z/source` retained a compile failure from an undefined test fixture `ledgerPath`; corrected later source does not turn C2 into PASS. C3 source `5b8f151377455ded03a5b71113528c51c3c1e2363855bad0d4e59ce517b9ebf3`, Hub image `sha256:cbf57db3f960ff752ae93832ddf50dcc0636469e7cb9b453d3459d9cefda9546`, and snapshot driver `6194502fd8df82514f4e77a2626620f3faa39949d7fec3b7b77e3cd69376a797` recorded Browser FAIL in `closure-20261001T161902Z/browser-final-1/result.json`. Recovery, directory-only registration and keyboard steps passed, but admission preview was rejected by the UI.

The two separate C3 diagnostic runs remain FAIL. Diagnostic 2 used driver `8e01a4a8e3a4247503d9355c392596b710e6ee260dcab38f96450a2cf1c6dfd5`, verified actual pointer target hits, and recorded only safe comparison booleans/enums. The sole failed preview comparison was context policy: `BuildClientTopologySnapshot` omitted the persisted Group `ContextPolicy`, while the authentic admission preview included it. Core corrected the snapshot projection and regression tests; strict UI/Guard checks were not weakened. All C3 Browser cleanup passed.

## C4 complete Browser PASS

Frozen source: `.cicada-data/next-checkpoint/closure-20261001T165647Z/source`, dirty f4-based fingerprint `31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2`. Contract/wire/catalog remain v1.6/1/55. Exact local Hub image: `sha256:c104b7bcce16389543f62000a7e399dfe8aab33e288de940cba2f92486a77626`, reference `cicada:closure-20261001T165647Z`. Build metadata SHA-256: `0f27cf16f5d02dc60d8350b44473d9fada842ac8dc44eef5bf19d7fc28cd9b11`.

Frozen browser driver SHA-256: `57f8a069e375883270ca63c8828f81b58567fb0c16007bd767380c32a4583668`. UI and deterministic test hashes remain `d1a15d7c31bb89f2a573899d2f0fe745a3bd26f0af9ed62933fc49396551777d` (`panel-canvas.js`) and `8c0d4d47c444b6529468c89588f4c6763cd9a7601835d8cdab7e729a72131ad3` (`test-web-panel.mjs`). Syntax, deterministic Web/model + existing Go WASM PQ/Wire checks, and whitespace checks passed; these do not substitute for Browser acceptance.

The exact frozen-snapshot command used Node `/home/zyf/.nvm/versions/node/v24.16.0/bin/node`:

```sh
CICADA_HUB_IMAGE=cicada:closure-20261001T165647Z \
CICADA_BUILD_METADATA=/home/zyf/CICADA/.cicada-data/next-checkpoint/closure-20261001T165647Z/hub-build.json \
CICADA_EXPECT_SOURCE_FINGERPRINT=31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2 \
CICADA_CHROMIUM_IMAGE=chromedp/headless-shell@sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04 \
CICADA_BROWSER_RESULT_DIR=/home/zyf/CICADA/.cicada-data/next-checkpoint/closure-20261001T165647Z/browser-final-1 \
/home/zyf/.nvm/versions/node/v24.16.0/bin/node scripts/test-hub-web-panel-browser.mjs
```

Working directory was the C4 source above. Exit `0`, 29.755 s, all 12 required steps PASS. Evidence: `closure-20261001T165647Z/browser-final-1/result.json`, SHA-256 `bac1721fdc02b625ce5d149ffa5e42fae0494e0a72556de06b31bd437f7e4ec4` (0600, adjacent private log).

The 1440×1000 desktop run used product zoom/pan and actual pointer hit checks. Both synthetic protocol Endpoints were admitted through real encrypted preview/confirm; box geometry, Enter selection, modified Space toggle and Escape cancellation passed without gesture management writes. Pointer Link review produced one exact inactive `PROPOSED` Link. Monitor role persisted with broadcast disabled, followed by a separately confirmed broadcast grant with a new CAS version. Real response loss/exact recovery and the controlled durable-state uncertainty/reload/cross-tab/explicit review checks all passed with the limitations above.

The adapter performed actual Node PQ Owner confirmation and directory-only signed Network Join/native-binding protocol registration; `native_session_verification=NOT_RUN`, model calls `0`. Owned Node, Hub, Chromium, network and private fixture directory cleanup were all true/PASS. No shared deployment was used. Full Go, three disposable Docker suites and auxiliary checks passed as recorded below; clean checkpoint/delivery metadata remains separate. Physical dual-Node, public HTTPS and native current-authority are not claimed.

## C4 final source gates

On the same frozen `31dccec5…` source, `full-go-exit.json` records `go test -buildvcs=false -json -count=1 -timeout 15m ./...` in pinned Go 1.27.1, networking disabled and source mounted read-only: exit 0. Independent JSON event counting of `full-go.jsonl` confirms **27 packages, 1,105 top-level + 553 subtests PASS, 12 top-level SKIP, 0 FAIL**. A skip is not a pass. `vet-exit.json`, `contract-exit.json`, `python-exit.json` and `hub-build-exit.json` record exit 0; the Python suite has 26 tests. Contract remains v1.6/wire 1/55 operations, catalog `1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`.

Each Docker suite passed with its own built Hub image and real disposable TCP protocol client; none uses the Browser's `c104…` image ID. Evidence paths below are relative to `.cicada-data/next-checkpoint/closure-20261001T165647Z/` and all build metadata records the same `31dc…` source.

| Suite / result | Exact local Hub image ID | Result |
|---|---|---|
| `client-interop/result.json` | `sha256:03111ee0d1688d5ab80ea3f7db84da1582450224ac288f3cacef86a1f165e620` | PASS, exit 0; Smoke + Recovery fixtures |
| `network-m1-interop/result.json` | `sha256:8525089912c6f8b566d72901afa03a47b97f7482b080024f0ca88d6f489a41ff` | PASS, exit 0; Network/direct control-free protocol scope |
| `group-spaces-m2-interop/result.json` | `sha256:9818dbbb24554f0ed1d3b9f1e26d93a5f5851f2db7a83d67c8a5adf7f4883f71` | PASS, exit 0; Group spaces + HTTP history/topic CAS |

Docker fixtures use synthetic native sessions and do not establish real native runtime, Android, physical Nodes or public HTTPS. Browser recovery is bounded as stated above. Wider v0.1/v2 completion, native autonomous wake, provider structured throttle enablement and pure PQ TLS are not claimed.

## Independent old clean Client evidence

[Client v1.6 f4 validation](../../CICADA_CLIENT/docs/client-hub-v1.6-f4e4725-validation.md) reports bounded Android/Kotlin/encrypted interoperability on the old clean f4 Hub (`c3d22f3d…`, local image `6a7e0af7…`). It is independent evidence, with its own Client source/APK/bundle pins and remaining operation gates. Client delivery commit `9cf2b81c256b6a3f17681f28993e7857726e2121` is clean; Root verified the 17 receipt/APK hashes and built-source match to its filtered 102-file committed source. Delivery receipt: `/gpu1-share/data/cicada-client/v16-f4e4725-20261001/delivery.redacted.json`. A rebuild from the final clean Client commit is NOT_RUN; 20 Client operations remain closed. It is not transferred to candidate C or the future final recovery/panel candidate. Earlier native ASK/REPLY, broadcast and Worker results likewise retain their own tested sources in the [previous checkpoint report](v01-completion-checkpoint-validation.md).
