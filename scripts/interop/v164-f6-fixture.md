# Fresh v1.6.4 F6 fixture adapter

## Scope

This adapter prepares an isolated Android acceptance run against either the fixed clean Core `25bc586232db43362c6e03eccef1fa3a0dbec8ee` or a separately verified clean `dd81575b160aa901b642137e54d7a60961e4bd68` delivery. It changes test configuration only. Product TypeScript, Native/Kotlin, protocol snapshots and APKs are unchanged.

The frozen application and instrumentation SHA-256 values are respectively:

- `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67`
- `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`

The v1.6.4 catalog, wire, OpenAPI and two public Link evidence vectors are byte-identical between these Core Git commits. The application pins protocol/catalog and independently confirmed Hub identity, rather than a compiled Docker image or Core commit. That supports binary reuse planning; new-image interoperability is **NOT_RUN** until actually verified.

## Trusted inputs

`v164-link-fixture-pins.py` defines two internal test documents, not Hub API schemas:

| Document | Fields and trust source |
|---|---|
| Root trust envelope (`cicada.client-v164-f6-root-pins.v1`) | `scope=fresh-F6`, exact `fixture_root`, local delivery metadata digest, complete `core` and `images`, exact `fixture` file digests/Hub ID/port/label. Caller supplies its raw-byte SHA-256 through an independent trusted channel. File must be owned, regular, mode 0600 and not symlinked. |
| Local normalized clean-delivery metadata (`cicada.client-v164-local-delivery.v1`) | Exact authorized Core revision, `source_dirty=false`, source fingerprint, producer and package digests, full immutable Hub/interop image IDs, protocol/catalog/wire/schema/operation count. Its complete bytes must match both the Root envelope and the separately supplied metadata SHA-256. |

Generate normalized metadata only after independently checking the **real** archive manifest/payload/source cleanliness, full Core commit, producer receipt, complete source inventory and actual image IDs/labels. The parser compares those already verified facts and bytes; it does not itself reconstruct the source inventory or certify a build. No new image, package or source fingerprint has been supplied for this preparation record. Tests use explicitly synthetic values and establish no delivery acceptance.

Fixed compatibility values remain `client-hub-v1.6.4`, wire 1, schema 57, 55 operations and catalog SHA-256 `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`. Missing fields, duplicate JSON keys, boolean/float numeric coercion, changed hashes, dirty/unlisted sources, mismatched images, wrong permissions/symlinks and F5 scope reuse are rejected.

The Root-pinned fixture path must be inside `/gpu1-share/data/cicada-client/v164-<selected seven-character commit prefix>-.../fixture-f6` and use label `client-link-v164-06`. Core owns fixture creation. READY must prove zero preceding Android operations/signatures and bind exact setup/reference/owned-manifest hashes. Carrier retains selected-field checks for Docker IDs, images/labels, mounts, user, loopback port, network membership and ownership. Neither READY nor a Hub response selects a trust pin.

## Command interfaces

The deterministic runner and every Link stage/selector/export action require all five F6 arguments together:

```text
--delivery-pins <absolute Root-envelope file>
--delivery-pins-sha256 <independently supplied full digest>
--delivery-metadata <absolute normalized verified-delivery file>
--delivery-metadata-sha256 <independently supplied full digest>
--fixture-root <exact Root-authorized fresh F6 root>
```

The opaque carrier calls the first two arguments `--root-pins` and `--root-pins-sha256`; its metadata and fixture arguments have the same meaning. F6 refuses mixed legacy per-file/Hub overrides. The historical no-argument F1-F5 paths retain their fixed pins.

Android evidence uses a completely new empty directory with a `v16-deterministic-v164-f6-...` parent run name. Start requires the frozen APK pair. Each later stage, selector, export, deterministic test or UI action rereads both pin documents and rechecks recorded metadata/APK hashes. The F6 matrix expects **49 tests**; historical 47-test results remain attached to their original APKs. Stop can still clean the exactly owned emulator without pin files.

Before any business request, capture four real emulator properties with individual commands, exits and redacted evidence: SDK, release, ABI and qemu. Expected cached-image values are 35 / 15 / x86_64 / 1, but none are reported as a new observation here. Keep the emulator network `none`.

## Execution gates and remaining requirements

Actual execution waits for newly verified delivery inputs, trusted fresh READY and explicit Root GO. No F5 proof, nonce, device/session state or pending packet is reused.

Use Source enrollment/fresh capabilities/full independent Owner pins, Source KEY and NONE review/sign/submit, then fresh Target enrollment/pins. The **first Target KEY** must go through `LinkConsentPhoneUiTest#actualReactNativeLinkConsentAlertUsesCurrentExternallySignedReview`: actual rendered review export, external signing, signed-proof paste, visible one-use `提交此授权？` / `明确授权` Alert and fresh bilateral status. Never submit Target KEY through the Native helper first. Complete Target NONE and verify the authoritative head and both complete proofs. Emulator automation is not physical or human confirmation.

The Native selector driver does not itself run that phone UI class or asynchronous signer exchange; a separately pinned fresh coordinator remains required. The carrier still permits only `fault=none`. Exact original-write response loss and 409/uncertainty scenarios therefore remain **BLOCKED/NOT_RUN** until a separately authorized safe opaque fault driver and outcome-specific receipts exist. A skipped recovery selector is never PASS. Keep the original signed packet/proof, operation ID and counters; recover through `/v2/client/rpc/recover`, without a new submit/nonce or guessed response sequence. Client never reads Hub DB or handles Node bearer/model credentials.

## Offline verification

Frozen-source Docker verification ran the following command with exit **0**, source unchanged, and **25 synthetic adapter tests PASS**:

```sh
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -B -m unittest discover -s scripts/interop \
  -p test_v164_link_fixture_pins.py -v
```

Receipt: `/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-adapter-check/receipt.redacted.json`, SHA-256 `3fc422494243b97d17f012f137b6cdb21b4be4e11b2f2087e61fe2ab38c6a99a`.

Source-only comparison receipt: `source-comparison.redacted.json` in that directory, SHA-256 `177ebea73260ae92116625cf9bf033fc83faa3d4e8da39dcc1390c030a16c3ef`. The detailed future execution order is in restricted `execution-plan.md`. The actual harness commit is bound after commit in restricted `adapter-delivery.redacted.json`.

Current fresh-image/READY interoperability, actual 49-test emulator execution, actual Alert, bilateral consent, fault recovery, native Worker/model, physical Android and public HTTPS are **NOT_RUN**. No Hub/emulator/RPC/signer/model operation was executed by this offline adapter check. F1-F5 receipts remain unchanged; this preparation is not an accepted release.
