# Hub web topology panel

The Hub web panel is a browser Client for owner-managed topology. It uses the existing Client Wire v1 packet format and the same Go `e2ee` ML-KEM-768, ML-DSA-65, and AES-256-GCM implementation used by other CICADA Clients. It does not use the legacy `/v1` bearer API.

## Trust and device enrollment

On first use, the browser displays the Hub ID and Control public key ID returned by `/v2/client/identity`. The browser does not trust that response on its own. Compare both identifiers with an independent operator source, then type them into the pin ceremony. A later identity change for the same origin stops the panel; it never replaces a saved pin automatically. Use a separate browser profile for a different Hub.

The browser creates a device identity in Go WASM memory. Its private bytes are encrypted for browser storage with WebCrypto AES-256-GCM and a PBKDF2-SHA-256 password key (600,000 iterations). IndexedDB stores only the encrypted vault, public device manifest, pin, session counters, and opaque sealed packets. An optional backup download contains the encrypted vault. The Owner's private identity is never imported into the browser or sent to the Hub.

The exported `cicada-device-enrollment.json` file contains the public browser identity and its full SHA-256 fingerprint. An Owner signs that exact key offline with an existing private identity whose file mode is `0600`:

```sh
cicada owner device-grant-sign \
  --private /secure/path/owner-identity.bin \
  --manifest ./cicada-device-enrollment.json \
  --output ./owner-device-grant.json \
  --expect-owner-id OWNER_ID \
  --expect-owner-key-id OWNER_KEY_ID \
  --expect-hub-id INDEPENDENTLY_PINNED_HUB_ID \
  --expect-device-id BROWSER_DEVICE_ID \
  --expect-device-key-id DEVICE_KEY_ID \
  --expect-device-fingerprint FULL_SHA256_FINGERPRINT \
  --expires-at "$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')" \
  > ./owner-device-grant-summary.json
```

The example uses GNU `date` to choose a future UTC expiry one hour away; choose an explicit expiry no more than 24 hours away. The grant output is canonical signed JSON with mode `0600` and is created without overwriting an existing file. The separate summary contains public identity and scope metadata so Go WASM can verify the grant locally before submission. It neither enrolls the device nor pins the Hub. The Hub still checks the Owner key, Hub, device, purpose, expiry, and nonce before activating enrollment.

Import both the signer summary and grant into the browser. The panel stores the exact enrollment request before sending it. If the browser loses the `201 Created` response, retry uses the same request, key, and grant nonce. It does not generate another key or grant automatically.

## Encrypted requests and topology changes

After enrollment, the panel sends `topology.snapshot` and `status.snapshot` as separate encrypted Client Wire v1 RPCs. It shows Hub, Owner, and selected Network context, and distinguishes unknown or stale observations from known status. Endpoints can appear as local references in more than one Group. Group nesting, links, membership roles, and explicit `message.broadcast` permissions come from authoritative snapshots and actions; canvas placement remains local presentation and never grants access.

An edit first displays the exact single `topology.apply` action and its version or binding fence. The user confirms one action at a time. After each response, the panel reloads topology and status before presenting the next queued item. Until the browser authenticates a response, its exact sealed packet and sequence remain pending; recovery resends that packet only. When an authenticated `OUTCOME_UNCERTAIN` response resolves the transport request, the packet leaves the pending slot and the response sequence advances, while the separate semantic write fence remains. Group creation with a parent is one API action, but the current Control implementation persists the Group and parent relation in two steps; if parent assignment fails, the new root Group can remain and the panel refreshes the snapshot.

An authenticated `OUTCOME_UNCERTAIN` response also creates a separate semantic write fence in IndexedDB with the operation ID, operation, SHA-256 digest of the submitted JSON, scope identifiers, and resolution time. Client request and response sequences can advance while that fence remains. Read-only topology and status snapshots remain available, but a new write is blocked across tabs. The user must explicitly refresh both snapshots, inspect them, and confirm a separate authorization button; that button records an acknowledgment and never resends the old action. A tab with an unresolved sealed request still must recover it before this review flow.

Changing a Membership role does not grant `message.broadcast`; that permission has its own explicit action. A Link proposal stays `PROPOSED` until the other Owner reviews and accepts it. The panel never labels a proposal active. Shared Group Thread memory and policy can affect every member, so the canvas warns before adding an Endpoint.

## Build and validation

`docker/Dockerfile.hub` and `docker/Dockerfile` build the WebCrypto module from Go 1.27.1 source, copy that toolchain's matching `wasm_exec.js`, gzip the WASM, and embed a manifest with the uncompressed hash/size, compressed hash/size, and runtime hash. Docker builds exclude any host-generated panel assets and regenerate them in the builder stage. The small Hub runtime does not include Go, Node, Python, or Codex. Generated source-tree assets live in the ignored `cicada-go/internal/server/ui/generated/` directory; the uncompressed production WASM and test-tag interop WASM stay outside the embedded UI tree. A binary built without generated assets returns HTTP 503 for the WebCrypto module and has no alternate crypto fallback.

For an offline local Go/WASM and Node 24 check, use the repository's pinned Go builder image and cached modules:

```sh
CICADA_WEB_PANEL_OFFLINE=1 scripts/build-web-panel.sh
```

Without offline mode, the script uses its pinned Go image and downloads the module graph through the configured Go proxy. `NODE_BIN` can select a Node 24 executable. Both paths run the dependency-free geometry, pin, transaction-state, actual Go WASM PQ/Wire request/response, tamper, and Owner-grant verification checks. The test-only interop methods are compiled behind `cicada_interop_test` and are not present in the Hub-served module.

The Go UI handler tests verify static routes, CSP and fail-closed asset behavior. The Node 24 model gate covers the durable write-fence lifecycle alongside the real Go WASM PQ/Wire vectors.

The one-shot real-browser gate requires Docker and Node 24. It creates a labelled disposable Hub, synthetic Owner key, ACTIVE Network, Chromium profile, and Docker bridge. No resident Hub or model is used, and the generated Owner private key is mounted only into offline CLI operations, never into Chromium. It uses the same immutable Hub image selected by build metadata and can pin Chromium by image ID:

```sh
CICADA_HUB_IMAGE=cicada-wide-local:20260930 \
CICADA_BUILD_METADATA=.cicada-data/architecture-wide-accepted-20260930T121202Z/build.json \
CICADA_EXPECT_SOURCE_FINGERPRINT=5414d6edee44e2be1cad04d10181fd1a23ccd3bf0004fa3fb7bb66776448de83 \
CICADA_CHROMIUM_IMAGE=sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04 \
node scripts/test-hub-web-panel-browser.mjs
```

`CICADA_EXPECT_SOURCE_FINGERPRINT` is required and must be supplied independently
by the caller as 64 lowercase hexadecimal characters. The gate checks that
exact value against both the build metadata and the Hub image label; metadata
cannot attest to itself. For another candidate, set this variable to the
fingerprint recorded for that exact build.

The script uses Node's built-in WebSocket API for CDP and has no npm dependencies. It checks that a first visit requires the exact Hub pin; serves and loads the production Go WASM; generates and password-encrypts a device identity in IndexedDB; signs the exact public enrollment manifest offline with a synthetic Owner key; imports the signed grant and enrolls the device through the real Hub; reads encrypted topology and status into the SVG canvas; commits one exact `topology.apply` Group action and observes it after refresh; and verifies that a second browser tab cannot issue another RPC while the first exact packet is pending. Releasing the first request must advance its request and response sequence and clear the pending slot. The script records the Hub/Chromium image IDs, source fingerprint, browser version, script and metadata hashes, step results, and cleanup results in an ignored `.cicada-data/hub-web-panel-browser/<run-id>/result.json`; it removes that run's fixture directory and exact labelled containers/network.

The local HTTP fixture is forwarded to `localhost:8787` by `socat` inside the disposable Chromium container so Chromium uses its standard trustworthy-loopback WebCrypto context. This bridge is test-only; it does not exercise TLS certificates or public HTTPS.

On 2026-09-30 the gate **PASS**ed using Hub image `sha256:6a21824109c755cc47b345d0cd63b97c49b0d51306420c160ba4ab7b8aa9b475` built from dirty revision `f30892fcd79a27bfe5604575deaecebe52c5ec50`, source fingerprint `5414d6edee44e2be1cad04d10181fd1a23ccd3bf0004fa3fb7bb66776448de83`, and catalog SHA-256 `a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68`. It used Node `24.16.0`, Chromium `151.0.7922.109` (`sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04`), and script SHA-256 `28acaa8dc1c9a68926643b32418fe84f1a38d22999c11e6fbc1863906021589a`. The exact redacted result is `.cicada-data/hub-web-panel-browser/20260930t131113z-251515-c3ac163f/result.json`; all listed fixture cleanup checks passed. The uncertain-write fence path remains **NOT_RUN_NO_FAULT_INJECTION**. This real headless-browser result does not substitute for Android, native Runtime, physical-device, or public HTTPS validation.
