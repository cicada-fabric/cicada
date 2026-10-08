# Clean e286 artifact and shipped-fixture validation

This checkpoint is SHIPPED_ARTIFACT_SCOPED_PASS, overall v0.1 PARTIAL. Product/protocol inputs were clean `e286c8153b0ad840334de12fe947d4c3d9a186a6`, not the later documentation commit. Contract `client-hub-v1.6.4`, wire 1, catalog 55 and DB 58 are unchanged. Source fingerprint: `365b182a8363c36423274b6c57569ac83a338688a23aeaa718aed4679a7d798d`; catalog SHA256: `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`.

## Results and provenance

The [Main independent review](../.cicada-data/clean-e286-pq-20261008a/root-shipped-gate-review.NONAUTH.json) verifies one top-level test / four subtests, zero failures/skips, identical source inventories/package identity, 24 protocol files matching current clean source, owned container absence and six residents unchanged. The top-level gate took 14.69 s and package test 14.70 s. Its four subtests were `protected-MCP-metadata-over-current-PQTLS`, `borrowed-bearer`, `strict-frontdoor`, and `Client-and-WebCrypto`. The package archive is 13,329,045 bytes and protocol bundle 440,323 bytes; these are file sizes, distinct from Docker Engine size semantics. The actual two Node Agent processes join; checked fixture clients perform sends. No Native/model consumption, paid context, Android/Browser TLS acceptance or FIPS certification is claimed. Control business counters remain NOT_INSTRUMENTED; G2 FAIL/G3 NOT_REACHED, V67 UNSUPPORTED, remaining G4/G5/current Client/physical/public gates and sandbox BLOCKED are separate.

| Artifact | Exact identity |
|---|---|
| Software version | `0.1.0-e286-pq-20261008a` |
| Local image | `sha256:9c0c7442488aafc9c8477bbff218cf2753049f804a826f777e2dd8244df3fe71` |
| Image metadata receipt | `cfe87a3b68a059dcf4fc2253fddef29f07b23634b2757be948be44167ce82055` |
| Package archive | `64b4514376d14b88f49a4a4a45b39d41e6b0f0a92a76262f6121467668103a46` |
| Package receipt | `dd42a0c626a2ca3aa0d9a351b8539ffc97dfdf2e818559d96911d3f53ee8ed4b` |
| Package binary | `7fcb5e5be2932e326bb92121a5fec83b67c9a273a454d6f00a6423dea09835e0` |
| Image binary | `a2a0bfe2bc234bfef336a0a4cf7896b0001de3d2ddd91b9d41f842f24d32b2a8` |
| Protocol bundle | `6b8f31669843c7f915615fc4cad1e0463f8b139e6023fe27b2c7201b008418f0` |
| Protocol manifest | `e42c3adbefbcbd8215865dfdc30828078837cb7c9242517e64c794c7cf7724e1` |
| Shipped RESULTS | `1ad8eed408ff459df3274e5e14368c1a6e716fc56193b7639452c9b139fe0ffc` |

Package and image binary hashes differ; no byte-equality claim. Docker Size 14,611,521 bytes is ENGINE_REPORTED_ONLY, without compression semantics. Optional Linux/amd64 PQ uses pinned Go 1.27.1 builder `69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195` and accepted OpenSSL 3.5.9 stage; the ordinary CGO0 variant does not inherit PQ claims.

## Executed recipes and isolation

These commands describe the completed single run, not instructions to repeat it. `OUT=/home/zyf/CICADA/.cicada-data/clean-e286-pq-20261008a`, `TAG=cicada-codex:hub-clean-e286-pq-20261008a`, `VERSION=0.1.0-e286-pq-20261008a`, `STAGE=/home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9`.

```sh
CICADA_BUILD_VERSION="$VERSION" CICADA_BUILD_PROXY=http://127.0.0.1:7890 \
 timeout 15m bash scripts/build-hub-image.sh --image "$TAG" --transport pqtls \
 --pqtls-stage "$STAGE" --metadata-file "$OUT/hub-image.NONAUTH.json"
```

The existing image wrapper uses host build networking and exposes no CPU/memory bounds. The exact [package Docker argv](../.cicada-data/clean-e286-pq-20261008a/package-command.NONAUTH.json) records UID1000, network-none, read-only root, cap-drop ALL/NNP, four CPUs/3 GiB/512 PIDs, bounded 2 GiB temporary filesystem, source/stage/module-cache RO and owned output/cache RW. Its inner command is `bash scripts/build-release.sh 0.1.0-e286-pq-20261008a /out --transport pqtls --pqtls-stage /pqtls-stage`, bounded to 900 seconds. GOTOOLCHAIN=local/GOPROXY=off/GOSUMDB=off prohibit dependency fetching.

Phase 1 mounted the whole checkout read-only, exposing ignored `.cicada-data`; private access was NOT_AUDITED. It was not a masked build and was not rerun. Original [phase1 receipt](../.cicada-data/clean-e286-pq-20261008a/phase1-result.NONAUTH.json) retains absent=false from a case-sensitive error matcher; [Main's separate phase1 review](../.cicada-data/clean-e286-pq-20261008a/root-phase1-review.NONAUTH.json) independently confirms owned package CID/name absence.

The verified archive was extracted once into fresh `OUT/relocated`; all 26 package hashes matched. Protocol export ran once:

```sh
python3 -B scripts/client-contract.py export --output "$OUT/protocol"
```

The [extraction/export receipt](../.cicada-data/clean-e286-pq-20261008a/extraction-protocol-result.NONAUTH.json) records the bundle/manifest identities. No Client repin or protocol change followed.

Before the gate, a [metadata-only mask proof](../.cicada-data/clean-e286-pq-20261008a/mask-proof-result.NONAUTH.json) passed: known public image metadata hidden through the checkout, source script readable, exact nested evidence writable; owned proof container absent. The operational wrapper SHA256 `c12663360169a3c9d1c5262c72d379feedbaf5a2c6e3c0758cd9c7832552cd66` differs from its reviewed predecessor only by using owned `OUT/go-cache`. It validates the complete driver argv, then inserts a 16 MiB `rw,noexec,nosuid,nodev` tmpfs mask at `/home/zyf/CICADA/.cicada-data`; deeper exact evidence remains RW. [Actual closed mount metadata](../.cicada-data/clean-e286-pq-20261008a/driver-mounts.NONAUTH.txt) records the driver mounts. Git RO exposure is retained; no claim covers every ignored path.

For the executed gate, PATH prepended OUT, CICADA_REAL_DOCKER=/usr/bin/docker, producer root=/home/zyf/CICADA, module-cache=/home/zyf/CICADA/.cicada-data/m1-gomodcache, build-cache=OUT/go-cache; package/image receipt hashes were the table values, expected source fingerprint was `365b182a8363c36423274b6c57569ac83a338688a23aeaa718aed4679a7d798d`, and expected WebCrypto manifest SHA256 was `679868b5f4f6f559f61dc4a5aa4fbfedb365cf7d81ce1e9edb056ced14328862`. CICADA_PQTLS_OBSERVE_IDLE=1. The timeout launch shell exported CICADA_GATE_PID=$$ then exec preserved PID 3363893:

```sh
export PATH="$OUT:$PATH" CICADA_REAL_DOCKER=/usr/bin/docker
export CICADA_PQTLS_PRODUCER_ROOT=/home/zyf/CICADA
export CICADA_TEST_MODULE_CACHE=/home/zyf/CICADA/.cicada-data/m1-gomodcache
export CICADA_TEST_BUILD_CACHE="$OUT/go-cache" CICADA_PQTLS_OBSERVE_IDLE=1
export CICADA_PQTLS_EXPECTED_RECEIPT_SHA256=dd42a0c626a2ca3aa0d9a351b8539ffc97dfdf2e818559d96911d3f53ee8ed4b
export CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256=cfe87a3b68a059dcf4fc2253fddef29f07b23634b2757be948be44167ce82055
export CICADA_PQ_FINGERPRINT=365b182a8363c36423274b6c57569ac83a338688a23aeaa718aed4679a7d798d
export CICADA_PQ_WASM_SHA=679868b5f4f6f559f61dc4a5aa4fbfedb365cf7d81ce1e9edb056ced14328862
timeout 7m bash -c 'export CICADA_GATE_PID=$$; exec bash scripts/test-pqtls-packaging.sh \
 /home/zyf/CICADA/.cicada-data/clean-e286-pq-20261008a/relocated/cicada-linux-amd64-pqtls \
 /home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9 \
 /home/zyf/CICADA/.cicada-data/clean-e286-pq-20261008a/shipped-gate \
 /home/zyf/CICADA/.cicada-data/clean-e286-pq-20261008a/package/PQ-BUILD-RECEIPT.json \
 /home/zyf/CICADA/.cicada-data/clean-e286-pq-20261008a/hub-image.NONAUTH.json'
```

The driver runs network-none with four CPUs/3 GiB/512 PIDs and the Hub shares only that container network, with two CPUs/512 MiB/128 PIDs. [Phase2 receipt](../.cicada-data/clean-e286-pq-20261008a/phase2-result.NONAUTH.json) and [gate RESULTS](../.cicada-data/clean-e286-pq-20261008a/shipped-gate/RESULTS.json) record driver `186b064e…` and Hub `c91f0e54…` absent, no remaining private fixture roots, identical before/after roots/inputs/identity and six residents unchanged. No old deployment, keys or global configuration changed.

Four one-second idle observations after a three-second warmup measured Node VmRSS 37,892 / 36,552 kB; one Docker stats sample is separate. Shared pages and Go/CGo accounting make these neither exclusive memory totals nor peak/throughput/production benchmarks. Full Native G2/G3, sandbox execution, V67 and external gates receive no acceptance transfer.
