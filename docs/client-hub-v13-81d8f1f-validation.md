# Client / Hub v1.3 candidate validation — `81d8f1f`

**Result: PASS for the clean Hub candidate, deterministic gates and exact-image
real-TCP interop. Android, native Monitor delivery and public HTTPS are not part
of this result.** This candidate includes the stale-presence lease fix. The
separate native attempt on this exact candidate is **BLOCKED** before dispatch
by automatic approval review; see the [candidate native acceptance record](client-monitor-native-81d8f1f-validation.md).
The earlier frozen-image failure remains in the [historical joint report](client-monitor-native-joint-validation.md).

## Candidate identity

| Identity | Value |
|---|---|
| CICADA source | Clean detached `dev` snapshot `81d8f1f90895f41c4f5ea5c67a6281ccda9e1264`; source fingerprint `50d0a9250631381949f2aa5e155424996aa13490759107e597d354e620a8b2c8` |
| Software version | `0.4.0-dev` |
| Contract | `client-hub-v1.3`, wire version `1`, 33 operations |
| Catalog | SHA-256 `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Exported contract bundle | `.cicada-data/client-v13-after-lease-fix-81d8f1f/contracts/client-hub-6eaa692cc9e31e0482d94ed9f26ed277dfc91fd37333949d3e2517f498ba4061.tar.gz`; SHA-256 `6eaa692cc9e31e0482d94ed9f26ed277dfc91fd37333949d3e2517f498ba4061`; manifest source is the same revision with `source_dirty=false` |
| Local Hub image | `cicada:client-hub-v1.3-lease-fix-81d8f1f-candidate`; exact image ID `sha256:0c484d1c10a9fd71e6ae74ddd7fec85ae6ae8cbecf2ece6f90d393892990a04f` |
| Client-consumable build metadata | `.cicada-data/client-v13-after-lease-fix-81d8f1f/build.json` (`cicada.hub-build.v1`, `source.dirty=false`) |

The candidate was built from an isolated clean detached worktree at the exact
commit above. The generated metadata records the Git revision, source
fingerprint, catalog digest, image reference and full image ID separately. The
image is local and was not pushed or installed as a resident Hub.

## Fresh idle-Hub footprint

A fresh idle instance of this exact image was measured on 2026-09-27 at
06:26:49 UTC with no enrolled devices or native Threads, a 0.5-core CPU limit
and a 128 MiB memory limit. Process RSS was 27,164,672 bytes (about 25.9 MiB);
the cgroup memory baseline was 20,750,336 bytes (about 19.8 MiB), with a
23.4 MiB observed cgroup peak during the short sample. This is one idle Hub
measurement only; it excludes Nodes, models, Android and loaded Hub behavior.
The raw structured measurement is

    .cicada-data/client-v13-after-lease-fix-81d8f1f/footprint/idle-hub-20260927T062649Z-67e95925.json.

## Deterministic gates

The source was isolated with a clean detached worktree (no branch created):

```bash
git worktree add --detach /tmp/cicada-hub-candidate-81d8f1f \
  81d8f1f90895f41c4f5ea5c67a6281ccda9e1264
cd /tmp/cicada-hub-candidate-81d8f1f
```

From that worktree, the Hub build command was:

```bash
./scripts/build-hub-image.sh \
  --image cicada:client-hub-v1.3-lease-fix-81d8f1f-candidate \
  --metadata-file /home/zyf/CICADA/.cicada-data/client-v13-after-lease-fix-81d8f1f/build.json
```

It exited `0`, with `source.dirty=false` and the image identity above. The
contract catalog check, content-addressed export and bundle verification each
exited `0`. The seven standard-library contract and recovery-proxy tests passed
in 1.693 seconds:

```bash
python3 scripts/client-contract.py check
python3 scripts/client-contract.py export \
  --output /home/zyf/CICADA/.cicada-data/client-v13-after-lease-fix-81d8f1f/contracts
python3 scripts/client-contract.py verify \
  /home/zyf/CICADA/.cicada-data/client-v13-after-lease-fix-81d8f1f/contracts/client-hub-6eaa692cc9e31e0482d94ed9f26ed277dfc91fd37333949d3e2517f498ba4061.tar.gz
python3 -m unittest scripts.test_client_contract scripts.test_client_recovery_fault_proxy -v
```

The full Go suite and vet both passed from the same read-only source snapshot,
offline in the pinned Go 1.27.1 image `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244`:

```bash
# These Go commands ran inside the pinned Docker image against the read-only
# detached worktree; exact docker argv and exit codes are recorded below.
go test -count=1 -timeout 15m ./...   # exit 0; 120 seconds
go vet ./...                          # exit 0; 2 seconds
```

The exact Docker invocation arrays, exits and private full-suite logs are in
`.cicada-data/client-v13-after-lease-fix-81d8f1f/go-commands.json` and the
adjacent `go-test-all.exit`, `go-vet-all.exit` and `*.private.log` files.

## Disposable TCP interop on the exact candidate

The existing `scripts/test-client-hub-interop.sh` completed with **PASS**, but
its independently rebuilt Hub ID was `sha256:733c34ccdcd32438628d0f6ced914b5a0831086093a2c32fa35fd4903b123007`, not the retained
candidate ID. Its source revision, clean flag, source fingerprint and catalog
matched; its result is retained at
`.cicada-data/client-v13-after-lease-fix-81d8f1f/interop/result.json`, but it is
not evidence for testing image `0c484d…2990a04f`.

To exercise the exact retained image without rebuilding the Hub, the one-off
runner built only the existing `interop-test` Dockerfile target from the same
clean worktree, started an isolated Hub by the full candidate image ID and
verified `/healthz` provenance plus the advertised v1.3 catalog before tests.
The two required Go tests both ran and passed:

| Test | Result |
|---|---|
| `TestClientDockerHubSmoke` | PASS |
| `TestClientDockerHubRecoveryFixture` | PASS |

The disposable interop test image was `sha256:627fe764d5e9b50712729a79c6ca61c153a391d62e1639a7b0d7a52a954df577`; its source and catalog labels matched the candidate. The runner command exited `0`. Its source SHA-256 is `2616dc5cae44a919ce8865341b98ae344a3ca6809e10037b203934673142f33d`.

The successful invocation was:

```bash
python3 /home/zyf/CICADA/.cicada-data/client-v13-after-lease-fix-81d8f1f/exact-candidate-interop/run.py attempt-02
```

For another run, use a new attempt name whose evidence directory does not
already exist; the runner refuses to overwrite previous results.

The exact argv, exit codes, test names, provenance response, runner result and
cleanup checks are retained under
`.cicada-data/client-v13-after-lease-fix-81d8f1f/exact-candidate-interop/attempt-02/`.
The build-proxy values are redacted in recorded argv. The temporary test image,
Hub/test containers and marked state directory were removed; follow-up inspect
checks found no remaining fixture container or test image tag, and the stable
candidate tag still resolved to image `0c484d…2990a04f`. The Hub's `--rm`
auto-removal raced a redundant `docker rm -f` (stop exited `0`, that redundant
remove exited `1`); the subsequent inspect confirmed the Hub container absent.

An earlier exact-candidate runner attempt is retained at
`.cicada-data/client-v13-after-lease-fix-81d8f1f/exact-candidate-interop/attempt-01/`.
That setup attempt omitted the configured Docker build-proxy arguments, so the
test-image build failed at `go mod download` with exit `1`. Its cleanup path
then mishandled the nonexistent test-image tag. No Hub container started and no
protocol test ran; this was a fixture setup failure, not a Hub test failure.
The runner source SHA-256 for that attempt is recorded in its
`failure-summary.json`.

The Hub build metadata can be passed to the current disposable Client fixture:

```bash
./scripts/client-group-key-fixture.sh start \
  --build-metadata /home/zyf/CICADA/.cicada-data/client-v13-after-lease-fix-81d8f1f/build.json
```

That command was not run as part of this candidate gate. Android validation,
physical-device testing and public HTTPS remain outside this result. On this
same candidate, native Monitor acceptance is **BLOCKED**: the fresh d76 attempt
was rejected before MCP execution and had no dispatch; recipient consumption
is **NOT_RUN**. The candidate-native report gives the precise scope and must
not be summarized as a native pass.
