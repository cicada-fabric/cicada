# v0.1 current-source Go validation — 2026-10-09

This note records deterministic Go test and vet results for the current dirty
source. It does not convert the first full-suite failure into a product failure
or report the full normal suite as one passing command.

## Source and execution identity

The source was based on HEAD `37ae1036b95d67629639d7b5bb09f6688116dad2` with
uncommitted changes. The inventory covers 932 tracked files under `cicada-go`,
including the current test bytes; its fingerprint is
`fe72ff6c66ff48607ea57bc0b1cd24f6af37d6fd6a8ab3914a3db6b3f0f4d294` and the
inventory receipt SHA-256 is
`79f8ed6d936aebc85bd87e0afc91ec13c19e38bbc9bf7c29ed768438f8bbff11`.
The two pending test files were:

| File | SHA-256 in the tested inventory |
| --- | --- |
| [machine_native_real_queue_crash_test.go](../cicada-go/cmd/cicada/machine_native_real_queue_crash_test.go) | `b87b59d151b56d4bb8437c37463f81f7db5618cba57188b61eb99814e402bd57` |
| [task_peer_privacy_fixture_test.go](../cicada-go/cmd/cicada/task_peer_privacy_fixture_test.go) | `32dddeb989eacae2177e9de4dfe6ae46113fcb3ad1580e25802e78a691dbe105` |

The builder was pinned to
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`.
Each run used UID 1000, network none, two CPUs, a 3 GiB memory limit,
read-only source/module/OpenSSL mounts, `--cap-drop ALL`, and
`no-new-privileges`; module lookup was offline. No credentials were read,
provider calls or model calls were made, and no native acceptance gate ran.

## Results and attribution

The actual default-tag full command was:

```text
go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=15m -json ./...
```

It exited **1** after 687.77 seconds. It ran all 30 package paths: 27 packages
passed and three failed because that first container mounted only the Go subtree
at `/src`, while these tests resolve repository-root files through
`runtime.Caller`:

| Test | Missing public input observed |
| --- | --- |
| `internal/buildinfo.TestVersionMatchesRepositoryMetadata` | `/VERSION`; the same test also requires `.agents/plugins/cicada/plugin.json` and `.agents/plugins/cicada/.codex-plugin/plugin.json` after it reads `VERSION` |
| `internal/clientcontract.TestCatalogIsVersionedCompleteAndPointsIntoWireContract` | `/docs/client-hub-wire-v1.md` |
| `internal/server.TestClientV2OwnerGrantAndEncryptedSnapshotAcrossRestart` | `/docs/client-hub-v1.openapi.yaml` |

These are fixture-layout failures, not evidence of product regressions. No
failure was removed or relabeled. The full-run counts were 1,500 top-level
passes, 3 failures, and 22 skips; 1,400 subtests passed with no subtest failures;
package results were 27 pass / 3 fail. No `-run` selector or skip-hiding filter
was used.

The 22 skipped tests remain skips in
[`skips.NONAUTH.json`](../.cicada-data/g5-final-go-20261009a/test-default-retry1/skips.NONAUTH.json)
(SHA-256 `e18e352e5aba314891bd23cbdf5b6e9075e456eb81a21caf74515123e6963d22`):

- Native, Android, daemon, or real queue opt-ins (not executed):
  `TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative`,
  `TestMCPSealedCrossNodeGroupAskReplyNative`,
  `TestMCPSealedSameGroupBroadcastNative`,
  `TestMCPSealedSameNodeGroupAskReplyNative`,
  `TestMCPMonitorBroadcastAndroidClientNative`,
  `TestMCPMonitorBroadcastClientV13Native`,
  `TestMCPSealedNativeThreadJoinsTwoIndependentHubsNative`,
  `TestFabricDirectoryHidesRealUnjoinedNativeThreadHTTP`,
  `TestProxyClientRealDaemonReadSmoke`,
  `TestMachineNativeRealQueueCrashAcceptance`.
- Disposable Docker/Hub fixtures not supplied:
  `TestClientDockerHubRecoveryFixture`, `TestMachineMultiHubDockerFixture`,
  `TestMachineRestoreRecoveryDisposableFixture`, `TestHubBoundedCapacityDocker`,
  `TestClientDockerHubSmoke`, `TestTaskPeerPrivacyIsolatedHubFixture`,
  `TestTaskPeerPrivacyIsolatedNodeFixture`, `TestGroupSpacesM2DockerHub`,
  `TestNetworkM1DockerHub`.
- Disposable bind-mount inputs not supplied:
  `TestStateBackupRestorePhysicalBindAliases`,
  `TestStateMaintenanceNonrootBindMountAliases`,
  `TestHubForwardPrepareRejectsPhysicalBindCapsuleBeforeFence`.

For the correction, the five public repository-root files above were added to a
read-only stage beside the same 932 Go inputs. The module ran from
`/repo/cicada-go`, so `runtime.Caller` resolved the root as `/repo`. A
network-none, no-test preflight verified all five expected paths and hashes;
it exited 0 in 1.13 seconds. The corrected focused command then exited 0 in
139.09 seconds:

```text
go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=15m -json ./internal/buildinfo ./internal/clientcontract ./internal/server
```

All three packages passed: 139 top-level passes, 5 skips, and 163 subtests
passed with no failures. Those five skips are existing isolated Hub/Docker
requirements (`TestHubBoundedCapacityDocker`, `TestClientDockerHubSmoke`,
`TestFabricDirectoryHidesRealUnjoinedNativeThreadHTTP`,
`TestGroupSpacesM2DockerHub`, `TestNetworkM1DockerHub`). Their reasons are in
[`focused skips`](../.cicada-data/g5-final-go-20261009a/test-missing-root-context-20261009a/skips.NONAUTH.json)
(SHA-256 `c0b5b05a89b09c97c2fcab4f2456696b9a39d2eebd1fb835b14a23b378992e74`).

Full tagged static analysis also passed:

```text
go vet -tags cicada_pqtls -mod=readonly -p 2 ./...
```

It exited 0 in 73.92 seconds. This is a tagged vet result, not a PQ-TLS runtime
acceptance result.

All 30 package paths were exercised across the full attempt and the corrected
focused run, on identical Go-source inventory bytes. The counts above are
per-command and must not be added: the full `go test ./...` command remains
exit 1, and there was no single corrected full-suite run recorded here.

## Receipts and corrected-layout command

The ignored local receipts retain exact commands, counts, skips, source bytes,
container identity, cleanup, and resident-container snapshots:

| Receipt | SHA-256 |
| --- | --- |
| [Full normal result](../.cicada-data/g5-final-go-20261009a/test-default-retry1/result.NONAUTH.json) | `35f753e7c9f69b1e8d01d8cc26d33ff2b1e7be9d1e271af33509d6eb67817209` |
| [Full normal counts](../.cicada-data/g5-final-go-20261009a/test-default-retry1/counts.NONAUTH.json) | `44d0e1b91e16c3e649ac68153bbb4d157bc2c608ba13ddee15b566d04777f635` |
| [Corrected layout inventory](../.cicada-data/g5-final-go-20261009a/repository-context.NONAUTH.json) | `73b42d22fabfa285fc7f6dac57a943fa794ccae977ee266a08839d8f8b683e1d` |
| [Five-file preflight result](../.cicada-data/g5-final-go-20261009a/preflight-root-context-20261009a/result.NONAUTH.json) | `d1cf62f8b36440c854a67ae9050386afec1f32c06e26c7d714ce26266bdf2b34` |
| [Focused normal result](../.cicada-data/g5-final-go-20261009a/test-missing-root-context-20261009a/result.NONAUTH.json) | `8c9ae6ecc650a1fc2645ffa57e6d4598a7d251db68322cb0a06d41134acf8f2b` |
| [Focused normal counts](../.cicada-data/g5-final-go-20261009a/test-missing-root-context-20261009a/counts.NONAUTH.json) | `8b6ae65332246159d092e4caa74a22c9cbf521052e90473a62140b70d0e49fc4` |
| [Full tagged vet result](../.cicada-data/g5-final-go-20261009a/vet-pqtls-retry1/result.NONAUTH.json) | `88a0f7a5adab01878f9565bcb7817f3cccffd2b93d1a3519800f021d2ece3f6c` |
| [Closeout index](../.cicada-data/g5-final-go-20261009a/closeout.NONAUTH.json) | `6f18bb4d5e3f46cfe9068df4350e94519b8931250a4d2d5520802fc5ce36430e` |

The receipts report all owned container IDs absent, all six resident containers
unchanged, and tested Go-source bytes unchanged. They record zero credential,
provider, model, and native-acceptance calls. This validation does not establish
native CLI/model behavior, PQ-TLS runtime behavior, Android or physical-device
acceptance, package/image distribution, or public HTTPS acceptance. Historical
and missing history remains attributed only to its own source and receipt.

For a future full normal rerun, use the corrected repo-relative stage and the
existing offline caches. This command was **not** run as a corrected full-suite
pass in this record:

```bash
IMAGE='golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
ROOT_STAGE='/home/zyf/CICADA/.cicada-data/g5-final-go-20261009a/recheck-root-stage'
GOMOD='/home/zyf/CICADA/.cicada-data/m1-gomodcache'
OSSL='/home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9'
GOCACHE='/home/zyf/CICADA/.cicada-data/g5-final-go-20261009a/go-cache-test-retry1'
docker run --rm --user 1000:1000 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --network none --cpus 2 --memory 3g \
  --pids-limit 256 --tmpfs /tmp:rw,exec,nosuid,nodev,size=1g,mode=1777 \
  -w /repo/cicada-go \
  -v "$ROOT_STAGE:/repo:ro" -v "$GOMOD:/gomod:ro" \
  -v "$OSSL:/opt/cicada-openssl/3.5.9:ro" -v "$GOCACHE:/cache" \
  -e HOME=/tmp/home -e GOCACHE=/cache -e GOMODCACHE=/gomod \
  -e GOPROXY=off -e GOSUMDB=off -e GOTOOLCHAIN=local -e GOMAXPROCS=2 \
  -e CGO_ENABLED=1 \
  -e PKG_CONFIG_PATH=/opt/cicada-openssl/3.5.9/lib/pkgconfig \
  -e LD_LIBRARY_PATH=/opt/cicada-openssl/3.5.9/lib \
  -e CGO_CFLAGS=-I/opt/cicada-openssl/3.5.9/include \
  -e CGO_LDFLAGS=-L/opt/cicada-openssl/3.5.9/lib \
  -e OPENSSL_CONF=/dev/null -e GOFLAGS=-buildvcs=false \
  --entrypoint /bin/sh "$IMAGE" -c '
    set -eu
    test "$(go version)" = "go version go1.27.1 linux/amd64"
    mkdir -p /tmp/home
    exec go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=15m -json ./...
  '
```

The matching tagged-vet invocation uses the same container options and mounts,
replacing the final `go test ...` with
`go vet -tags cicada_pqtls -mod=readonly -p 2 ./...`.
