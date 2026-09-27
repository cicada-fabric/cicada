# Client Hub v1.3 clean candidate validation: 25013b5

**Final bounded checkpoint result (2026-09-27): PASS for the fixed candidate and controlled Android/native Monitor chain.** The fixed runner (`0d532f2e3bb57a9c82df4967044e4f40861c45a6`) exited `0`; it reports one read-only preview, one separate dispatch and successful receive/context assertions in both original recipient Threads. Client's final strict status passed, Core's scoped ciphertext scan found no body/context plaintext in the marked Hub database/WAL/SHM, and Intake's independent read-only Hub audit confirmed the original approval plus two unique outcomes (`NODE_REPORTED` locally and `RELAY_PERSISTED` remotely). Client/emulator and Hub fixture cleanup both exited `0`; no marked containers or fixture directory remain. Evidence is split by owner and layer below. This PASS is limited to the exact identities and run; it does not establish full React Native consent UX, physical dual-Node/Android behavior, public HTTPS, or general prompt-injection protection.

## Fixed candidate identities

| Component | Identity |
|---|---|
| Hub source | Clean commit `25013b51915124fa1da25e5fd37088eadf0e3d2d`; source dirty `false`; fingerprint `2e0bb4c34f77c30cc1d631e51e16cdf2741045284e05dddcbac0a2fbd3091725` |
| Hub image | `sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c` (`cicada:monitor-review-25013b5-candidate`) |
| Interop test image | `sha256:1520ded8774906663a33c3a252c203cfacfef3f788813c9be490307a9337c38f` (`cicada:monitor-review-25013b5-interop`) |
| Contract | `client-hub-v1.3`, wire version 1, 33 operations; catalog SHA-256 `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Exported contract archive | `.cicada-data/monitor-approval-review-25013b5/contracts/client-hub-5ad36a7492dd7751308eef6fe22c44175079cd212411ffbef580576b7f2597ce.tar.gz`; SHA-256 `5ad36a7492dd7751308eef6fe22c44175079cd212411ffbef580576b7f2597ce` |
| Build metadata | `.cicada-data/monitor-approval-review-25013b5/build.json` |
| Native runner source | Commit `0d532f2e3bb57a9c82df4967044e4f40861c45a6`; helper SHA-256 `d542ca5df79983210bd58a6261384efd5d90cfb6890c8b4680d7b87f90ab9e7a`; test binary SHA-256 `c992dd4ce9fdaeb6895ad827ae8e196155abba5009e2b3da1c4e5931eccd8589` |
| Runtime | Codex image `sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`, CLI 0.157.1; fixed model `gpt-5.6-luna` |

The Go source was archived from the clean commit to `.cicada-data/monitor-approval-review-25013b5/source.tar` (SHA-256 `aa96b295126b38641044a083563e2dcba24d5b855c34e6c450d7ab1c58c75bfd`). The temporary detached source worktree was clean at the pinned commit and has been removed; the archive and all gate evidence remain. The build metadata keeps source identity, contract bundle, Hub image and interop image distinct. The candidate is a local disposable-test image; it was not published or deployed to the resident Hub.

The pinned images were built once from that clean source with the existing build script:

```sh
scripts/build-hub-image.sh --image cicada:monitor-review-25013b5-candidate \
  --interop-test-image cicada:monitor-review-25013b5-interop \
  --metadata-file .cicada-data/monitor-approval-review-25013b5/build.json
```

Build exit was `0`; the exact command and identities are also preserved in mode-0600 `.cicada-data/monitor-approval-review-25013b5/build-command.txt`. The script verified source dirty=false and the recorded catalog before writing metadata.

## Deterministic and TCP gates

All Go checks used Go 1.27.1 image `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244`, the clean archived source, pre-populated module/build caches, and `--network none` with `GOPROXY=off`.

| Gate | Result |
|---|---|
| `go test -count=1 -timeout=15m ./...` | PASS, exit 0 |
| `go vet ./...` | PASS, exit 0 |
| Focused `-race` over `./internal/store ./internal/nodekeys ./cmd/cicada` for Monitor preview Guard, replay non-consumption, MCP structured output and per-turn tool restrictions | PASS, exit 0 |
| `python3 scripts/client-contract.py check` | PASS, exit 0 |
| `python3 -m unittest discover -s scripts -p test_client_contract.py` | PASS, exit 0 |
| Contract export and `scripts/client-contract.py verify <archive>` | PASS, both exit 0 |

The exact argv, test selector list, logs and exits are preserved in `.cicada-data/monitor-approval-review-25013b5/{go-test-all.json,go-vet-all.json,preview-race.json,contract-check.json,contract-python-unittest.json,contract-export.json,client-contract-verify.json}` and their corresponding `.exit` files. Sensitive/private logs remain in that ignored artifact directory and are not reproduced here.

The exact-image disposable TCP command was:

```sh
python3 .cicada-data/monitor-approval-review-25013b5/exact-candidate-interop/run.py attempt-02
```

The run used the fixed Hub image above and verified the matching interop test image before starting a disposable Hub. `TestClientDockerHubSmoke` and `TestClientDockerHubRecoveryFixture` both passed; test process and runner exit were `0`. Full argv, per-test events, provenance, exit and cleanup records are in `.cicada-data/monitor-approval-review-25013b5/exact-candidate-interop/attempt-02/` and `exact-tcp-gate-attempt02.json`. The one-off runner expects its clean Git checkout at `/tmp/cicada-hub-candidate-25013b5`; after this run that temporary worktree was removed. A replay can recreate it without a branch using `git worktree add --detach /tmp/cicada-hub-candidate-25013b5 25013b51915124fa1da25e5fd37088eadf0e3d2d`, then invoke the command above. The fixed images and archive remain local artifacts.

Attempt 01 is preserved as a runner setup failure, not a Hub test failure: its preflight exited `1` with `NameError: name 'GO_IMAGE' is not defined`; no candidate Hub or test process was started. Its argv and result are in `exact-candidate-interop/attempt-01/`. The corrected attempt-02 runner SHA-256 is `d979030515e4be4903a3d70882df6b26998bffa0b8b7531b56ac1b7cfffa69ce`.

TCP test exit and fixture-state cleanup both returned `0`. Docker's `--rm` had already removed the test container, so the subsequent test-container inspect returned `1`; the Hub stop returned `0`, and its subsequent forced-remove attempt returned `1` because auto-removal had already occurred. The cleanup record confirms the fixture state was removed, the candidate image remained available, and the candidate-labeled container query was empty. These expected post-`--rm` misses do not change the successful test result; cleanup was not reported as all-zero.

## Live Android/native boundary

This candidate adds a Node-local read-only preview of the exact confirmed Monitor body, ordered recipients and authorization evidence. Preview does not dispatch, mutate approval/outcome state, consume replay state, or create an outbox entry. In the recorded run, one preview was followed by one separately reviewed dispatch with the same approval ID; both original recipient Threads then passed receive/context assertions. This is evidence for that exact controlled run, not a general prompt-injection defense or guarantee for arbitrary payloads.

The final Client evidence is in [`CICADA_CLIENT` validation report](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md), current Client HEAD `fa6e73a9feebaf4f06335deef005a68d169eae28`. Its 10 selectors and final strict status passed; the report identifies app/test APK hashes and their source commits separately from the documentation HEAD. Core's `native-final.redacted.json` and `native-run.json` are in `.cicada-data/native-review-0d532f2/`; Intake's `hub-readonly-audit.json` confirms one original `DISPATCH_AUTHORIZED` approval and two unique outcomes (`NODE_REPORTED` locally, `RELAY_PERSISTED` remotely, exact one Hub message); `cleanup.redacted.json` records native removal and marked-Hub fixture stop with exit `0`, with no owned containers or `/tmp/cgk.W3dw9mwf` directory remaining. Client emulator/reverse cleanup also exited `0`. The test used two logical Nodes in one container and three original Threads. The tested instrumentation flow does not establish a complete product-facing React Native consent experience. Physical dual-Node/Android operation and public HTTPS remain **NOT_RUN**; unattended cold wake remains **UNSUPPORTED**. See [the fixed-Hub native fixture runbook](client-monitor-native-fixture.md) and [approval/Runtime limits](monitor-broadcast-approval-review.md).

The bounded result is complete for the recorded candidate; future physical dual-Node, public HTTPS or full React Native consent results must be reported separately. A skip or empty ledger is not a pass.
