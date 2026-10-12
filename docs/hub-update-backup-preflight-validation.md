# Local Hub update backup preflight validation

This checkpoint adds an opt-in backup gate to
[`scripts/install-cicada-server.sh`](../scripts/install-cicada-server.sh). The
first-install path and its default project and volume remain unchanged. For an
existing project, the installer requires `CICADA_DEPLOY_UPDATE=1` and a new
private external backup destination. It checks the exact Compose Hub, current
image ID, named volume, state owner and mode, Docker's candidates filtered by
the exact named volume, and the existing image's `migration backup` and
`migration verify` CLI forms before stopping the Hub. The named-volume filter
limits which containers are inspected; it is not a census of host processes
or arbitrary bind-mounted writers. Operators must stop every writer. The
existing backup command's StateDir maintenance lease and SQLite snapshot lock
remain the authoritative Hub-state consistency checks. After the container
stops, the currently deployed image runs the backup helper with networking
disabled and a read-only container root; the same image verifies it from a
read-only backup mount. Compose rebuild/up is reached only after the CLI
output, verifier output and on-disk manifest match and report a complete
supported Hub backup.

The JSON checks are consolidated in
[`hub-update-backup-check.py`](../scripts/hub-update-backup-check.py). It
bounds Compose/inspect metadata at 2 MiB and backup manifests at 8 MiB,
rejects duplicate object keys, and checks the manifest field names against
the current `StateBackupManifest`, `StateBackupDatabase`,
`StateBackupContacts`, `StateBackupTable`, and `StateBackupFile` JSON tags.

Verification used only a fake Docker executable; it did not contact Docker or
create containers, volumes, backups, or other runtime resources:

```sh
bash -n scripts/install-cicada-server.sh
python3 -m py_compile scripts/hub-update-backup-check.py scripts/test-install-cicada-server-update.py
python3 scripts/test-install-cicada-server-update.py
```

The 21 tests cover the unchanged default fresh-install selection, a distinct
local project and derived volume, refusal of an orphan named or Compose-owned
volume, exact single-container selection, required fresh backup destination,
backup-before-rebuild ordering with the old image ID, failed or mismatched
backup/verify results, unsupported CLI, extra running read-write consumers,
existing or non-private/symlinked backup paths, an allowed non-overlapping
ancestor parent, stop failure/state
confirmation, path-mount encoding refusal, Hub-only inventory, duplicate-key
and oversized metadata rejection, validator-to-Go-JSON-tag/CLI-shape checks,
proof that unrelated containers are not inspected during the volume-filtered
candidate scan, per-run update-helper labels, and private scratch cleanup. They
establish installer control flow under fake Docker responses; the disposable
run below is separate runtime evidence.

## One disposable Docker update attempt

On 2026-10-12, the frozen A2 operator ran once with 600 seconds for work and
60 seconds for cleanup. It loaded the archived c292 Hub image
`sha256:d69edf867632f1ac8adec83ecc689e5cdf9654505ccdd4eeb1ed489ec4e2e496`
and started the initially empty `cicada-v2-update-a1` project. The deployed
image's backup and verify commands returned the same manifest digest
`0e06e14f251c55078c1e4c6c940fbe887f983c41de0d963c3701952d55482c01`; the
private backup was verified and retained.

The installer then attempted its real checkout build from dirty revision
`9465299e4684cb9486ebdf4489911debb20efe53` (962 Hub inputs;
`hub_build_source_fingerprint_v4`
`045079bcfd72da6d66832496babfeb9a4b5af92dddbb356807f04280c375522d`). It
failed at `Dockerfile.hub`'s `RUN go mod download`: the request for
`github.com/cloudflare/circl@v1.6.5` timed out while contacting
`proxy.golang.org`. The installer exited 1; the update did not build or reach
a replacement Hub. This is a verified-backup/update-failure result, not a
successful update or release.

The operator removed only the exact disposable project container, named
volume and temporary tags after the failure. Independent postchecks found the
project and helper containers, volume and temporary tags absent; the protected
six containers and Hub source inventory matched their pre-run snapshots. The
private verified backup remains available. The result is recorded at
`../.cicada-data/v00-clean-delivery-c2929fc-20261012/hub-update-disposable-a1/RESULT-A2.NONAUTH.json`
(SHA-256
`6a3c4ec61d18ea32d8e942fcaa80925667636a38f36f88a4bec90129c448acb2`), using
driver SHA-256
`74bd23d29c0d044ae54596dc658c3a072af529c2fe6617a2b64cda902e80682e` and
readiness SHA-256
`d0a6012eecfd69acc6aa29e44a4cebbf9fa084ebaba44fec2981acd5f501d6b1`.

## Separate A3 disposable update with a build-only proxy override

On 2026-10-12, a separate one-shot A3 run used the fresh project
`cicada-v2-update-a2`, volume `cicada-v2-update-a2-hub-state`, and loopback
port `18880`. Its readiness receipt records the archived c292 Hub IID, absent
project/volume/tags/backup destination, the dirty source snapshot, Docker
engine, and private override inputs. The initial Hub was started from the
archive with `--no-build`; the installer then performed its real `--build`
update and exited 0 with the resulting Hub healthy before cleanup. This run
followed the A2 timeout above; it does not replace the A2 failure record.

The build-only network change was scoped to that run. A private `DOCKER_CONFIG`
contained only the existing `default` context, and a mode-0700 per-run Docker
shim used `/usr/bin/docker` (SHA-256
`a8f65e346400b9f3d3732b2ef4bb85c54bf1eb753cf7b026550a0ea70753d923`; shim
SHA-256 `5a6243adde407ac4ce7915b447b752403694851ac8ce0ec18d8c02740850bf68`).
The private Docker config file SHA-256 was
`cb6c92a4a91d8bf6f7400a3fa6913446edf07a0939a99ca2bff994282a5f5ca3`. It
rewrote only the exact project, base Compose file, and known installer
invocations to add the mode-0600 Compose override (SHA-256
`00614d411fba81cfd6e2b8c542109bccf72e7ffbb7891fd3681e8e281266f481`). The
override adds `build.network: host` and `HTTP_PROXY`/`HTTPS_PROXY` build args
pointing to the authorized host loopback proxy at `127.0.0.1:7890`. It sets no
Hub runtime environment or daemon/global Docker configuration. A host-only
proxy probe returned HTTP 206 and 155 bytes; its body was not retained (probe
receipt SHA-256
`c87559d18db07c1fc5451815708f9975dfacba19fd646bc5c8859e9f93d55e1c`).
The recorded, one-shot invocation (the readiness and result files already
exist; this is not a rerun command) used a 700-second outer timeout around the
operator's 600-second work and 60-second cleanup limits:

```sh
timeout --signal=INT --kill-after=10s 700s /usr/bin/env -i \
  PATH=/home/zyf/CICADA/.cicada-data/v00-clean-delivery-c2929fc-20261012/hub-update-disposable-a2/docker-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  HOME=/home/zyf LANG=C.UTF-8 \
  DOCKER_CONFIG=/home/zyf/CICADA/.cicada-data/v00-clean-delivery-c2929fc-20261012/hub-update-disposable-a2/docker-config \
  /usr/bin/python3 \
  /home/zyf/CICADA/.cicada-data/v00-clean-delivery-c2929fc-20261012/hub-update-disposable-a2/hub-update-disposable-a2.py \
  --run
```

Before the run, the real Docker CLI resolved the base and shimmed Compose
configuration for both image tags. The non-build configuration was identical;
the only added build fields were the proxy args and `network: host`. For the
update tag, the base and overridden config SHA-256 values were
`880a9b9c12db0bad9348de5b7c7315d027d9c6ec802c9d4cbb3cac56abe88713` and
`f8776c177221e979716358db1f019a4978fae270bf8ef240704fbba0e2882c90`. The
initial-tag values were
`a4137cc51f009325ddba39c909086917ccec31d1517886efcbd00b8fa50ad18d` and
`81acb7000c36783f8892e8b865ffd945655ea16010c4cc8e8d6bcc8333c244a2`.

The installer built from revision `9465299e4684cb9486ebdf4489911debb20efe53`
with a dirty worktree, 962 Hub inputs, and source fingerprint
`045079bcfd72da6d66832496babfeb9a4b5af92dddbb356807f04280c375522d`. The
fingerprint, Git status and protected-six snapshot matched before and after.
The updated image ID was
`sha256:a0e1ecbb32fc4e79fc61548ee88673e7e4ce4b3d9bbf44bc9d8d38b6a5d0458a`.
This records the disposable build's input checkout and output digest; it is not
a clean-source, signed or released image.

The current-image backup and verifier matched manifest SHA-256
`30e6b4256a3835d86e13ffb8da4ee23ef95430c6e49f6b7bcd30ff435b75c371`, and the
private backup at
`/home/zyf/.cache/cicada-hub-update-a2/hub-before-update` was retained
separately from A2. The operator removed only the exact A3 Hub, volume and
temporary tags. Independent postchecks confirmed the project/helper
containers, volume and tags absent; the backup, source and six protected
residents matched their receipts.

The result is
`../.cicada-data/v00-clean-delivery-c2929fc-20261012/hub-update-disposable-a2/RESULT-A3.NONAUTH.json`
(SHA-256
`706e81e76f4531ab2e3ccb174841998c5c6150ac0789ae2d20bc7f142e24117e`). Its
readiness receipt is `READINESS-A3.NONAUTH.json` in the same directory (SHA-256
`1baa50d9e628be459e1f8c9473fc7173f486a66278de14e9b2999f9790392b26`); the
one-shot driver SHA-256 is
`b5a4170c01fc5f3a7ce188cbb07833c801234931a841ff6345bdedf3a5bd84c6`. This
disposable update does not publish the image or establish a production release.

The backup verifier checks the logical database snapshot and file inventory.
The backup can use SQLite locking/checkpoint-related mechanisms, so this gate
does not claim byte-for-byte immutability of the source volume. Hub backups
exclude Node subtrees; retain Node-local state and keys separately. A failure
before stop leaves the container as found. A backup or verify failure after
stop leaves the Hub stopped and skips rebuild/recreate. The installer never
removes the volume or restores automatically. A later Compose build, `up`, or
health-check failure also has no automatic restart or restore path; the Hub may
remain stopped or unhealthy, and an administrator must choose the next step
using the retained backup. Each disposable attempt removed only its own test
volume, and neither attempt targeted the resident development Hub.
