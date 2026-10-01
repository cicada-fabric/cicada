# Disposable Client Network fixture

Create a local Hub fixture from an explicit clean Hub build record:

```bash
scripts/client-network-fixture.sh setup \
  --build-metadata .cicada-data/v01-checkpoint-20260930T133728Z/clean-build.json
```

The script checks that the metadata is `cicada.hub-build.v1`, clean, bound to
the checked Client catalog, and names an image present in the local Docker
store. It also compares the exact image ID and its revision, clean-source,
source-fingerprint, catalog and Hub-role labels. There is no unpinned or
historical f308 default. Keep the build metadata file: the fixture marker
records its image ID, revision, fingerprint, catalog digest and contract
revision so `grant` and `cleanup` do not depend on whichever build is current
later.

Setup creates one disposable Hub with a single synthetic API token, two
independent synthetic Owner keypairs, and one ACTIVE Network per Owner. Owner
private keys stay in the host-only `owner-private/` directory with mode 0600;
the Hub mounts only its SQLite state and workspace. Setup stops the Hub for
operator CLI provisioning, verifies both Networks from the same SQLite file,
then restarts the same image against that file. It checks that the Hub public
identity and both ACTIVE Network rows recover. The returned localhost port is
fixed in the marker and can be reused for later container restarts. This is
fixture recovery evidence, not an Android or peer-message acceptance result.

`client-public.json` contains public Hub, Owner and Network identifiers plus
the exact build pins. It deliberately does not contain a device grant. To
create one from an offline signer and manifest, use:

```bash
scripts/client-network-fixture.sh grant /tmp/cn.XXXXXXXX \
  --signer /path/to/cicada --manifest /path/to/device-manifest.json \
  --device-id DEVICE_ID --device-key-id DEVICE_KEY_ID \
  --device-fingerprint SHA256 --expires-at 2026-09-30T18:00:00Z
```

This signs for the primary Owner. Add `--owner foreign` before `--signer` to
sign for the second synthetic Owner. The grant is written to a separate
mode-0600 file and is never automatically registered or trusted. The signer
must enforce the exact Hub, Owner, device identity and expiry. Use a fresh
fixture for another grant of the same Owner.

Inspect the fixture marker and current Docker labels before cleanup. Cleanup
refuses a changed/unowned container or network, then removes only the named
fixture container, network and its `/tmp/cn.XXXXXXXX` directory:

```bash
scripts/client-network-fixture.sh cleanup /tmp/cn.XXXXXXXX
```

Focused metadata and image-label rejection tests run with:

```bash
python3 -m unittest scripts/test_client_network_fixture.py
```
