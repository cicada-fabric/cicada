# Windows Owner approval with external OpenSSL

This opt-in helper supports public-key adaptation and device-grant signing for
the existing software 0.0.3 Hub, wire 1, catalog 55 and `client-hub-v1.6.5`.
It is compatible with the existing Hub enrollment/registration path and does not
require replacing an existing Hub image or trusted device keys. Its executable has separate
source/build fingerprint and SHA-256 attribution; use the reviewed helper artifact,
not an assumed published release. Actual Windows execution, Windows ACL enforcement
validation and physical Android enrollment remain **NOT_RUN**; native Windows
secure-storage adaptation remains **NOT_IMPLEMENTED**. WSL is not required.

All URLs, paths and IDs below are placeholders. `HTTPS_HUB_URL` is the final
trusted HTTPS application entry chosen by the operator. Owner key generation and
custody remain with the user and external OpenSSL; the helper neither creates keys
nor imports/converts private PEM. Use a fresh local folder with user-controlled
access, outside Documents/OneDrive/cloud synchronization/shared folders. OpenSSL prompts for the
encryption passphrase; put no secret or seed in arguments, environment variables,
Hub uploads or online converters. Run commands individually and stop on any error.

## 1. Generate encrypted keys and export public SPKI on Windows

Use the absolute path of the user's installed OpenSSL 3.5.9 executable; the example
path may differ. `New-Item` must succeed for a new folder: never regenerate over an
existing Owner identity. The [OpenSSL genpkey](https://docs.openssl.org/3.5/man1/openssl-genpkey/)
and [pkey](https://docs.openssl.org/3.5/man1/openssl-pkey/) commands provide key
generation/encryption and public-key export.

```powershell
$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
$Helper = 'C:\CicadaTools\cicada.exe'
$OwnerDir = Join-Path $env:LOCALAPPDATA 'CicadaOwner-fresh'
New-Item -ItemType Directory -Path $OwnerDir -ErrorAction Stop
Set-Location $OwnerDir
& $OpenSSL version
& $OpenSSL genpkey -algorithm ML-DSA-65 -aes-256-cbc -out owner-signing-private.pem
& $OpenSSL genpkey -algorithm ML-KEM-768 -aes-256-cbc -out owner-kem-private.pem
& $OpenSSL pkey -in owner-signing-private.pem -pubout -out owner-signing-public.pem
& $OpenSSL pkey -in owner-kem-private.pem -pubout -out owner-kem-public.pem
& $Helper owner-key from-openssl --kem-public owner-kem-public.pem --signing-public owner-signing-public.pem --output owner-public.json
```

The two private files are encrypted PKCS#8 PEM and stay on this laptop. The last
command reads only `PUBLIC KEY` SPKI and prints `key_id` and the complete public
identity fingerprint. Independently verify these before registering
`owner-public.json` on Hub; public-file adaptation is not Owner authorization.

## 2. Obtain the exact Owner Human Principal ID and register its public key

`OWNER_ID` is the independently confirmed Human Principal ID. The Client-Control
public key ID shown by `/v2/client/identity` is a different identity; a private
identity JSON is not an ID lookup source. There is no existing public Manager-ID
lookup command. For an independently known fresh Hub with only its default
creator Owner, an operator may use this optional read-only check on the Linux
Docker host during a stopped-Hub maintenance window:

```sh
docker stop cicada-hub
CICADA_BOOTSTRAP_STATE=$(docker volume inspect --format '{{ .Mountpoint }}' cicada-hub-state)
python3 - "$CICADA_BOOTSTRAP_STATE/cicada.sqlite3" <<'PY'
import pathlib, sqlite3, sys
db = pathlib.Path(sys.argv[1])
if db.is_symlink() or not db.is_file():
    raise SystemExit('refused: existing regular database required')
wal = pathlib.Path(str(db) + '-wal')
if wal.exists() and wal.stat().st_size:
    raise SystemExit('refused: nonempty WAL; no Owner ID returned')
with sqlite3.connect(db.resolve().as_uri() + '?mode=ro&immutable=1', uri=True) as conn:
    rows = conn.execute("SELECT id FROM principals WHERE kind='human' AND status='active' AND owner_id=id AND (trust_domain_id='' OR trust_domain_id=id) ORDER BY id").fetchall()
if len(rows) != 1:
    raise SystemExit('refused: exactly one candidate required; no Owner ID returned')
print(rows[0][0])
PY
docker start cicada-hub
```

Restart the same stopped container after this read-only check even if lookup
refuses. Run as a host user allowed to read the volume. Refusal requires inspection, not
WAL deletion or selecting the first row. A sole eligible row is only a candidate;
the fresh/default-creator prerequisite and Owner association must be independently
known. With multiple Humans, use an independently known Manager Owner ID.

Transfer only `owner-public.json` to an operator-selected public-file location.
Replace the public-file placeholder below with its verified absolute host path;
mode `0644` makes this public file readable by the Hub image's runtime UID (normally
1000). Do not change permissions on any private key. Under a chosen stopped-Hub window,
run the existing 0.0.3 image's local command against its retained state volume:

```sh
CICADA_OWNER_IMAGE=$(docker inspect --format '{{ .Image }}' cicada-hub)
chmod 0644 /ABSOLUTE/owner-public.json
docker stop cicada-hub
docker run --rm --network none \
  --mount type=volume,src=cicada-hub-state,dst=/state \
  --mount type=bind,src=/ABSOLUTE/owner-public.json,dst=/owner-public.json,readonly \
  "$CICADA_OWNER_IMAGE" owner-key register --db /state/cicada.sqlite3 \
  --owner-id OWNER_ID --public /owner-public.json --expect-key-id REVIEWED_OWNER_KEY_ID
docker start cicada-hub
```

This one-shot container retains the original image's ENTRYPOINT (including the
optional PQ image's binary path), state volume and read-only single-public-file
mount. Its local Store lease
is shared, so the chosen stopped-Hub boundary is operational, not an exclusive CLI
stop guard. Restart the original Hub with its retained volume afterward; do not
reinitialize state or upload either private PEM.

## 3. Pin Hub and copy the phone's public identity

In the current APK, open bottom **我的 → 连接与安全**, enter `HTTPS_HUB_URL` and read
the public candidate. Independently obtain/verify the Hub ID and **complete Control
public identity JSON**, then fill both and select **核对并固定 Hub 公钥**. The pin field
needs the full public JSON, not only a key ID or URL response copied as a trust root.

Select **生成 / 读取设备公钥身份**. The current UI displays selectable bare public
JSON; there is no enrollment-manifest export button. Copy that exact JSON into a
UTF-8 `device-public.json` on the laptop. Choose one unique `DEVICE_ID`, retain the
same value for signing and phone enrollment, and keep the generated phone identity.

## 4. Prepare and independently review one manifest

```powershell
& $Helper owner device-enrollment-prepare --device-public device-public.json --owner-public owner-public.json --owner-id OWNER_ID --hub-id PINNED_HUB_ID --device-id DEVICE_ID --output device-manifest.json
```

This public-input helper constructs the existing enrollment manifest and prints its
complete fields, including `device_key_fingerprint`. Review Owner ID, Owner key ID,
Hub ID, Device ID, device public key ID and full fingerprint against the independent
Owner/Hub inputs and the exact phone JSON. Its calculated fingerprint does not
independently establish trust, and it never guesses the Owner ID or signs approval.

## 5. Sign with OpenSSL and paste the exact proof bytes

Choose an explicit current UTC expiry no more than 24 hours ahead, written as
`YYYY-MM-DDTHH:MM:SSZ`. Replace every expected value with the reviewed tuple above:

```powershell
& $Helper owner device-grant-sign-openssl --owner-public owner-public.json --signing-private owner-signing-private.pem --openssl $OpenSSL --manifest device-manifest.json --output owner-device-grant.json --expect-owner-id OWNER_ID --expect-owner-key-id REVIEWED_OWNER_KEY_ID --expect-hub-id PINNED_HUB_ID --expect-device-id DEVICE_ID --expect-device-key-id REVIEWED_DEVICE_KEY_ID --expect-device-fingerprint REVIEWED_FULL_SHA256 --expires-at REVIEWED_UTC_EXPIRY
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $OwnerDir 'owner-device-grant.json')))
```

Review the scope printed before OpenSSL asks for the passphrase. OpenSSL alone
opens the encrypted signing PEM; the helper verifies its returned signature and
writes a new canonical proof file without overwriting. The second command encodes
those exact file bytes as **standard padded base64**; do not reserialize its JSON,
paste raw JSON, use URL-safe base64 or submit the signer's summary as the grant.

On the phone, fill Owner ID, Owner key ID, complete `owner-public.json`, the same
Device ID and that base64 string, then select **验证 Grant 并登记此设备**. Successful
authenticated enrollment/session capabilities determine the role and permitted
operations. If the response is lost, use **原样恢复设备登记** with the existing identity
and request; do not regenerate keys or sign a replacement to hide an uncertain result.

This enrollment does not approve a Node, Join a native Thread, grant peer keys or
establish enrolled Node pure-PQ TLS. Those remain separate approved operations.

## Validation scope — 2026-10-13

The tested helper source is dirty `2a5791e`, with unchanged pre/post build inputs:
standard `source_fingerprint_v4` is `ecc00877af17b5fa2f5db0935496128772897e6b23681b0a9499b0937c919dcd`.
The [input inventory](../.cicada-data/external-owner-openssl-20261013/windows-build/input-inventory.json)
has the separate inventory-domain digest `9b12b2e436f522bff7b49b008f3651e7b2f2e393c4a5e6d135f7615540f78272`.
The [QA receipt](../.cicada-data/external-owner-openssl-20261013/qa-20261013-a1/QA-RECEIPT.md)
records focused tests passed 12 top-level/47 subtests and vet passed; full `e2ee` regression
passed 47/134 with its optional actual-OpenSSL case explicitly SKIP, while existing
Owner CLI/local-operator regressions passed 8/8 combined. The separate actual OpenSSL 3.5.9 gate passed
Linux interactive encrypted-key signing, production-handler enrollment and
[exact-image TCP compatibility](../.cicada-data/external-owner-openssl-20261013/qa-20261013-a1/actual-openssl-gates.exact-image-tcp.private.jsonl)
against the original `ab2362f` Hub image
`sha256:1d8cf76c59bfb6919748f8911d07ee991c46658e9a9c4be82b0dedc93796aa71`.
That synthetic receipt (2 top-level/6 subtests PASS) has SHA-256
`dcbea084106d8344af86395b5e49864f0866cc8a59c9e5dba46e2250fc128ac6`;
it covers refusal, exact retry and encrypted snapshot/recovery, not user deployment.
The earlier pre-test `noexec` preparation failure remains recorded separately.

From `cicada-go`, a focused actual-OpenSSL reproduction is:

```sh
go test -count=1 -json -run 'Test(OwnerDeviceGrant|OwnerDeviceExternalSigner|NewPublicIdentity|OwnerOpenSSL|OwnerKeyFromOpenSSL)' ./internal/e2ee ./cmd/cicada
CICADA_TEST_OWNER_OPENSSL=/ABSOLUTE/verified-openssl-3.5.9/bin/openssl \
  go test -count=1 -run '^(TestExternalOwnerOpenSSLRealSignatureInterop|TestOwnerDeviceOpenSSLActualCoreEnrollment)$' ./internal/e2ee ./cmd/cicada
go vet ./internal/e2ee ./cmd/cicada
```

The default fixture is synthetic production-handler/TCP testing. Exact Docker
image replay additionally uses `CICADA_TEST_EXTERNAL_OWNER_HUB_URL`,
`CICADA_TEST_EXTERNAL_OWNER_HUB_DB`, optional synthetic-only
`CICADA_TEST_EXTERNAL_OWNER_HUB_TOKEN`, and
`CICADA_TEST_EXTERNAL_OWNER_DISPOSABLE=SYNTHETIC_OWNED_FIXTURE`; prepare a disposable
fixture instead of pointing these at a resident Hub/state. Go 1.27.1 full CLI
`CGO_ENABLED=0 GOOS=windows GOARCH=amd64` cross-build also passed under network-none.
Actual Windows/ACL execution, physical Android and public HTTPS remain **NOT_RUN**.
