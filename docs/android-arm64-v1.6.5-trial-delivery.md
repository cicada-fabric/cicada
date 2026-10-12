# ARM64 Android debug trial delivery — Client-Control v1.6.5

## Artifact and provenance

The phone package was built from clean Client commit
`0351ee5d01f13158533f56c4c4cf1959ab9c1ebc` on `dev/react-native`.
No protocol, security, application or dependency source was changed for this
build. The later documentation checkpoint is separate from the APK producer.

| Item | Actual value |
| --- | --- |
| APK | `/gpu1-share/data/cicada-client/v165-0351ee5-arm64-debug-trial-20261012/cicada-client-v165-0351ee5-arm64-debug.private.apk` |
| APK SHA-256 | `158e9fe72e660324aed2325a70b45582130244398d5ead03b7906c9cce61b90c` |
| APK bytes | `85,681,811` |
| Package / version | `ai.cicada.client` / `0.1.0-dev`, version code `1` |
| Actual native ABI | Only `arm64-v8a`; all 17 libraries are ELF64/AArch64 |
| Manifest min / target / compile SDK | `26` / `36` / `37` |
| Signature | Android debug signature verifies, exit `0` |
| JavaScript | Bundled in `assets/index.android.bundle`; no Metro required |
| Contract | `client-hub-v1.6.5`, wire `1`, catalog `55` |
| Catalog SHA-256 | `a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9` |
| Producer source inventory | `635` tracked inputs; SHA-256 `e251998370cff45d14d8a8cd07e8e8a2ab7283a42b06ec0233e193e03cd3bcbc` |

The imported catalog digest was independently recomputed. Both the contract
revision and catalog digest are present in the actual APK DEX. This static
check does not replace an authenticated runtime `session.capabilities` check.
The app version and Core's software version identify different artifacts;
this debug package is not a store release.

## Build and static verification

The existing Gradle architecture override produced this APK without source
changes. The pinned Docker builder is
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
Docker root was `/gpu1-share/data/docker-root`; build caches remained under
`/gpu1-share/data/cicada-client`. The container ran as the server UID/GID,
with `--pull=never --network none`, and was confirmed absent after completion.

```sh
gradle --offline --no-daemon --project-dir /workspace/android \
  -PreactNativeArchitectures=arm64-v8a :app:assembleDebug
```

The build exited **0** in **32.3852 seconds**. The producer was clean before
and after the build, and all recorded source bytes remained unchanged. Only
the product APK was built; the historical x86_64 app/test pair is preserved.

The existing `scripts/audit-android-apk.py` ran in the same network-disabled
builder with `--single-abi`, NDK `llvm-readelf` and Android `apksigner`.
Packaging audit exited **0** in **2.2192 seconds**; `aapt2 dump badging`
exited **0** in **0.5661 seconds**. ZIP paths and each ELF machine header
both identify ARM64, rather than relying on the requested Gradle property.

Evidence root:
`/gpu1-share/data/cicada-client/v165-0351ee5-arm64-debug-trial-20261012`.
`DELIVERY.NONAUTH.json` joins the APK, actual build argv/exit/log, immutable
builder, source inventory, static audit and manifest output. A local summary
reader's initial use of the older `sdkVersion` label
was corrected to the actual `aapt2` `minSdkVersion` label without another build.

## Acceptance scope

| Check | Result |
| --- | --- |
| Clean ARM64 build, ABI/ELF, manifest and debug signature | **PASS**, static packaging only |
| Installation and launch on an actual ARM64 phone | **NOT_RUN** |
| Actual phone HTTPS, independent Hub identity pin and OwnerDeviceGrant | **NOT_RUN** |
| Actual phone encrypted capabilities/RPC and key lifecycle | **NOT_RUN** |
| Actual phone local speech models and resource limits | **NOT_RUN** |

Root separately reported A7's eight Link-policy status/restart cases **PASS**
against clean Core c2929fc and producer 0351ee5, using the immutable x86_64
pair. Its evidence is under Core's
`.cicada-data/v00-clean-delivery-c2929fc-20261012/link-status-fixture-prep/v165-link-policy-status-core-a7`.
That result remains attributed to that pair and emulator, including the two
COMPLETED original-packet recoveries and exact cleanup. It does not establish
physical Android, public HTTPS, Native model consumption, a foreign-Owner Hub
Guard or nonempty uncertainty recovery. No models or online fixtures were
started for this ARM64 build.

The trial Hub/Node deployment and exact new Hub public identity belong to
Root's separate trial delivery. A matching catalog alone grants no trust.
Phone HTTPS, independent full identity pinning, purpose-scoped enrollment and
encrypted session authorization retain their existing checks; packaging adds
no fallback, credential or permission.
