# Clean Core 0213538: F10 bootstrap and cancelled acceptance

## Result

The 2026-10-03 F10 attempt established Android bootstrap and teardown only.
Core fixture preparation exited `1` because its delivery was missing
`std-producer.json`. Root closed the launcher's stdin before delivering a
business ticket; the launcher exited `1` and removed its owned emulator.
Encrypted capabilities and Link business acceptance remain **NOT_RUN**.

This record does not supersede the historical F6–F9 evidence. The
[clean delivery review](client-hub-v1.6.4-0213538-provenance.md) establishes
package and image provenance separately.

## Fixed inputs

| Input | Value |
|---|---|
| Runtime Client checkpoint | `7f428d7ce0a1c2d46e9ccecc619333d377416889` |
| Frozen product checkpoint | `508ca333c8ae90d27a8191ac828a7be16b71c7b3` |
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract | `client-hub-v1.6.4`, wire `1`, schema `57`, operations `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7`, dirty `false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interop image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| App APK SHA-256 | `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` |
| Test APK SHA-256 | `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6` |

The runtime used 21 frozen, source-derived private adapters. Their complete
SHA/size/mode/origin inventory is `B/source-inputs.frozen.json`, SHA-256
`b9fa1ba1be7fd6f2eabdb28e9f2aeed0156d6e104ea62f0fe6d25ba42a7289b0`.
This is distinct from the committed launcher and frozen APK provenance.
No APK was rebuilt for F10.

## Evidence locations

The following abbreviations describe existing local evidence, not commands to
start another attempt:

```text
B=/gpu1-share/data/cicada-client/v164-0213538-cold-client-20261003
L=/gpu1-share/data/cicada-client/v164-f10-0213538-launcher-20261003
E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f10-0213538-main-20261003/android
D=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-10-clean021-20261003/evidence/attempt-08
```

| Evidence | SHA-256 |
|---|---|
| `B/bootstrap.F10.Root-approved.private.json` | `f886f777acbe5ee6a0b37d9f8893741a68cfe77d1fdfe2210e6cc0444996d8c6` |
| `E/launcher-boot.redacted.json` | `b6dddf83c8e70749df44e17ec5605141af648e0fcea06bf5900c0619216b2e6f` |
| `E/emulator-readiness.redacted.json` | `5937fac63da4b335029687f44cc469a6f7e43a7cb8fe3e77adfc9d1f59a36459` |
| `L/command-journal.private.jsonl` | `13ddcb7ca2c646e107da2249de8196ff888d69f48b5eb5312f11071d1b136a73` |
| `L/terminal.private.json` | `7f295b874b26770d829a3e330ebf955053004b0e9bc0b8324408076dc2749070` |
| `D/stage-command-execution.json` | `205ab025570580b07fb167e7cbc29c396aa9ac084d80c52443d61fdc72c6e512` |
| `B/actual-core-stage-failure-review.redacted.json` | `8754336e0ede9d231b2791ab684945f41eed530cc22ceb8589d500617b3a932e` |
| `B/actual-client-terminal-review.redacted.json` | `e1e06082abd7ebd18dbf246437afc33ea974751597208a27376b1823a3f04bc6` |

The Client independently checked all five original Core failure references and
retained byte-identical private copies in `B/actual-core-stage-failure/`.
Original receipts were not rewritten. Core private fixture deletion is
Core-attested; the Client did not inspect a Hub database or private fixture.

## Actual commands and outcomes

Root ran the bounded launcher with `--bootstrap-plan
B/bootstrap.F10.Root-approved.private.json`, the independent SHA above and
`--execute`, retaining stdin in execution session `57570`. The original idle
cutoff was `2026-10-03T05:15:05Z`; it was not extended. The journal contains
exact argv, timestamps, durations, exit codes and stdout/stderr hashes for the
following three child commands only:

| Phase and command | Exit | Result |
|---|---:|---|
| `/usr/bin/python3 B/runtime-artifacts/scripts/interop/v164-acceptance-boot.py --run-id v16-deterministic-v164-f6-f10-0213538-main-20261003 --evidence-root E --app-apk [frozen app] --test-apk [frozen test] --idle-deadline 2026-10-03T05:15:05Z --supervisor-pid 2568221 --execute` | `0` | **PASS**, 42.594 seconds |
| `/usr/bin/python3 B/runtime-artifacts/scripts/interop/v164-link-consent-android.py E bootstrap-preflight` | `0` | **PASS**, 0.208 seconds; Hub and Root delivery explicitly `NOT_CHECKED` |
| `/usr/bin/python3 B/runtime-artifacts/scripts/interop/v164-android-deterministic.py E stop` | `0` | **PASS**, 0.865 seconds |
| Core `coordinate.py … prepare`, exact argv in `D/stage-command-execution.json` | `1` | **FAIL**, 0.630 seconds; missing delivery input |
| Root launcher terminal, session `57570` | `1` | Controlled cancellation on stdin EOF, business `NOT_RUN` |
| Client `python3 B/verify-actual-terminal.private.py` | `1` | Verifier assertion failed on capitalization of Docker's absence message; retained separately |
| Client `python3 B/verify-actual-terminal-corrected.private.py` | `0` | **PASS**, independent original receipt and cleanup review |
| Client `docker inspect [owned full container ID] --format '{{.Id}}'` | `1` | **PASS**, expected `no such object` |

Both APK installs exited `0`. Four actual `adb shell getprop` commands exited
`0`: API `35`, Android release `15`, ABI `x86_64`, emulator `1`. Readiness was
observed at `2026-10-03T04:56:17.681402Z`; canonical BOOT contains all 17 required
fields and network `none`. Original teardown retained the immediate Docker
absence race (first inspect `0`, second `1`); the independent full-ID inspect
also confirmed absence. The terminal finished at `05:02:09.110552Z`.

## Acceptance gates and next prerequisite

| Gate | Status |
|---|---|
| Frozen COLD closure and final nonauthorizing plan validation | **PASS**; original check receipt retained separately |
| Actual Android bootstrap, installs, properties and preflight | **PASS**; bootstrap scope only |
| Core one-shot preparation | **FAIL**; `std-producer.json` absent from clean delivery |
| Core finalize, aggregate READY, fresh Scope/nine references/business GO | **NOT_RUN** |
| Encrypted enrollment/capabilities, six Owner signatures, bilateral KEY/`NONE`, Target RN Alert | **NOT_RUN**, blocked by preparation |
| Client owned emulator cleanup | **PASS**, independently confirmed |
| Core owned cleanup | **PASS**, Core receipt `OWNED_CLEANED`, resources empty; private deletion Core-attested |
| Link write lost-response/409 recovery | **BLOCKED**, no approved safe driver in this lane |
| Native Worker/model, physical Android, public HTTPS | **NOT_RUN** |

No business ticket, carrier, flow selector, signing request, business packet,
operation or sequence was created in this attempt. `CORE_ACK_NOT_SENT` is
retained; the Client did not issue an early terminal acknowledgment.

Core subsequently delivered a frozen fixture-path correction and artifact
preflight. The Client independently checked and copied the three public source
files byte-for-byte. Core's separate offline preflight and metadata-shape
receipts establish their declared offline scope only; F10 remains failed.

## COLD successor handoff

The private successor directory is
`/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003`.
Six adapters now derive the fixture namespace from independently SHA-pinned
existing Rootpins and Scope/GO. The BOOT plan/receipt and Android ownership
marker have separate pins; the immutable clean delivery and APKs remain fixed.
The supervisor retains its exact 27-field Scope, nine references, owned
resource checks, one ticket and deadlines. Flow and actor waits also stop at
the minimum original BOOT/Scope/GO deadline. Original F10 files are unchanged.

| COLD gate | Status and evidence |
|---|---|
| Three Core files imported in one adjacent private directory | **PASS**, `core-source-import.redacted.json`, SHA `779f38e9745e4d2399eb9f30d2c08d8e1c5959b8d9689237b9a42df9bdb40152` |
| Six adapter edits and dependency closure | **PASS** for static source/AST checks only; final source inventory is bound in the successor delivery receipt |
| Single nonauthorizing `--check-plan` | **FAIL**, exit `1`: `Client checkout is not clean` while these formal documents were uncommitted. Original receipt `check-plan-command.redacted.json`, SHA `b1d927c6fbaec03bf41dee36465486d5d2c0193abc4dd089f15cc287806a816b` |
| Successor BOOT, Core preparation and encrypted business | **NOT_RUN** |

The check was not silently retried. Its original input and sources are retained
separately from the final handoff revision. The formal F10 closure is committed
as one checkpoint to restore a clean checkout. A new actual plan must use that
checkpoint and its own independently approved hashes before execution. No
new BOOT or business authorization is inferred from COLD preparation.
