# Clean d86 candidate validation — 2026-10-12

**Scoped package and protocol gates passed; this is not an all-gates release.**
Producer `d86e214829db16fc7fe1df34ab6dcfca6df23b93` remains distinct from its
individual binary fingerprints, Hub image IDs and archive hashes. Software is
0.0.2, Client contract 1.6.5, wire 1, catalog 55 and SQLite schema 59. No release,
push, resident replacement or real-key rotation was performed.

## Current artifacts and actual gates

| Scope | Actual result and artifact boundary |
| --- | --- |
| Standard packages | `scripts/build-release.sh` produced Linux amd64/arm64, Darwin amd64/arm64 and Windows amd64 from clean d86. The standard metadata SHA-256 is `b25324f23dd354cd5b8f568c77751fc9c98fabcdc8ac9e91c8ee6a062dcb2eea`; Linux amd64 binary is `e5245e1a011449decdb41284326b3e4e3978def96cd38e3cd7e86213a3165a3b`. |
| PQ package | A fresh Linux amd64 Go binary was built with the accepted OpenSSL 3.5.9 headers/libraries; no older Go binary was reused. Package source fingerprint is `5399c7c9f13244da68b5d8875df599df10a8f80c3f705feb9b7651b6874c51ae`; binary SHA-256 is `3a0b1380fd835fc4515b959c52394f39f622ca0ef4d4ff6b72b58fd360651642`. The packaging run exited 0, two actual artifact tests PASS, zero skips/failures, 385.687s; this does not mean five operating systems were booted. |
| STD A2 protocol | Existing `test-client-hub-interop.sh --suite client` passed using image `sha256:d6c8545d29e9bffdc91a5411bab71328e0a7cdaccc005fd561c207462768ecc4`. Its archive shim was bypassed by the actual PATH mistake and cleanup removed the image. **No retained/importable A2 image archive exists.** |
| STD A1 retained candidate | The archive SHA-256 `5099dfda582dcdadb0a98fdc7c1df06eef47487e3c556b241ef33746d9471182` binds the distinct image `sha256:c536225d6efeb1e94a83fc44b3abc0d38f59cf266c82e53ce439f9f8b097d73c`. A1's original suite remains FAIL/tests NOT_RUN due the archive validator's OCI/config-digest assumption. Its clean labels/source fingerprint match A2 source, but it is not A2's tested IID. It directly passed the subsequent Native zero-only two-Node/two-Runtime preparation; the separate paid Board follow-ups failed before content acceptance. |
| PQ Hub/two-Node protocol | Existing relocated-package gate passed with one actual Hub and two independent shipped Node Agents: one top-level/four subtests, package exit 0/EOF, zero skips. Image `sha256:b796182fba11dd261b2fbc1ca31ac88a556282cf31090b4e0bd49712b04278b1`; retained archive SHA-256 `d80cdc3717e5764ae45c9e5b8b6f8ed5f3be7062efb26de8d8055555300e4666`. Metadata SHA-256 is `cf7253240c60871c086aff26fbafdbea22173d385c82aa1eecd9ed1aeeefc3a3`. The original outer result's cleanup assertion remains FAIL_OR_UNKNOWN; supplemental actual gate/closeout evidence resolved the lowercase Docker absence-oracle mismatch without rerunning the product gate. |

The shared generated WebCrypto manifest SHA-256 is
`679868b5f4f6f559f61dc4a5aa4fbfedb365cf7d81ce1e9edb056ced14328862`;
catalog SHA-256 is
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`.
STD binary, PQ package and Hub source fingerprints cover different domains.
Neither matching source nor a successful build transfers one image's runtime
result to another image.

Evidence remains under `.cicada-data/v00-clean-delivery-d86e214-20261012/`:
[packaging terminal](../.cicada-data/v00-clean-delivery-d86e214-20261012/packaging/run/RESULT.NONAUTH.json)
SHA-256 `874cd546393ba6299de54c43d3d28de80c91ec216992998231dcad48c3c935c2`;
[Root packaging check](../.cicada-data/v00-clean-delivery-d86e214-20261012/ROOT-PACKAGING-CHECK.NONAUTH.json);
[STD A2 result](../.cicada-data/v00-clean-delivery-d86e214-20261012/std-interop/run-client-standard-a2/result.json)
SHA-256 `ad3bed1e9d1894304b2a2f790cbe5258d5d3fc9d67aaec55b58271452b07cf38`;
[STD OCI identity](../.cicada-data/v00-clean-delivery-d86e214-20261012/std-interop/hub-image-oci-diagnostic-a2.json);
[PQ gate](../.cicada-data/v00-clean-delivery-d86e214-20261012/pqtls-interop/RESULTS.json)
SHA-256 `5acda6bc96b30b7dbb5803e8dfa2ed3d7c517a3b98449f068e39942d48bcf653`;
[PQ supplemental closeout](../.cicada-data/v00-clean-delivery-d86e214-20261012/PQ-READ-ONLY-CLOSEOUT.NONAUTH.json)
SHA-256 `1d23d035ef285e868e2f5d804ee5841ac0cbc285358f8a7fc13f7ef2eb5d948b`;
[PQ exact resource/tag closeout](../.cicada-data/v00-clean-delivery-d86e214-20261012/PQ-OWNED-RESOURCE-CLOSEOUT.NONAUTH.json).
Owned resources closed and source/six residents remained unchanged. Both
retained Hub archives are local validation artifacts, not published signed
release downloads.

## Deterministic segmented source coverage

The [final source-scoped coverage receipt](../.cicada-data/v00-clean-delivery-d86e214-20261012/full-go-store-tail-a1/FINAL-REGRESSION-COVERAGE.NONAUTH.json)
SHA-256 is `77b8db1086a6b0e5244d0f1f49dbeb60a4b69cc5f6bbafa8666bef1a747a4e60`.
Four actual JSONL logs were deduplicated by `(package, full Test name)`, counting
child events only under terminal passing parents: **1,566 top-level PASS +
1,552 subtest PASS = 3,118 PASS events; 24 top-level SKIP; zero top/subtest FAIL**.
Thirty-package segmented coverage is closed. The actual Store inventory of
487 top selectors is complete: 484 PASS, three SKIP, zero missing/FAIL, plus
502 passing subtests. Store's package PASS terminals belong to subset commands;
this is complete selector coverage, **not one full-package/full-repository
command exit 0**. Source stayed clean d86, protected residents were unchanged,
and the selected owned compiler resources closed.

The original 600s-bounded full command's `FAIL_TIMEOUT`, Store's 300.022s
package timeout, and the earlier `sleep 450` container-lifetime interruption
with exec exit 137 (`OOMKilled=false`) remain in their original receipts.
The interrupted migration selector had run only 0.366s when its inherited
package deadline expired; this does not show a 300s migration-test runtime.
The final exact 13-selector tail passed 13 top/five subtests, exit 0, completing
the union without rewriting those failures. Every skip, including opt-in
Native/Docker prerequisites, remains SKIP rather than PASS. No new Runtime,
Android, physical or public deployment acceptance is inferred.

## Upgrade and remaining acceptance

Use [the deployment instructions](distribution.md) with independently retained
Hub and Node backups. Stop managed scheduling and all writers first. Upgrade
and verify the Hub before upgrading Nodes; then reopen the existing Node state
only with the intended new binary and review identity, binding/lease epochs and
uncertain work before resuming managed scheduling. A Hub backup does not cover
Node-local identities, Endpoint keys, inbox or execution journals.

Failure after stop/build/migration/health remains a retained failed or UNKNOWN
terminal requiring operator review. Do not downgrade state fields, run an older
binary against newer state, delete directories to simulate rollback, or replay
an old uncertain attempt. No automatic retry/restore or new authorization is
implied by these candidate files.

[Native Board A6](native-board-current-validation.md) made two newly authorized
fresh batches: nine actual POSTs, two fixed TLS upstream HTTP 500s, cleanup
confirmed. Board content/Owner-consent acceptance remains NOT_RUN; upstream
error type and service cause remain UNKNOWN. Original-SID cold Runtime
recovery, complete native failure combinations, physical Android/StopVerifier
and public HTTPS are not promoted to PASS. Earlier C14, A11, Android and Worker
records retain their own tested-source scope; they are not reissued as d86
Runtime/Android results.
