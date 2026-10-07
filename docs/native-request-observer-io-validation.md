# Native request observer I/O validation — 2026-10-07

Final latest-CLI checkpoint (Oct 7): one retained image build, three separately authorized network-none CLI-only checks. The first two strict failures remain immutable; the third passed with exact PATH-selected CLI 0.160.1 and matching companion hashes, empty stderr, and exact owned-container absence. Only the two verified original context binary copies were removed. Companion was hashed, never launched. No Native Runtime session, protocol/observer readiness or model execution was tested; the paid entry remains blocked by LATEST_RUNTIME_NOT_READY. Historical 0.160 fixture proofs are not latest-CLI readiness.


The optional closed I/O sink passed **37 offline methods (8 new + 29 frozen compatibility), 0 failures/errors/skips**, and the default-off CLI check. This is offline evidence only; v0.1 remains **PARTIAL**.

[scripts/native_request_observer.py](../scripts/native_request_observer.py) now accepts an optional `io_sink=None`. It records fixed TCP_CONNECT, PROXY_CONNECT_SEND/READ and TLS_HANDSHAKE phases, the first failure before `plain.close`, and at most three separate cleanup failures. Each failure samples the local shutdown-requested flag at catch time; a bounded local sequence supplies ordering without a cross-Runtime clock claim. Diagnostics contain no exception messages, payloads, headers, paths or arbitrary type names. Optional diagnostic failure does not change the original failure control.

Publication occurs outside the observer lock, before releasing busy/idle ownership, with unconditional ownership release on diagnostic failure. A deterministic blocked-sink/concurrent-quiesce test verifies that drain and the next handler cannot advance before publication. The original v1 record shape, POST send-attempt counter, forwarded bytes and TLS behavior are preserved; POST attempts do not prove provider acceptance.

The new tests use AF_UNIX and injected transport/TLS doubles, with external operations denied before fixture construction. The 29 compatibility methods use the frozen Checks source with only its observer module path redirected. Neither scope proves real TLS/proxy parity, native readiness, model completion or G1. No shipped product dependency, configuration, schema, wire or capability changes are included.

Tested source SHA-256:

- Observer: `160873a002d53c50a6fe1b203d9c9aeb69744254965cd6f7f3e73cb19452848a`.
- [New tests](../scripts/test_native_request_observer.py): `b4fd46578b4ae32b1f112d8657210b04f62283dc5151541fdeb78229844da7ef`.

Root evidence:

- [Offline checks and default-off CLI](../.cicada-data/native-observer-io-20261007/root-offline.NONAUTH.json), SHA-256 `c5b373a21cdbeacd065d1b66b516d1d5bd51610cbb62f8c90392bd980053c23a`.
- [Frozen forwarding compatibility](../.cicada-data/native-observer-io-20261007/root-forwarding-compat.NONAUTH.json), SHA-256 `9c7fd6caaa4ee77685a0c6702492f769a6fdcae0ca006d2965fcc528079c91ea`.
- [Corrected preservation verification](../.cicada-data/native-observer-io-20261007/root-preservation-v2.NONAUTH.json), SHA-256 `98dec9378b32dedb27d8531909bf380ba5f88132c4dccc9d5523e989d1cc6f4c`: 926 Go inputs, frozen eight files and existing dirty 31 paths unchanged. Go and Docker interop were not rerun. The retained initial verifier receipt had a type/raw-mode comparison error; its correction is not a product-source failure.

The actual Oct 5 `349bd71f…` remains A1 FAIL / A3 NOT_REACHED, provider cause UNKNOWN and partial POST accounting. Original cleanup=false / A EOF UNKNOWN remains distinct from independent absence of nine owned objects. This implementation does not reclassify that result; its GO/deadline is expired.

The standalone `validate_io_diagnostic` is the required validate-before-sibling-export boundary for future wiring. At the primitive checkpoint no Runtime hook was wired. The subsequent offline wiring checkpoint below validates installed synthetic boundaries; it does not prove live Native readiness or authorize an actual run.

## Oct 7 wiring — offline only

The new codec and promoted helpers passed **7 IO methods + 8 guard methods**, each with 0 failure/error/skip; the installed full-object regression passed **4 ordering cases** and removed its owned temporary state. These are additional offline scopes, not a new 37-method result or Native PASS. The first IO positive fixture and first promoted guard assertions failed; their receipts remain retained, and only the fixture/assertion corrections were retested.

The Runtime bootstrap uses ordinary pinned imports of both observer and IO codec, explicit IO opt-in, and the original `Observer(io_sink=...)` boundary. The sibling sink validates before canonical 0600/O_EXCL output (16 rows, 2048 bytes each, 32768 total). Existing quiesce seals admission/success/failure counts without another wait. Runtime export validates rows and watermark before stdout; the host independently checks that watermark, ordinal v1 association and the POST before/after chain. A pre-send failure can retain the same POST counter. Missing, failed, nonsealed or mismatched evidence—including an absent sibling field—is UNKNOWN; it does not change the original v1 report or upgrade POST/provider/native acceptance.

Actual Root commands from repository cwd (sterile PATH=/usr/bin:/bin, LANG=C.UTF-8, PYTHONDONTWRITEBYTECODE=1; IO suite additionally PYTHONPATH=scripts):

```sh
/usr/bin/python3 -B -m unittest -v test_native_request_observer_io.IOChecks
/usr/bin/python3 -B scripts/native_observer/request_observer_wiring_checks.py
/usr/bin/python3 -B scripts/native_observer/request_observer_wiring_checks.py --reproduce-fixed-ordering
/usr/bin/python3 -B scripts/native_observer/request_observer_run.py --preflight --binding-sha eb2eaf6b402c4753615e444f7ed6694fc6ddfe2041918d008423cecb6471f3a9
```

[IO7 receipt](../.cicada-data/native-observer-wiring-20261007/root-io-suite-v2.NONAUTH.json) (`19514661…`) and [installed four-case receipt](../.cicada-data/native-observer-wiring-20261007/root-installed-ordering-v1.NONAUTH.json) (`4ff4dea6…`) retain tested binding `f72cec42…`. [Final guards8](../.cicada-data/native-observer-wiring-20261007/root-wiring-guards-v2.NONAUTH.json) (`05e0d25b…`) and [final preflight](../.cicada-data/native-observer-wiring-20261007/request-observer-wiring-preflight-root-v3.NONAUTH.json) (`86d479a2…`) bind [tested historical public sources](../.cicada-data/native-observer-wiring-20261007/binding-eb2-historical.NONAUTH.json) `eb2eaf6b…`. The functional helpers, codec, IO tests and effective sources are identical across those bindings; the checker successor only corrects stale assertions. These commands used no actual Runtime, provider, model or credential access.

The unchanged 0.160.0 fixture/preparation is historical evidence. Its NONAUTH template has false execution flags and zero expiry/cutoff; it cannot authorize a live run. Main requires the installed 0.160.1 CLI for the next actual test: fresh Runtime/image/CLI/protocol pins and separately reviewed preparation are still required. The offline wiring proofs did not build or run a Runtime; the separate latest-CLI image checkpoint below retains its own failure attribution. Next is review of that minimal refresh proposal and wiring, then exactly one separately bounded actual run only if Root issues fresh pins, budget and GO.

## Latest CLI image inventory — third CLI-only check PASS


Version inventory: repository new-build default is 0.160.1; historical fixture/image preparation is 0.160.0 and remains unchanged. The retained image contains the shell-installed musl CLI and matching companion. Neither companion execution nor TLS/proxy/protocol/G1 readiness is proven.

[Build result](../.cicada-data/native-observer-runtime-161-20261007/cicada-runtime-161-20261007a/result.NONAUTH.json) `1b755978…` stopped at the pre-create absence-format guard. [Check result](../.cicada-data/native-observer-runtime-161-20261007/cicada-runtime-161-20261007acheckonly/result.NONAUTH.json) `b97370e8…` has byte-exact expected stdout but failed strict stderr validation. [Retained failed-check reference v2](../.cicada-data/native-observer-wiring-20261007/latest-runtime-161-reference-v2.NONAUTH.json) is NONAUTH, expiry/cutoff zero. No second build occurred. The separately authorized [second check result](../.cicada-data/native-observer-runtime-161-20261007/cicada-runtime-161-20261007bcheckonly/result.NONAUTH.json) `93911a69…` and [second execution receipt](../.cicada-data/native-observer-runtime-161-20261007/cicada-runtime-161-20261007bcheckonly/execution-receipt.NONAUTH.json) `95ffe2c3…` preserve its strict FAIL and exact container absence. Both failed results and v1/v2 references remain historical evidence; the third PASS is recorded below.

## Final binding and readiness guard

The current public binding is `e7b1c48a78b519ef1fb2c671c0ad3b392331e7653252b309b7adc9552f4d41a9`. Root's [read-only preflight v2](../.cicada-data/native-observer-wiring-20261007/root-latest-preflight-v2.NONAUTH.json), SHA `b091ec66859214387f99dd6985f46de3fc5fe6a7bdd3923aceb50b3911ca9e33`, passed exact source binding. This checks the historical 0.160 wiring dependency domain, not latest 0.160.1 Native readiness. The [initial stale-row failure](../.cicada-data/native-observer-wiring-20261007/root-latest-preflight-v1.NONAUTH.json), SHA `a214a4abfb360459dc3e8ded2a4f3c8570592ddd5cd6aa98e666b8fd97554be9`, remains retained: binding `1f16…` still had the pre-guard run pin in its public-files map. Correcting that metadata did not change source or retag any offline proof.

Root's [latest-not-ready guard receipt](../.cicada-data/native-observer-wiring-20261007/root-latest-not-ready-guard.NONAUTH.json), SHA `8d90a63a6a179ba1ad2a9e34b83bc87285f50ee5b802772d139e3a85d71b5f87`, confirms execute/main block before file, network, process or helper attempts. The [independent second-check review](../.cicada-data/native-observer-wiring-20261007/root-cli161-second-check-review.NONAUTH.json), SHA `90aa15f8e9dfb15e296541a3751050c557d71905e5170182db9b4a3b208cf575`, confirms exact stdout, strict FAIL, image labels and owned-container absence. Neither receipt authorizes paid execution or proves Native readiness.

## Final latest-CLI evidence

[Third result](../.cicada-data/native-observer-runtime-161-20261007/cicada-runtime-161-20261007ccheckonly/result.NONAUTH.json) `f1b73a57…` and [execution/deletion receipt](../.cicada-data/native-observer-runtime-161-20261007/cicada-runtime-161-20261007ccheckonly/execution-receipt.NONAUTH.json) `e424bb22…` retain strict PASS and exact two-file removal. [Current v3 reference](../.cicada-data/native-observer-wiring-20261007/latest-runtime-161-reference-v3.NONAUTH.json) supersedes v1/v2 without overwriting either. The image remains an artifact; Native/protocol/observer readiness is NOT_RUN and no GO exists.

Root [independent final CLI check review](../.cicada-data/native-observer-wiring-20261007/root-cli161-final-check-review.NONAUTH.json) SHA `1b8a773f4186a8aa474a970fedd442b7359501caf9058d3c276964de70a64e6c` verifies 21 result files, exact container absence, image and context deletion. [Frozen-source preflight](../.cicada-data/native-observer-wiring-20261007/root-source-frozen-preflight.NONAUTH.json) SHA `f38b920b4e631e8756169ac3b831251b7cbfebc5b3612252e0ed4c126b2a6b67` checks source `63e557e7…`, paid guard `8c10227f…`, binding `e7b1c48a…`, default NONAUTH, shell syntax, two default literals and historical 0.160 wiring only. [Protected state](../.cicada-data/native-observer-wiring-20261007/root-final-protected-state.NONAUTH.json) SHA `69f3225e4bb24289fa7587bc0dd87b2b92f509c1a08d5c85483390f9c80411b5` preserves 174 paths, dirty31, HEADs/dev and no staged files. These do not upgrade old eb2/f72 scopes or establish Native readiness.
