# Native Board current validation — 2026-10-12

**FAIL_OR_UNKNOWN; Native Board content acceptance NOT_RUN.** The new six-manual-turn
plan reached its third attempted turn and stopped after a nonzero CLI exit.
This does not change C14, the A11 protocol/Android result, V34 Worker acceptance,
or any historical PASS. Hub backup/update has its own
[disposable validation](hub-update-backup-preflight-validation.md).
Software remains 0.0.2 / contract 1.6.5 / wire 1 / catalog 55 / schema 59.

## Current d86 A6 bounded follow-up

The latest product is clean `d86e214829db16fc7fe1df34ab6dcfca6df23b93`:
actual A1 Hub candidate `c536225d…` / archive `5099dfda…`, distinct from STD A2's
passed but unarchived `d6c8545d…` image. See the
[candidate artifact boundaries](v00-candidate-d86-validation.md).
The helper remains c292 AUX: [source comparison](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/AUX-SOURCE-EQUALITY.NONAUTH.json)
records 216/217 identical inputs, with only three unrelated Worker-result
functions changed. [A6 frozen pure QA](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/QA-A6-FINAL.NONAUTH.json)
passed 10/10; [zero preparation](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/board-prepare20261012d/TERMINAL.NONAUTH.json)
passed in 28.543s with two Node/two Runtime sparse mounts, six heartbeat 204s,
28 other HTTP 200s and zero denied/error/overflow/Control routes. Root then
approved two fresh batches, each six manual/zero automatic business turns,
32 total POSTs including auto-review/partial/failure, request/stream retries zero,
900s work + 60s cleanup / 975s outer. The [first result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/board-native20261012f/RESULT.NONAUTH.json)
failed in 27.757s on its first inference HTTP 500; the [final result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/board-native20261012g/RESULT.NONAUTH.json)
failed in 116.171s during the first exact resume, after two fresh turns and
seven HTTP 200s followed by HTTP 500. Together: nine POSTs (six main/three
auto-review), two fixed TLS upstream 500/BODY_EOF responses, no cap hit and no
third batch. Upstream error type/service cause remain UNKNOWN; a failed resume
does not prove a partial Join never committed. Both batches have confirmed
cleanup and 19/19 scoped read-only closeout checks; frozen source and six
resident full-canonical records stayed unchanged. [Exact holder closeout](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a6/OWN-HOLDER-CLOSEOUT.NONAUTH.json)
removed only the owned native holder/import-created tag and kept the archive,
earlier c292 anchor and other tags. **Overall Native Board remains
FAIL_OR_UNKNOWN; Board Owner-consent/content acceptance are NOT_RUN.** The
original c292 results below retain their original source/SHA attribution.

## Earlier c292 A5 source and scope

The Hub and host Node binary are immutable clean
`c2929fc3b66c5debf92230e1e052b8b0e35a9e80` artifacts, separate from the
Worker checkpoint `9465299e4684cb9486ebdf4489911debb20efe53` and subsequent dirty
installer work. Hub image ID is
`sha256:d69edf867632f1ac8adec83ecc689e5cdf9654505ccdd4eeb1ed489ec4e2e496`;
archive SHA-256 is
`a308731a24cc4449ab2090f6282832d22c907de0924fbd051634f2117e65f307`.
The standard Linux Node binary SHA-256 is
`dfe91204c5ff0ca7baa504b9f9c8be1c3d5fe3cd441299b74bc6d0df458d64c9`.
Official shell-installed CLI 0.162.1 has SHA-256
`628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1`.

The test-only helper is a different binary:
`b48484af936b07b01fa7d3b9e20d4d44071012676b28673c20788bc8551a3f10`.
Its [actual build receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/HELPER-BUILD.ACTUAL.NONAUTH.json)
SHA-256 is `2055c5f5c5be50873be568e4aa34ea9aacdbb869d83153ade5740e4ee5841342`:
two selected Go tests/package terminal and build passed, with exact owned
cleanup. Its 217 immutable c292 inputs plus explicit test overlay have closure
SHA-256 `a34290b9e8a285e3ae9c7e6de96b581cdbbca586bd2784470b4e077480273b8b`.
It was not rebuilt after the Python fixture corrections. The final
[freeze](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/FREEZE-A5.NONAUTH.json)
SHA-256 is `a3a2407d2ef42217bf1a7b59ee0fdfd76e5d0bf01aff45f97131c4817dd1cb11`;
[offline QA](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/QA-A5.NONAUTH.json)
passed 21 tests, zero failures/skips, exit 0/EOF.

This is a same-Owner visibly synthetic, preapproved legacy Node-binding fixture.
It is not Android, physical/public deployment, fresh enrollment or current
Worker Runtime acceptance. Actual original SID/cwd and completed MCP child
results remain required; a queue ACK, mock or HTTP success cannot satisfy them.
The Hub used production `serve --fabric-only`, which constructs no Control
business object. No new product, Client, protocol or helper Go change was made.

## Retained attempts and preparation

All paths below are under
`.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/`.
No failed receipt was rewritten or upgraded.

| Attempt | Actual result and boundary |
| --- | --- |
| A1 | Root session 7050 exited 1/EOF before bootstrap: the pinned A9 collector returns `(module, digest)`, but the fixture treated it as a module. AttributeError / cleanup UNKNOWN; no serving or model work. No inner result was written. Original source/freeze remain in `history-a1/`. |
| A3, `board-native20261012c` | `SPARSE_MOUNT_MISSING` after the first Node became ready, because empty private `endpoint-keys` preparation was omitted. Zero manual turns/provider construction; cleanup CONFIRMED. Result SHA-256 `6376bef68e1622e17313ce865b025526eaf7a10803326ff6dbb92f0468f9e02d`. |
| Prepare a | Two Node/Runtime mounts and cleanup passed, but trace recorded 7 rejected routes and 7 errors. It was not clean paid readiness; those historical observations remain unchanged. |
| Prepare b | `IMAGE_PIN_EXIT` / exact Hub image absent before bootstrap; exit 1/EOF in 1.356s. No serving resources/model work. Result SHA-256 `389b6755f6026f4ab929907d79344f40ec6e9cfcc348c15a640eda6497371b1b`. A disposable-update cleanup had removed the last temporary image tag; Root later restored the exact archived image and retained an anchor, without replacing a resident. |
| Prepare c | Exit 0/EOF in 25.640s; two real Nodes and two Runtime containers passed sparse mount checks and were removed. Both Nodes' exact POST heartbeat returned 204 (six total); the other 28 observed responses were 200. Trace denial/error/overflow were all zero. No credential reader/provider, business CLI turn or Board Owner-consent call ran. |

The clean [prepare-c terminal](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/board-prepare20261012c/TERMINAL.NONAUTH.json)
SHA-256 is `ccf12c0e7f27c0f12ff3ad8c469e629903840dd38c3ee0d3dafa0d54793377fd`;
its actual result SHA-256 is
`dfd72d408b39d3c29347a8e0afce7ff50374825dfa663737fa707b0067e680ce`.
The read-only exact-owned postcheck passed 14/14. This is startup/cleanup evidence,
not a Native Board pass. The exact heartbeat is the c292 Fabric bound-Node
liveness route; jobs and Control RPC remain refused by the trace.

## One bounded paid attempt

Run `board-native20261012e` used the same frozen bytes, six manual/zero automatic
turns, 16 total provider POST attempts including auto-review/partial/failed
attempts, retries zero, 900s work + 60s cleanup and 975s outer bound.
The [outer result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/PAID-OUTER-A5-E/RESULT.NONAUTH.json)
SHA-256 is `106fcc5e4b6e1ef4246ae4e0dbf1f102bf75551dd5c442c63efca9ae19c1a8c4`:
exit 1/EOF in 198.746s. The
[actual result](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/board-native20261012e/RESULT.NONAUTH.json)
SHA-256 is `9b1f2579a3997f41407d2c864b01c3b9678a045924404302dd50642e9f77872e`.
Two fresh CLI turns completed; the third attempted manual turn, the first exact
resume, failed `PhaseError / EXEC_NONZERO`. Eight external POST attempts were
recorded: five `gpt-5.6-luna`, three `codex-auto-review`; seven HTTP 200 and the
last main-model response HTTP 500. There was no retry or provider probe.

The pinned proxy SHA-256 is
`1e88afff1fb5c60e3e992e37bce39c2e283f8efda40e3870a80f96e341fa5586`.
Its `do_POST` records `conn.getresponse().status` at lines 343–344 and records
that same status at bounded `BODY_EOF` at line 383. Its local pre-attempt refusal
only emits 403/502 at line 391; it does not synthesize 500. Therefore this
recorded 500/BODY_EOF is an actual fixed TLS upstream response, not a local
handler-generated 500. Error type/body and service root cause were not retained:
**UNKNOWN**, with no balance, permission or quota inference.

The actual peer trace also observed one Fabric `node/join` HTTP 201, whoami and
key-publication HTTP 200s. The failed CLI exit does not prove Join never
committed, nor does HTTP alone prove the required ordered MCP completion.
Two joined Endpoint projections and Board Owner authorization were not reached;
Journal author/correction, Discussion/topic/reply, reader cursors/unread and the
committed Board oracle are **NOT_RUN**. The earlier C14 and protocol results
cannot close this new Native scope.

Cleanup is CONFIRMED with no errors. The
[read-only postcheck](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/PAID-OUTER-A5-E/READONLY-POSTCHECK.NONAUTH.json)
SHA-256 `175bec421c06191c069846f484a7b1632cc0de0139a9b7f12f6b71f1b274f226`
passed 17/17 scoped checks: exact Hub/two Runtime IDs and names, label, Node and
outer PID/groups, socket closeout, unchanged frozen source/six residents and
retained exact Hub anchor. The full controller did not record the removed short
root pathname: its original dev/inode/marker check and deletion support its
CONFIRMED result; the postcheck does not invent an independent pathname check.
The [closed summary](../.cicada-data/v01-next-gates-20261011/native-direct-audit/native-board-prep-a1/A5-ACTUAL-CLOSEOUT.NONAUTH.json)
SHA-256 is `95f6f990ec75ce0fffdca02f951e753cdfa98acbb9c0709d0c5027407ec9ee9c`.
No resource/model retry or release is implied; Root manages the remaining image
anchor separately.
