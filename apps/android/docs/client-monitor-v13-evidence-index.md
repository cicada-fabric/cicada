# Client Monitor v1.3 — historical early-run evidence index

For the completed acceptance, final implementation and APKs, see the
[fixed-image validation record](client-hub-v1.3-be0269e-validation.md).

This index records the executed checks captured in the private evidence directory for the 2026-09-27 v1.3 interoperability run. It is a point-in-time index, not an overall acceptance statement. The evidence directory contains private fixture material; this document intentionally records no Owner, Node, Group, Endpoint, device-code, or message identifiers and no payloads.

For instrumentation records, **ADB exit** is the recorded `exit_code` for `adb shell am instrument`; **driver exit** is `driver_exit_code` from `monitor-android.py`; **JUnit** is the driver's parsed instrumentation summary. A driver `PASS` requires a successful command and a non-empty successful JUnit result. `NR` means the JSON summary did not record that value. The exact selectors below come from the recorded instrumentation commands.

## Recorded Android artifacts

The app APK hash is identical in both artifact sets. Instrumentation records identify which test APK and Client source revision were used.

| Set | Client source commit | App APK SHA-256 | Test APK SHA-256 |
|---|---|---|---|
| A | `537b92e99bf45476d8e0ea2793308cb70e8023df` | `832045f5fa2044a99f54c61534c0554abc563549937973a27c7e9e678f30315d` | `2cc6acbb9fe47427728930b8954f3c665d3f4b18d647f108dc6a87f0bf3245c5` |
| B | `586e736691d9ebcc8e672d2ecbe98ac802248f7d` | `832045f5fa2044a99f54c61534c0554abc563549937973a27c7e9e678f30315d` | `05d40d5ee8a36f8796c145f5e996911db2ed04a3e89f4e969a5d73523577b71c` |

The corresponding metadata is in each instrumentation JSON's `android_artifacts` object and the immutable hash-named artifact records. The mutable `android-artifacts.json` was subsequently replaced by later builds. Do not infer a source revision for rows marked `NR` from a neighboring run.

## Early recorded acceptance suite

These are the `acceptance-*.json` records. Every listed instrumentation command recorded ADB exit `0`, driver exit `0`, and the JUnit result shown. They cover the exact Client/Hub test selectors only; the Node and three Endpoint authorizations are synthetic protocol fixtures, not evidence of native Thread, native Monitor, Runtime delivery, or model consumption.

| Evidence record | Exact selector | ADB / driver exit | JUnit | Artifact set |
|---|---|---:|---|---|
| `acceptance-capabilities.json` | `ai.cicada.client.hub.MonitorHubInteropTest#readFixedCapabilitiesAfterAppUpdate` | `0 / 0` | `OK (1 test)` | A |
| `acceptance-group-grants.json` | `ai.cicada.client.hub.MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | `0 / 0` | `OK (1 test)` | A |
| `acceptance-prepare-roster.json` | `ai.cicada.client.hub.MonitorHubInteropTest#prepareExactTextAndReviewRoster` | `0 / 0` | `OK (1 test)` | A |
| `acceptance-confirm-status.json` | `ai.cicada.client.hub.MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus` | `0 / 0` | `OK (1 test)` | A |
| `acceptance-endpoint-vectors.json` | `ai.cicada.client.hub.EndpointAttestationVectorTest` | `0 / 0` | `OK (4 tests)` | B |
| `acceptance-monitor-vectors.json` | `ai.cicada.client.hub.MonitorBroadcastVectorTest` | `0 / 0` | `OK (5 tests)` | A |
| `acceptance-wire-vectors.json` | `ai.cicada.client.hub.ClientWirePublicVectorTest` | `0 / 0` | `OK (5 tests)` | B |
| `acceptance-recovery-locks.json` | `ai.cicada.client.hub.ClientHubRecoveryLockTest` | `0 / 0` | `OK (5 tests)` | A |

## Response-loss evidence and recovery limitation

The records distinguish a genuine Hub-accepted lost response from an earlier offline attempt. A `PASS` label alone is not sufficient to establish that the Hub accepted the request.

| Evidence | Exact selector or proxy record | ADB / driver exit | JUnit / Hub observation | Artifact set | Interpretation |
|---|---|---:|---|---|---|
| `dropped-prepare-original-packet.json` | `ai.cicada.client.hub.MonitorHubInteropTest#prepareResponseLossKeepsOriginalPacket` | `0 / 0` | `OK (1 test)` | A | Recorded `PASS`, but the original request was made while offline and was not Hub-accepted. This is not proof of a Hub response being dropped. |
| `retry-unreceived-prepare-original-packet.json` | `ai.cicada.client.hub.MonitorHubInteropTest#explicitlyRetryUnreceivedPrepareThenLoseItsResponse` | `0 / 0` | `OK (1 test)` | B | Valid lost-response evidence. `proxy-prepare-accepted-drop.private.log` records `READY` for `/v2/client/rpc` and `DROPPED` for `monitor.broadcast_prepare` with `hub_status=200`. The proxy log contains no payload in this index. |
| `recovered-prepare-accepted-200.json` | `ai.cicada.client.hub.MonitorHubInteropTest#recoverLostPrepareWithoutAnotherOperation` | `0 / 1` | No successful JUnit summary | B | **FAIL.** At verification, the Owner grant was still current (through 02:16:40 UTC) and the preview expired later. An additional Client-side full-coverage check rejected the still-current grant because it required the grant to cover the later preview expiry; Core confirmed this restriction was too strict. This is a recovery-verifier failure, not proof that the grant had already expired. Keep it distinct from the successful lost-response test above. |

An additional expired-status check, `final-recover-expired-status.json`, passed selector `ai.cicada.client.hub.MonitorHubInteropTest#recoverExpiredStatusWithOriginalPacket` (ADB / driver `0 / 0`, `OK (1 test)`, artifact set A). It verifies that expired status can be read; it does not turn the failed unexpired recovery case above into a pass.

## Earlier failed attempts

These historical records are retained even where a later acceptance selector passed. The JSON summaries for these attempts recorded ADB exit `0`, driver exit `1`, and no successful JUnit summary unless noted. A driver failure with ADB exit `0` means instrumentation launched but the driver did not observe a passing JUnit result; it is not an ADB transport failure.

| Evidence record | Exact selector | ADB / driver exit | JUnit | Artifact set | Follow-up / scope |
|---|---|---:|---|---|---|
| `final-prepare-roster.json` | `ai.cicada.client.hub.MonitorHubInteropTest#prepareExactTextAndReviewRoster` | `0 / 1` | NR | NR | Later `acceptance-prepare-roster.json` passed the same selector. |
| `final-confirm-status.json` | `ai.cicada.client.hub.MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus` | `0 / 1` | NR | NR | Later `acceptance-confirm-status.json` passed the same selector. |
| `final-recovery-locks.json` | `ai.cicada.client.hub.ClientHubRecoveryLockTest` | `0 / 1` | NR | NR | Later `acceptance-recovery-locks.json` passed the suite. |
| `kotlin-monitor-vectors.json` | `ai.cicada.client.hub.MonitorBroadcastVectorTest` | `0 / 1` | NR | NR | Later `acceptance-monitor-vectors.json` passed the suite. |
| `late-prepare-expiry.json` | `ai.cicada.client.hub.MonitorHubInteropTest#recoverOriginalPrepareAfterPreviewExpiry` | `0 / 1` | NR | NR | Historical failure; the later passing expired-status check uses a different selector and is not a pass of this case. |

The first drop-proxy startup record, `proxy-start-drop-prepare.json`, failed with Docker exit `125` because its container name was already in use. A later proxy instance used a distinct name; the accepted-prepare evidence above is based on that later proxy log, not on the failed startup.

## Scope and handling

The index covers only JSON summaries and the sanitized proxy event facts identified above. Keep the private evidence directory, raw logs, fixture state, and screenshots access-controlled. Do not copy secret or public-payload files into this index. No delivery or consumption claim follows from Hub `200`, approval, `NODE_REPORTED`, or `RELAY_PERSISTED`; those are separate lifecycle states.

This snapshot contains passing vector, prepare/roster, confirmation/status, grant, capability, and recovery-lock checks alongside a failed accepted-prepare recovery attempt. It supports no blanket claim that the full Monitor lifecycle or every loss-recovery path passed. Record later executed checks in a dated follow-up rather than silently replacing these results.
