# Android and native Monitor joint validation on the lease-fix Hub

**Result: BLOCKED for complete joint native acceptance.** This record separates
two disposable attempts on the same clean Hub candidate. The first native
chain failed after a real local receive; the fresh attempt's Monitor tool call
was rejected by Codex automatic approval review before MCP execution. Neither
result changes the earlier `be0269e` failure in
[the historical joint report](client-monitor-native-joint-validation.md).

| Fixed component | Identity |
|---|---|
| Hub source / image | Clean `81d8f1f90895f41c4f5ea5c67a6281ccda9e1264` / `sha256:0c484d1c10a9fd71e6ae74ddd7fec85ae6ae8cbecf2ece6f90d393892990a04f` |
| Contract / catalog | `client-hub-v1.3` / SHA-256 `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Codex / model | Image `sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`, CLI `0.157.1`, `gpt-5.6-luna` |
| Go builder | Go 1.27.1 image `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244` |
| Installed Client app | Source `9568b2ff6d4e156b70484c10b7fd5195405004b0`, APK SHA-256 `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| AndroidTest APK for setup and Confirm | Source `10cd3dcb3bd73e6513df428ced81d95788e1cb84`, SHA-256 `8c2f122e76e22f6845bbdaf0518146ed94a1f6895abdab1147d3010b4c531e09` |
| AndroidTest APK for final read-only status | Test source `02cefa94bc6096f7196d1df572a22a1f64774d74`, SHA-256 `4cbc0e1ff0546b665e55136c1453334e282d19c380e26b63aa8601cd27a3f90b`; installed app remains the same |

The Hub image and contract remained fixed across both attempts. The helper,
native test binary, Client app, and AndroidTest APK have separate identities;
their test results must not be transferred between attempts. The candidate's
exact-image Docker interop ran the two real TCP Client tests and passed with
exit `0`. Its result is under
`.cicada-data/client-v13-after-lease-fix-81d8f1f/exact-candidate-interop/attempt-02/`.
The unchanged 33-operation Client contract checker also passed with exit `0`;
the helper shell syntax check passed with exit `0`. There was no protocol or
catalog revision for these test-only changes.
The setup/Confirm AndroidTest APK changes a synthetic RFC3339Nano timestamp
generator; the later APK changes only the read-only status selector. The
installed Client app bytes were retained. This joint run uses the fixed Hub's
real Control path for encrypted Client operations, not a disabled or stubbed
Control. Native model execution likewise uses the real Codex CLI and Node
adapters, not a mocked Thread.

## First attempt: native FAIL after accepted dispatch

The Client completed fresh owner/device setup, two Node confirmations, Group
creation, explicit Monitor broadcast permission, three reviewed Owner Group
proofs and encrypted Group grants, one Prepare, and one Confirm. Its later
read-only status showed two ordered `ACCEPTED` children with local
`NODE_REPORTED` and remote `RELAY_PERSISTED` evidence. Those Android/Hub
results are real but do not establish native model consumption.

The native runner came from clean `28bd4626a2f29553a07c7e0f881da6c939016c01`
and binary SHA-256
`3af7d347f2aba99d5d17366b6edcc70b631c422149434dbcf368d401064d26fe`.
It joined three real original Threads on two logical Nodes in one container:

| Role | Node | Original Thread | Endpoint |
|---|---|---|---|
| Monitor | `cgk-cgkqguzwdfu` | `01a0e193-a182-72e2-b623-0ce80af89842` | `ep_3e3ec89750af1a6b` |
| Local recipient | `cgk-cgkqguzwdfu` | `01a0e194-0194-7193-ad5f-ff9a56954213` | `ep_4d44ce8b0cc1a290` |
| Remote recipient | `cgr-cgkqguzwdfu` | `01a0e194-4d4b-72b3-a52a-c7e065141b84` | `ep_893e18f8c2d215f4` |

The original Monitor Thread sent once using only its queued approval ID. Its
one durable outbox operation was `SENT`, with two stable accepted child IDs.
The local original Thread called `cicada_receive`; the test verified the exact
sender, message ID, and body bytes returned by the tool. The subsequent
tool-disabled checkpoint stayed in the same Thread and recalled the initial
context marker, but the agent reported the child message ID instead of the
human-readable body marker. The test therefore failed at the local model
consumption assertion, exit `1` after 683.49 seconds. The remote original
Thread's model receive was **NOT_RUN**; no completed native chain marker exists.
After this failure, no approval, Join, or model turn was retried on the failed
fixture.

The restricted evidence is in `.cicada-data/native-joint-leasefix-28bd4626/`:
`native-run.json` has the actual Docker argv and exit, `native-run.private.log`
the first assertion, and `failure-analysis.json` the bounded stage and marker
booleans. `failed-attempt-sidecars/` holds only private identity/context and
approval metadata; original rollout files are retained by hash only. A
read-only scan of the disposable Hub SQLite/WAL/SHM found no raw or JSON-escaped
synthetic body or Thread context in those three files; see
`failure-scoped-hub-scan.json`. That narrow result does not prove a general
absence of sensitive text. The native container was removed after its full ID,
image and fixture labels matched (`cleanup-old-native.json`); the Client then
removed its owned old emulator, reverse mapping and marked Hub fixture. Old
Session bindings cannot be recovered after that cleanup.
The separate helper fix `1ef25baf1a5d39e51394dcb87e00ec93a6826cc8`
opened the controlling terminal as the pinned external Owner signer's stdin;
it preserved typed scope review and failed closed without a terminal. This
helper change was used for the three real signatures; it did not change the
fixed Hub image or the already compiled native test binary.

## Fresh attempt: automatic tool approval rejected

The fresh runner changes only two recipient prompts: they ask the model to
quote the first line of the body returned by `cicada_receive`, rather than a
message or receipt ID. The prompt gives neither the expected body nor context
marker. All exact body, sender, stable ID, same-Thread, and tool-free recall
assertions remain intact. It was compiled from clean
`d76e63009192422d13e0e3b413e857a27866c750`; binary SHA-256 is
`15a436025b69c85e74b6151efdc4d0414cc082ff60cd2e0b6b643b47c64ae2e8`.
Offline helper tests passed; the opt-in native test was a **SKIP** offline.

The Client's new disposable fixture completed fresh owner/device enrollment,
two Node confirmations and Group creation. The new native runner has joined
these original Threads, all at binding epoch 1:

| Role | Node | Original Thread | Endpoint |
|---|---|---|---|
| Monitor | `cgk-cgkyhdqkupy` | `01a0e1ae-4bbb-75a1-bbb6-af5bfb4207cd` | `ep_a6c7211ac299314c` |
| Local recipient | `cgk-cgkyhdqkupy` | `01a0e1ae-9fe1-7fa1-b8d5-8f6ad84a8935` | `ep_078a1d9cf8e4a88f` |
| Remote recipient | `cgr-cgkyhdqkupy` | `01a0e1af-0f93-7c23-a931-0b45c26c3e7f` | `ep_48617c7fccae3d0e` |

The Client completed fresh Group grants and one reviewed Prepare/Confirm; the
strict handoff matched the approved body digest and two original recipient
Endpoints. The original Monitor Thread resumed at its controlled safe point,
but Codex automatic approval review rejected both `cicada_monitor_broadcast`
attempts made by the model in that one turn. The review treated an
`approval_id`-only call as sending an unknown sealed payload to a destination
it did not trust by default, without the payload contents being specified to
the reviewer. Both tool events were `failed`; there was no completed MCP call,
no local Monitor outbox operation, no child send, and no native recipient
model receive. The runner exited `1` after 468.00 seconds, with no completed
native chain marker. The original three Thread IDs and binding epoch 1 were
unchanged. No model call, Prepare/Confirm, or Join was retried after this
rejection. This is a safety review block; the test must not bypass it or claim
successful native delivery.

The Client then read the original preview's status through exactly one new
encrypted status RPC. That read passed with ADB/driver exit `0/0`, JUnit
`OK (1 test)`, and reported
`APPROVED` with zero recipient outcomes. The read advanced the Client sequence
once, left no pending request, and preserved the original Confirm operation ID,
sequence, consent, sealed payload metadata and roster; it did not Prepare or
Confirm again. This is factual status after blocked native execution, not a
native delivery PASS. Redacted Client evidence is
`android-observed-status.redacted.json` and `native-observed-status.json` under
`/gpu1-share/data/cicada-client/monitor-v13-81d8f1f-recall-20260927T065926Z/evidence/`.

The actual Docker argv, container exit and private test log are in
`.cicada-data/native-joint-recall-d76e630/`. `blocked-analysis.json` records
the bounded rejection stage and original Thread IDs without copying rollout
contents or credentials. `blocked-attempt-sidecars/` preserves only restricted
identity/context and approval metadata. A read-only scan of the disposable
Hub SQLite/WAL/SHM found no raw or JSON-escaped synthetic body or Thread
context in those three files; see `blocked-scoped-hub-scan.json`. That is a
narrow at-rest observation, not a general privacy proof. The independent route
check is **NOT_RUN** because it requires native exit `0` and a final accepted
Client status; its gate was not changed to fit a blocked run. After archiving
the failure, the native container was removed with
exit `0` only after its full ID, image and owned fixture labels matched;
`cleanup-native.json` records its absence. The Client then removed its owned
reverse mapping, emulator and marked Hub fixture, each with exit `0`; the
aggregate `native-teardown.redacted.json` records cleanup **PASS** and that the
resident Hub was untouched. A final read-only check found neither disposable
Hub fixture nor native container from either attempt. No old approval, child,
or Thread was reused. Both attempts used two logical Nodes inside one native
test container with controlled safe-point
queue/resume; they do not establish two physical Nodes, unattended cold wake,
physical Android, or public HTTPS.

## Next reviewable engineering boundary

A separate candidate can offer the original Monitor Endpoint a read-only,
current-Guard preview by approval ID. It would return the exact signed body,
ordered targets, expiry and Owner approval evidence only after Node-local
trust and signature verification; the Hub would continue to handle sealed
bytes, not plaintext. It must not call the current dispatch authorization,
which changes approval state and seeds outcomes, or the current Node decrypt
helper, which durably records replay. Preview must neither send a child nor
consume approval. A later `cicada_monitor_broadcast` remains subject to its
own automatic review and current Guard. Whether the provider accepts that
review sequence needs a new real test; this report makes no such claim.
