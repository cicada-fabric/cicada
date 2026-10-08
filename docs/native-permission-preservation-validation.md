# Native permission preservation validation

## Current scoped checkpoint — v0.1 PARTIAL

Main’s isolated normal protocol QA passed 8 top-level / 8 subtests, zero failures/skips, exit 0; command package 1.062 s / Control package 5.549 s / host 25.996 s. Race protocol QA also passed 8 top-level / 8 subtests, zero failures/skips, command package 2.276 s / Control package 86.527 s / host 115.380 s; the separate installed CLI probe passed one synthetic durable-thread cold-resume continuity/policy case. Wire assertions alone do not establish filesystem enforcement or complete Native acceptance.

### Minimal change and source

Existing-thread resume no longer supplies `sandbox`; turn/start no longer supplies `sandboxPolicy`, in [machine_codex_approval.go](../cicada-go/cmd/cicada/machine_codex_approval.go) and [control/appserver.go](../cicada-go/internal/control/appserver.go). Fresh managed thread/start retains `sandbox:workspace-write`. Approval policy remains on-request; cwd, model, exact SID checks, writer leases and management behavior are unchanged. No permissions profile is selected by the fix.

The two new wire tests, `TestManagedCodexSandboxPolicyWire` and `TestControlAppServerSandboxPolicyWire`, run the actual adapters against existing fake-process harnesses. Fresh, resumed-read-only and resumed-named-profile cases capture outgoing JSON requests: fresh defaults remain explicit; resume/turn omit sandbox overrides and named permissions while retaining approval/cwd/model/SID fields. Fake response metadata is not actual installed Native enforcement evidence.

Tested source is 926-input dirty base `a7a50d338f7328cf9cc830f4ff5190df4199ea7f` plus four owned files, not a clean HEAD build. [Source inventory](../.cicada-data/native-observer-wiring-20261007/native-policy-qa-a7a50d3-20261008a/output-normal/source.NONAUTH.json), SHA-256 `cc0a4c1879375935066c638cd1c17befa61051c81a140fb2adcfe7b0a8d08fb5`, records fingerprint `a4377e21e59a1a0c30bffa53c0159d0bd90a6e663a9f4ab1970e7d2282a6b2aa`.

| File | Frozen SHA-256 / bytes |
| --- | --- |
| cmd/cicada/machine_codex_approval.go | `6c2609513ec5b5542bbf53c503d4f4c4073e214a153cdf1f15c5fac550afbf80` / 15,483 |
| internal/control/appserver.go | `994f6f6f649d32c0eb316c3aa9dcc2360398826e9dc4c764f3b1d0327b142ddf` / 7,144 |
| cmd/cicada/machine_codex_approval_test.go | `3251ac2ac0fdba49e9acfb2b74f629019f9cfac91ee9acfe74b7e908ffcfa9cd` / 17,252 |
| internal/control/appserver_policy_test.go | `723e4748ae5d56067bc03e3ba54ec5f202b5651b5d7f62eb27d492152464d101` / 4,838 |

### Main-executed normal gate

[Command](../.cicada-data/native-observer-wiring-20261007/native-policy-qa-a7a50d3-20261008a/output-normal/command.NONAUTH.json), SHA-256 `d03ec5af3b6259c331b0a1cb6812cdf385b14954654c8ca5df964ea78de48eb8`, recorded this selector inside its disposable pinned environment:

```sh
go test -tags cicada_pqtls -mod=readonly -p 2 -count=1 -json -timeout=5m -run '^(TestManagedCodexSandboxPolicyWire|TestControlAppServerSandboxPolicyWire|TestRemoteCodexApprovalReturnsToOriginalAppServerTurn|TestRemoteCodexApprovalRejectsStaleHubAttempt|TestMachineApprovalStateDecodesNodeControlCreateAndStatusDTOs|TestControlRecoversCodexProcess|TestControlApprovalPausesUntilResolved|TestHubStartHoldsAcceptedRemoteApprovalAndCancelsOldPending)$' ./cmd/cicada ./internal/control
```

[Normal result](../.cicada-data/native-observer-wiring-20261007/native-policy-qa-a7a50d3-20261008a/output-normal/result.NONAUTH.json), SHA-256 `48e58ec465e4f1d8701bae528c8355b9a2226881afaac3cf283855d480de0044`, reports source unchanged, owned container absent and six residents’ limited metadata equal. These are locally retained ignored NONAUTH receipts, not published assets. Runtime is pinned Go 1.27.1 / accepted OpenSSL 3.5.9, offline module cache, network none, UID 1000, cap-drop ALL, NNP, read-only root, bounded executable tmpfs and owned build cache. No real Native/model call is performed by the fake-process protocol gate.

[Race result](../.cicada-data/native-observer-wiring-20261007/native-policy-qa-a7a50d3-20261008a/output-race/result.NONAUTH.json), SHA-256 `f8763a3db34203897c6b4b44701b69a58aedcd7308231fc90dcf993235af231c`, and [race command](../.cicada-data/native-observer-wiring-20261007/native-policy-qa-a7a50d3-20261008a/output-race/command.NONAUTH.json), SHA-256 `dc4f393c031c8b25a0c267611f47d470cc293506e0e72a6419cf507d31c4a930`, retain the same selector with `-race` and report source unchanged, owned container absent and resident equality. This remains fake-process wire QA.

### Separate installed CLI probe

Main’s C result is `PASS_SYNTHETIC_CONTINUITY_POLICY_PRESERVED`: exact CLI 0.161.0 SHA `9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c`, durable synthetic SID `01a11b6e-ade8-71d2-b272-6445b7610736`, one completed turn / one local synthetic HTTP request / zero paid or external provider calls. The first app-server stopped, then a new process resumed the same SID without permission overrides. Returned readOnly/networkAccess=false and on-request matched the original; persisted one-turn history retained the original synthetic prompt/reply markers. There was no second turn. These are effective metadata/history assertions, not actual filesystem/network enforcement, named-profile Native enforcement or product G2/G3 execution.

| Attempt | Retained boundary |
| --- | --- |
| A | FAIL `INITIALIZE_NOT_CODEX` before thread/start; zero synthetic HTTP. The userAgent prefix assumption was invalid. [Result](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output/result.NONAUTH.json), SHA `50f9b88598f01d8c203610105c91ce8ea174907cbba40bc12970ab4d87e2b583`. |
| B | First real synthetic turn completed, then fixture FAIL before the second app-server because its exclusive log path was reused (Main’s inspected-source diagnosis). Continuity NOT_PROVEN. [Result](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output-b/result.NONAUTH.json), SHA `899cdca6f3d71cffca23c514c5334e038d2bbf66e2ed132f5b8937319ef826d5`. |
| C | Distinct start/resume log paths only; bounded case PASS. [Result](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output-c/result.NONAUTH.json), SHA `283be57950c80cf6c8bc36b7b62aeb9e61d2c8ca0ec2c3d8381cc9305c5de15f`; [host receipt](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output-c/host-result.NONAUTH.json), SHA `a01efa60445e67c87f9c2629d07dab2aa046abcbe4f3299c96752cfaa4be20b2`. |

C’s [command](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output-c/execution-command.NONAUTH.json), SHA `5e6f31329b56f1d2b5088a85f3fc9d0ff2ab17a0eac18c67b533370b8c58ef02`, [input manifest](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output-c/input-manifest.NONAUTH.json), SHA `b1ba7ea29cc7bc4d62c0174473433ac7e78df121a53147d42cda7c6238cb21c0`, and [Main independent review](../.cicada-data/native-observer-wiring-20261007/native-policy-preservation-a7a50d3-20261008a/output-c/root-review.NONAUTH.json), SHA `281b9dd317ce670ce033fda3b33f2a23168d929224f0ae5863d831b1557cc8c8`, retain the actual fixture/source scope. The separate [Go QA review](../.cicada-data/native-observer-wiring-20261007/native-policy-qa-a7a50d3-20261008a/root-review.NONAUTH.json), SHA `7ef46966caa03b9c90ff3f4f66d8bfc26f6c03839233cff2df5dec39074d3d7c`, covers normal/race wire gates. Main verified owned cleanup and resident metadata separately; earlier failures remain immutable.

### Separate semantics and retained limits

Pinned Codex 0.161 [permission override detection](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/app-server/src/request_processors/thread_processor.rs#L285) and [persisted resume restoration](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/app-server/src/request_processors/thread_processor.rs#L4252) restore persisted active permission metadata only without a supplied permission override; turn sandbox/permissions overrides persist. Cached Rust SHA-256 `2c4786cb9b9fc2a4401d4bdd6f4af53fb18c8481cdb0277ba26c719d5f0a91e4` / 252,240 bytes is source evidence, not installed binary/source equivalence or filesystem enforcement. This motivates the omission, but the C metadata/history observation does not establish filesystem/network enforcement, every cwd/model case or named-profile behavior. No result is borrowed between the fake adapters and installed synthetic probe.

No Client protocol, DB/schema, dependency or resource policy changed. This does not establish full G2/G3 or general Worker PASS, repair namespace restrictions, explain A6, or replace strict original-thread context/reply evidence. G2 FAIL / G3 NOT_REACHED, A6 UNKNOWN, general Worker/sandbox BLOCKED, inspected V67 UNSUPPORTED and full G5/v0.1 PARTIAL remain; Client/device/public HTTPS and remaining gates stay separate. Earlier evidence and counts retain their tested source.
