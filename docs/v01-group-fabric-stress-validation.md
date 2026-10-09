# v0.1 Group and Fabric stress validation

This is a bounded, offline component stress slice, not a full Hub-plus-Node
deployment benchmark or native Runtime continuity result. The final run used
dirty source at HEAD `1ad5a96414c2d888f70c5b61467b3b1e4a382a91`; the runner
recorded 946 Go files, source-tree SHA-256
`a33879ff3b8efdcf19b1c4cc0fe4c9029634c5ae4b4e1eba2b1bf405b40fd0ae`, and
`cicada-go` diff SHA-256
`64af5af620200db6c6e81b0eec94f6bd66361f727d8f68d9a530a1e22a100808`.
Do not attribute this result to HEAD alone.

The final evidence is
`.cicada-data/group-fabric-stress-20261009g/RUN.NONAUTH.json` (SHA-256
`dde4a97b54137556c76c5bf258c6008bdc9d1207084a4995f848a24a56995902`). The
runner SHA-256 was
`61146672771127219f9136c7864d3735afb3d47face332fe25348b1780d2e0b2`.
Using the pinned Go 1.27.1 image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
the separate test-binary build exited 0 in 29.831665 s. All four selected
workload stages then exited 0 in 30.623550 s, below the combined 180 s budget:
9 top-level tests passed, with 0 failures and 0 skips. Each owned container was
removed and verified absent; the six protected residents were unchanged, no
unknown running container appeared, and the Go source inventory was unchanged.

| Stage | Selected tests | Result | Workload elapsed | cgroup peak memory | cgroup CPU |
| --- | --- | --- | ---: | ---: | ---: |
| `server-broadcast-guard` | `TestRelayNodeGroupBroadcastSnapshotIsOwnerBoundAndImmutable` | 1 pass | 0.781 s | 27.1 MB | 0.675 s |
| `store` | `TestStressGroupDirectoryAndMembershipLimits`; `TestStressSameGroupBroadcastSnapshotCapAndRevocation`; `TestStressConcurrentLinkSendAskReplyAndBacklogIsolation`; `TestStressFourSendersSixteenAsksEachAndShuffledReplies` | 4 pass | 10.854 s | 34.9 MB | 11.508 s |
| `cmd-cicada` | `TestStressGroupBroadcast32RecipientPagination`; `TestStressFabricHTTPDirectory1001JoinBoundaryAndAlias`; `TestStressMachineNativeQueueSerializesSameEndpoint` | 3 pass | 13.175 s | 36.6 MB | 12.683 s |
| `control-alias` | `TestStressResolveEndpointAliasBeyondListLimitFailsClosed` | 1 pass | 1.994 s | 29.5 MB | 1.735 s |

The measured component results are bounded to these fixtures:

- Store Group and membership lists returned 100, 500, and 1,000 rows with 12
  samples per size. Group-list p50/p95 were 1.215/2.521 ms, 3.900/4.274 ms,
  and 6.321/9.148 ms; membership-list p50/p95 were 2.384/3.992 ms,
  6.348/8.220 ms, and 9.784/11.724 ms. The fixture created 1,000 Groups and
  1,000 memberships through Store methods.
- The authenticated Fabric HTTP fixture returned 100, 500, and 1,000 rows,
  with 10 samples per size and p50/p95 of 20.118/22.641 ms, 33.124/35.942 ms,
  and 51.923/56.466 ms. It joined 1,001 synthetic Endpoints through the
  production Node-join handler and confirmed that an alias duplicated across
  the 1,000-row boundary is rejected as ambiguous. This does not add paging to
  the existing 1,000-row list contract.
- The Group broadcast fixture accepted the 32-recipient snapshot, rejected 33,
  and excluded a revoked member from the next snapshot. Eight 32-recipient
  samples had p50/p95 of 233.692/246.929 ms. The separate planner test ran ten
  synthetic sweeps of eight-recipient pages; its delivery callbacks are fake.
- Relay exercised one sender at its 16-open-Ask limit and rejected its 17th
  Ask without a durable row. A separate 4-sender workload accepted 64 Asks,
  rejected the 65th receiver admission atomically, and correlated shuffled
  Replies to the exact request/message/binding. Send/Ask and Reply p50/p95 were
  195.003/362.806 ms and 84.079/163.807 ms for 40 and 16 samples respectively
  in the separate single-sender workload. In the 4-sender workload, 64 Ask
  p50/p95 were 318.739/607.683 ms and shuffled Reply p50/p95 were
  343.099/661.205 ms; throughput was 100.1 Ask/s and 92.0 Reply/s. It ended
  with 128 durable payloads, inbox rows, and claimed attempts, and 64 replied
  requests. Wrong-request Reply and wrong-attempt ACK checks remained
  negative. Sealed payloads are synthetic; this does not test Node replay
  counters, decryption, or Runtime consumption.
- The same-session writer test issued 32 concurrent operations through the
  production writer lock and durable operation path using a synthetic shell
  queue, not Codex. Each operation was recorded once, with no overlap; p50/p95
  were 447.486/831.631 ms. This is not model, provider, or native CLI
  throughput.

Measurements are component-test measurements. The per-stage cgroup values
come from the workload container's PID 1 footer before exit; test-process
high-water RSS and CPU are separately emitted where supported. The maximum
workload-container cgroup memory peak was 36,601,856 bytes. Build ran in a
separate 3 GiB container and is excluded from workload resource figures. The
containers used two CPUs, 1 GiB memory, 256 PIDs, UID 1000, no network,
read-only source/module mounts, dropped capabilities, no-new-privileges, no
secrets, and no Docker socket. Workload `/tmp` is mounted executable for the
command fixture's mode-0700 synthetic shell executable; build `/tmp` remains
`noexec`. This is a test-harness setting, not a production runtime policy
change.

Earlier attempts are retained and are not overwritten by `g`:

| Attempt | Receipt SHA-256 | Outcome and attribution |
| --- | --- | --- |
| `.cicada-data/group-fabric-stress-20261009c/RUN.NONAUTH.json` | `64a9d04e0086968726ff6211a13300fc7b1d40ee60506cff843368bfaddc8f69` | Build-stage fixture compilation failed before workload tests. Exact builder absence was later confirmed in `.cicada-data/group-fabric-stress-20261009c/BUILDER-ABSENCE-RECHECK.NONAUTH.json` (SHA-256 `bca869853515b54e40727ffdca1725cc10adc5523cf09e54ff1a524417c0e53e`). |
| `.cicada-data/group-fabric-stress-20261009d/RUN.NONAUTH.json` | `aa588ba2578deb5ccb121449a3c689eea9090fa9ab38fc24710b0709eeef4ff` | Store fixture errors: an unbound synthetic endpoint, a single sender exceeding the 16-Ask sender limit, and an attempt-state check using a privacy-filtered public getter. These were fixture mistakes, not a product verdict. |
| `.cicada-data/group-fabric-stress-20261009e/RUN.NONAUTH.json` | `9634d02c3d28648064595208e58724da4d68d5d8a45fe39280c91f801068b451` | Two Store assertions queried nonexistent `relay_v2_attempts`; the actual table is `relay_v2_delivery_attempts`. |
| `.cicada-data/group-fabric-stress-20261009f/RUN.NONAUTH.json` | `f366dcb189b36369445a821c8b033b003c3e7e0b56c801b149ab08a687529fcc` | Store passed; the synthetic queue executable was denied because workload `/tmp` defaulted to `noexec`. The Control stage was not reached. Run `g` applies the explicit workload-only `exec` correction. |

The completed command used evidence directory
`.cicada-data/group-fabric-stress-20261009g`; that directory is immutable and
the runner refuses to overwrite it. For another run, choose a new, unused
direct-child basename under `.cicada-data`. For example, only if this path does
not already exist:

```sh
python3 scripts/test-group-fabric-stress.py --run \
  --evidence-dir .cicada-data/group-fabric-stress-replay-01 \
  --go-cache-dir .cicada-data/group-fabric-stress-20261009a/alias-repro-build/gocache \
  --protected-residents-file .cicada-data/coherent-full-go-febb-20261009a/residents-before.NONAUTH.json
```

The runner requires a new evidence directory and refuses to overwrite one. It
records the exact source inventory, commands, container IDs, outcomes,
resource measurements, cleanup, and protected-resident comparison. This pass
does not establish full v0.1 acceptance, real Hub-plus-Node memory/throughput,
native Runtime continuity, model/provider behavior, real-key isolation,
Android behavior, or public HTTPS behavior.
