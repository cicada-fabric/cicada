# Machine capability discovery

Control registers two local records at startup: `control-local` and
`worker-local`. Their capability maps are collected from the running process and
include OS, architecture, CPU count, `/proc/meminfo` memory, available
toolchains, container runtimes, compilers, `/proc/loadavg` 1-minute load,
free/total disk space for the workspace mount, a network-up indicator, and an
accelerator class. When `nvidia-smi`, `rocminfo`, or `npu-smi` is available,
Control records CUDA, ROCm, or Ascend/CANN model information and aggregate
memory where the tool reports it; otherwise the accelerator is explicitly
`cpu`.

Inspect the current inventory:

```bash
curl http://127.0.0.1:8787/v1/machines
```

For a Node that can make an outbound connection to Hub, run its resident agent
on that Node. It generates and keeps its own Relay bearer, submits only a
digest to Hub, and prints a short-lived device code. The owner confirms it
through an enrolled Client using encrypted `nodes.preview` and `nodes.confirm`:

```bash
cicada machine agent --id gpu2 --name 'GPU server 2' \
  --control-url https://hub.example --state-dir /var/lib/cicada-node --relay-only
```

The checkout installer uses this relay-only behavior by default. Opt into the
single-Node managed Worker and Monitor notice handlers only when that host is
intended to execute its authorized local work:

```bash
CICADA_CONTROL_URL=https://hub.example \
CICADA_MACHINE_ID=gpu2 \
scripts/install-cicada-worker.sh --mode managed
```

Managed mode uses the same Node-scoped bearer and does not auto-join, enroll or
approve a Thread, Group or Node. The Owner still confirms the displayed device
code; multi-Hub agents remain relay-only.

The `/client/device` verification path is reserved for the separately developed
Android Client and is not a Hub-hosted approval page yet. Node Relay calls do
not start until owner confirmation. Remote HTTP is rejected for Node enrollment;
loopback HTTP remains usable for an isolated development Hub. The Node uses
outbound SSE wake hints, durable claim/receipt and an authenticated heartbeat,
so Hub does not need to connect inbound to Node.

For local-network discovery, opt a machine agent into the unauthenticated UDP
profile responder and query it from the operator host:

```bash
cicada machine agent --lan-discovery --lan-port 8788
cicada machine discover-lan --port 8788 --wait 2s
```

LAN discovery returns non-secret profiles only and never registers or trusts a
machine automatically. It does not replace the owner-confirmed Node binding.

A remote worker can register its own capabilities through `POST /v1/machines`,
refresh liveness through `POST /v1/machines/MACHINE_ID/heartbeat`, and claim
Workers assigned by Control. Goal
resources use the same capability names: `os`, `arch`, `accelerator`,
`min_memory_gb`, `harness`, and `required_harness`. Control excludes stale or
unavailable records before selecting a machine; `max_load_1m`,
`min_disk_free_gb`, `required_toolchains`, `required_container`, and
`network_required` reject machines that cannot satisfy an explicit constraint.

For a machine that can reach Control, the bundled agent registers, sends the
same non-secret profile on a heartbeat interval, and executes queued Codex or
Shell Workers:

```bash
CICADA_MACHINE_ID=gpu2 \
CICADA_MACHINE_NAME='GPU server 2' \
CICADA_CONTROL_URL=https://control.example \
cicada machine agent --interval 30s
```

Use `--once` only after the Node is already bound; a first run prints a code and
returns without accepting Relay work until approval.
The agent reads `CICADA_API_TOKEN` when Control authentication is enabled and
retries result delivery without declaring the Machine available in between; it
never logs the token or private network addresses. The complete execution and
shared-workspace contract is in
[`remote-execution.md`](remote-execution.md).

Managed Node Workers do not reserve the whole host by default. A Worker only
uses the physical-resource execution fence when its authenticated Hub claim
contains `resources.physical_resource_id` and that exact canonical ID is also
configured locally as `CICADA_NODE_RESOURCE_ID` (for example, `gpu/0`). A
missing or mismatched local mapping fails closed before starting the provider.
If a Worker completes but the Node cannot prove that every process using an
explicitly leased resource has stopped, it reports the business result and
keeps that resource quarantined. A process-group exit alone is not stop proof;
the quarantine blocks later jobs for that same resource but does not retain the
Node's single Worker claim slot or block jobs that use no physical resource.
There is currently no automatic release of an unverified quarantine.

The discovery code records executable paths and interface names, never command
output, IP addresses, or credentials. GPU and disk probing have short
timeouts; missing utilities degrade to an empty capability map or CPU-only
capabilities.
