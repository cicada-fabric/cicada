# Node enrollment and Machine capabilities

Use [distribution](distribution.md) for current checkout-based Node commands.
The Node retains its locally generated credential, submits only a digest for a
short-lived device code, and initiates outbound HTTPS/SSE. An authenticated Owner
must independently review `nodes.preview` and call `nodes.confirm`; the device
code alone is not authorization. `nodes.list` and `nodes.revoke` remain
Owner-scoped encrypted Client operations. The `/client/device` route belongs to
Client navigation; Hub does not host an approval page.

The optional Node installer defaults to relay mode. Explicit managed mode also
processes the existing authorized single-Node Worker/Monitor paths. Neither mode
joins every Thread, grants Group membership or approves work. Multi-Hub operation
uses independent Hub state/credentials and currently keeps managed work closed;
consult the exact distribution and Runtime boundaries before enabling execution.

Machine profiles record bounded OS, architecture, memory, load, toolchain,
container, network and accelerator capabilities used in scheduling. Presence of
an executable or a capability does not prove installed Runtime authentication,
native continuity or permission to execute. See [Runtime capability metadata](runtime-operation-capabilities.md)
and [harness boundary](harnesses.md).

The older `/v1/machines` inventory/registration surface is legacy plaintext
Manager HTTP, disabled when no management bearer is configured and guarded when
explicitly enabled. It is not the enrolled Client/Node security boundary. Old
anonymous curl and shared management-token agent recipes have been removed;
source and repository history retain those implementation records. Current
Node enrollment uses its own credential and Owner trust, not a Control bearer.

Physical-resource fencing requires an authenticated exact resource identity and
a matching local mapping. Lease expiry or process-group exit alone does not prove
all resource users stopped; uncertain resources retain quarantine. Back up Node
and shared writer state separately from Hub state using [Node backup](node-backup.md).
Node, actual native Runtime, Android, physical device and public HTTPS acceptance
are distinct; use the [current closeout](v01-current-closeout-20261009-validation.md).
