# CICADA Fabric membership and peer collaboration

This is the current v0.1.x entry point for Fabric. The adopted architecture is
v2.3; actual implementation and acceptance are recorded separately in the
[technical guide](v01-technical-guide.md), [status](architecture-v2-status.md)
and [completion ledger](completion-ledger.md).

## Join and authorization

Install a local Hub and optional host Node using [distribution](distribution.md).
Use a reviewed checkout; the public main placeholder is not a runnable installer.
Hub images have no Codex or provider credentials. Node generates its own local
credential, initiates outbound connections and requires separate Owner Preview
and Confirm through an authenticated Client. Installation and Node confirmation
do not join every native Thread.

MCP and the trusted Node-local Join bridge bind an explicitly joined original
Thread to a stable Endpoint and current SessionBinding. Network registration,
Group membership, roles, directory permissions, peer traffic grants and Owner
key consent are distinct. Caller identity comes from the trusted connection,
not model fields. Read [native Join self identity](native-join-self-identity.md)
and [Network contract](network-m1-contract.md) before changing these boundaries.

## Peer operations and transport

Existing MCP/service surfaces offer identity/discovery, SEND, asynchronous ASK,
correlated REPLY, receive/status/cancellation, and scoped Task and Group-space
operations. A durable ASK identity is acceptance, not an answer. Current Guard
checks exact identity, binding, scope, grants and revocation on actual operations.
Public capability discovery does not authorize a device or Thread.

The default peer route carries Endpoint ciphertext through one common HubRelay.
Local sealed delivery uses Node state and an exact native target; optional direct
transport requires the same physical host, same Codex account and a callable
exact-target native API in addition to current authorization. A shared Node
label is insufficient. Native queue acceptance does not prove cold wake,
consumption or business completion. See [Runtime limits](runtime-operation-capabilities.md)
and [native writer recovery](native-writer-recovery.md).

New plaintext Fabric SEND/ASK/REPLY and legacy plaintext inbox receive are retired;
authorized requests receive the appropriate retired-route rejection, while
unauthenticated/unauthorized requests remain guarded. Historical plaintext rows
remain historical data and are not retroactively encrypted. Do not restore an
old unsealed path to bypass Endpoint key consent. See [E2EE](e2ee.md).

Nested Groups do not inherit permission. Monitor is optional and is not a
mandatory MA→MB forwarding layer. Cross-Group/Owner Links require current
bilateral proofs; Task responsibility, Artifact access and old history remain
independently authorized. Journal/Discussion are bounded encrypted collaboration
records rather than automatic full Thread history. Exact surfaces and limits
are in the [Task privacy contract](task-peer-privacy-contract.md),
[Group spaces contract](group-spaces-m2-contract.md),
[multi-owner contract](group-spaces-multi-owner-contract.md) and
[Group directory permission](group-directory-permission.md).

## Evidence boundary

Use [current closeout](v01-current-closeout-20261009-validation.md) for real native
attempts and retained failures. Fake/synthetic tests, disposable TCP, native
Runtime, Android, physical Nodes and public HTTPS are separate evidence layers.
The latest real G1/G2 paths remain incomplete. Prior scoped PASS records retain
their tested source and do not qualify the current whole product.

The former installation recipes using curl from main, model credentials at Hub,
and legacy plaintext examples were superseded. Their prior text remains in Git
history; use the checkout-based deployment guide and current contracts.
