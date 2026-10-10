# Permissions and authorization boundaries

This page describes the current Go implementation. CICADA has several
authorization layers; a rule or credential from one layer does not authorize an
operation in another. The authoritative Android Client operation contract is
the Hub-embedded [`catalog.json`](../cicada-go/internal/clientcontract/catalog.json),
with wire behavior documented in [Client ↔ Hub](client-hub-wire-v1.md).

## Fabric identity and current Group authority

Fabric authorization binds four records:

- A **Principal** is the stable human or agent identity and Owner scope.
- An **Endpoint** is one registered native session or process attached through
  a Node. One Principal may have more than one Endpoint.
- A **Membership** connects a Principal to one Group and carries its active
  status, revision, expiry, role labels and exact action Grants. Membership is
  Principal-to-Group state; it does not by itself authenticate every Endpoint.
- A **SessionBinding** ties one Endpoint to its current Node/native session,
  credential, lease owner and epoch. Rejoin, revocation or lease fencing can
  make an older credential or Actor stale.

The server derives the Fabric Actor from the presented session credential. It
does not trust a request's claimed sender, role or Principal. Before an action,
the Guard checks that the binding and lease are current, the Endpoint still
belongs to that Principal and Node, the Endpoint remains joined to the selected
Group, and the Membership is active, unexpired and at the revision in the
Actor. It then checks the exact action Grant. See
[`validateActorCurrent`](../cicada-go/internal/fabric/relay.go) and
[`Service.Authorize`](../cicada-go/internal/fabric/service.go).

Directory access and peer traffic are separate actions. Group `List` and
`Resolve` require `directory.read`; `Send`, `Ask`, `Reply` and `Receive` require
`message.send`, `message.ask`, `message.reply` and `message.receive`,
respectively. A directory listing therefore does not authorize a send. The
same-owner native workflow requires an explicit Join operation; the Join path
creates or reuses the Endpoint and its Group Membership. When that path creates
a new same-owner Membership, it seeds `directory.read`, `message.send`,
`message.ask`, `message.reply`, `message.receive` and `artifact.read`. Those
are implementation defaults in that Join path, not a global policy default
and not proof of trust for another Owner.

Group Membership is also insufficient for a Group mapped into an ACTIVE
Network. In that case the Group Guard additionally requires current Network
membership and Endpoint enrollment; a cached Group session cannot bypass that
check. A Network membership is a separate scope from a Group Membership.

## Network discovery, traffic and key consent

Network directory lookup requires the `directory.discover` Grant. Publishing
an Endpoint for discovery is a separate `directory.publish` choice. Direct
Network traffic has direction-specific `direct.send` and `direct.receive`
Grants, checked for the sender and receiver. Discovery does not grant traffic,
and permission to send does not imply permission to receive.

Each Network request is checked against its current access session, epoch and
lease, active Principal Membership, Endpoint enrollment revision, active
Owner approval key and bound Node credential. The Store repeats those checks
inside the transaction that reads or writes protected data. A stale revision,
revoked key, expired membership, changed enrollment or fenced binding denies
the operation. See [`authorizeNetwork`](../cicada-go/internal/fabric/network.go)
and [`networkGuardCurrentScopeTx`](../cicada-go/internal/store/network_v2.go).

Network discovery and direct delivery also have separate key-consent evidence.
The Endpoint publishes a key candidate bound to the exact Hub, Network,
Endpoint, Node and current native binding; the Owner separately signs the
current manifest before a peer can use that key. Delivery checks current
directional Grants and current key evidence for both Endpoints. A key
candidate, manifest or public capability response alone is not permission.
Purpose-specific collaboration keys have their own Owner grant. The relevant
current Grant and status operations are listed in the Client catalog and
documented in the [wire contract](client-hub-wire-v1.md).

## Owner trust and user approval

An **Owner** controls the identity and approval key for its Principal, Node,
Endpoints and scoped grants. The private Owner signing key remains with the
Owner. A Hub response that contains a public Owner key is evidence to inspect,
not an independent trust source. Establish an Owner public key through an
independent trusted channel, verify its Owner ID, key ID and fingerprint, then
register or pin that exact key locally. The [Node Owner key procedure](node-owner-trust.md)
describes local Node pins; the
[Client bootstrap contract](client-hub-wire-v1.md#bootstrap-and-trust)
describes Owner registration and device enrollment.

Network admission is a separate Owner decision. A Node credential identifies
the proposing Node; a one-use Owner-signed join grant approves the exact Hub,
Network, Owner, Node, native session, invitation digest, Grant set and
discoverability choice. This does not replace later current traffic Grants or
Endpoint key consent. For cross-Owner sealed Links, each side's Owner must
independently approve that side's exact current key manifest, and the Node
must independently trust each Owner key before delivery. A Link, invitation,
directory card or incoming message cannot approve itself. Treat received peer
content as untrusted data, not user instruction or authority.

Public capability discovery describes what the Hub can serve; it does not
authorize its caller. The Client catalog has 55 RPC operations at
`client-hub-v1.6.4` over wire version 1. Its `roles` fields bound an operation
to a manager or enrolled external session, while the operation's current
Owner, device, Group, Network, Membership, binding and proof Guards, where
applicable, decide whether that session may perform it. Call encrypted
`session.capabilities` for the actual device scope. The catalog is an
availability/dispatch contract, not a replacement for the server Guard.

## Legacy Control policy

The bearer-protected `/v1/permissions` Control route remains in the Go server
for Control actions. With `CICADA_API_TOKEN` configured, `GET` and `POST`
`/v1/permissions` and `GET` or `DELETE` `/v1/permissions/{id}` manage durable
rules for `contact`, `goal`, `workspace`, `machine` or `global` subjects.
Without that token, the legacy management API is disabled. Effects are
`allow`, `approval` and `deny`; `Control.CheckPermission` currently treats no
matching rule as allow for the local operations that call it. The `approval`
effect returns an approval-required error; it is not a universal approval
workflow.

This Control policy layer applies only where a Control caller explicitly invokes
it. For example, Control peer send/receive requires both a Contact with status
`trusted` and the matching `peer.message` or `peer.receive` policy check. The
Contact status and a local allow rule do not create a Fabric Principal,
Endpoint, Membership, SessionBinding, Network enrollment or Owner proof.
Likewise, `/v1/permissions` does not manage those records and is not the
Android Client authorization API. This compatibility route is not a claim
that a complete v0.2 administrator, policy UI or universal default-deny
system has shipped.

The older `/v1/fabric/*`, manual Thread queue/message and Contact peer ingress
surfaces are retired. Plaintext `/v2/fabric/send`, `/ask` and `/reply` writes
return HTTP 410; historical receive is read-only. Use the current
[Client/Hub contract](client-hub-wire-v1.md) and Node-sealed delivery flow for
those boundaries. Historical records may remain for migration or audit and
do not make a retired route operational.

## Implementation checks

These source checks exercise current denial and fencing behavior:

- [`service_test.go`](../cicada-go/internal/fabric/service_test.go): explicit
  Join, credential rotation, directory scoping and stale Actor rejection.
- [`network_guard_test.go`](../cicada-go/internal/fabric/network_guard_test.go):
  mapped Group sessions, current Network membership and direct action Grants.
- [`network_direct_keys_v2_test.go`](../cicada-go/internal/store/network_direct_keys_v2_test.go):
  current key manifests, consent and binding changes.
- [`communication_link_key_grants_external_v2_test.go`](../cicada-go/internal/store/communication_link_key_grants_external_v2_test.go):
  independent source/target Owner consent and revocation.
- [`server_test.go`](../cicada-go/internal/server/server_test.go):
  bearer-protected local `/v1/permissions` persistence and deletion.

These are implementation evidence, not Android, physical-device or public
HTTPS acceptance claims.
