# Owner-approved IP dial locator for Node PQ TLS

Node PQ transport can use a literal IPv4 or IPv6 socket without a registered
public domain or a DNS/hosts lookup. The stable Hub ID, exact certificate DNS
SAN service identity, Hub SPKI pin, trust anchor and application origin remain
separate values. A private service identity such as `hub.example.invalid` can
be explicitly chosen for the certificate; it is an identity label and need not
resolve. Deployment procedures must still independently establish the Hub
identity, certificate trust and Owner authority.

The private Node config v2 adds `dial_address`: one canonical `IP:port` or
`[IPv6]:port`. The signed Owner leaf grant v2 adds `hub_dial_address`; the offline
`TLSPreparationRequest` and Store `NodeTLSCandidateInput` use `HubDialAddress`.
The explicit presence of that field selects v2 when preparing or reserving a
new candidate. `HubPQOrigin` remains an HTTPS DNS service origin and must match
the prepared Hub service SAN identity. HTTP requests retain that service Host
and TLS validates that SAN and pin while `pqtls.Client.DialContext` dials the
literal socket. `ApplicationOrigin` continues to bind the application-facing
logical origin and may use an IP. There is no DNS alias, proxy, alternate TLS
verifier or plaintext fallback.

Addresses reject missing/zero/out-of-range/alternate-spelling ports, unbracketed
IPv6, zones, mapped IPv4, DNS names, noncanonical IP spellings, unspecified and
multicast addresses. Private and loopback unicast addresses remain usable.
The logical service port and physical socket port are independently approved;
they need not be equal.

Owner grants, NodeControl install ACKs and HubControl activations all use version
2 with their own `.../v2\0` signature domains when an IP locator is selected.
Each enclosing proof must have the same version as its nested proof. The signed
locator is included in the immutable candidate digest, exact independent local
preparation, staged config, complete current Store authority, activation,
retained receipt and checked runtime loading. The normal Owner/device/binding,
serial, epoch, nonce, CAS and actual TLS leaf checks still apply. Public fields,
a CSR, a bearer or model-supplied claims never authorize installation.

## Compatibility and migration

DNS config/preparation/grant/ACK/activation v1 remains supported. New fields are
omitted from v1 canonical JSON, and v1 rejects any IP override. Existing signed
bytes, active state, keys, epoch floors, serial/nonce tombstones and application
replay history are retained; no v1 record is rewritten or reinterpreted. The
fixed synthetic v1 proof fixture was signed by the original implementation at
`5fb93553e56f0f6308f8cf778c2ebe49e40e4585`; current verification checks its exact
canonical public wire. It contains no private keys and must never initialize a
deployment.

Moving an existing installation to an IP locator, or changing an approved IP or
port, requires a fresh exact offline Owner maintenance cycle and a higher TLS
epoch. Reservation or issuance preserves the previous ACTIVE authority;
committed activation replaces it. Failure and crash semantics remain those of
[D1](node-tls-authority-install.md) and [checked restart](node-tls-runtime-startup.md).
Operator listener/Guard narrowing still needs its supported controlled restart.
Old binaries reject v2 private data and must not be used to read an activated
v2 installation. Upgrade Hub and Node code before that activation; repair
forward with the retained authority and floors instead of restoring older data.

No Hub schema migration, Client operation, encrypted application wire change or
application key reset is required. Client catalog 55 remains independent of
these private TLS proof/config versions. Actual Android, native model Runtime,
physical openEuler/Ubuntu machines and public HTTPS acceptance require separate
evidence. Deterministic, native socket and disposable Docker results are
recorded against their tested source by the unified checkpoint; source alone
is not a PASS.
