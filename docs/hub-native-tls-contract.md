# Hub native TLS and numeric connection contract

Contract revision **hub-native-tls-v1** freezes the additive public connection
descriptor, secret bootstrap wrapper and shared verified HTTP transport.
The machine-readable inventory is
`cicada-go/internal/hubtransport/contract.json`. This checkpoint implements
those shared primitives only. Hub certificate persistence, CLI/listeners,
App consumers and Node consumers are subsequent implementation work; their
absence must not be reported as a usable single-Hub installation. See the
[producer validation](hub-native-tls-validation.md).

## Identity, origin and reachability

A pristine Hub may initialize without knowing its public IP or external port.
Its default logical origin is `https://h-<label>.cicada.invalid`, where label is
lowercase, unpadded RFC 4648 base32 of
SHA-256(`cicada/hub/logical-origin/v1\0` || exact UTF-8 Hub ID). The first DNS
label is 54 characters. This certificate service identity is not resolved.
The existing full Hub PQ fingerprint remains a separate trust check.

Existing READY origin, account/Owner IDs, retained application keys, epochs,
vault scope, signed request and receipt bytes are immutable. Omitted origin
on a repeat setup reads the existing origin; it never derives a replacement.
An existing loopback-HTTP scope stays in its explicit development mode and is
not reinterpreted as HTTPS. This contract adds no origin migration.

The operator's listen host/port, the user's reachable numeric DialAddress and
the signed logical origin are distinct. Neither Host, Forwarded headers,
observed local interfaces nor an unauthenticated network response can establish
an origin or pin. Numeric locators use the existing
`pqtls.ValidateIPDialAddress`: one canonical IPv4:port or [IPv6]:port, positive
canonical port, no zone, mapped IPv4, unspecified/multicast address or DNS name.
Private and loopback unicast are valid. Logical and physical ports may differ.

An explicit user locator change creates a new per-Hub transport and closes the
old idle pool. TLS still authenticates the same signed service identity, anchor
and SPKI; scope, grants and original encrypted packets do not change. No
automatic alternate address, DNS or plaintext fallback is allowed. Existing
Owner-approved Node PQ locator/epoch maintenance remains unchanged.

## Public descriptor and trusted installation channel

Descriptor JSON has exactly `claims` and `signature`, in declaration order.
Claims has exactly these fields, in this order:

| Field | Meaning |
| --- | --- |
| format, version | `cicada.hub-transport.v1`, integer 1 |
| origin | Existing exact canonical HTTPS application origin |
| hub | Complete existing Client-Control `HubIdentity`, including stable Hub ID |
| hub_fingerprint | Existing account protocol's full Hub fingerprint, recomputed |
| node_control | Complete retained Node-Control public identity, distinct from Client-Control |
| node_control_key_version | Current existing version 1 |
| transport_epoch | Positive signed-64-bit-compatible native transport generation |
| server_name | Exactly origin hostname; DNS SAN or IP SAN as appropriate |
| root_certificate_der | One bounded, self-signed CA certificate in DER; JSON standard base64 |
| server_spki_sha256 | Lowercase 64-hex SHA-256 of service leaf SPKI DER |

Claims commitment is SHA-256 of `cicada/hub/connection-claims/v1\0` followed
by Go encoding/json compact declaration-order Claims JSON. The existing
Client-Control ML-DSA-65 signer signs
`cicada/hub/transport-binding/v1\0` followed by compact JSON of the 32-byte
commitment as a fixed 32-element unsigned-integer array. Existing CIRCL-backed
sign/verify services perform the signature; no new cryptographic primitive or
Owner signer is introduced. The signature binds Node-Control to the retained
Client-Control identity and TLS profile.

The descriptor is public and contains no activation code, password, private key,
account session, Owner grant or business authorization. A self-consistent
signature is not an independent trust source. Initial trust comes from the
controlled local Hub installation channel; an existing consumer may match its
already independently retained complete Hub fingerprint. Do not accept an
arbitrary network descriptor or metadata as verified. Do not add this CA to the
system trust store or replace global HTTP transports.

Public text is `cicada-hub-transport-v1:` followed by unpadded canonical
base64url of compact canonical Descriptor JSON. JSON decoding rejects unknown
fields recursively, duplicates, null substitutions, alternate order/whitespace,
trailing data and alternate base64 spellings. Maximum decoded Descriptor is
32768 bytes; one root certificate is at most 8192 bytes. A zero validation time
permits historical parsing without a CA time assertion, never live TLS bypass.
The old App account card prefix `cicada-hub-connection-v1:` and its payload
remain unchanged and are rejected by this descriptor decoder; the existing
account-card parser likewise rejects the new transport descriptor prefix.

## Secret bootstrap wrapper

Bootstrap JSON has exactly `format`, `version`, `descriptor`, `activation_code`.
Format is `cicada.hub-bootstrap.v1`, version is integer 1. Text prefix is
`cicada-hub-bootstrap-v1:`, followed by the same strict canonical base64url/JSON
encoding, bounded to 65536 decoded bytes. The contained activation_code is the
original complete activation-v1 string, byte for byte. The inner existing v1
format, purposes, IDs, account/Owner scope, expected legacy Owner public key,
secret, epochs and expiry remain governed by the unchanged
[Owner activation contract](hub-owner-activation-contract.md).

The decoder cross-checks descriptor and inner activation Hub ID, exact origin
and complete Hub fingerprint, and runs existing activation shape validation.
`ValidateBootstrap` with current time additionally checks original expiry.
The descriptor is Hub-wide, so it invents no account/Owner claims to compare or
authorize. It never consumes the code, grants Root or bypasses the existing
atomic reservation, dual possession proof, finite grant, current Guard,
revocation, reconciliation or exact-retry state machines. Secret wrapper text
and decoded activation must never enter diagnostics or public descriptors.

App first obtains the user-entered locator and trusted bootstrap together,
validates the public trust binding offline, establishes verified TLS and
independently recomputes the live Client-Control fingerprint. Only then may it
send activation material, passwords or encrypted account requests. A fresh Node
uses the same public descriptor without any activation secret, verifies its live
Node-Control identity against the signed binding before device-code requests,
and retains the same transport for later Relay, Control, MCP/Hook and bridge
requests. Device-code approval and the manual FB-03 independent Owner peer pin
remain separate requirements.

## Shared Go API and verified transport

Package `internal/hubtransport` exports Claims, Descriptor, Bootstrap and:

* `DefaultOrigin(hubID) (string, error)` for pristine setup only.
* `SignDescriptor(hub, claims) (Descriptor, error)` and
  `ValidateDescriptor(descriptor, at) error`.
* `EncodeDescriptor(descriptor) (string, error)` and
  `DecodeDescriptor(text) (Descriptor, error)` for public material.
* `EncodeBootstrap(descriptor, originalActivationCode) (string, error)`,
  `DecodeBootstrap(text) (Bootstrap, error)` and
  `ValidateBootstrap(bootstrap, at) (hubaccountwire.ActivationMaterial, error)`.
* `MatchNodeControl(descriptor, hubID, public, keyVersion, fingerprint) error`.
* `NewTransport(descriptor, dialAddress) (*Transport, error)`,
  `Transport.RoundTrip` and `Transport.CloseIdleConnections`.
* `NewHTTPClient(descriptor, dialAddress, timeout) (*http.Client, error)`.

Constructors validate the descriptor using current time and require a canonical
numeric locator. Normal Go TLS 1.3 verification uses an explicit isolated CA
pool, exact ServerName and the live clock, with InsecureSkipVerify false.
VerifyConnection checks leaf SPKI after chain/name/time checks, including on
resumption. Offline parsing time is never installed as a fixed TLS clock.
The RoundTripper rejects any different URL scheme/authority, userinfo, fragment,
Host override or nonmatching nonempty Origin header before dialing. Requests
retain the logical URL and Host; DialContext permits only that logical socket
target and connects solely to the selected numeric address. Proxy and redirect
following are disabled. Timeout zero supports Node streaming; per-request
cancellation and bounded handshake/header waits still apply.

## Required subsequent Hub and consumer implementation

The Hub uses Go standard-library TLS/x509, a private installation CA and a
separate stable service key/certificate. It does not reuse application private
keys for TLS. Initialization uses the existing exclusive StateDir operation,
private directories, mode-0600 files and atomic durable writes. Existing
profiles with missing, corrupt or mixed-generation material fail closed;
existing application identities must also be loaded without regeneration.
Leaf renewal may reuse the same service key/CA and stable transport epoch/SPKI.
Root CA or service-key rotation requires a future explicit controlled update;
there is no ACME, CA service, automatic key rotation or changed Node PQ PKI.

The new server selector is `serve --hub-nodes-only --native-tls`; it directly
serves the Hub handler with TLS, independently of Control inference. Legacy
HTTP/reverse-proxy mode remains explicit and is not a fallback. Simultaneous
native TLS and enrolled Node PQ transport selection rejects. New setup may omit
external origin; explicit old origin behavior and original public-config format
remain compatible. Native activation issuance wraps the original v1 code;
public descriptor export never contains that code. The following CLI surfaces
are reserved for the next implementation checkpoint; this shared-codec
checkpoint does not implement them:

| Stage | CLI and selection |
| --- | --- |
| Fresh Hub setup | `hub setup --owner-label NAME --public-config FILE` may omit origin and then selects native TLS and the stable default origin; the old public-config format remains unchanged. Explicit origin without native selection retains legacy behavior. |
| Existing HTTPS Hub | `hub native-tls-init --state-dir DIR --descriptor-file NEW_FILE` adds only the local transport profile, loading all original application identities without replacement. It refuses HTTP scope or incompatible existing material. |
| Public trust export | `hub connection-export --state-dir DIR --descriptor-file NEW_FILE` reads the existing profile and writes only the canonical public descriptor. |
| One-use bootstrap export | `hub activation-issue --native-tls --purpose initial\|legacy-pending --code-file NEW_0600_FILE` wraps the unchanged v1 activation text; without native selection the existing v1 output stays unchanged. |
| Explicit Hub start | `serve --hub-nodes-only --native-tls --host LISTEN_HOST --port LISTEN_PORT --state-dir DIR` loads the saved profile and serves TLS directly, with no external origin discovery. |
| First Node pairing and explicit daemon start | `machine agent --hub-connection-file FILE --hub-dial-address IP:port ...` verifies public trust before any first request and obtains its logical control URL from the descriptor. Explicit conflicting control URL or PQ configuration rejects. |
| Later Codex connection | Existing protected local discovery retains the exact encoded descriptor and numeric locator; MCP/Hook/bridge use the same verified transport without a new daemon, new keys, default-client fallback or DNS. |

File installation, explicitly starting a Hub/Node and connecting Codex remain
separate actions. Public export does not issue an activation code or start a
service. File-only output handling may be refined while preserving the named
mode selections and original signed formats.

Once a StateDir has a native TLS profile, omitting the native selector must
reject startup rather than silently opening plaintext for that state. An
operator-requested legacy mode must be explicit. Existing legacy installations
that have never enabled a native profile retain their original behavior.

App owns its locator/public-descriptor persistence and HTTP-client lifecycle,
while preserving original protected vault scope and pending bytes. Node must
carry the verified canonical descriptor and locator through protected discovery
pins to MCP/Hook/bridge requests, including paths that currently construct a
separate HTTP client. Standard native transport and original PQ mode are
mutually exclusive with no silent fallback.

This revision does not change Client wire 1, client-hub-v1.6.5/catalog 55,
activation v1, Owner/Node grant semantics or deployed data. Standard TLS is not
a native strict-PQTLS claim. Disposable socket/Docker checks, actual single-Hub
process installation, Windows, physical machines, public IPv4/IPv6 and real
native Runtime require separately attributed results.
