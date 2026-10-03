# Node PQTLS MCP metadata bridge validation

When `CICADA_NODE_PQTLS_CONFIG` selects the checked Node PQTLS transport, MCP
Fabric metadata calls (`whoami`, `find`, `resolve`, `inspect`, and
`heartbeat`) cross the existing owner-local Node Agent Unix socket. The Agent
checks the native session record, selected Hub origin and Node identity, then
uses its existing current-authority-checked transport and the caller's
session credential. Protected MCP routes fail closed when that bridge or
transport is unavailable. Standard non-PQTLS MCP routing is unchanged.

`CICADA_PQTLS_DIAGNOSTIC_FILE` is optional and off by default. When set, the
Node records bounded JSON lines only for connections made by the selected
checked transport, using the connection's actual `PQTLSState`. It records
public request/message correlation IDs, a route class, negotiated profile,
peer identity and certificate/SPKI fingerprints, connection reuse, and
Relay SSE ready/wake event names keyed to the same per-request observation ID.
The observation ID is not a physical socket identifier; the separate reuse
flag reports whether Go reused the connection. It never records request bodies, session or
Node credentials, ciphertext, or message history. The target must be a new
file in an existing owner-only mode-0700 directory; the file is created
exclusively with mode 0600, no symlink following, and a finite 4096-record /
8-MiB limit. Sink errors do not change authorization, routing, or request
results. Linux also verifies the current UID; on other platforms the opt-in
writer relies on private directory permissions and exclusive creation.

The tagged `TestPQDistributionActualHubNode` packaging gate includes a
current-authority fixture for the owner-local MCP bridge. It uses synthetic
OwnerDevice and Node authority, performs no model, provider, or native-runtime
calls, and is not evidence of a live native Thread roundtrip. A future live
acceptance still needs its own bounded approval and must separately record
actual protected Ask/Reply and SSE connection evidence.
