# IP locator, ARM64 PQ TLS and first-install checkpoint

This is the local checkpoint plan. [Current preflight evidence](docker-ip-arm64-validation.md)
and [manual operator steps](node-tls-first-install-cli.md) are recorded separately.
The clean d86 software 0.0.2 trial and its historical results retain their own
attribution. The next unified checkpoint targets software 0.0.3. Client wire 1,
the 55-operation catalog and Hub schema 59 remain separate identities.

## Implementation seams

| Lane | Owned work | Required boundary |
| --- | --- | --- |
| IP locator | Node transport, Owner TLS claims, Store and Node wire | Canonical IPv4/IPv6 locator is signed independently of HubID, service SAN and SPKI pin; no DNS resolution or hosts substitution. |
| ARM64 PQ | OpenSSL build target, packaging and explicit user-mode QEMU | Actual AArch64 product binary and target OpenSSL; no binfmt registration, privileged container or standard TLS fallback. |
| First install | Local operator CLI, independent Owner signer, new Docker fixture and evidence | Existing enrollment/Guard plus exact Prepare, Reserve, external Grant, Issue, Stage, Install ACK, activation and remotely confirmed Apply. |

Implement and test the interface before producing the final packages. Freeze
product build inputs, build the Hub and both Node packages, then run the new
isolated gate against those exact artifacts. Record fixture-source identity
separately and preserve every failed attempt. Root owns the implementation checkpoint commit, clean artifact build and later
validation/delivery checkpoint. Software is now 0.0.3; package results remain pending.

## First-install authorization sequence

1. Initialize fresh isolated Hub state. Independently generate the Owner identity
   on the Owner's trusted signing machine and register only its public key on Hub.
2. Enroll a Client device using the existing signed Owner device grant. Start each
   Node's current public-key pairing request and explicitly review/confirm the
   exact pending candidate through the authenticated encrypted Client path.
   Pending credentials and possession/device codes supply no approval.
3. Independently pin Owner public trust on each Node. Export the approved full
   binding for initial TLS preparation with an authenticated, purpose-bound
   offline HubControl-to-Node envelope. Match the existing approved local keys,
   binding and a Node-generated nonce; never copy Hub SQLite state to a Node.
4. Prepare a fresh dedicated TLS key on the Node; reserve the exact CSR, serial,
   epoch, issuer, Hub identity and IP locator at Hub. Transfer only public claims
   to the independent Owner signer for explicit exact-file digest review.
5. Return the canonical Owner grant to Hub. Issue and commit the public leaf,
   stage on the Node, return its NodeControl-signed ACK, and commit activation
   using the existing independently approved HubControl identity.
6. Restart the isolated Hub with the approved peer narrowing configuration.
   Node Apply must obtain a new signed, encrypted current-authority response over
   its exact staged strict PQ TLS transport; a supplied ACTIVE bundle is never
   sufficient. Start the product Node from checked active.json.
7. Joining a native Thread/Network/Group remains a separate explicit action.

This manual trusted-operator ceremony does not supply an Android TLS Owner
approval UI, automatic renewal or a production CA/key ceremony. The independent
Client repository currently has no TLS-leaf-grant signer; record that follow-up
without changing its source or silently substituting device approval.

## Bounded local acceptance matrix

| Scenario | Required evidence | Initial status |
| --- | --- | --- |
| Fresh enrollment | Empty Hub DB; actual encrypted Owner-device enrollment and Node pairing; pending denial | NOT_RUN |
| Independent first TLS install | Separate Owner signer and Node keys; exact reservations/grants; Stage/ACK/activation/Apply | NOT_RUN |
| IPv4 and IPv6 sockets | IP-only locator, no DNS/hosts override; unchanged HubID/SAN/pin checks | NOT_RUN |
| Identity refusals | Wrong HubID, SAN, SPKI pin, locator, changed signed locator and old epoch denied | NOT_RUN |
| Two isolated Nodes | Separate network namespaces, both outbound to one Hub; no Node-to-Node access | NOT_RUN |
| Fabric-only | Product Hub without Control business; real NIST transport and application ciphertext | NOT_RUN |
| Restart/offline recovery | Hub/Node restart, offline queued delivery, original-ID retry and ACK dedup | NOT_RUN |
| ARM64 product | Actual packaged binary under explicit QEMU plus amd64 Node | NOT_RUN |
| Native Runtime, physical phone, public HTTPS | Separate external acceptance | NOT_RUN |

All tests default OFF. Use synthetic keys in private throwaway roots, exact owned
cleanup, container labels, finite timeouts and CPU/memory/PID bounds. Resident
services, existing volumes, real keys, accepted OpenSSL stages and Client sources
remain outside the disposable fixture. No model/provider call is needed for this
protocol/deployment gate; mock native consumers do not prove Runtime consumption.
