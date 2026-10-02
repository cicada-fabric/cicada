# Authenticated Node recovery metadata query

This checkpoint adds a read-only recovery query to the existing guarded encrypted
`POST /v2/node/control/rpc` route. `node.recovery.status` uses a distinct
application cryptographic domain with the existing ML-KEM, ML-DSA and AES-256-GCM
identity envelope. It does not admit an ordinary RPC sequence. Ordinary stale
sequences remain denied.

The authenticated request binds the current Node/Hub keys, binding version and
key epoch, credential digest, fresh 32-byte nonce, saved logical Hub origin,
verified restore-manifest digest and caller-supplied immutable plan digest. At
most 16 exact operation ID/sequence/request-packet SHA-256 tuples may be queried.
The Store shares ordinary RPC's current Owner/device/credential/key predicate;
a single read transaction authenticates the proof and reads current binding,
accepted Node-Control highwater and requested durable operation states. A
conflicting ID/digest or inconsistent inbox/highwater fails closed. The encrypted
signed reply echoes the complete request and its packet digest. It exposes no
prompt, result, cached response, bearer or private key.

`cicada machine recovery query --backup DIR --state-dir DIR --writer-root DIR
--plan-sha256 SHA256 [--node-pqtls-config FILE]` requires an existing verified
archive and pending restored Node quarantine. It rejects nonprivate or symlinked
paths and incomplete lock layouts. It inspects existing databases read-only,
acquires exclusive Node maintenance and WriterRoot ownership, checks unchanged
restored bytes/modes and archive digest across the inspection handoff, and loads
existing identities/credentials without the ordinary cached key-creating loader.
Only the saved Hub origin/key pins are used. An explicit PQ transport mapping
uses the existing per-Hub HTTP helper; redirects and origin escape are rejected.
A transport/read failure allows one retry of the identical encrypted read packet.
It never recovers a pending dispatch, claims work, heartbeats or persists state.
The CLI currently queries only an existing exact restored pending RPC packet;
with none pending it returns binding/highwater metadata only.

`NOT_RECORDED` means receipt absence, including possible Hub rollback/pruning;
it never proves nonexecution. `COMPLETE` authenticates durable metadata, not
result acceptance. No returned highwater authorizes resetting any local crypto
counter, peer replay window, message ID or resource/provider history. The plan
digest is a request binding, not a new signed plan approval or authorization.
The existing approved Node private-key proof and current credential authorize
this read; a copied bearer alone does not. A read snapshot may linearize before
concurrent revocation; later reads must observe committed revocation.

Quarantine remains held. This is the first status primitive, not complete restore
reconciliation, admission repair, automatic key rotation, native retry, verified
process stop/handoff or resource-fence release. Unknown external outcomes and
incomplete forward state still require verified stop/handoff evidence. Validation
uses disposable synthetic fixtures only; it provides no native/provider/physical
or public HTTPS runtime proof. Test commands and exact source evidence accompany
the isolated patch rather than being attributed solely to its base commit.
