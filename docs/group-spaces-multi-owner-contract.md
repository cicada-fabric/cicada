# Multi-owner Group Space consent candidate

**Status:** unreleased v40 candidate. Hub admission/Join and dual Owner key routes, plus Node-local proof verification, are implemented in this dirty source tree. Final whole-repository and disposable transport acceptance is pending. This does not change M2's same-owner acceptance or the shipped Client v1.4 contract.

## Authority chain

One authoritative Hub and one ACTIVE Network own each Group. A foreign Owner's Endpoint first needs its own current Network enrollment. The Group Owner creates an exact restricted Membership through an encrypted Owner request with a Group revision and prior Membership revision. Grants must include `space.read` and can add only `space.write` or `space.moderate`. The Endpoint Owner separately consents to the current Node/native binding, then that same Node performs a fresh trusted Group Join. A key proof creates none of those relationships. The current native SessionBinding, Node credential, binding epoch and local writer remain independent checks.

The Endpoint Owner's encrypted Join consent must include `shared_context_risk_acknowledged:true`. Group ACLs do not clear an existing native model's memory, so the reused Thread may retain information from other Groups. The current entry allows reuse only under `group_scoped` context policy; dedicated, sensitive or unknown policies fail closed. The Node/MCP actor cannot acknowledge this risk for the Owner.

The Endpoint publishes a self-attested key candidate for its current native binding. Two different human Owners then approve the **same** immutable manifest:

1. The Endpoint Owner consents to this key being used for exactly this Group and the listed space actions.
2. The Group Owner admits that Endpoint and key into this Group's reader/writer policy.

The manifest binds Hub, Network, Group and Group revision; Endpoint and Principal; both Owners; Node, binding ID and epoch; Group Membership and Endpoint Join revisions; candidate key ID/version/fingerprint and full self-attestation; action set and expiry. Each Owner signs the manifest digest and key binding digest with the existing ML-DSA Owner proof primitive under a new operation and distinct signer side. The Hub accepts proofs only through current encrypted Client requests from the corresponding Owner and rechecks all scope versions in the same transaction. The Node pins and verifies **both** Owner identities independently; Hub acceptance alone is not a local trust decision.

Same-owner M2 grants keep their v1 semantics. A cross-owner reader enters a new write snapshot only after both current proofs pass. Every prepare, commit and read rechecks current Network, Group grants, Endpoint Join and session/Node fences. The Hub stores only encrypted reader envelopes and bounded metadata. Revoking the admission removes the restricted Membership and Endpoint Group Join and invalidates Join consent and both key proofs in one Store transaction. Re-admission requires the exact previous Membership revision, fresh Endpoint Owner consent and two fresh signatures. Changing a key, revoking either Owner proof or changing the Group revision prevents new writes and connected reads. Already delivered plaintext cannot be recalled.

## History and visibility

The existing `read_from_seq` cutoff still starts at explicit Join. Neither proof grants pre-join history. Cross-owner old history requires a separate exact-record dual-Owner decision and re-encrypted material from a current prior reader; it remains denied until that extension is implemented and validated. Parent/child Groups do not inherit readers or keys, and citing an Artifact does not grant access to it.

The Group Owner may review a proposed recipient only within its own Group and Network. An Endpoint Owner may review only its own Endpoint. Neither side gets a global directory, full reader roster or another Owner's private Thread locator through the consent preview. Client public capabilities state availability; they do not authorize a device. Android implementation remains owned by `../CICADA_CLIENT`.

## Wire and failure rules

The seven new encrypted Owner operations in the single candidate `client-hub-v1.5` catalog are `space.foreign_member_admit`, `space.foreign_member_revoke`, `space.foreign_endpoint_join`, `space.key_manifest_v2`, `space.key_consent_v2`, `space.key_admission_v2` and `space.key_status_v2`. The accepted Client device request durably binds its authenticated route operation in the same transaction; public capability listing and a model-side MCP call are not Owner approval. The two key writes accept only `{group_id,endpoint_id,owner_key_id,signed_proof_base64}`; the Hub reconstructs the current manifest rather than trusting caller-supplied scope. Duplicate exact proof returns the prior result; altered proof or stale scope conflicts. If one proof succeeds and the other is absent, the Endpoint stays unavailable for cross-owner board writes. No plaintext fallback or same-owner signature substitution is allowed.

The v40 gate covers same Hub/Network and explicit Group joins; independent Owners; complete attestation and fingerprint; both signature sides and Node-local public key pins; current revision, binding and key; exact retry; revocation; late-join history denial; and Store migration rollback. Android, real native Runtime, physical devices and public HTTPS are separate evidence layers. A skip is not a pass.
