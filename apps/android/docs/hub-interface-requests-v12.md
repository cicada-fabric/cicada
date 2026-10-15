# Hub v1.2 interface requests and v1.2.1 status

**Current fixed target:** CICADA Hub commit `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`, contract `client-hub-v1.2.1`, protocol archive SHA-256 `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a`, catalog SHA-256 `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`, and full image ID `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7`.

This file tracks the requests previously raised against v1.2 and their current disposition. The exact command results and evidence boundaries are in the [v1.2.1 validation report](client-hub-v1.2.1-967dbd-validation.md). The [41beaf0 report](client-hub-v1.2-41beaf0-validation.md) remains a historical record and does not establish behavior of this image.

## Resolved in the v1.2.1 contract

### Endpoint attestation signature input

The v1.2 wire prose required `EndpointKeyAttestation` v1 signing bytes to omit the `signature` field. The Hub implementation instead marshals the complete DTO with its nil `[]byte` signature, producing a final `"signature":null` property. This made the prose and implementation disagree.

The v1.2.1 wire contract now defines the exact implemented bytes: compact JSON fields in order `version, endpoint_id, principal_id, node_id, binding_id, binding_epoch, public_identity, signature`, with `signature` set to JSON `null` while producing the unsigned claims. The signature input is:

```text
UTF-8("cicada/fabric/endpoint-key-attestation/v1\x00") || compact_JSON(unsigned_claims)
```

The fixed package includes a complete public synthetic vector with signed input, public identity, proof, and proof digest. A timestamp-format bug found in candidate `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197` was fixed in commit `af3ad451e29d0c43142b3fc792272bbd6df75c84`. Corrected APK `2762a2defd13a0d85bc9a7c96647cbe626f632314ac958d4d1fe689ebd346b76` passed `EndpointAttestationVectorTest` (`OK (4 tests)`), including the full proof, synthetic manifest digests, and owner proof. The native Group preview/grant path imports an external signed proof and requires explicit Android confirmation. The owner private key is not imported into the APK; the app verifies using the owner public approval key saved from authenticated enrollment. A later disposable fixture supplied an authorized native Endpoint candidate and passed the positive Group path on a separate final APK; see the [Group acceptance report](client-group-key-v1.2.1-disposable-validation.md).

### Deterministic recovery fault cases

The fixed v1.2.1 test fixture provides deterministic recovery fault cases on a disposable Hub. The Android Client passed each case with an independent session. The uncertain case waited for `FAULT_READY` and restarted the disposable Hub before `/v2/client/rpc/recover`.

| Case | Fixed-image Android result |
|---|---|
| Accepted request remains processing | **PASS** — original packet recovery returns HTTP 409 `STILL_PROCESSING`; Client retains the same pending request. |
| Accepted request becomes uncertain after Hub restart | **PASS** — after `FAULT_READY` and restart of the disposable Hub, recovery returns a signed encrypted `OUTCOME_UNCERTAIN`; Client reconciles without issuing a second write. |
| Legacy request has no reserved response sequence | **PASS** — recovery returns HTTP 409 `RECOVERY_UNAVAILABLE`; Client fences the original packet and does not guess a response sequence. |

The scenario runner, setup/recovery tests, exits, and Git-external logs are listed in the [validation report](client-hub-v1.2.1-967dbd-validation.md#recovery-faults-on-the-disposable-fixed-image). An earlier attempt outside `/tmp` failed with HTTP 502; the corrected `/tmp` run is the passing evidence.

## Current validation gates

- **Android Group Endpoint grant on the fixed Hub: PASS.** A real native Codex Thread published the leased candidate. Final APK `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1` verified the complete manifest, accepted an externally signed Owner proof after an explicit on-device confirmation, and read encrypted `CURRENT`, `STALE`, then `PROOF_EXPIRED`. The [separate report](client-group-key-v1.2.1-disposable-validation.md) records exact evidence and narrower negative-test limits.
- **Real Node/Codex approval on this image: PASS.** One original Codex turn was accepted on the same native Thread and Worker attempt 1; one Android approval was recorded; Worker/Goal completed, Intent resolved, and `goal.result` matched the 30-byte result. Exact evidence is in the [validation report](client-hub-v1.2.1-967dbd-validation.md). This result is specific to the fixed image and candidate APK noted there.
- **Physical Android and public HTTPS: NOT_RUN.** Emulator loopback tests do not establish a device key boundary, public certificate validation, or network recovery.

The package, manifest, image-label, encrypted Android `session.capabilities`, real Node/Codex approval flow, and later disposable Group Endpoint grant passed. Each result has its own APK identity and evidence record. Physical Android and public HTTPS remain **NOT_RUN**.

### Resolved request: disposable authorized Endpoint candidate for Group grant validation

The core repository supplied `client-group-key-fixture.sh` and `client-group-key-disposable-fixture.md`. The Client used those fixed-image, disposable setup materials, then completed a real native Join and separate key-candidate publication. Android used only encrypted Hub RPCs; the Node retained its bearer and the external signer retained the Owner private key. The positive path passed on the final APK. The fixture's long Node state path exceeded the Unix socket limit; the [core handoff](cicada-core-handoff.md#core-fixture-feedback) requests a shorter real path for future runs.

The completed validation sequence was:

1. Start only the fixed image from this report with new disposable Hub and Node state; establish an independently trusted Client session and owner Grant.
2. Create a leased Endpoint owned by that session's owner and joined to a Group, then use encrypted `group.key_manifest` to return the complete `candidate_attestation`, public identity, proof digest, binding digest, membership/group/join revisions, and manifest digest.
3. Run the candidate through the final Android verifier. Sign the owner proof with the owner's external signer, import only the signed proof, and require explicit confirmation before encrypted `group.key_grant`.
4. Query `group.key_status`; for unchanged current state expect `current_status=CURRENT`. Also demonstrate that tampered proof and wrong owner/Endpoint are rejected; after acceptance, changed membership or binding should report `STALE`, and an expired proof should report `PROOF_EXPIRED`. Preserve only redacted identifiers, state, commands, exits, and digests.

This request is resolved for the one-Owner positive path. A second independently enrolled Owner is still required to prove cross-owner authorization rejection. The one-Owner fixture provided local wrong-key rejection and encrypted nonexistent Group/Endpoint business rejection; these are not counted as a two-Owner test.

## Safety constraints for future Hub work

- Keep all Client-Control requests on `/v2/client/rpc` and recovery on `/v2/client/rpc/recover`, using independent Hub pinning, OwnerDeviceGrant, and encrypted `session.capabilities`. Do not restore a legacy `/v1` bearer route as a fallback.
- Keep recovery fixtures restricted to disposable state. Android must not inspect or edit the Hub database; do not add a production RPC fault switch.
- A Group Endpoint key signature requires independent verification of the complete candidate proof and all binding/revision/digest fields. An Endpoint self-signature is not user approval.
- `external_thread_links=false` means invitation and key-consent records remain proposals; they do not authorize message delivery. Ordinary peer content is not claimed to be Hub-blind.
- Any new Hub release must be pinned by a clean commit, `source_dirty=false` manifest, protocol archive SHA-256, catalog SHA-256, and full image ID. A tag or earlier validation report is insufficient.
