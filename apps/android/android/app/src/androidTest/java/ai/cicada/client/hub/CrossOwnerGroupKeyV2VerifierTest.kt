package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * Frozen from CICADA/cicada-go/internal/e2ee/testdata/cross-owner-group-key-v2.json.
 * Observed source SHA-256: 0cc1f40baf754870f36da1ba0a28be9b60036186ef1c02ed2aa6de64d29d778c.
 * It is a public synthetic WIP vector, not a pinned production contract or live-auth result.
 */
@RunWith(AndroidJUnit4::class)
class CrossOwnerGroupKeyV2VerifierTest {
    private val validAt = Instant.parse("2026-09-30T12:05:00Z")
    private val fixtureBytes by lazy {
        InstrumentationRegistry.getInstrumentation().context.assets
            .open("cross-owner-group-key-v2.json").use { it.readBytes() }
    }
    private val fixture by lazy {
        assertEquals(
            "0cc1f40baf754870f36da1ba0a28be9b60036186ef1c02ed2aa6de64d29d778c",
            sha256(fixtureBytes),
        )
        JsonParser.parseString(String(fixtureBytes, StandardCharsets.UTF_8)).asJsonObject.also {
            assertEquals(1, it.get("fixture_version").asInt)
            assertEquals("PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT",
                it.get("warning").asString)
        }
    }

    private val endpointAttestationFields = listOf(
        "version", "endpoint_id", "principal_id", "node_id", "binding_id", "binding_epoch",
        "public_identity", "signature",
    )
    private val ownerClaimsFields = listOf(
        "version", "owner_id", "link_id", "contract_digest", "key_binding_digest",
        "expected_link_version", "side", "issued_at", "expires_at", "nonce",
    )

    private fun vectorStatus(): JsonObject = JsonObject().apply {
        // These fields and their DTO meanings match Core CrossOwnerGroupKeyStatus.
        add("manifest", fixture.getAsJsonObject("manifest").deepCopy())
        add("endpoint_consent", fixture.getAsJsonObject("endpoint_consent").deepCopy())
        add("group_admission", fixture.getAsJsonObject("group_admission").deepCopy())
        addProperty("current", true)
    }

    private fun authority(status: JsonObject = vectorStatus()): CrossOwnerGroupKeyV2Verifier.AuthorityContext {
        val manifest = status.getAsJsonObject("manifest")
        val endpointProof = status.getAsJsonObject("endpoint_consent")
        val groupProof = status.getAsJsonObject("group_admission")
        fun ownerAuthority(record: JsonObject, identityField: String) =
            CrossOwnerGroupKeyV2Verifier.OwnerAuthority(
                ownerId = record.get("signer_owner_id").asString,
                keyId = record.get("owner_key_id").asString,
                publicIdentity = ClientWireCrypto.PublicIdentity.parse(
                    fixture.getAsJsonObject(identityField),
                ),
                proofId = record.get("proof_id").asString,
                acceptedAt = record.get("accepted_at").asString,
                grantIssuedAt = ownerGrant(record).get("issued_at").asString,
                grantExpiresAt = ownerGrant(record).get("expires_at").asString,
            )
        return CrossOwnerGroupKeyV2Verifier.AuthorityContext(
            hubId = manifest.get("hub_id").asString,
            networkId = manifest.get("network_id").asString,
            groupId = manifest.get("group_id").asString,
            groupRevision = manifest.get("group_revision").asLong,
            endpointId = manifest.get("endpoint_id").asString,
            principalId = manifest.get("principal_id").asString,
            endpointOwner = ownerAuthority(endpointProof, "endpoint_owner_public_identity"),
            groupOwner = ownerAuthority(groupProof, "group_owner_public_identity"),
            nodeId = manifest.get("node_id").asString,
            bindingId = manifest.get("binding_id").asString,
            bindingEpoch = manifest.get("binding_epoch").asLong,
            membershipRevision = manifest.get("membership_revision").asLong,
            endpointJoinRevision = manifest.get("endpoint_join_revision").asLong,
            candidateVersion = manifest.get("candidate_version").asLong,
            candidatePublicIdentity = ClientWireCrypto.PublicIdentity.parse(
                manifest.getAsJsonObject("candidate_public_identity"),
            ),
            capabilities = manifest.getAsJsonArray("capabilities").map { it.asString },
            manifestExpiresAt = manifest.get("expires_at").asString,
        )
    }

    private fun ownerGrant(record: JsonObject): JsonObject {
        val raw = Base64.getDecoder().decode(record.get("signed_proof").asString)
        return JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
    }

    private fun wire(status: JsonObject): ByteArray =
        status.toString().toByteArray(StandardCharsets.UTF_8)

    private fun parse(raw: ByteArray): JsonObject =
        JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject

    private fun signedProof(status: JsonObject, recordName: String): String {
        val record = status.getAsJsonObject(recordName)
        val raw = Base64.getDecoder().decode(record.get("signed_proof").asString)
        return String(raw, StandardCharsets.UTF_8)
    }

    private fun withSignedProof(
        status: JsonObject,
        recordName: String,
        changedRawProof: String,
    ): JsonObject = status.deepCopy().apply {
        getAsJsonObject(recordName).addProperty("signed_proof",
            Base64.getEncoder().encodeToString(changedRawProof.toByteArray(StandardCharsets.UTF_8)))
    }

    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun assertRejected(
        message: String,
        status: JsonObject = vectorStatus(),
        context: CrossOwnerGroupKeyV2Verifier.AuthorityContext = authority(status),
        now: Instant = validAt,
    ) {
        try {
            CrossOwnerGroupKeyV2Verifier.verify(wire(status), context, now)
            fail(message)
        } catch (_: Exception) {
            // Rejection is expected; do not include synthetic proof bytes in test output.
        }
    }

    private fun assertActionRejected(message: String, action: () -> Unit) {
        try {
            action()
            fail(message)
        } catch (_: Exception) {
            // Rejection is expected; keep malformed synthetic evidence out of logs.
        }
    }

    @Test fun frozenPublicVectorVerifiesEndpointAttestationAndBothOwnerSides() {
        val status = vectorStatus()
        val context = authority(status)
        assertNotEquals(context.endpointOwner.keyId, context.groupOwner.keyId)
        assertNotEquals(context.endpointOwner.publicIdentity?.id, context.groupOwner.publicIdentity?.id)

        val manifest = status.getAsJsonObject("manifest")
        val candidateRaw = Base64.getDecoder().decode(manifest.get("candidate_attestation").asString)
        assertEquals(manifest.get("candidate_proof_digest").asString, sha256(candidateRaw))
        val endpointProofText = String(candidateRaw, StandardCharsets.UTF_8)
        val endpointProof = parse(candidateRaw)
        val unsignedEndpointProof = JsonObject().apply {
            for (field in endpointAttestationFields) {
                if (field == "signature") add(field, JsonNull.INSTANCE)
                else add(field, endpointProof.get(field).deepCopy())
            }
        }
        val endpointSigned = bytes("cicada/fabric/endpoint-key-attestation/v1\u0000") +
            bytes(unsignedEndpointProof.toString())
        assertTrue(endpointProofText.endsWith(",\"signature\":\"${endpointProof.get("signature").asString}\"}"))
        assertTrue(ClientWireCrypto.verify(
            requireNotNull(context.candidatePublicIdentity), endpointSigned,
            Base64.getDecoder().decode(endpointProof.get("signature").asString),
        ))
        val checked = CrossOwnerGroupKeyV2Verifier.verify(wire(status), context, validAt)
        assertEquals(manifest.get("candidate_key_id").asString, checked.publicIdentity.id)
        assertEquals(manifest.get("digest").asString, checked.manifestDigest)
        assertEquals(manifest.get("candidate_binding_digest").asString, checked.candidateBindingDigest)
        assertEquals(Instant.parse("2026-09-30T12:20:00Z"), checked.effectiveExpiresAt)

        for ((recordName, publicField, expectedInputField, expectedHashField) in listOf(
            listOf("endpoint_consent", "endpoint_owner_public_identity",
                "endpoint_consent_signed_input_base64", "endpoint_consent_signed_input_sha256"),
            listOf("group_admission", "group_owner_public_identity",
                "group_admission_signed_input_base64", "group_admission_signed_input_sha256"),
        )) {
            val record = status.getAsJsonObject(recordName)
            val rawGrant = Base64.getDecoder().decode(record.get("signed_proof").asString)
            val grant = parse(rawGrant)
            val claims = JsonObject().apply {
                for (field in ownerClaimsFields) add(field, grant.get(field).deepCopy())
            }
            assertFalse("OwnerLinkKeyGrant v2 signs ten claims without signature", claims.has("signature"))
            assertEquals(ownerClaimsFields, grant.keySet().toList().take(ownerClaimsFields.size))
            val signed = bytes("cicada/communication-link/owner-key-grant/v2\u0000") + bytes(claims.toString())
            assertArrayEquals(Base64.getDecoder().decode(fixture.get(expectedInputField).asString), signed)
            assertEquals(fixture.get(expectedHashField).asString, sha256(signed))
            assertTrue(ClientWireCrypto.verify(
                ClientWireCrypto.PublicIdentity.parse(fixture.getAsJsonObject(publicField)), signed,
                Base64.getDecoder().decode(grant.get("signature").asString),
            ))
        }
    }

    @Test fun exactExternalIdentityAndEveryAuthorityRevisionAreRequired() {
        val status = vectorStatus()
        val expected = authority(status)
        val endpointOwnerPublic = requireNotNull(expected.endpointOwner.publicIdentity)
        val groupOwnerPublic = requireNotNull(expected.groupOwner.publicIdentity)
        val changed = listOf(
            expected.copy(hubId = "hub_other"),
            expected.copy(networkId = "network_other"),
            expected.copy(groupId = "group_other"),
            expected.copy(groupRevision = expected.groupRevision + 1),
            expected.copy(endpointId = "ep_other"),
            expected.copy(principalId = "pr_other"),
            expected.copy(nodeId = "node_other"),
            expected.copy(bindingId = "binding_other"),
            expected.copy(bindingEpoch = expected.bindingEpoch + 1),
            expected.copy(membershipRevision = expected.membershipRevision + 1),
            expected.copy(endpointJoinRevision = expected.endpointJoinRevision + 1),
            expected.copy(candidateVersion = expected.candidateVersion + 1),
            expected.copy(candidatePublicIdentity = endpointOwnerPublic),
            expected.copy(capabilities = listOf("space.write")),
            expected.copy(manifestExpiresAt = "2026-09-30T12:31:00Z"),
            expected.copy(endpointOwner = expected.endpointOwner.copy(ownerId = "owner_other")),
            expected.copy(groupOwner = expected.groupOwner.copy(keyId = endpointOwnerPublic.id)),
            expected.copy(endpointOwner = expected.endpointOwner.copy(publicIdentity = null)),
            expected.copy(groupOwner = expected.groupOwner.copy(publicIdentity = endpointOwnerPublic)),
            expected.copy(groupOwner = expected.groupOwner.copy(
                keyId = endpointOwnerPublic.id, publicIdentity = endpointOwnerPublic,
            )),
            expected.copy(groupOwner = expected.groupOwner.copy(
                grantExpiresAt = "2026-09-30T12:19:00Z",
            )),
            expected.copy(groupOwner = expected.groupOwner.copy(proofId = expected.endpointOwner.proofId)),
            expected.copy(groupOwner = expected.groupOwner.copy(acceptedAt = "2026-09-30T12:01:00Z")),
        )
        assertNotEquals(endpointOwnerPublic.id, groupOwnerPublic.id)
        changed.forEachIndexed { index, context ->
            assertRejected("Changed external authority context $index was accepted", status, context)
        }
    }

    @Test fun exactOwnerRecordsAndBusinessRolesCannotBeSwapped() {
        val valid = vectorStatus()
        val swapped = valid.deepCopy().apply {
            val endpoint = get("endpoint_consent").deepCopy()
            add("endpoint_consent", get("group_admission").deepCopy())
            add("group_admission", endpoint)
        }
        assertRejected("Swapped Endpoint and Group Owner proof records were accepted", swapped)

        val wrongBusinessRole = valid.deepCopy().apply {
            getAsJsonObject("endpoint_consent").addProperty("signer_side", "GROUP")
        }
        assertRejected("Wrong business role was accepted", wrongBusinessRole)

        val wrongSignedSourceSide = withSignedProof(valid, "endpoint_consent",
            signedProof(valid, "endpoint_consent").replace("\"side\":\"SOURCE\"", "\"side\":\"TARGET\""))
        assertRejected("Endpoint Owner grant with TARGET signed side was accepted", wrongSignedSourceSide)

        val wrongSignedTargetSide = withSignedProof(valid, "group_admission",
            signedProof(valid, "group_admission").replace("\"side\":\"TARGET\"", "\"side\":\"SOURCE\""))
        assertRejected("Group Owner grant with SOURCE signed side was accepted", wrongSignedTargetSide)

        val wrongOwner = valid.deepCopy().apply {
            getAsJsonObject("group_admission").addProperty("signer_owner_id",
                getAsJsonObject("endpoint_consent").get("signer_owner_id").asString)
        }
        assertRejected("Wrong Owner identity in Group admission was accepted", wrongOwner)

        val missingProof = valid.deepCopy().apply { remove("group_admission") }
        assertRejected("Missing Group Owner proof was accepted", missingProof, authority(valid))
        val validAuthority = authority(valid)
        val missingOwnerKey = validAuthority.copy(groupOwner = validAuthority.groupOwner.copy(
            publicIdentity = null,
        ))
        assertRejected("Missing independent Group Owner key was accepted", valid, missingOwnerKey)
    }

    @Test fun sharingFlagsCapabilitiesAndCurrentStateAreChecked() {
        val valid = vectorStatus()
        val history = valid.deepCopy().apply {
            getAsJsonObject("manifest").addProperty("history_included", true)
        }
        assertRejected("History inclusion was accepted", history)
        val noContext = valid.deepCopy().apply {
            getAsJsonObject("manifest").addProperty("cross_owner_context_shared", false)
        }
        assertRejected("Missing cross-owner context sharing was accepted", noContext)
        val changedCapabilities = valid.deepCopy().apply {
            getAsJsonObject("manifest").add("capabilities", JsonParser.parseString("[\"space.write\"]"))
        }
        assertRejected("Changed capability set was accepted", changedCapabilities)
        val stale = valid.deepCopy().apply { addProperty("current", false) }
        assertRejected("Stale Group key status was accepted", stale)
        val revoked = valid.deepCopy().apply {
            getAsJsonObject("group_admission").addProperty("current_status", "REVOKED")
        }
        assertRejected("Revoked Group Owner approval was accepted", revoked)
    }

    @Test fun expiryIsCheckedForManifestAndBothSignedOwnerGrants() {
        val status = vectorStatus()
        assertRejected("Expired manifest was accepted", status, authority(status),
            Instant.parse("2026-09-30T12:30:00Z"))
        assertRejected("Expired Owner grants were accepted", status, authority(status),
            Instant.parse("2026-09-30T12:20:00Z"))
        assertRejected("Future-issued Owner grant was accepted", status, authority(status),
            Instant.parse("2026-09-30T11:58:00Z"))

        val changedManifestExpiry = status.deepCopy().apply {
            getAsJsonObject("manifest").addProperty("expires_at", "2026-09-30T12:19:00Z")
        }
        assertRejected("Changed manifest expiry was accepted", changedManifestExpiry)
        val changedOwnerExpiry = status.deepCopy().apply {
            getAsJsonObject("endpoint_consent").addProperty("accepted_at", "2026-09-30T12:21:00Z")
        }
        assertRejected("Owner proof accepted after its grant expiry was accepted", changedOwnerExpiry)
    }

    @Test fun ownerProofCanonicalizationRejectsDuplicatesUnknownsPaddingAndIntegers() {
        val status = vectorStatus()
        for (recordName in listOf("endpoint_consent", "group_admission")) {
            val raw = signedProof(status, recordName)
            val signature = parse(raw.toByteArray(StandardCharsets.UTF_8)).get("signature").asString
            val deeplyNested = raw.replaceFirst(
                "{\"version\":2,",
                "{\"nested\":" + "[".repeat(40) + "0" + "]".repeat(40) + ",\"version\":2,",
            )
            val cases = listOf(
                raw.replaceFirst("{\"version\":2,", "{\"version\":2,\"version\":2,"),
                raw.replaceFirst("{", "{\"unknown\":0,"),
                raw.replace("\"signature\":\"$signature\"",
                    "\"signature\":\"${signature}=\""),
                raw.replaceFirst("\"version\":2", "\"version\":2.0"),
                raw.replaceFirst("\"side\":\"${if (recordName == "endpoint_consent") "SOURCE" else "TARGET"}\"",
                    "\"side\":\"${if (recordName == "endpoint_consent") "TARGET" else "SOURCE"}\""),
                deeplyNested,
            )
            for ((index, changed) in cases.withIndex()) {
                assertRejected("Noncanonical Owner proof $recordName case $index was accepted",
                    withSignedProof(status, recordName, changed))
            }
        }
        val unknownRecordField = status.deepCopy().apply {
            getAsJsonObject("endpoint_consent").addProperty("unexpected", "field")
        }
        assertRejected("Unknown Owner proof record field was accepted", unknownRecordField)
        val missingSignedProof = status.deepCopy().apply {
            getAsJsonObject("group_admission").remove("signed_proof")
        }
        assertRejected("Missing signed Owner grant was accepted", missingSignedProof, authority(status))
    }

    @Test fun endpointAttestationCanonicalizationRejectsDuplicateUnknownPaddingAndIntegers() {
        val manifest = fixture.getAsJsonObject("manifest")
        val original = Base64.getDecoder().decode(manifest.get("candidate_attestation").asString)
        val proofText = String(original, StandardCharsets.UTF_8)
        val signature = parse(original).get("signature").asString
        val altered = listOf(
            proofText.replaceFirst("{\"version\":1,", "{\"version\":1,\"version\":1,"),
            proofText.replaceFirst("{", "{\"unknown\":true,"),
            proofText.replace("\"signature\":\"$signature\"",
                "\"signature\":\"${signature}=\""),
            proofText.replaceFirst("\"version\":1", "\"version\":1.0"),
        )
        val public = manifest.getAsJsonObject("candidate_public_identity")
        for ((index, changedText) in altered.withIndex()) {
            val changed = changedText.toByteArray(StandardCharsets.UTF_8)
            assertActionRejected("Endpoint proof canonicality case $index was accepted") {
                GroupKeyManifestVerifier.verifyProof(
                    changed, manifest.get("endpoint_id").asString,
                    manifest.get("principal_id").asString, manifest.get("node_id").asString,
                    manifest.get("binding_id").asString, manifest.get("binding_epoch").asLong,
                    public, sha256(changed),
                )
            }
        }
        val paddedAttestation = vectorStatus().apply {
            val current = getAsJsonObject("manifest").get("candidate_attestation").asString
            getAsJsonObject("manifest").addProperty("candidate_attestation", "$current=")
        }
        assertRejected("Noncanonical padded Endpoint attestation base64 was accepted", paddedAttestation)
    }

    @Test fun endpointAndOwnerSignaturesBindDifferentCanonicalByteShapes() {
        val status = vectorStatus()
        val candidateRaw = Base64.getDecoder().decode(
            status.getAsJsonObject("manifest").get("candidate_attestation").asString,
        )
        val endpointText = String(candidateRaw, StandardCharsets.UTF_8)
        val endpointPrefix = endpointText.substringBeforeLast(",\"signature\":\"")
        val endpointNullSignatureBytes = bytes(
            "cicada/fabric/endpoint-key-attestation/v1\u0000$endpointPrefix,\"signature\":null}",
        )
        val endpointProof = parse(candidateRaw)
        val candidatePublic = ClientWireCrypto.PublicIdentity.parse(
            endpointProof.getAsJsonObject("public_identity"),
        )
        assertTrue(ClientWireCrypto.verify(candidatePublic, endpointNullSignatureBytes,
            Base64.getDecoder().decode(endpointProof.get("signature").asString)))

        val ownerRaw = Base64.getDecoder().decode(
            status.getAsJsonObject("endpoint_consent").get("signed_proof").asString,
        )
        val ownerProof = parse(ownerRaw)
        val ownerClaims = JsonObject().apply {
            for (field in ownerClaimsFields) add(field, ownerProof.get(field).deepCopy())
        }
        val claimsOnlyBytes = bytes("cicada/communication-link/owner-key-grant/v2\u0000") +
            bytes(ownerClaims.toString())
        val ownerPublic = ClientWireCrypto.PublicIdentity.parse(
            fixture.getAsJsonObject("endpoint_owner_public_identity"),
        )
        val ownerSignature = Base64.getDecoder().decode(ownerProof.get("signature").asString)
        assertTrue(ClientWireCrypto.verify(ownerPublic, claimsOnlyBytes, ownerSignature))
        val withNullSignature = bytes("cicada/communication-link/owner-key-grant/v2\u0000") +
            bytes(ownerClaims.deepCopy().apply { add("signature", JsonNull.INSTANCE) }.toString())
        assertFalse(ClientWireCrypto.verify(ownerPublic, withNullSignature, ownerSignature))
        val withOmittedEndpointSignature = bytes(
            "cicada/fabric/endpoint-key-attestation/v1\u0000" + endpointPrefix + "}",
        )
        assertFalse(ClientWireCrypto.verify(candidatePublic, withOmittedEndpointSignature,
            Base64.getDecoder().decode(endpointProof.get("signature").asString)))
    }

    @Test fun statusParserRejectsInvalidTypesAndBoundsUntrustedJson() {
        val context = authority()
        val canonical = String(wire(vectorStatus()), StandardCharsets.UTF_8)
        for (raw in listOf(
            bytes(canonical.replace("\"current\":true", "\"current\":TRUE")),
            bytes("\uFEFF$canonical"),
            byteArrayOf(0xc3.toByte(), 0x28),
            bytes(canonical + "{}"),
        )) {
            assertActionRejected("Invalid status JSON was accepted") {
                CrossOwnerGroupKeyV2Verifier.verify(raw, context, validAt)
            }
        }
        for (field in listOf("manifest", "endpoint_consent", "group_admission")) {
            val status = vectorStatus().apply { add(field, JsonNull.INSTANCE) }
            assertRejected("Missing typed proof object was accepted", status, context)
        }
        val boundedInputs = listOf(
            bytes("{\"extra\":" + "[".repeat(40) + "0" + "]".repeat(40) + "}") to "nesting limit",
            bytes("{\"extra\":[" + List(9000) { "0" }.joinToString(",") + "]}") to "item limit",
            bytes("{\"extra\":" + "9".repeat(64) + "}") to "Integer overflow",
        )
        for ((raw, expectedReason) in boundedInputs) {
            try {
                CrossOwnerGroupKeyV2Verifier.verify(raw, context, validAt)
                fail("Untrusted JSON resource limit was not enforced")
            } catch (error: IllegalArgumentException) {
                assertTrue("Parser rejected for the wrong reason",
                    error.message?.contains(expectedReason) == true)
            }
        }
        // Gson may reject an oversized numeric token before our Long overflow guard.
        assertActionRejected("Oversized numeric token was accepted") {
            CrossOwnerGroupKeyV2Verifier.verify(
                bytes("{\"extra\":" + "9".repeat(10_000) + "}"), context, validAt,
            )
        }
    }

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)
}
